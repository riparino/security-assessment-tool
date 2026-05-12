"""DNS enumeration scanner."""
from __future__ import annotations

import time
from typing import Any

import dns.exception
import dns.resolver
import dns.query
import dns.zone

from src.models import ScanResult


_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]

# Patterns that may indicate subdomain takeover risk
_TAKEOVER_PATTERNS = [
    "azurewebsites.net",
    "github.io",
    "herokuapp.com",
    "s3.amazonaws.com",
    "cloudfront.net",
    "ghost.io",
    "fastly.net",
]


def run(target_host: str, timeout: int = 15) -> ScanResult:
    """Perform DNS enumeration on the target host."""
    start = time.monotonic()
    records: dict[str, Any] = {}
    lines: list[str] = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    for rtype in _RECORD_TYPES:
        try:
            answers = resolver.resolve(target_host, rtype)
            values = [str(r) for r in answers]
            records[rtype] = values
            lines.append(f"{rtype}: {', '.join(values)}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            records[rtype] = []
        except dns.exception.DNSException as exc:
            records[rtype] = [f"ERROR: {exc}"]

    # Zone transfer attempt (should fail on well-configured servers; failure is expected)
    zone_transfer_result = _attempt_zone_transfer(target_host, records.get("NS", []))
    records["zone_transfer"] = zone_transfer_result
    lines.append(f"Zone transfer: {zone_transfer_result}")

    # Dangling CNAME check
    cnames = records.get("CNAME", [])
    dangling = _check_dangling_cname(cnames)
    if dangling:
        records["dangling_cname_risk"] = dangling
        lines.append(f"⚠ Possible dangling CNAME: {dangling}")

    raw = "\n".join(lines)
    duration = time.monotonic() - start

    return ScanResult(
        probe_type="dns_query",
        probe_name="DNS Enumeration",
        target=target_host,
        raw_output=raw,
        parsed_data=records,
        duration_seconds=round(duration, 2),
    )


def _attempt_zone_transfer(host: str, ns_servers: list[str]) -> str:
    """Try AXFR against each NS server; return outcome string."""
    for ns_raw in ns_servers:
        ns = ns_raw.rstrip(".")
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, host, timeout=5))
            names = list(zone.nodes.keys())
            return f"VULNERABLE – zone transfer succeeded on {ns}: {names[:10]}"
        except Exception:
            pass
    return "Refused (expected)"


def _check_dangling_cname(cnames: list[str]) -> str | None:
    """Check if a CNAME points to a known cloud service that may be unclaimed."""
    for cname in cnames:
        for pattern in _TAKEOVER_PATTERNS:
            if pattern in cname:
                # Check if the target itself resolves
                try:
                    dns.resolver.resolve(cname.rstrip("."), "A")
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    return f"{cname} → possible subdomain takeover via {pattern}"
    return None
