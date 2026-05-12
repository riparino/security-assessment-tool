"""SSL/TLS analysis scanner."""
from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any

from src.models import ScanResult


def run(host: str, port: int = 443, timeout: int = 15) -> ScanResult:
    """Analyse SSL/TLS configuration for the given host:port."""
    start = time.monotonic()
    parsed: dict[str, Any] = {}
    lines: list[str] = []

    # --- Certificate info ---
    cert_info, cert_error = _get_certificate(host, port, timeout)
    if cert_error:
        parsed["error"] = cert_error
        lines.append(f"Certificate retrieval error: {cert_error}")
    else:
        parsed.update(cert_info)  # type: ignore[arg-type]
        for k, v in cert_info.items():  # type: ignore[union-attr]
            lines.append(f"{k}: {v}")

    # --- Protocol & cipher probe ---
    proto_results = _probe_protocols(host, port, timeout)
    parsed["protocol_support"] = proto_results
    for proto, supported in proto_results.items():
        flag = "✓" if supported else "✗"
        lines.append(f"Protocol {proto}: {flag}")

    raw = "\n".join(lines)
    duration = time.monotonic() - start

    return ScanResult(
        probe_type="ssl_check",
        probe_name="SSL/TLS Analysis",
        target=f"{host}:{port}",
        raw_output=raw,
        parsed_data=parsed,
        duration_seconds=round(duration, 2),
    )


def _get_certificate(host: str, port: int, timeout: int) -> tuple[dict | None, str | None]:
    """Return (cert_dict, error_string). Only one is non-None."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                proto = ssock.version()

        # Parse expiry
        not_after_str = cert.get("notAfter", "")
        not_before_str = cert.get("notBefore", "")
        try:
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days_remaining = (not_after - datetime.now(timezone.utc)).days
        except ValueError:
            not_after = None
            days_remaining = None

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        sans = [
            v for t, v in cert.get("subjectAltName", []) if t == "DNS"
        ]

        return {
            "subject_cn": subject.get("commonName", ""),
            "issuer_cn": issuer.get("commonName", ""),
            "not_before": not_before_str,
            "not_after": not_after_str,
            "days_until_expiry": days_remaining,
            "san": sans,
            "negotiated_protocol": proto,
            "negotiated_cipher": cipher[0] if cipher else "",
            "cipher_bits": cipher[2] if cipher else 0,
        }, None

    except ssl.SSLCertVerificationError as exc:
        return None, f"Certificate verification failed: {exc}"
    except ssl.SSLError as exc:
        return None, f"SSL error: {exc}"
    except (ConnectionRefusedError, socket.timeout, OSError) as exc:
        return None, f"Connection error: {exc}"


def _probe_protocols(host: str, port: int, timeout: int) -> dict[str, bool]:
    """Probe which TLS protocol versions the server accepts."""
    results: dict[str, bool] = {}

    # Map of label → ssl.PROTOCOL_* or minimum_version
    probes: list[tuple[str, ssl.TLSVersion | None]] = [
        ("TLSv1.0", ssl.TLSVersion.TLSv1),   # type: ignore[attr-defined]
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1), # type: ignore[attr-defined]
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ]

    for label, version in probes:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version  # type: ignore[assignment]
            ctx.maximum_version = version  # type: ignore[assignment]
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    results[label] = True
        except (ssl.SSLError, OSError, socket.timeout):
            results[label] = False

    return results
