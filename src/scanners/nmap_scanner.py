"""Nmap port and service scanner — subprocess wrapper with XML output parsing."""
from __future__ import annotations

import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Any

from src.models import ScanResult


def is_available() -> bool:
    return shutil.which("nmap") is not None


def run(
    target: str,
    ports: str = "21,22,23,25,53,80,110,143,443,445,993,995,1723,3306,3389,5900,8080,8443,8000,9000,9090,9443",
    timeout: int = 180,
    service_detection: bool = True,
) -> ScanResult:
    """
    Run an nmap TCP connect scan against the target.

    Uses -sV for service/version detection and -sC for default safe NSE scripts.
    The target must already be validated (hostname or IP only — no shell metacharacters).
    """
    start = time.monotonic()

    if not is_available():
        return ScanResult(
            probe_type="port_scan",
            probe_name="Nmap Port Scan",
            target=target,
            raw_output="nmap is not installed or not in PATH.",
            parsed_data={"available": False},
            success=False,
            error="nmap not found",
            duration_seconds=0.0,
        )

    cmd: list[str] = [
        shutil.which("nmap"),  # type: ignore[list-item]
        "-sT",        # TCP connect scan (no root required)
        "-p", ports,
        "--open",     # Only show open ports
        "-oX", "-",   # XML output to stdout
        "--host-timeout", str(timeout) + "s",
        "--max-retries", "1",
    ]
    if service_detection:
        cmd += ["-sV", "--version-intensity", "5"]
        cmd += ["-sC"]  # default safe NSE scripts

    cmd.append(target)

    try:
        proc = subprocess.run(  # noqa: S603  # target is pre-validated
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 30,
        )
    except subprocess.TimeoutExpired:
        duration = time.monotonic() - start
        return ScanResult(
            probe_type="port_scan",
            probe_name="Nmap Port Scan",
            target=target,
            raw_output="Scan timed out.",
            parsed_data={},
            success=False,
            error="Timeout",
            duration_seconds=round(duration, 2),
        )

    duration = time.monotonic() - start
    parsed = _parse_xml(proc.stdout)
    raw = _format_text(parsed) or proc.stdout or proc.stderr

    return ScanResult(
        probe_type="port_scan",
        probe_name="Nmap Port Scan",
        target=target,
        raw_output=raw,
        parsed_data=parsed,
        success=proc.returncode in (0, 1),
        error=proc.stderr[:500] if proc.returncode not in (0, 1) else None,
        duration_seconds=round(duration, 2),
    )


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------


def _parse_xml(xml_text: str) -> dict[str, Any]:
    if not xml_text.strip().startswith("<"):
        return {"raw": xml_text}

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {"parse_error": True, "raw": xml_text[:2000]}

    hosts: list[dict[str, Any]] = []
    for host_el in root.findall("host"):
        host_data: dict[str, Any] = {}

        # Address
        addr_el = host_el.find("address")
        if addr_el is not None:
            host_data["address"] = addr_el.get("addr", "")
            host_data["addr_type"] = addr_el.get("addrtype", "")

        # Status
        status_el = host_el.find("status")
        if status_el is not None:
            host_data["status"] = status_el.get("state", "")

        # Ports
        ports: list[dict[str, Any]] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port: dict[str, Any] = {
                    "protocol": port_el.get("protocol", ""),
                    "portid": port_el.get("portid", ""),
                }
                state_el = port_el.find("state")
                if state_el is not None:
                    port["state"] = state_el.get("state", "")
                svc_el = port_el.find("service")
                if svc_el is not None:
                    port["service"] = svc_el.get("name", "")
                    port["product"] = svc_el.get("product", "")
                    port["version"] = svc_el.get("version", "")
                    port["extrainfo"] = svc_el.get("extrainfo", "")
                # NSE script output
                scripts: dict[str, str] = {}
                for script_el in port_el.findall("script"):
                    scripts[script_el.get("id", "")] = script_el.get("output", "")
                if scripts:
                    port["scripts"] = scripts
                ports.append(port)
        host_data["ports"] = ports

        # OS detection
        os_el = host_el.find("os")
        if os_el is not None:
            matches = [
                {
                    "name": m.get("name", ""),
                    "accuracy": m.get("accuracy", ""),
                }
                for m in os_el.findall("osmatch")
            ]
            if matches:
                host_data["os_matches"] = matches[:3]

        hosts.append(host_data)

    return {"hosts": hosts}


def _format_text(parsed: dict[str, Any]) -> str:
    lines: list[str] = []
    for host in parsed.get("hosts", []):
        lines.append(f"Host: {host.get('address')} ({host.get('status')})")
        for p in host.get("ports", []):
            svc = p.get("service", "")
            product = p.get("product", "")
            version = p.get("version", "")
            svc_str = " ".join(filter(None, [svc, product, version]))
            lines.append(
                f"  {p['portid']}/{p['protocol']}  {p.get('state', '')}  {svc_str}"
            )
            for script_id, output in p.get("scripts", {}).items():
                lines.append(f"    [NSE:{script_id}] {output[:300]}")
        for os_m in host.get("os_matches", []):
            lines.append(f"  OS: {os_m['name']} ({os_m['accuracy']}% accuracy)")
    return "\n".join(lines)
