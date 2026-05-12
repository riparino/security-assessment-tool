"""Shared utilities: input validation, formatting helpers."""
from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse


# Strict allowlist for valid hostname characters
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")


def validate_target(raw: str) -> tuple[str, str]:
    """
    Validate the user-supplied target and return (hostname_or_ip, original_url).

    Raises ValueError for anything that doesn't look like a URL or IP address.
    This is critical to prevent command injection into scanner subprocesses.
    """
    original = raw.strip()

    # --- Try as a full URL ---
    try:
        parsed = urlparse(original)
        if parsed.scheme in ("http", "https") and parsed.hostname:
            hostname = parsed.hostname.lower()
            _validate_hostname_or_ip(hostname)
            return hostname, original
    except Exception:
        pass

    # --- Try as a bare IP ---
    try:
        ipaddress.ip_address(original)
        return original, original
    except ValueError:
        pass

    # --- Try as a bare hostname ---
    clean = original.lower()
    _validate_hostname_or_ip(clean)
    return clean, clean


def _validate_hostname_or_ip(value: str) -> None:
    """Raise ValueError if value is neither a valid hostname nor a valid IP."""
    try:
        ipaddress.ip_address(value)
        return
    except ValueError:
        pass

    if not _HOSTNAME_RE.match(value):
        raise ValueError(
            f"'{value}' is not a valid hostname or IP address. "
            "Only alphanumeric characters, hyphens, and dots are allowed."
        )
    if len(value) > 253:
        raise ValueError(f"Hostname too long: {value!r}")


def resolve_ip(hostname: str) -> str | None:
    """Resolve a hostname to its first IPv4 address, or None on failure."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def safe_truncate(text: str, max_chars: int = 4000) -> str:
    """Truncate text for LLM context windows while preserving structure."""
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    return text[:half] + "\n... [truncated] ...\n" + text[-half:]
