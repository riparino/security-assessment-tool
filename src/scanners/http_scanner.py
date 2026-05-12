"""HTTP/HTTPS security analysis scanner — headers, cookies, CORS, SAML probes."""
from __future__ import annotations

import time
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
import urllib3

from src.models import ScanResult

# Suppress warnings when TLS verification is disabled (analyst opt-in only)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_USER_AGENT = (
    "SecurityAssessment/1.0 (Internal Authorized Scanner)"
)

# Security headers and their recommended values / presence check
_SECURITY_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "max-age",
    "Content-Security-Policy": "",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "",
    "Referrer-Policy": "",
    "Permissions-Policy": "",
    "Cache-Control": "",
}

_LEAKY_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "Via",
]

_INTERESTING_PATHS = [
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    ".well-known/change-password",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    "web.config",
    ".env",
    ".git/HEAD",
    "admin",
    "api",
    "swagger",
    "swagger/index.html",
    "openapi.json",
    "health",
    "actuator/health",
    "metrics",
]

_SAML_PATHS = [
    "saml/metadata",
    "saml2/metadata",
    "saml/idp/metadata",
    "Saml2/Idp/metadata",
    "federation/metadata",
    "wsfed",
    ".well-known/openid-configuration",
]


def run(
    target_url: str,
    verify_tls: bool = True,
    timeout: int = 15,
    rate_delay: float = 0.3,
) -> ScanResult:
    """Run the full HTTP security scan suite."""
    start = time.monotonic()
    parsed_url = urlparse(target_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

    session = requests.Session()
    session.headers["User-Agent"] = _USER_AGENT

    results: dict[str, Any] = {}
    lines: list[str] = []

    # 1. Baseline request to the supplied URL
    baseline = _fetch(session, target_url, verify=verify_tls, timeout=timeout)
    results["baseline"] = baseline
    lines.append(f"=== Baseline: {target_url} ===")
    lines += _format_baseline(baseline)

    # 2. Security headers analysis
    time.sleep(rate_delay)
    header_findings = _check_security_headers(baseline.get("response_headers", {}))
    results["security_headers"] = header_findings
    lines.append("\n=== Security Headers ===")
    for item in header_findings:
        lines.append(item)

    # 3. Cookie analysis
    cookie_findings = _check_cookies(baseline.get("cookies", {}))
    results["cookies"] = cookie_findings
    lines.append("\n=== Cookies ===")
    for item in cookie_findings:
        lines.append(item)

    # 4. CORS check
    time.sleep(rate_delay)
    cors = _check_cors(session, target_url, verify=verify_tls, timeout=timeout)
    results["cors"] = cors
    lines.append("\n=== CORS ===")
    lines.append(cors)

    # 5. Redirect chain
    results["redirect_chain"] = baseline.get("redirect_chain", [])
    if baseline.get("redirect_chain"):
        lines.append("\n=== Redirect Chain ===")
        for r in baseline["redirect_chain"]:
            lines.append(r)

    # 6. Error page disclosure
    time.sleep(rate_delay)
    error_info = _check_error_page(session, base_url, verify=verify_tls, timeout=timeout)
    results["error_disclosure"] = error_info
    lines.append("\n=== Error Page Info Disclosure ===")
    lines.append(error_info)

    # 7. Interesting paths probe
    lines.append("\n=== Interesting Path Discovery ===")
    path_results: dict[str, int] = {}
    for path in _INTERESTING_PATHS:
        time.sleep(rate_delay)
        url = urljoin(base_url + "/", path)
        resp = _fetch(session, url, verify=verify_tls, timeout=timeout)
        status = resp.get("status_code", 0)
        path_results[path] = status
        if status not in (404, 403, 401):
            lines.append(f"  {path}: HTTP {status}")
    results["path_discovery"] = path_results

    # 8. SAML-specific probes (if endpoint looks like SAML)
    is_saml = "saml" in target_url.lower() or "sso" in target_url.lower()
    if is_saml:
        lines.append("\n=== SAML-Specific Probes ===")
        saml_results = _saml_probes(
            session, base_url, target_url, verify=verify_tls, timeout=timeout,
            rate_delay=rate_delay,
        )
        results["saml_probes"] = saml_results
        for key, val in saml_results.items():
            lines.append(f"  {key}: {val}")

    raw = "\n".join(lines)
    duration = time.monotonic() - start

    return ScanResult(
        probe_type="http_request",
        probe_name="HTTP Security Analysis",
        target=target_url,
        raw_output=raw,
        parsed_data=results,
        duration_seconds=round(duration, 2),
    )


def run_custom_http(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    body: str | None = None,
    verify_tls: bool = True,
    timeout: int = 15,
) -> ScanResult:
    """Execute a single custom HTTP request (LLM-directed probe)."""
    start = time.monotonic()
    session = requests.Session()
    session.headers["User-Agent"] = _USER_AGENT
    if headers:
        session.headers.update(headers)

    result = _fetch(
        session,
        url,
        method=method,
        params=params or {},
        data=body,
        verify=verify_tls,
        timeout=timeout,
    )
    lines = _format_baseline(result)
    duration = time.monotonic() - start

    return ScanResult(
        probe_type="http_request",
        probe_name=f"Custom HTTP {method} → {url}",
        target=url,
        raw_output="\n".join(lines),
        parsed_data=result,
        duration_seconds=round(duration, 2),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _fetch(
    session: requests.Session,
    url: str,
    method: str = "GET",
    params: dict | None = None,
    data: str | None = None,
    verify: bool = True,
    timeout: int = 15,
) -> dict[str, Any]:
    """Make an HTTP request and return a structured result dict."""
    try:
        resp = session.request(
            method=method,
            url=url,
            params=params,
            data=data,
            allow_redirects=True,
            verify=verify,
            timeout=timeout,
        )
        redirect_chain = [r.url for r in resp.history]
        cookies_parsed: dict[str, Any] = {}
        for cookie in resp.cookies:
            rest = getattr(cookie, "_rest", {}) or {}
            cookies_parsed[cookie.name] = {
                "value": cookie.value,
                "secure": bool(cookie.secure),
                "httponly": bool(rest.get("HttpOnly")),
                "samesite": rest.get("SameSite"),
                "expires": cookie.expires,
            }
        return {
            "status_code": resp.status_code,
            "final_url": resp.url,
            "redirect_chain": redirect_chain,
            "response_headers": dict(resp.headers),
            "cookies": cookies_parsed,
            "body_excerpt": resp.text[:2000],
            "content_length": len(resp.content),
        }
    except requests.exceptions.SSLError as exc:
        return {"error": f"SSL error: {exc}", "status_code": 0}
    except requests.exceptions.ConnectionError as exc:
        return {"error": f"Connection error: {exc}", "status_code": 0}
    except requests.exceptions.Timeout:
        return {"error": "Request timed out", "status_code": 0}
    except requests.exceptions.RequestException as exc:
        return {"error": str(exc), "status_code": 0}


def _format_baseline(data: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    if "error" in data:
        lines.append(f"  ERROR: {data['error']}")
        return lines
    lines.append(f"  Status: {data.get('status_code')}")
    lines.append(f"  Final URL: {data.get('final_url')}")
    lines.append(f"  Content-Length: {data.get('content_length', 0)} bytes")
    for h in _LEAKY_HEADERS:
        val = data.get("response_headers", {}).get(h)
        if val:
            lines.append(f"  {h}: {val}")
    return lines


def _check_security_headers(headers: dict[str, str]) -> list[str]:
    findings: list[str] = []
    normalised = {k.lower(): v for k, v in headers.items()}
    for header, expected_value in _SECURITY_HEADERS.items():
        present = normalised.get(header.lower())
        if present:
            findings.append(f"  [PRESENT]  {header}: {present}")
            if expected_value and expected_value not in present:
                findings.append(
                    f"  [WARN]     {header} present but may lack '{expected_value}'"
                )
        else:
            findings.append(f"  [MISSING]  {header}")
    return findings


def _check_cookies(cookies: dict[str, Any]) -> list[str]:
    if not cookies:
        return ["  No cookies set on this response."]
    lines: list[str] = []
    for name, attrs in cookies.items():
        secure = attrs.get("secure", False)
        httponly = attrs.get("httponly", False)
        samesite = attrs.get("samesite")
        issues = []
        if not secure:
            issues.append("Secure flag missing")
        if not httponly:
            issues.append("HttpOnly flag missing")
        if not samesite:
            issues.append("SameSite not set")
        status = "✓ OK" if not issues else f"⚠ {', '.join(issues)}"
        lines.append(f"  {name}: {status}")
    return lines


def _check_cors(
    session: requests.Session, url: str, verify: bool, timeout: int
) -> str:
    """Send an Origin header and inspect the CORS response."""
    try:
        resp = session.options(
            url,
            headers={"Origin": "https://evil.example.com"},
            verify=verify,
            timeout=timeout,
            allow_redirects=False,
        )
        acao = resp.headers.get("Access-Control-Allow-Origin", "Not set")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "Not set")
        return (
            f"Access-Control-Allow-Origin: {acao} | "
            f"Access-Control-Allow-Credentials: {acac}"
        )
    except requests.exceptions.RequestException as exc:
        return f"CORS probe failed: {exc}"


def _check_error_page(
    session: requests.Session, base_url: str, verify: bool, timeout: int
) -> str:
    """Request a non-existent path and look for stack traces or version info."""
    probe_url = f"{base_url}/security-probe-nonexistent-path-{int(time.time())}"
    resp = _fetch(session, probe_url, verify=verify, timeout=timeout)
    body = resp.get("body_excerpt", "")
    sensitive_patterns = [
        "stack trace", "exception", "at System.", "at Microsoft.",
        "ASP.NET", "Server Error", "DEBUG", "traceback", "line ",
    ]
    found = [p for p in sensitive_patterns if p.lower() in body.lower()]
    if found:
        return f"Potential disclosure in 404 page: {found}"
    return f"HTTP {resp.get('status_code')} — no obvious disclosure"


def _saml_probes(
    session: requests.Session,
    base_url: str,
    original_url: str,
    verify: bool,
    timeout: int,
    rate_delay: float,
) -> dict[str, Any]:
    """SAML-specific lightweight probes."""
    results: dict[str, Any] = {}

    # Metadata endpoints
    for path in _SAML_PATHS:
        time.sleep(rate_delay)
        url = urljoin(base_url + "/", path)
        resp = _fetch(session, url, verify=verify, timeout=timeout)
        status = resp.get("status_code", 0)
        if status == 200:
            body = resp.get("body_excerpt", "")
            contains_xml = "<" in body and "EntityDescriptor" in body
            results[path] = f"HTTP 200 – {'XML metadata exposed' if contains_xml else 'accessible'}"
        else:
            results[path] = f"HTTP {status}"

    # Open redirect via RelayState
    time.sleep(rate_delay)
    evil_relay = "https://evil.example.com"
    redirect_url = f"{original_url}?RelayState={evil_relay}"
    resp = _fetch(session, redirect_url, verify=verify, timeout=timeout)
    final = resp.get("final_url", "")
    if "evil.example.com" in final:
        results["relay_state_open_redirect"] = f"VULNERABLE – redirected to {final}"
    else:
        results["relay_state_open_redirect"] = f"Not vulnerable (landed on {final})"

    # Missing SAMLRequest parameter – does it leak an error?
    time.sleep(rate_delay)
    resp = _fetch(session, original_url, verify=verify, timeout=timeout)
    body = resp.get("body_excerpt", "")
    if any(kw in body for kw in ["exception", "stack", "error", "null", "NullReference"]):
        results["missing_saml_request_error"] = f"Potential error disclosure: {body[:200]}"
    else:
        results["missing_saml_request_error"] = "No obvious error disclosed"

    return results
