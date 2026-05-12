"""Pydantic data models for the security assessment tool."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "white",
}

# Lower number = higher severity
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    severity: Severity
    title: str
    description: str
    evidence: str
    remediation: str
    cve: Optional[str] = None
    cwe: Optional[str] = None
    probe_source: str = "unknown"
    timestamp: datetime = Field(default_factory=datetime.now)


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


class ProbeType(str, Enum):
    HTTP_REQUEST = "http_request"
    PORT_SCAN = "port_scan"
    SSL_CHECK = "ssl_check"
    DNS_QUERY = "dns_query"
    SAML_PROBE = "saml_probe"
    NIKTO_SCAN = "nikto_scan"
    HEADER_CHECK = "header_check"
    CUSTOM = "custom"


class ProbeParameters(BaseModel):
    """Structured parameters for executing any probe type."""

    url: Optional[str] = None
    host: Optional[str] = None
    ports: Optional[str] = None
    method: str = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    params: dict[str, str] = Field(default_factory=dict)
    follow_redirects: bool = True
    timeout: int = 30
    extra_args: dict[str, Any] = Field(default_factory=dict)


class NextProbe(BaseModel):
    type: ProbeType
    description: str
    reasoning: str
    parameters: ProbeParameters
    expected_outcome: str
    risk_level: str = "Low"  # Risk to the target system of running this probe


# ---------------------------------------------------------------------------
# LLM output
# ---------------------------------------------------------------------------


class LLMAnalysis(BaseModel):
    findings: list[Finding]
    risk_summary: str
    overall_severity: Severity
    next_probe: Optional[NextProbe] = None
    analyst_notes: str = ""


# ---------------------------------------------------------------------------
# Scan results
# ---------------------------------------------------------------------------


class ScanResult(BaseModel):
    probe_type: str
    probe_name: str
    target: str
    raw_output: str
    parsed_data: dict[str, Any] = Field(default_factory=dict)
    success: bool = True
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


class AssessmentSession(BaseModel):
    session_id: str
    target_url: str
    target_host: str
    target_ip: Optional[str] = None
    started_at: datetime = Field(default_factory=datetime.now)
    scan_results: list[ScanResult] = Field(default_factory=list)
    analyses: list[LLMAnalysis] = Field(default_factory=list)
    all_findings: list[Finding] = Field(default_factory=list)

    def add_result(self, result: ScanResult) -> None:
        self.scan_results.append(result)

    def add_analysis(self, analysis: LLMAnalysis) -> None:
        self.analyses.append(analysis)
        # Merge findings, deduplicating by title
        existing_titles = {f.title for f in self.all_findings}
        for finding in analysis.findings:
            if finding.title not in existing_titles:
                self.all_findings.append(finding)
                existing_titles.add(finding.title)

    @property
    def highest_severity(self) -> Severity:
        if not self.all_findings:
            return Severity.INFO
        return min(
            self.all_findings,
            key=lambda f: SEVERITY_ORDER[f.severity],
        ).severity

    @property
    def findings_by_severity(self) -> list[Finding]:
        return sorted(
            self.all_findings,
            key=lambda f: SEVERITY_ORDER[f.severity],
        )
