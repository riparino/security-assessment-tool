"""LLM-powered security analyst — drives adaptive probe selection."""
from __future__ import annotations

import json
import textwrap
from typing import Any

from azure.identity import AzureCliCredential, get_bearer_token_provider
from openai import AzureOpenAI, OpenAI

from src.config import Config
from src.models import (
    AssessmentSession,
    Finding,
    LLMAnalysis,
    NextProbe,
    ProbeParameters,
    ProbeType,
    ScanResult,
    Severity,
)

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = textwrap.dedent("""
    You are a senior offensive security engineer conducting an authorized internal \
authorized internal purple-team assessment.
    Your mission: analyse scan/probe results, surface real exploitable vulnerabilities, \
and guide the analyst toward the highest-value next test.

    Core principles:
    - Ground every finding in concrete evidence from the scan data.
    - Only suggest probes that are safe for a live production system \
(no DoS, no destructive writes, no credential brute-force).
    - Classify each finding by severity using CVSS-aligned reasoning:
        Critical – immediate exploitation possible, data at risk
        High     – likely exploitable with moderate effort
        Medium   – exploitable under specific conditions or needs chaining
        Low      – hardening / defence-in-depth gap
        Info     – informational, no direct risk
    - Prioritise SAML/authentication flaws, sensitive data exposure, \
broken access control, and misconfigured TLS — all common in Azure-hosted SSO.

    You MUST respond with valid JSON ONLY — no prose outside the JSON block.
    Schema:
    {
      "findings": [
        {
          "severity": "Critical|High|Medium|Low|Info",
          "title": "<short title>",
          "description": "<detailed explanation>",
          "evidence": "<exact snippet from scan data>",
          "remediation": "<actionable fix>",
          "cve": "<CVE-XXXX-XXXXX or null>",
          "cwe": "<CWE-NNN or null>",
          "probe_source": "<scanner name>"
        }
      ],
      "risk_summary": "<one paragraph overall risk assessment>",
      "overall_severity": "Critical|High|Medium|Low|Info",
      "next_probe": {
        "type": "http_request|port_scan|ssl_check|dns_query|saml_probe|custom",
        "description": "<what to test and why>",
        "reasoning": "<security rationale>",
        "parameters": {
          "url": "<target url or null>",
          "host": "<hostname or null>",
          "ports": "<port spec or null>",
          "method": "GET",
          "headers": {},
          "body": null,
          "params": {},
          "follow_redirects": true,
          "timeout": 15,
          "extra_args": {}
        },
        "expected_outcome": "<what a positive or negative result means>",
        "risk_level": "Low|Medium|High"
      },
      "analyst_notes": "<anything the analyst should know before running the next probe>"
    }

    If you have no further valuable probes to suggest, set next_probe to null \
and explain why in analyst_notes.
""").strip()


class SecurityAnalyst:
    """Wraps an OpenAI/Azure OpenAI client and maintains conversation state."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._client: AzureOpenAI | OpenAI | None = None  # built lazily
        # Conversation history (system + alternating user/assistant)
        self._messages: list[dict[str, str]] = [
            {"role": "system", "content": _SYSTEM_PROMPT}
        ]

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def analyse(
        self,
        new_results: list[ScanResult],
        session: AssessmentSession,
    ) -> LLMAnalysis:
        """
        Feed new scan results into the conversation and get an analysis back.

        Raises RuntimeError if no LLM provider is configured.
        """
        if self._config.llm_provider == "none":
            raise RuntimeError(
                "No LLM provider configured. Add AZURE_OPENAI_* or OPENAI_API_KEY "
                "to your .env file."
            )

        if self._client is None:
            self._client = self._build_client()

        user_content = self._build_user_message(new_results, session)
        self._messages.append({"role": "user", "content": user_content})

        raw_response = self._call_llm()
        analysis = self._parse_response(raw_response)

        self._messages.append({"role": "assistant", "content": raw_response})
        return analysis

    def reset_conversation(self) -> None:
        """Restart the conversation history (keep system prompt)."""
        self._messages = [self._messages[0]]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_client(self) -> AzureOpenAI | OpenAI:
        cfg = self._config
        if cfg.llm_provider == "azure":
            if cfg.azure_openai_api_key:
                return AzureOpenAI(
                    azure_endpoint=cfg.azure_openai_endpoint,
                    api_key=cfg.azure_openai_api_key,
                    api_version=cfg.azure_openai_api_version,
                )
            if cfg.azure_use_cli_auth:
                token_provider = get_bearer_token_provider(
                    AzureCliCredential(),
                    "https://cognitiveservices.azure.com/.default",
                )
                return AzureOpenAI(
                    azure_endpoint=cfg.azure_openai_endpoint,
                    azure_ad_token_provider=token_provider,
                    api_version=cfg.azure_openai_api_version,
                )
            raise RuntimeError(
                "Azure OpenAI selected but no auth method is configured. "
                "Set AZURE_OPENAI_API_KEY or AZURE_USE_CLI_AUTH=true."
            )
        return OpenAI(api_key=cfg.openai_api_key)

    def _build_user_message(
        self, results: list[ScanResult], session: AssessmentSession
    ) -> str:
        parts: list[str] = [
            f"TARGET: {session.target_url}",
            f"TARGET HOST: {session.target_host}",
            f"TARGET IP: {session.target_ip or 'unknown'}",
            "",
            "=== NEW SCAN RESULTS ===",
        ]
        for r in results:
            parts.append(f"\n--- {r.probe_name} ({r.probe_type}) ---")
            parts.append(f"Duration: {r.duration_seconds}s")
            if r.error:
                parts.append(f"Error: {r.error}")
            # Truncate to avoid exceeding context window
            truncated = r.raw_output[:5000]
            if len(r.raw_output) > 5000:
                truncated += "\n... [output truncated] ..."
            parts.append(truncated)

        if session.all_findings:
            parts.append("\n=== FINDINGS DISCOVERED SO FAR ===")
            for f in session.all_findings:
                parts.append(f"[{f.severity}] {f.title}")

        parts.append(
            "\nAnalyse the above results. Identify ALL security issues. "
            "Suggest the single highest-value next probe."
        )
        return "\n".join(parts)

    def _call_llm(self) -> str:
        cfg = self._config
        model = (
            cfg.azure_openai_deployment
            if cfg.llm_provider == "azure"
            else cfg.openai_model
        )
        assert self._client is not None  # guaranteed by analyse()
        response = self._client.chat.completions.create(
            model=model,
            messages=self._messages,  # type: ignore[arg-type]
            response_format={"type": "json_object"},
            temperature=0.2,
            max_completion_tokens=4096,
        )
        return response.choices[0].message.content or "{}"

    def _parse_response(self, raw: str) -> LLMAnalysis:
        try:
            data: dict[str, Any] = json.loads(raw)
        except json.JSONDecodeError:
            return LLMAnalysis(
                findings=[],
                risk_summary="LLM returned non-JSON output. Check logs.",
                overall_severity=Severity.INFO,
                analyst_notes=raw[:500],
            )

        findings = [
            Finding(
                severity=_coerce_severity(f.get("severity", "Info")),
                title=f.get("title", "Untitled"),
                description=f.get("description", ""),
                evidence=f.get("evidence", ""),
                remediation=f.get("remediation", ""),
                cve=f.get("cve"),
                cwe=f.get("cwe"),
                probe_source=f.get("probe_source", "llm"),
            )
            for f in data.get("findings", [])
        ]

        next_probe: NextProbe | None = None
        np_data = data.get("next_probe")
        if np_data:
            params_data = np_data.get("parameters", {})
            next_probe = NextProbe(
                type=_coerce_probe_type(np_data.get("type", "http_request")),
                description=np_data.get("description", ""),
                reasoning=np_data.get("reasoning", ""),
                parameters=ProbeParameters(
                    url=params_data.get("url"),
                    host=params_data.get("host"),
                    ports=params_data.get("ports"),
                    method=params_data.get("method", "GET"),
                    headers=params_data.get("headers", {}),
                    body=params_data.get("body"),
                    params=params_data.get("params", {}),
                    follow_redirects=params_data.get("follow_redirects", True),
                    timeout=params_data.get("timeout", 15),
                    extra_args=params_data.get("extra_args", {}),
                ),
                expected_outcome=np_data.get("expected_outcome", ""),
                risk_level=np_data.get("risk_level", "Low"),
            )

        return LLMAnalysis(
            findings=findings,
            risk_summary=data.get("risk_summary", ""),
            overall_severity=_coerce_severity(data.get("overall_severity", "Info")),
            next_probe=next_probe,
            analyst_notes=data.get("analyst_notes", ""),
        )


# ---------------------------------------------------------------------------
# Type coercions
# ---------------------------------------------------------------------------


def _coerce_severity(value: str) -> Severity:
    mapping = {s.value.lower(): s for s in Severity}
    return mapping.get(value.lower(), Severity.INFO)


def _coerce_probe_type(value: str) -> ProbeType:
    mapping = {p.value.lower(): p for p in ProbeType}
    return mapping.get(value.lower(), ProbeType.HTTP_REQUEST)
