"""Configuration management for Security Assessment Tool."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    """Central configuration loaded from environment variables."""

    # --- LLM provider ---
    azure_openai_endpoint: str = field(
        default_factory=lambda: os.getenv("AZURE_OPENAI_ENDPOINT", "")
    )
    azure_openai_api_key: str = field(
        default_factory=lambda: os.getenv("AZURE_OPENAI_API_KEY", "")
    )
    azure_openai_deployment: str = field(
        default_factory=lambda: os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
    )
    azure_openai_api_version: str = field(
        default_factory=lambda: os.getenv(
            "AZURE_OPENAI_API_VERSION", "2024-08-01-preview"
        )
    )
    azure_use_cli_auth: bool = field(
        default_factory=lambda: os.getenv("AZURE_USE_CLI_AUTH", "false").lower() == "true"
    )
    openai_api_key: str = field(
        default_factory=lambda: os.getenv("OPENAI_API_KEY", "")
    )
    openai_model: str = field(
        default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o")
    )

    # --- Scan settings ---
    max_probe_timeout: int = field(
        default_factory=lambda: int(os.getenv("MAX_PROBE_TIMEOUT", "120"))
    )
    request_timeout: int = field(
        default_factory=lambda: int(os.getenv("REQUEST_TIMEOUT", "15"))
    )
    nmap_timeout: int = field(
        default_factory=lambda: int(os.getenv("NMAP_TIMEOUT", "180"))
    )
    max_redirects: int = field(
        default_factory=lambda: int(os.getenv("MAX_REDIRECTS", "10"))
    )
    rate_limit_delay: float = field(
        default_factory=lambda: float(os.getenv("RATE_LIMIT_DELAY", "0.5"))
    )
    verify_tls: bool = field(
        default_factory=lambda: os.getenv("VERIFY_TLS", "true").lower() == "true"
    )
    nmap_ports: str = field(
        default_factory=lambda: os.getenv(
            "NMAP_PORTS",
            "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,"
            "1723,3306,3389,5900,8080,8443,8000,9000,9090,9443",
        )
    )

    # --- Runtime flags (set by CLI) ---
    report_dir: Path = Path("reports")
    mode: str = "interactive"   # interactive | auto | quick
    skip_nmap: bool = False
    verbose: bool = False
    max_probes: int = 10

    @property
    def llm_provider(self) -> str:
        """Determine which LLM provider to use."""
        if self.azure_openai_endpoint and (
            self.azure_openai_api_key or self.azure_use_cli_auth
        ):
            return "azure"
        if self.openai_api_key:
            return "openai"
        return "none"

    def validate(self) -> list[str]:
        """Return list of configuration warnings."""
        warnings: list[str] = []
        if self.azure_openai_endpoint and not (
            self.azure_openai_api_key or self.azure_use_cli_auth
        ):
            warnings.append(
                "AZURE_OPENAI_ENDPOINT is set, but neither AZURE_OPENAI_API_KEY nor "
                "AZURE_USE_CLI_AUTH=true is configured."
            )
        if self.llm_provider == "none":
            warnings.append(
                "No LLM credentials configured. Set AZURE_OPENAI_* or OPENAI_API_KEY "
                "in your .env file."
            )
        return warnings
