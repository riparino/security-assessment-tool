# Security Assessment Tool

**Internal Purple Team / Security Assurance Platform**

> ⚠️ **Authorised internal use only.** Only scan infrastructure you own or have explicit written permission to test. Scanning infrastructure without authorisation is illegal.

---

## Overview

An analyst-driven, LLM-guided security assessment CLI. Pass a URL or IP belonging to authorised infrastructure and the tool will:

1. **Recon** — DNS enumeration, SSL/TLS analysis, HTTP security header audit, nmap port scan
2. **Analyse** — Feed all results to an LLM (Azure OpenAI / GPT-4o) acting as a security engineer; receive severity-classified findings and a risk summary
3. **Probe** — LLM suggests the highest-value next test; analyst approves, overrides, or provides a custom probe
4. **Report** — Full Markdown + JSON report saved to `reports/`

## Quick Start

### 1. Prerequisites

```bash
# Python 3.11+
pip install -r requirements.txt --break-system-packages

# nmap (optional but recommended)
sudo apt-get install nmap   # Debian/Ubuntu
brew install nmap           # macOS
```

### 2. Configure LLM credentials

```bash
cp .env.example .env
# Edit .env with your Azure OpenAI or OpenAI credentials
```

Minimum required (Azure OpenAI):
```
AZURE_OPENAI_ENDPOINT=https://YOUR_RESOURCE.openai.azure.com/
AZURE_OPENAI_API_KEY=your-key
AZURE_OPENAI_DEPLOYMENT=gpt-4o
```

### 3. Run an assessment

```bash
# Interactive mode (default) — analyst approves each probe
python3 main.py https://app.example.com/saml/login

# Auto mode — LLM drives all probes autonomously (up to --max-probes)
python3 main.py https://api.example.com --mode auto --max-probes 15

# Quick mode — initial recon + one LLM analysis, then report
python3 main.py https://app.example.com/saml/login --mode quick

# Skip nmap (faster, no port scan)
python3 main.py https://app.example.com --skip-nmap

# Verbose (print raw scanner output)
python3 main.py https://app.example.com -v
```

## Modes

| Mode | Description |
|------|-------------|
| `interactive` | Analyst approves each LLM-suggested probe; can override or enter custom probes |
| `auto` | Runs all LLM suggestions automatically (up to `--max-probes`); analyst reviews the report afterward |
| `quick` | Initial recon + one LLM analysis only; fastest option for triage |

## What Gets Scanned

### Initial Reconnaissance (always runs)
| Scanner | What it checks |
|---------|---------------|
| **DNS** | A/AAAA/CNAME/MX/NS/TXT/SOA records, zone transfer attempt, dangling CNAME (subdomain takeover) |
| **SSL/TLS** | Certificate validity/expiry, TLS 1.0/1.1/1.2/1.3 support, cipher strength |
| **HTTP** | Security headers (HSTS, CSP, X-Frame-Options, etc.), cookie flags, CORS, error page disclosure, robots.txt, swagger, `.env`, `.git/HEAD` |
| **SAML-specific** | Metadata endpoint exposure, RelayState open redirect, SAMLRequest error disclosure |
| **nmap** | Top service ports, service/version detection, default NSE scripts |

### Adaptive Probes (LLM-directed)
The LLM decides what to test next based on accumulated evidence. Typical follow-up probes include:
- Custom HTTP requests with crafted headers/parameters
- Deeper port scans (specific port ranges)
- Additional SSL cipher enumeration
- SAML-specific probes (XML signature, assertion replay)
- DNS subdomain enumeration

## Output

Reports are saved to `reports/` (configurable via `--report-dir`):

```
reports/
  20260512_143022_app_example_com_a1b2c3d4.md   ← Markdown report
  20260512_143022_app_example_com_a1b2c3d4.json ← Full JSON dump
```

The Markdown report includes:
- Executive summary with overall risk rating
- Findings table (Critical → Info)
- Detailed finding: description, evidence, CVE/CWE, remediation
- Technical appendix with raw scan output

## Architecture

```
security-assessment-tool/
├── main.py                     # CLI entry point (Click)
├── src/
│   ├── config.py               # Environment-based configuration
│   ├── models.py               # Pydantic data models
│   ├── utils.py                # Input validation, helpers
│   ├── scanners/
│   │   ├── dns_scanner.py      # dnspython-based DNS enumeration
│   │   ├── ssl_scanner.py      # Python ssl module — cert + protocol probe
│   │   ├── http_scanner.py     # requests — headers, CORS, SAML, paths
│   │   └── nmap_scanner.py     # nmap subprocess wrapper (XML parsing)
│   ├── llm/
│   │   └── analyst.py          # OpenAI/Azure OpenAI conversation driver
│   ├── workflow/
│   │   └── engine.py           # Recon → analyse → probe → report loop
│   └── reporting/
│       └── reporter.py         # Markdown + JSON report generation
└── reports/                    # Generated reports (gitignored)
```

## Security Notes

- All target inputs are strictly validated (hostname regex + `ipaddress` module) before being passed to subprocesses — no shell injection possible
- `subprocess.run` is always called with a list (never `shell=True`)
- TLS verification is enabled by default; `--no-tls-verify` is an explicit opt-in
- The LLM is instructed to suggest only safe, non-destructive probes
- No credentials are ever logged or included in reports
- The tool does not store any session data outside the local `reports/` directory

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `AZURE_OPENAI_ENDPOINT` | — | Azure OpenAI resource URL |
| `AZURE_OPENAI_API_KEY` | — | Azure OpenAI API key (primary auth method) |
| `AZURE_USE_CLI_AUTH` | `false` | Use Azure CLI auth token instead of API key |
| `AZURE_OPENAI_DEPLOYMENT` | `gpt-4o` | Model deployment name |
| `AZURE_OPENAI_API_VERSION` | `2024-08-01-preview` | API version |
| `OPENAI_API_KEY` | — | Fallback: standard OpenAI key |
| `OPENAI_MODEL` | `gpt-4o` | Fallback: OpenAI model |
| `REQUEST_TIMEOUT` | `15` | HTTP request timeout (seconds) |
| `NMAP_TIMEOUT` | `180` | nmap scan timeout (seconds) |
| `RATE_LIMIT_DELAY` | `0.5` | Delay between HTTP requests (seconds) |
| `VERIFY_TLS` | `true` | Verify TLS certificates |
| `NMAP_PORTS` | *(common ports)* | Port range for nmap scans |
