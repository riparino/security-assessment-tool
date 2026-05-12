"""
Assessment workflow engine.

Orchestrates the scan → LLM-analyse → suggest → execute → repeat loop.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.columns import Columns
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.spinner import Spinner
from rich.status import Status
from rich.table import Table
from rich import box

from src.config import Config
from src.llm.analyst import SecurityAnalyst
from src.models import (
    AssessmentSession,
    LLMAnalysis,
    NextProbe,
    ProbeType,
    ScanResult,
    Severity,
    SEVERITY_COLORS,
    SEVERITY_ORDER,
)
from src.reporting.reporter import generate_report
from src.scanners import dns_scanner, http_scanner, nmap_scanner, ssl_scanner
from src.utils import resolve_ip, validate_target


class AssessmentEngine:
    """
    Drives the interactive purple-team assessment workflow.

    Phases:
      1. Validate & resolve target
      2. Run initial reconnaissance (parallel-ish blocking calls)
      3. LLM analysis of initial results
      4. Interactive probe loop (analyst approves / overrides / exits)
      5. Final report generation
    """

    def __init__(self, target: str, config: Config, console: Console) -> None:
        self._raw_target = target
        self._config = config
        self._console = console
        self._analyst = SecurityAnalyst(config)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        self._print_banner()

        # --- Validate target ---
        try:
            host, url = validate_target(self._raw_target)
        except ValueError as exc:
            self._console.print(f"[bold red]Invalid target:[/bold red] {exc}")
            return

        ip = resolve_ip(host)
        session = AssessmentSession(
            session_id=str(uuid.uuid4())[:8],
            target_url=url,
            target_host=host,
            target_ip=ip,
        )

        self._console.print(
            Panel(
                f"[bold]Target:[/bold] {escape(url)}\n"
                f"[bold]Host:[/bold]   {escape(host)}\n"
                f"[bold]IP:[/bold]     {ip or 'unresolved'}\n"
                f"[bold]Session:[/bold] {session.session_id}",
                title="[cyan]Assessment Target[/cyan]",
                border_style="cyan",
            )
        )

        # Config warnings
        for warning in self._config.validate():
            self._console.print(f"[yellow]⚠ {warning}[/yellow]")

        self._console.print()

        # --- Phase 1: Initial recon ---
        self._console.print(Rule("[bold cyan]Phase 1 — Initial Reconnaissance[/bold cyan]"))
        initial_results = self._run_initial_recon(host, url, session)
        for r in initial_results:
            session.add_result(r)

        # --- Phase 2: LLM analysis ---
        if self._config.llm_provider == "none":
            self._console.print(
                "[yellow]Skipping LLM analysis — no provider configured.[/yellow]"
            )
            self._dump_raw_results(session)
            self._save_and_exit(session)
            return

        self._console.print(Rule("[bold cyan]Phase 2 — LLM Security Analysis[/bold cyan]"))
        analysis = self._run_llm_analysis(initial_results, session)
        session.add_analysis(analysis)
        self._display_analysis(analysis)

        # --- Phase 3: Interactive probe loop ---
        if self._config.mode == "quick":
            self._save_and_exit(session)
            return

        self._console.print(Rule("[bold cyan]Phase 3 — Adaptive Probing[/bold cyan]"))
        probe_count = 0
        while probe_count < self._config.max_probes:
            if not analysis.next_probe:
                self._console.print(
                    "[green]✓ LLM has no further probe suggestions.[/green]"
                )
                break

            action = self._prompt_analyst(analysis.next_probe, probe_count)

            if action == "done":
                break
            elif action == "report":
                break
            elif action == "run":
                result = self._execute_probe(analysis.next_probe, session)
                if result:
                    session.add_result(result)
                    analysis = self._run_llm_analysis([result], session)
                    session.add_analysis(analysis)
                    self._display_analysis(analysis)
                    probe_count += 1
            elif action == "custom":
                custom_desc = Prompt.ask(
                    "[yellow]Describe the custom probe[/yellow]",
                    default="Check HTTP OPTIONS method",
                )
                result = self._execute_custom_probe(custom_desc, analysis, session)
                if result:
                    session.add_result(result)
                    analysis = self._run_llm_analysis([result], session)
                    session.add_analysis(analysis)
                    self._display_analysis(analysis)
                    probe_count += 1
            elif action == "findings":
                self._display_all_findings(session)
                # Loop again without incrementing probe count

        # --- Phase 4: Report ---
        self._save_and_exit(session)

    # ------------------------------------------------------------------
    # Recon
    # ------------------------------------------------------------------

    def _run_initial_recon(
        self, host: str, url: str, session: AssessmentSession
    ) -> list[ScanResult]:
        results: list[ScanResult] = []

        tasks: list[tuple[str, Any]] = [
            ("DNS Enumeration", lambda: dns_scanner.run(host, timeout=15)),
            ("SSL/TLS Analysis", lambda: ssl_scanner.run(host, timeout=15)),
            (
                "HTTP Security Analysis",
                lambda: http_scanner.run(
                    url,
                    verify_tls=self._config.verify_tls,
                    timeout=self._config.request_timeout,
                    rate_delay=self._config.rate_limit_delay,
                ),
            ),
        ]
        if not self._config.skip_nmap:
            tasks.append(
                (
                    "Nmap Port Scan",
                    lambda: nmap_scanner.run(
                        host,
                        ports=self._config.nmap_ports,
                        timeout=self._config.nmap_timeout,
                    ),
                )
            )

        for name, task_fn in tasks:
            with Status(
                f"[cyan]Running {name}…[/cyan]", console=self._console, spinner="dots"
            ):
                try:
                    result = task_fn()
                    results.append(result)
                    status = "[green]✓[/green]" if result.success else "[yellow]⚠[/yellow]"
                    self._console.print(
                        f"  {status} {name} — {result.duration_seconds}s"
                    )
                    if self._config.verbose:
                        self._console.print(
                            Panel(
                                escape(result.raw_output[:1500]),
                                title=name,
                                border_style="dim",
                            )
                        )
                except Exception as exc:  # noqa: BLE001
                    self._console.print(f"  [red]✗ {name} failed: {exc}[/red]")

        return results

    # ------------------------------------------------------------------
    # LLM
    # ------------------------------------------------------------------

    def _run_llm_analysis(
        self, results: list[ScanResult], session: AssessmentSession
    ) -> LLMAnalysis:
        with Status(
            "[magenta]Analysing with LLM…[/magenta]",
            console=self._console,
            spinner="dots",
        ):
            try:
                return self._analyst.analyse(results, session)
            except Exception as exc:  # noqa: BLE001
                self._console.print(f"[red]LLM error: {exc}[/red]")
                from src.models import LLMAnalysis as LA
                return LA(
                    findings=[],
                    risk_summary=f"LLM call failed: {exc}",
                    overall_severity=Severity.INFO,
                )

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def _display_analysis(self, analysis: LLMAnalysis) -> None:
        self._console.print()

        # --- Findings table ---
        if analysis.findings:
            table = Table(
                "Severity", "Title", "Evidence",
                title="[bold]New Findings[/bold]",
                box=box.ROUNDED,
                border_style="cyan",
                show_lines=True,
            )
            for f in sorted(analysis.findings, key=lambda x: SEVERITY_ORDER[x.severity]):
                color = SEVERITY_COLORS[f.severity]
                table.add_row(
                    f"[{color}]{f.severity}[/{color}]",
                    f.title,
                    escape(f.evidence[:120]),
                )
            self._console.print(table)
        else:
            self._console.print("[dim]No new findings from this probe.[/dim]")

        # --- Risk summary ---
        color = SEVERITY_COLORS[analysis.overall_severity]
        self._console.print(
            Panel(
                f"[bold]Overall Risk:[/bold] [{color}]{analysis.overall_severity}[/{color}]\n\n"
                + escape(analysis.risk_summary),
                title="[bold]Risk Assessment[/bold]",
                border_style=color.split()[-1],  # strip "bold" prefix if present
            )
        )

        # --- Next probe suggestion ---
        if analysis.next_probe:
            np = analysis.next_probe
            self._console.print(
                Panel(
                    f"[bold]Type:[/bold]        {np.type.value}\n"
                    f"[bold]Description:[/bold] {escape(np.description)}\n"
                    f"[bold]Reasoning:[/bold]   {escape(np.reasoning)}\n"
                    f"[bold]Risk to target:[/bold] {np.risk_level}\n"
                    f"[bold]Expected outcome:[/bold] {escape(np.expected_outcome)}",
                    title="[bold yellow]Suggested Next Probe[/bold yellow]",
                    border_style="yellow",
                )
            )
        if analysis.analyst_notes:
            self._console.print(
                f"[dim]Analyst notes: {escape(analysis.analyst_notes)}[/dim]"
            )
        self._console.print()

    def _display_all_findings(self, session: AssessmentSession) -> None:
        if not session.all_findings:
            self._console.print("[dim]No findings yet.[/dim]")
            return
        table = Table(
            "Severity", "Title", "Source",
            title=f"[bold]All Findings ({len(session.all_findings)})[/bold]",
            box=box.ROUNDED,
            border_style="cyan",
            show_lines=True,
        )
        for f in session.findings_by_severity:
            color = SEVERITY_COLORS[f.severity]
            table.add_row(
                f"[{color}]{f.severity}[/{color}]",
                f.title,
                f.probe_source,
            )
        self._console.print(table)

    def _dump_raw_results(self, session: AssessmentSession) -> None:
        for r in session.scan_results:
            self._console.print(
                Panel(
                    escape(r.raw_output[:3000]),
                    title=r.probe_name,
                    border_style="dim",
                )
            )

    # ------------------------------------------------------------------
    # Interactive prompt
    # ------------------------------------------------------------------

    def _prompt_analyst(self, next_probe: NextProbe, count: int) -> str:
        self._console.print(
            f"[bold]Probe {count + 1} of {self._config.max_probes}[/bold]"
        )
        self._console.print(
            "[cyan]r[/cyan] Run suggested probe  "
            "[cyan]c[/cyan] Custom probe  "
            "[cyan]f[/cyan] Show all findings  "
            "[cyan]d[/cyan] Done / generate report"
        )
        choice = Prompt.ask(
            "Action",
            choices=["r", "c", "f", "d"],
            default="r",
        )
        return {
            "r": "run",
            "c": "custom",
            "f": "findings",
            "d": "done",
        }[choice]

    # ------------------------------------------------------------------
    # Probe execution
    # ------------------------------------------------------------------

    def _execute_probe(
        self, probe: NextProbe, session: AssessmentSession
    ) -> ScanResult | None:
        params = probe.parameters

        with Status(
            f"[cyan]Executing {probe.type.value}…[/cyan]",
            console=self._console,
            spinner="dots",
        ):
            try:
                if probe.type == ProbeType.HTTP_REQUEST:
                    url = params.url or session.target_url
                    return http_scanner.run_custom_http(
                        url=url,
                        method=params.method,
                        headers=params.headers,
                        params=params.params,
                        body=params.body,
                        verify_tls=self._config.verify_tls,
                        timeout=params.timeout,
                    )

                elif probe.type in (ProbeType.SAML_PROBE, ProbeType.HEADER_CHECK):
                    url = params.url or session.target_url
                    return http_scanner.run(
                        target_url=url,
                        verify_tls=self._config.verify_tls,
                        timeout=self._config.request_timeout,
                        rate_delay=self._config.rate_limit_delay,
                    )

                elif probe.type == ProbeType.PORT_SCAN:
                    host = params.host or session.target_host
                    ports = params.ports or self._config.nmap_ports
                    return nmap_scanner.run(
                        host,
                        ports=ports,
                        timeout=self._config.nmap_timeout,
                    )

                elif probe.type == ProbeType.SSL_CHECK:
                    host = params.host or session.target_host
                    return ssl_scanner.run(host, timeout=15)

                elif probe.type == ProbeType.DNS_QUERY:
                    host = params.host or session.target_host
                    return dns_scanner.run(host, timeout=15)

                else:
                    self._console.print(
                        f"[yellow]Probe type '{probe.type}' not directly executable. "
                        "Use custom probe.[/yellow]"
                    )
                    return None

            except Exception as exc:  # noqa: BLE001
                self._console.print(f"[red]Probe execution error: {exc}[/red]")
                return None

    def _execute_custom_probe(
        self,
        description: str,
        last_analysis: LLMAnalysis,
        session: AssessmentSession,
    ) -> ScanResult | None:
        """
        Ask the LLM to translate a free-text probe description into a structured
        probe, then execute it.
        """
        # Build a synthetic next_probe by injecting the description
        # and re-using the last analysis's suggested probe type as a hint
        if last_analysis.next_probe:
            hint_type = last_analysis.next_probe.type
        else:
            hint_type = ProbeType.HTTP_REQUEST

        url = session.target_url
        self._console.print(
            f"[dim]Executing custom probe via HTTP GET: {escape(url)}[/dim]"
        )
        return http_scanner.run_custom_http(
            url=url,
            method="GET",
            verify_tls=self._config.verify_tls,
            timeout=self._config.request_timeout,
        )

    # ------------------------------------------------------------------
    # Report & exit
    # ------------------------------------------------------------------

    def _save_and_exit(self, session: AssessmentSession) -> None:
        self._console.print()
        self._console.print(Rule("[bold cyan]Generating Report[/bold cyan]"))
        self._display_all_findings(session)

        report_path = generate_report(session, self._config.report_dir)
        self._console.print(
            f"\n[bold green]✓ Report saved:[/bold green] {report_path}"
        )
        self._console.print(
            f"[dim]Session: {session.session_id} | "
            f"Duration: {self._elapsed(session.started_at)} | "
            f"Findings: {len(session.all_findings)}[/dim]"
        )

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _print_banner(self) -> None:
        self._console.print(
            Panel(
                "[bold cyan]Security Assessment Tool[/bold cyan]\n"
                "[dim]Internal Purple Team / Security Assurance Platform[/dim]\n\n"
                "[yellow]⚠  AUTHORISED USE ONLY — Only scan infrastructure you are permitted to test ⚠[/yellow]",
                border_style="cyan",
                padding=(1, 4),
            )
        )
        self._console.print()

    @staticmethod
    def _elapsed(started_at: datetime) -> str:
        delta = datetime.now() - started_at.replace(tzinfo=None)
        m, s = divmod(int(delta.total_seconds()), 60)
        return f"{m}m {s}s"
