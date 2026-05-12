#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Assessment Tool
Internal Purple Team / Security Assurance Platform

Usage:
    python main.py <TARGET> [OPTIONS]

Examples:
    python main.py https://app.example.com/saml/login
    python main.py https://api.example.com --mode auto --max-probes 15
    python main.py 10.0.0.1 --skip-nmap --mode quick
"""
from __future__ import annotations

import sys
from pathlib import Path

import click
from dotenv import load_dotenv
from rich.console import Console

load_dotenv()


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target")
@click.option(
    "--report-dir",
    "-r",
    default="reports",
    show_default=True,
    help="Directory where reports are saved.",
)
@click.option(
    "--mode",
    "-m",
    type=click.Choice(["interactive", "auto", "quick"], case_sensitive=False),
    default="interactive",
    show_default=True,
    help=(
        "interactive: analyst approves each probe  "
        "auto: run all suggested probes automatically  "
        "quick: initial recon + LLM analysis only"
    ),
)
@click.option(
    "--skip-nmap",
    is_flag=True,
    default=False,
    help="Skip nmap port scan (useful when nmap is unavailable or output is slow).",
)
@click.option(
    "--no-tls-verify",
    is_flag=True,
    default=False,
    help="Disable TLS certificate verification (use only for self-signed cert targets).",
)
@click.option(
    "--max-probes",
    default=20,
    show_default=True,
    type=click.IntRange(1, 50),
    help="Maximum number of LLM-directed probes in the adaptive loop.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Print raw scanner output to the terminal.",
)
def main(
    target: str,
    report_dir: str,
    mode: str,
    skip_nmap: bool,
    no_tls_verify: bool,
    max_probes: int,
    verbose: bool,
) -> None:
    """
    Run a security assessment against TARGET (URL or IP).

    Only scan infrastructure you own or have explicit written permission to test.
    Authorised internal use only.
    """
    # Import here so dotenv is loaded first
    from src.config import Config
    from src.workflow.engine import AssessmentEngine

    console = Console()

    config = Config(
        report_dir=Path(report_dir),
        mode=mode.lower(),
        skip_nmap=skip_nmap,
        verify_tls=not no_tls_verify,
        verbose=verbose,
        max_probes=max_probes,
    )

    engine = AssessmentEngine(target=target, config=config, console=console)

    try:
        engine.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Assessment interrupted by analyst.[/yellow]")
        sys.exit(0)


if __name__ == "__main__":
    main()
