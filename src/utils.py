#!/usr/bin/env python3
"""BinSmasher – utils.py"""

import logging
import os
import sys
from dataclasses import dataclass
from typing import Optional
from argparse import HelpFormatter

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.logging import RichHandler

console = Console()


def setup_logging(log_file: str) -> logging.Logger:
    logger = logging.getLogger("binsmasher")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    rh = RichHandler(console=console, rich_tracebacks=True, markup=True)
    rh.setLevel(logging.INFO)
    logger.addHandler(rh)
    fh = logging.FileHandler(log_file, mode="w", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)-8s] %(message)s"))
    fh.setLevel(logging.DEBUG)
    logger.addHandler(fh)
    return logger


@dataclass
class ExploitConfig:
    binary: str
    host: str = "localhost"
    port: int = 4444
    pattern_size: int = 200
    return_addr: Optional[str] = None
    return_offset: int = 80
    test_exploit: bool = False
    log_file: str = "binsmasher.log"
    output_ip: str = "127.0.0.1"
    output_port: int = 6666
    reverse_shell: bool = False
    cmd: str = "id"
    fuzz: bool = False
    afl_fuzz: bool = False
    frida: bool = False
    file_input: Optional[str] = None
    protocol: str = "raw"
    tls: bool = False
    heap_exploit: bool = False
    safeseh_bypass: bool = False
    privilege_escalation: bool = False
    binary_args: str = ""
    agave_mode: bool = False
    source_path: Optional[str] = None
    solana_rpc: str = "http://localhost:8899"
    bpf_fuzz: bool = False
    agave_exploit_type: Optional[str] = None
    afl_timeout: int = 60
    mutation_fuzz: bool = False
    cfi_bypass: bool = False
    # v4 additions
    force_srop: bool = False
    force_orw: bool = False
    flag_path: str = "/flag"
    dos_only: bool = False
    generate_scripts: bool = False

    def validate(self) -> None:
        if not os.path.isfile(self.binary):
            console.print(Panel(f"[bold red]Binary not found:[/] {self.binary}", border_style="red"))
            sys.exit(1)
        if not (1 <= self.port <= 65535):
            console.print(Panel(f"[bold red]Invalid port:[/] {self.port}", border_style="red"))
            sys.exit(1)
        if self.output_port and not (1 <= self.output_port <= 65535):
            console.print(Panel(f"[bold red]Invalid output port:[/] {self.output_port}", border_style="red"))
            sys.exit(1)
        if self.return_addr:
            try:
                int(self.return_addr, 16)
            except ValueError:
                console.print(Panel(f"[bold red]Invalid hex return address:[/] {self.return_addr}", border_style="red"))
                sys.exit(1)

    @property
    def binary_args_list(self) -> list:
        return self.binary_args.split() if self.binary_args else []


class RichHelpFormatter(HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=40, width=100)


def print_summary(offset, stack_addr, return_addr, exploit_type,
                  status, canary, target_function, suggestions: list,
                  # static protection flags from check_protections()
                  nx=None, pie=None, relro=None, canary_enabled=None, aslr=None) -> None:
    """Print the exploitation results table.

    Stack Address / Canary show runtime-leaked values (need GDB or fmt-string oracle).
    Return Address shows the win() function address when available.
    Binary protections (NX, PIE, RELRO, Canary) always show from static checksec.
    """
    def _bool(v, yes="Enabled", no="Disabled"):
        if v is None: return "—"
        return f"[red]{yes}[/]" if v else f"[green]{no}[/]"

    table = Table(title="[bold cyan]BinSmasher — Exploitation Summary[/]",
                  show_header=True, header_style="bold cyan", min_width=52)
    table.add_column("Property", style="bold cyan", min_width=24, no_wrap=True)
    table.add_column("Value", min_width=24)

    # ── Exploit results ───────────────────────────────────────────────────────
    table.add_row("Offset", str(offset) if offset is not None else "N/A")
    table.add_row("Stack Address",
                  hex(stack_addr) if stack_addr else "[dim]N/A  (needs GDB or fmt-string leak)[/]")
    table.add_row("Return Address",
                  (f"[bold green]{hex(return_addr)}[/]  ← win()" if return_addr and return_addr > 0x1000
                   else ("[dim]N/A[/]")))
    table.add_row("Canary  (leaked)",
                  (f"[bold]{hex(canary)}[/]" if canary
                   else "[dim]N/A  (not bruted / not present)[/]"))
    table.add_row("Exploit Type", exploit_type or "N/A")
    table.add_row("Target Function", target_function or "N/A")

    # ── Binary protections (static) ───────────────────────────────────────────
    table.add_section()
    if nx is not None:
        table.add_row("NX  (no-exec stack)", _bool(nx, yes="ON — shellcode blocked", no="OFF — shellcode OK"))
    if pie is not None:
        table.add_row("PIE  (ASLR base)", _bool(pie, yes="ON — base randomised", no="OFF — fixed base"))
    if relro is not None:
        relro_val = (f"[red]{relro}[/]" if "Full" in str(relro)
                     else (f"[yellow]{relro}[/]" if "Partial" in str(relro)
                           else f"[green]{relro}[/]"))
        table.add_row("RELRO", relro_val)
    if canary_enabled is not None:
        table.add_row("Stack Canary  (static)", _bool(canary_enabled,
                      yes="ON — canary present", no="OFF — no canary"))
    if aslr is not None:
        table.add_row("ASLR  (system)", _bool(aslr, yes="ON", no="OFF"))

    # ── Final status ──────────────────────────────────────────────────────────
    table.add_section()
    table.add_row("Status",
                  f"[bold green]  ✓  {status}[/]" if status == "Success"
                  else f"[bold red]  ✗  {status}[/]")
    console.print(table)
    if suggestions:
        body = "\n".join(f"  • {s}" for s in suggestions)
        console.print(Panel(body, title="[bold yellow]Suggestions[/]", border_style="yellow"))
