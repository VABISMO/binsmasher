#!/usr/bin/env python3
"""
BinSmasher – utils.py
Centralized logging, config dataclass, Rich helpers.
"""

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

    rich_handler = RichHandler(console=console, rich_tracebacks=True, markup=True)
    rich_handler.setLevel(logging.INFO)
    logger.addHandler(rich_handler)

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


def print_summary(
    offset, stack_addr, return_addr,
    exploit_type, status,
    canary, target_function,
    suggestions: list,
) -> None:
    table = Table(
        title="[bold cyan]BinSmasher — Exploitation Summary[/]",
        show_header=True, header_style="bold cyan",
    )
    table.add_column("Property", style="cyan", min_width=22)
    table.add_column("Value", style="white")

    table.add_row("Offset", str(offset) if offset is not None else "N/A")
    table.add_row("Stack Address", hex(stack_addr) if stack_addr else "N/A")
    table.add_row("Return Address", hex(return_addr) if return_addr else "N/A")
    table.add_row("Canary", hex(canary) if canary else "N/A")
    table.add_row("Exploit Type", exploit_type or "N/A")
    table.add_row("Target Function", target_function or "N/A")
    table.add_row(
        "Status",
        f"[green]{status}[/]" if status == "Success" else f"[red]{status}[/]",
    )
    console.print(table)

    if suggestions:
        body = "\n".join(f"  • {s}" for s in suggestions)
        console.print(Panel(body, title="[bold yellow]Suggestions[/]", border_style="yellow"))
