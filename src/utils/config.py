import os
import sys
from dataclasses import dataclass
from typing import Optional
from ._console import console
from rich.panel import Panel


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
    # v4.1 – custom raw payload sender
    payload_data: Optional[str] = None
    udp: bool = False
    # v4.2 – spawn & manage the target process for UDP crash detection
    spawn_target: bool = False

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
