from argparse import HelpFormatter
from rich.table import Table
from rich.panel import Panel
from ._console import console


class RichHelpFormatter(HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=40, width=100)


def print_summary(offset, stack_addr, return_addr, exploit_type,
                  status, canary, target_function, suggestions: list,
                  nx=None, pie=None, relro=None, canary_enabled=None, aslr=None) -> None:
    def _bool(v, yes="Enabled", no="Disabled"):
        if v is None:
            return "—"
        return f"[red]{yes}[/]" if v else f"[green]{no}[/]"

    table = Table(title="[bold cyan]BinSmasher — Exploitation Summary[/]",
                  show_header=True, header_style="bold cyan", min_width=52)
    table.add_column("Property", style="bold cyan", min_width=24, no_wrap=True)
    table.add_column("Value", min_width=24)

    table.add_row("Offset", str(offset) if offset is not None else "N/A")
    # stack_addr is RSP at crash from corefile/GDB if available
    if stack_addr and stack_addr > 0x1000:
        _stack_display = f"[bold green]{hex(stack_addr)}[/]  (stack/buf addr)"
    elif return_addr and return_addr > 0x1000:
        _stack_display = f"[dim]N/A  (ret={hex(return_addr)}, stack addr not recovered)[/]"
    else:
        _stack_display = "[dim]N/A  (use --spawn-target or GDB to recover)[/]"
    table.add_row("Stack Address", _stack_display)
    table.add_row("Return Address",
                  (f"[bold green]{hex(return_addr)}[/]  ← win()" if return_addr and return_addr > 0x1000
                   else ("[dim]N/A[/]")))
    table.add_row("Canary  (leaked)",
                  (f"[bold green]{hex(canary)}[/] ✓ leaked" if canary
                   else "[dim]N/A  (not bruted / not present)[/]"))
    table.add_row("Exploit Type", exploit_type or "N/A")
    table.add_row("Target Function", target_function or "N/A")

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

    table.add_section()
    if status == "Success":
        _status_str = f"[bold green]  ✓  {status}[/]"
    elif "Generated" in status:
        _status_str = f"[bold yellow]  ⚠  {status}[/]"
    else:
        _status_str = f"[bold red]  ✗  {status}[/]"
    table.add_row("Status", _status_str)
    console.print(table)
    if suggestions:
        body = "\n".join(f"  • {s}" for s in suggestions)
        console.print(Panel(body, title="[bold yellow]Suggestions[/]", border_style="yellow"))
