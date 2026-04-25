"""Binary protection checking methods for BinaryAnalyzer."""
import subprocess
import logging
try:
    from .cache import load_cache, save_cache
except ImportError:
    load_cache = save_cache = lambda *a, **k: None
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("binsmasher")


class ProtectionsMixin:
    """Methods: check_protections, _checksec_linux, _checksec_windows, _checksec_macos."""

    def check_protections(self):
        cached = load_cache(self.binary, "protections")
        if cached:
            log.info("[cache] check_protections hit")
            return tuple(cached)
        log.info("Checking binary protections…")
        stack_exec = True
        nx = aslr = canary = pie = False
        relro = "No RELRO"
        safeseh = cfg = fortify = shadow_stack = "N/A"
        try:
            if self.platform in ("linux", "android"):
                stack_exec, nx, aslr, canary, relro, pie, fortify, shadow_stack = self._checksec_linux()
            elif self.platform == "windows":
                nx, aslr, canary, safeseh, cfg, pie = self._checksec_windows()
                stack_exec = not nx
            elif self.platform == "macos":
                stack_exec, nx, aslr, canary, pie = self._checksec_macos()
        except Exception as e:
            log.warning(f"Protection check error: {e}")
        table = Table(title="Binary Protections", show_header=True, header_style="bold cyan")
        table.add_column("Protection", style="cyan")
        table.add_column("Value", style="white")

        def yn(v):
            return "[green]Yes[/]" if v else "[red]No[/]"

        table.add_row("NX / DEP", yn(nx))
        table.add_row("Stack Canary", yn(canary))
        table.add_row("ASLR / PIE", f"{yn(aslr)} / {yn(pie)}")
        table.add_row("RELRO", relro)
        table.add_row("Stack Executable", yn(stack_exec))
        table.add_row("FORTIFY_SOURCE", str(fortify))
        table.add_row("Shadow Stack (CET)", str(shadow_stack))
        if self.platform == "windows":
            table.add_row("SafeSEH", str(safeseh))
            table.add_row("CFG", str(cfg))
        console.print(table)
        result = (stack_exec, nx, aslr, canary, relro, safeseh, cfg, fortify, pie, shadow_stack)
        save_cache(self.binary, "protections", list(result))
        return result

    def _checksec_linux(self):
        stack_exec = nx = aslr = canary = pie = False
        relro = "No RELRO"
        fortify = "Disabled"
        shadow_stack = "Disabled"
        try:
            re_out = subprocess.check_output(["readelf", "-W", "-l", self.binary],
                                             stderr=subprocess.DEVNULL).decode(errors="ignore")
            for line in re_out.splitlines():
                if "GNU_STACK" in line:
                    stack_exec = "RWE" in line
                    break
            nx = not stack_exec
            if "GNU_PROPERTY" in re_out:
                props = subprocess.check_output(["readelf", "-n", self.binary],
                                                stderr=subprocess.DEVNULL).decode(errors="ignore")
                if "IBT" in props or "SHSTK" in props:
                    shadow_stack = "Enabled (CET)"
        except Exception:
            pass
        try:
            cs = subprocess.check_output(["checksec", "--file", self.binary],
                                         stderr=subprocess.STDOUT).decode(errors="ignore")
            nx = nx or ("NX enabled" in cs)
            aslr = "PIE enabled" in cs
            canary = "Canary found" in cs
            pie = aslr
            fortify = "Fortified" if "FORTIFY" in cs else "Disabled"
            if "Full RELRO" in cs:
                relro = "Full RELRO"
            elif "Partial RELRO" in cs:
                relro = "Partial RELRO"
        except FileNotFoundError:
            log.warning("checksec not installed — using readelf/nm fallback")
            try:
                nm = subprocess.check_output(["nm", "-D", self.binary],
                                             stderr=subprocess.DEVNULL).decode(errors="ignore")
                canary = "__stack_chk_fail" in nm
            except Exception:
                pass
            try:
                re_dyn = subprocess.check_output(["readelf", "-d", self.binary],
                                                  stderr=subprocess.DEVNULL).decode(errors="ignore")
                if "BIND_NOW" in re_dyn:
                    relro = "Full RELRO"
                elif "GNU_RELRO" in re_dyn:
                    relro = "Partial RELRO"
            except Exception:
                pass
        return stack_exec, nx, aslr, canary, relro, pie, fortify, shadow_stack

    def _checksec_windows(self):
        import pefile
        nx = aslr = canary = False
        safeseh = cfg = "Disabled"
        pe = pefile.PE(self.binary)
        dc = pe.OPTIONAL_HEADER.DllCharacteristics
        nx = bool(dc & 0x0100)
        aslr = bool(dc & 0x0040)
        canary = bool(dc & 0x10000)
        safeseh = "Enabled" if dc & 0x0400 else "Disabled"
        cfg = "Enabled" if dc & 0x4000 else "Disabled"
        return nx, aslr, canary, safeseh, cfg, aslr

    def _checksec_macos(self):
        stack_exec = nx = aslr = canary = pie = False
        try:
            out = subprocess.check_output(["otool", "-l", self.binary],
                                          stderr=subprocess.DEVNULL).decode(errors="ignore")
            nx = "stack_exec" not in out
            aslr = pie = "PIE" in out
            nm = subprocess.check_output(["nm", self.binary],
                                         stderr=subprocess.DEVNULL).decode(errors="ignore")
            canary = "___stack_chk_guard" in nm
        except Exception as e:
            log.warning(f"macOS checksec: {e}")
        return stack_exec, nx, aslr, canary, pie
