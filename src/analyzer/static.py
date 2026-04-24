"""Static analysis methods for BinaryAnalyzer."""
import subprocess
import re
import logging
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("binsmasher")


class StaticAnalysisMixin:
    """Methods: static_analysis, _list_functions, _parse_function_list, _r2."""

    VULNERABLE_FUNCTIONS = [
        "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "sscanf",
        "read", "fread", "recv", "memcpy", "memmove", "strncpy", "strncat",
        "mpg123_decode", "malloc", "free", "realloc", "calloc",
    ]
    FORMAT_STRING_FUNCTIONS = [
        "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
        "vsprintf", "vsnprintf", "dprintf", "syslog",
    ]
    RUST_SPECIFIC = [
        "panic", "assert", "unwrap", "deserial", "borsh", "bincode",
        "execute_transaction", "process_transaction", "solana_program", "anchor_lang",
    ]

    def static_analysis(self):
        log.info("Running static analysis (radare2)…")
        network_funcs = {
            "linux":   ["socket", "bind", "connect", "listen", "accept", "recv", "send", "recvfrom", "sendto"],
            "android": ["socket", "bind", "connect", "listen", "accept", "recv", "send", "recvfrom", "sendto"],
            "windows": ["WSAStartup", "socket", "bind", "connect", "listen", "accept", "recv", "send"],
            "macos":   ["socket", "bind", "connect", "listen", "accept", "recv", "send"],
        }.get(self.platform, ["socket", "recv", "send"])
        findings = {"vulnerable_functions": [], "format_string_functions": [],
                    "network_functions": [], "heap_functions": [], "rust_functions": [], "all_functions": []}
        all_searched = (self.VULNERABLE_FUNCTIONS + self.FORMAT_STRING_FUNCTIONS
                        + network_funcs + self.RUST_SPECIFIC)
        r2_out = ""
        for r2_cmd in (f"aaa; iz~{'|'.join(all_searched)}", f"is~{'|'.join(all_searched)}",
                       f"ii~{'|'.join(all_searched)}"):
            try:
                r2_out += self._r2(r2_cmd) + "\n"
            except Exception as e:
                log.debug(f"r2 cmd failed: {e}")
        nm_out = ""
        for cmd in (["nm", "-D", self.binary], ["readelf", "-s", self.binary]):
            try:
                nm_out += subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode(errors="ignore")
            except Exception:
                pass
        combined = r2_out + nm_out
        for fn in self.VULNERABLE_FUNCTIONS:
            if fn in combined:
                findings["vulnerable_functions"].append(fn)
                if fn in ("malloc", "free", "realloc", "calloc"):
                    findings["heap_functions"].append(fn)
        for fn in self.FORMAT_STRING_FUNCTIONS:
            if fn in combined:
                findings["format_string_functions"].append(fn)
        for fn in network_funcs:
            if fn in combined:
                findings["network_functions"].append(fn)
        for fn in self.RUST_SPECIFIC:
            if fn in combined:
                findings["rust_functions"].append(fn)
        for k in findings:
            if k != "all_functions":
                findings[k] = list(dict.fromkeys(findings[k]))
        functions = self._list_functions()
        findings["all_functions"] = functions
        if not functions:
            log.warning("No functions detected — binary may be stripped.")
            return findings, None, []
        priority_keywords = ["main", "handle", "client", "process", "input", "recv", "read",
                             "transaction", "execute", "svm", "borsh"]
        target_function = None
        for kw in priority_keywords:
            for name, _ in functions:
                if kw in name.lower():
                    target_function = name
                    break
            if target_function:
                break
        if not target_function:
            target_function = functions[0][0]
        table = Table(title="Static Analysis", show_header=True, header_style="bold cyan")
        table.add_column("Category", style="cyan")
        table.add_column("Detected", style="white")
        for k, v in findings.items():
            if k != "all_functions":
                table.add_row(k.replace("_", " ").title(), ", ".join(v) or "—")
        table.add_row("Target Function", target_function)
        table.add_row("Fn sample (first 8)",
                      ", ".join(n for n, _ in functions[:8]) + ("…" if len(functions) > 8 else ""))
        console.print(table)
        log.debug(f"All functions ({len(functions)}): {[n for n, _ in functions]}")
        return findings, target_function, functions

    def _list_functions(self):
        for cmd in ("afl", "afll"):
            try:
                raw = self._r2(cmd)
                fns = self._parse_function_list(raw)
                if fns:
                    return fns
            except Exception:
                pass
        try:
            raw = self._r2("is")
            fns = []
            for line in raw.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0].startswith("0x") and "FUNC" in line:
                    try:
                        addr = int(parts[0], 16)
                        name = parts[-1]
                        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
                            fns.append((name, addr))
                    except Exception:
                        pass
            if fns:
                return fns
        except Exception:
            pass
        try:
            out = subprocess.check_output(["nm", self.binary], stderr=subprocess.DEVNULL).decode(errors="ignore")
            fns = []
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[1] in ("T", "t"):
                    name = parts[2]
                    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
                        fns.append((name, int(parts[0], 16) if parts[0] != "0" * len(parts[0]) else 0))
            if fns:
                return fns
        except Exception:
            pass
        return [("main", 0x0)]

    def _parse_function_list(self, raw):
        fns = []
        for line in raw.splitlines():
            parts = line.split()
            if not parts or not parts[0].startswith("0x"):
                continue
            try:
                addr = int(parts[0], 16)
                name = parts[-1]
                if (name and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name)
                        and not name.startswith(("sym.imp.", "loc.", "sub."))):
                    fns.append((name, addr))
            except Exception:
                pass
        return fns

    def _r2(self, cmd):
        full = f"r2 -A -q -c '{cmd}' {self.binary}"
        return subprocess.check_output(full, shell=True,
                                       stderr=subprocess.DEVNULL, timeout=30).decode(errors="ignore")
