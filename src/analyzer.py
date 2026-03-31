#!/usr/bin/env python3
"""
BinSmasher – analyzer.py
Static & dynamic binary analysis: protections, functions, libraries.

FIX (v2): static_analysis now searches both iz~ (strings) and is~ (symbols)
           so imported library functions (printf, snprintf, gets …) are
           correctly detected even in stripped or dynamically-linked binaries.
"""

import subprocess
import os
import re
import time
import logging

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
log = logging.getLogger("binsmasher")


class BinaryAnalyzer:
    """Static and dynamic analysis of a target binary."""

    VULNERABLE_FUNCTIONS = [
        "gets", "strcpy", "strcat", "sprintf", "vsprintf",
        "scanf", "sscanf", "read", "fread", "recv",
        "memcpy", "memmove", "strncpy", "strncat",
        "mpg123_decode", "malloc", "free", "realloc", "calloc",
    ]
    FORMAT_STRING_FUNCTIONS = [
        "printf", "fprintf", "sprintf", "snprintf",
        "vprintf", "vfprintf", "vsprintf", "vsnprintf",
        "dprintf", "syslog",
    ]
    RUST_SPECIFIC = [
        "panic", "assert", "unwrap", "deserial", "borsh",
        "bincode", "execute_transaction", "process_transaction",
        "solana_program", "anchor_lang",
    ]

    def __init__(self, binary: str, log_file: str) -> None:
        self.binary   = binary
        self.log_file = log_file
        self.platform: str = "linux"
        self.arch: str     = "amd64"

    # ────────────────────────────────────────────
    # 1. Platform / arch detection
    # ────────────────────────────────────────────

    def setup_context(self) -> tuple:
        try:
            result = subprocess.check_output(
                ["file", self.binary], stderr=subprocess.DEVNULL
            ).decode().lower()
        except FileNotFoundError:
            log.error("`file` command not found.")
            raise SystemExit(1)

        platform, arch = "linux", "amd64"

        if "elf" in result:
            platform = "android" if "arm" in result else "linux"
            if "32-bit" in result:
                arch = "arm" if "arm" in result else "i386"
            elif "64-bit" in result:
                arch = "aarch64" if "aarch64" in result else "amd64"
        elif "pe32+" in result:
            platform, arch = "windows", "amd64"
        elif "pe32" in result:
            platform, arch = "windows", "i386"
        elif "mach-o" in result:
            platform = "macos"
            arch = "arm64" if "arm64" in result else "amd64"
        else:
            log.warning("Unknown binary format — assuming Linux x86_64")

        try:
            from pwn import context as pctx  # type: ignore
            pctx(arch=arch, os=platform if platform != "macos" else "linux")
        except Exception as e:
            log.warning(f"pwntools context: {e}")

        log.info(f"Platform: {platform.upper()}  Arch: {arch}")
        self.platform = platform
        self.arch = arch
        return platform, arch

    # ────────────────────────────────────────────
    # 2. Static analysis via Radare2
    # ────────────────────────────────────────────

    def static_analysis(self) -> tuple:
        log.info("Running static analysis (radare2)…")

        network_funcs = {
            "linux":   ["socket","bind","connect","listen","accept","recv","send","recvfrom","sendto"],
            "android": ["socket","bind","connect","listen","accept","recv","send","recvfrom","sendto"],
            "windows": ["WSAStartup","socket","bind","connect","listen","accept","recv","send"],
            "macos":   ["socket","bind","connect","listen","accept","recv","send"],
        }.get(self.platform, ["socket","recv","send"])

        findings = {
            "vulnerable_functions":    [],
            "format_string_functions": [],
            "network_functions":       [],
            "heap_functions":          [],
            "rust_functions":          [],
            "all_functions":           [],
        }

        all_searched = (
            self.VULNERABLE_FUNCTIONS
            + self.FORMAT_STRING_FUNCTIONS
            + network_funcs
            + self.RUST_SPECIFIC
        )

        # ── FIX: use BOTH iz (strings) and is (dynamic symbols) ──
        r2_out = ""
        for r2_cmd in (
            f"aaa; iz~{'|'.join(all_searched)}",   # strings section
            f"is~{'|'.join(all_searched)}",          # symbol table (imports)
            f"ii~{'|'.join(all_searched)}",          # imports list
        ):
            try:
                r2_out += self._r2(r2_cmd) + "\n"
            except Exception as e:
                log.debug(f"r2 cmd '{r2_cmd[:40]}…' failed: {e}")

        # Also try nm / readelf as fallback for function detection
        nm_out = ""
        try:
            nm_out = subprocess.check_output(
                ["nm", "-D", self.binary], stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
        except Exception:
            pass
        try:
            nm_out += subprocess.check_output(
                ["readelf", "-s", self.binary], stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
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

        # Deduplicate
        for k in findings:
            if k != "all_functions":
                findings[k] = list(dict.fromkeys(findings[k]))

        # ── Function listing ──
        functions = self._list_functions()
        findings["all_functions"] = functions

        if not functions:
            log.warning("No functions detected — binary may be stripped.")
            return findings, None, []

        # ── Choose target function ──
        priority_keywords = [
            "main", "handle", "client", "process", "input",
            "recv", "read", "transaction", "execute", "svm", "borsh",
        ]
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

        # ── Pretty table ──
        table = Table(title="Static Analysis", show_header=True, header_style="bold cyan")
        table.add_column("Category", style="cyan")
        table.add_column("Detected", style="white")
        for k, v in findings.items():
            if k != "all_functions":
                table.add_row(k.replace("_", " ").title(), ", ".join(v) or "—")
        table.add_row("Target Function", target_function)
        table.add_row(
            "Fn sample (first 8)",
            ", ".join(n for n, _ in functions[:8]) + ("…" if len(functions) > 8 else ""),
        )
        console.print(table)
        log.debug(f"All functions ({len(functions)}): {[n for n,_ in functions]}")
        return findings, target_function, functions

    def _list_functions(self) -> list:
        for cmd in ("afl", "afll"):
            try:
                raw = self._r2(cmd)
                fns = self._parse_function_list(raw)
                if fns:
                    return fns
            except Exception:
                pass

        # symbol table fallback
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
                    except (ValueError, IndexError):
                        pass
            if fns:
                return fns
        except Exception:
            pass

        # nm fallback
        try:
            out = subprocess.check_output(
                ["nm", self.binary], stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            fns = []
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[1] in ("T", "t"):
                    name = parts[2]
                    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
                        fns.append((name, int(parts[0], 16) if parts[0] != "0"*len(parts[0]) else 0))
            if fns:
                return fns
        except Exception:
            pass

        return [("main", 0x0)]

    def _parse_function_list(self, raw: str) -> list:
        fns = []
        for line in raw.splitlines():
            parts = line.split()
            if not parts or not parts[0].startswith("0x"):
                continue
            try:
                addr = int(parts[0], 16)
                name = parts[-1]
                if (name
                        and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name)
                        and not name.startswith(("sym.imp.", "loc.", "sub."))):
                    fns.append((name, addr))
            except (ValueError, IndexError):
                pass
        return fns

    def _r2(self, cmd: str) -> str:
        full = f"r2 -A -q -c '{cmd}' {self.binary}"
        return subprocess.check_output(
            full, shell=True, stderr=subprocess.DEVNULL, timeout=30
        ).decode(errors="ignore")

    # ────────────────────────────────────────────
    # 3. Protection detection
    # ────────────────────────────────────────────

    def check_protections(self) -> tuple:
        """
        Returns:
            (stack_exec, nx, aslr, canary, relro,
             safeseh, cfg, fortify, pie, shadow_stack)
        """
        log.info("Checking binary protections…")

        stack_exec = True
        nx = aslr = canary = pie = False
        relro = "No RELRO"
        safeseh = cfg = fortify = shadow_stack = "N/A"

        try:
            if self.platform in ("linux", "android"):
                stack_exec, nx, aslr, canary, relro, pie, fortify, shadow_stack = \
                    self._checksec_linux()
            elif self.platform == "windows":
                nx, aslr, canary, safeseh, cfg, pie = self._checksec_windows()
                stack_exec = not nx
            elif self.platform == "macos":
                stack_exec, nx, aslr, canary, pie = self._checksec_macos()
        except Exception as e:
            log.warning(f"Protection check error: {e} — assuming weak protections.")

        table = Table(title="Binary Protections", show_header=True, header_style="bold cyan")
        table.add_column("Protection", style="cyan")
        table.add_column("Value",      style="white")

        def yn(v): return "[green]Yes[/]" if v else "[red]No[/]"

        table.add_row("NX / DEP",           yn(nx))
        table.add_row("Stack Canary",        yn(canary))
        table.add_row("ASLR / PIE",          f"{yn(aslr)} / {yn(pie)}")
        table.add_row("RELRO",               relro)
        table.add_row("Stack Executable",    yn(stack_exec))
        table.add_row("FORTIFY_SOURCE",      str(fortify))
        table.add_row("Shadow Stack (CET)",  str(shadow_stack))
        if self.platform == "windows":
            table.add_row("SafeSEH", str(safeseh))
            table.add_row("CFG",     str(cfg))
        console.print(table)

        return stack_exec, nx, aslr, canary, relro, safeseh, cfg, fortify, pie, shadow_stack

    def _checksec_linux(self):
        stack_exec = nx = aslr = canary = pie = False
        relro = "No RELRO"
        fortify = "Disabled"
        shadow_stack = "Disabled"

        try:
            re_out = subprocess.check_output(
                ["readelf", "-W", "-l", self.binary], stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            # GNU_STACK with RWE = executable stack
            for line in re_out.splitlines():
                if "GNU_STACK" in line:
                    stack_exec = "RWE" in line
                    break
            nx = not stack_exec

            if "GNU_PROPERTY" in re_out:
                props = subprocess.check_output(
                    ["readelf", "-n", self.binary], stderr=subprocess.DEVNULL
                ).decode(errors="ignore")
                if "IBT" in props or "SHSTK" in props:
                    shadow_stack = "Enabled (CET)"
        except Exception:
            pass

        # checksec
        try:
            cs = subprocess.check_output(
                ["checksec", "--file", self.binary], stderr=subprocess.STDOUT
            ).decode(errors="ignore")
            nx      = nx or ("NX enabled" in cs)
            aslr    = "PIE enabled" in cs
            canary  = "Canary found" in cs
            pie     = aslr
            fortify = "Fortified" if "FORTIFY" in cs else "Disabled"
            if "Full RELRO" in cs:
                relro = "Full RELRO"
            elif "Partial RELRO" in cs:
                relro = "Partial RELRO"
        except FileNotFoundError:
            log.warning("checksec not installed — using readelf/nm fallback")
            # Canary via nm
            try:
                nm = subprocess.check_output(
                    ["nm", "-D", self.binary], stderr=subprocess.DEVNULL
                ).decode(errors="ignore")
                canary = "__stack_chk_fail" in nm
            except Exception:
                pass
            # RELRO via readelf
            try:
                re_dyn = subprocess.check_output(
                    ["readelf", "-d", self.binary], stderr=subprocess.DEVNULL
                ).decode(errors="ignore")
                if "BIND_NOW" in re_dyn:
                    relro = "Full RELRO"
                elif "GNU_RELRO" in re_dyn:
                    relro = "Partial RELRO"
            except Exception:
                pass

        return stack_exec, nx, aslr, canary, relro, pie, fortify, shadow_stack

    def _checksec_windows(self):
        import pefile  # type: ignore
        nx = aslr = canary = False
        safeseh = cfg = "Disabled"
        pe = pefile.PE(self.binary)
        dc = pe.OPTIONAL_HEADER.DllCharacteristics
        nx      = bool(dc & 0x0100)
        aslr    = bool(dc & 0x0040)
        canary  = bool(dc & 0x10000)
        safeseh = "Enabled" if dc & 0x0400 else "Disabled"
        cfg     = "Enabled" if dc & 0x4000 else "Disabled"
        pie     = aslr
        return nx, aslr, canary, safeseh, cfg, pie

    def _checksec_macos(self):
        stack_exec = nx = aslr = canary = pie = False
        try:
            out = subprocess.check_output(
                ["otool", "-l", self.binary], stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            nx   = "stack_exec" not in out
            aslr = "PIE" in out
            pie  = aslr
            nm   = subprocess.check_output(
                ["nm", self.binary], stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            canary = "___stack_chk_guard" in nm
        except Exception as e:
            log.warning(f"macOS checksec failed: {e}")
        return stack_exec, nx, aslr, canary, pie

    # ────────────────────────────────────────────
    # 4. Frida dynamic analysis
    # ────────────────────────────────────────────

    def frida_analyze(self, binary_args: list) -> bool:
        log.info("Starting Frida dynamic analysis…")
        try:
            import frida  # type: ignore
        except ImportError:
            log.error("frida not installed: pip install frida-tools")
            return False

        script_code = """
'use strict';
const targets = ["gets","strcpy","sprintf","scanf","recv","read",
                 "malloc","free","printf","system"];
targets.forEach(function(fn) {
    var addr = Module.findExportByName(null, fn);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) {
            send({fn: fn, arg0: args[0].toString(), tid: this.threadId});
        }
    });
});
"""
        cmd = [self.binary] + binary_args if binary_args else [self.binary]
        try:
            import subprocess as sp
            proc = sp.Popen(cmd, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
            time.sleep(0.5)
            session = frida.attach(proc.pid)
            script  = session.create_script(script_code)
            msgs    = []
            script.on("message", lambda m, d: msgs.append(m))
            script.load()
            time.sleep(3)
            script.unload()
            session.detach()
            proc.terminate()
            log.info(f"Frida captured {len(msgs)} events")
            for m in msgs[:20]:
                log.debug(f"  Frida → {m.get('payload', m)}")
            return True
        except Exception as e:
            log.warning(f"Frida attach failed: {e}")
            return False

    # ────────────────────────────────────────────
    # 5. Library offset loading
    # ────────────────────────────────────────────

    def load_library_offsets(self) -> tuple:
        log.info("Loading library offsets…")
        base_addr = None

        # Built-in offset table
        LIBC_OFFSETS = {
            "libc.so.6": {
                "2.31": {"system": 0x055410, "binsh": 0x1B75AA, "execve": 0x0E6C70,
                         "tcache": 0x1B2C40, "puts":  0x080ED0},
                "2.35": {"system": 0x050D70, "binsh": 0x1B45BD, "execve": 0x0E63B0,
                         "tcache": 0x219C80, "puts":  0x080E50},
                "2.38": {"system": 0x054EF0, "binsh": 0x1BC351, "execve": 0x0EAEA0,
                         "tcache": 0x21B2C0, "puts":  0x0849C0},
                "2.39": {"system": 0x058740, "binsh": 0x1CB42F, "execve": 0x0F2C80,
                         "tcache": 0x21D2C0, "puts":  0x088D90},
            },
        }

        try:
            if self.platform in ("linux", "android"):
                ldd_cmd = (
                    ["adb", "shell", f"ldd {self.binary}"]
                    if self.platform == "android"
                    else ["ldd", self.binary]
                )
                try:
                    ldd_out = subprocess.check_output(
                        ldd_cmd, stderr=subprocess.DEVNULL
                    ).decode()
                except Exception:
                    ldd_out = ""

                maps_cmd = (
                    ["adb", "shell", "cat /proc/1/maps"]
                    if self.platform == "android"
                    else ["cat", f"/proc/{os.getpid()}/maps"]
                )
                try:
                    maps = subprocess.check_output(
                        maps_cmd, stderr=subprocess.DEVNULL
                    ).decode()
                    for line in maps.splitlines():
                        if "libc" in line and "r-xp" in line:
                            base_addr = int(line.split("-")[0], 16)
                            log.info(f"libc base: {hex(base_addr)}")
                            break
                except Exception:
                    pass

            elif self.platform == "windows":
                import pefile  # type: ignore
                pe   = pefile.PE(self.binary)
                dlls = [d.Name.decode() for d in pe.DIRECTORY_ENTRY_IMPORT]
                log.info(f"Imported DLLs: {dlls}")
                return dlls[0] if dlls else None, "unknown", {}, None

            version = self._detect_libc_version()
            offsets = LIBC_OFFSETS.get("libc.so.6", {}).get(version, {})
            if offsets:
                log.info(f"Loaded libc offsets for v{version}: {list(offsets.keys())}")
                return "libc.so.6", version, offsets, base_addr

            log.warning("No built-in offsets for detected libc version")
            return None, None, {}, base_addr

        except Exception as e:
            log.warning(f"Library offset loading failed: {e}")
            return None, None, {}, None

    def _detect_libc_version(self) -> str:
        try:
            out = subprocess.check_output(
                ["ldd", "--version"], stderr=subprocess.STDOUT
            ).decode()
            m = re.search(r"(\d+\.\d+)", out)
            if m:
                return m.group(1)
        except Exception:
            pass
        return "2.31"

    # ────────────────────────────────────────────
    # 6. Rust / Agave unsafe grep
    # ────────────────────────────────────────────

    def grep_unsafe_source(self, source_path: str) -> list:
        log.info(f"Grepping Rust source in {source_path} for 'unsafe'…")
        unsafe_files = []
        unsafe_total = 0
        try:
            for root, _, files in os.walk(source_path):
                for fname in files:
                    if not fname.endswith(".rs"):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        content = open(fpath, encoding="utf-8", errors="ignore").read()
                        n = content.count("unsafe")
                        if n:
                            unsafe_total += n
                            unsafe_files.append(fpath)
                            log.debug(f"  {fpath}: {n} unsafe block(s)")
                    except OSError:
                        pass
            log.info(f"unsafe occurrences: {unsafe_total} in {len(unsafe_files)} files")
            return unsafe_files
        except Exception as e:
            log.error(f"Source grep failed: {e}")
            return []
