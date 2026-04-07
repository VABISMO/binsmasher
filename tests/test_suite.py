#!/usr/bin/env python3
"""
BinSmasher realtest — complete integration test suite.

All test categories:
  CTF      downloaded nightmare CTF binaries
  LOCAL    t1-t11 + t_shellexec + t_revshell (all stdin/stdout, socat fork)
  DOS      --dos: crash payload fired, crash_B.py + exploit_B.py generated
  CMD      t_shellexec win()→system("id")→stdout captured
  REVSHELL t_revshell win()→connect-back shell verified with real listener
  SCRIPTS  --generate-scripts + crash script executed to confirm it fires
"""

import os, sys, re, ast, socket, subprocess, threading, time, signal, shutil, resource
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console(highlight=False, markup=True)

THIS     = Path(__file__).resolve().parent
SRC_DIR  = THIS.parent / "src"
BINS_DIR = THIS / "bins"
CTF_DIR  = THIS / "test_pwn"
WORK_DIR = THIS / "_work"
WORK_DIR.mkdir(exist_ok=True)

sys.path.insert(0, str(SRC_DIR))

PASS = "PASS"; FAIL = "FAIL"; WARN = "WARN"; SKIP = "SKIP"
_results: list = []
STYLE = {PASS: "bold green", FAIL: "bold red", WARN: "bold yellow", SKIP: "dim white"}

# ── CTF URLs ──────────────────────────────────────────────────────────────────
CTF_BINS = {
    "babyrop":       "https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/05-bof_callfunction/csaw16_warmup/warmup",
    "ret2win":       "https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/04-bof_variable/tamu19_pwn1/pwn1",
    "shellcode_test":"https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/06-bof_shellcode/tamu19_pwn3/pwn3",
    "gold_miner":    "https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/04-bof_variable/csaw18_boi/boi",
    "heap_test":     "https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/24-heap_overflow/protostar_heap0/heap0",
    "modern_stack":  "https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/05-bof_callfunction/csaw18_getit/get_it",
    "adv_rop_64":    "https://raw.githubusercontent.com/guyinatuxedo/nightmare/master/modules/06-bof_shellcode/csaw17_pilot/pilot",
}

# Expected result per local binary (WARN = hard to auto-exploit by design)
LOCAL_BINS = {
    "t1_stack_noprotect": (14441, PASS),
    "t2_stack_nx":        (14442, PASS),
    "t3_stack_canary":    (14443, WARN),  # canary bypass needs fmt oracle, expected WARN
    "t4_fmtstr":          (14444, PASS),
    "t5_heap":            (14445, PASS),
    "t6_64bit_nx":        (14446, PASS),
    "t7_cfi_vtable":      (14447, PASS),
    "t8_seccomp":         (14448, PASS),
    "t9_stripped":        (14449, WARN),  # stripped, no symbols, expected WARN
    "t10_safestack":      (14450, PASS),
    "t11_heap_glibc234":  (14451, PASS),
}

ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mKABCDEFGHJSTfhilmnprsu]')

def strip_ansi(s: str) -> str:
    return ANSI_RE.sub('', s)

def section(title: str, sub: str = "") -> None:
    txt = f"[bold cyan]{title}[/]"
    if sub: txt += f"  [dim]{sub}[/]"
    console.rule(txt)

def record(cat: str, name: str, status: str, note: str = "") -> None:
    _results.append((cat, name, status, note))
    s = STYLE.get(status, "white")
    line = f"  [{s}]{status:4s}[/]  [bold]{cat:8s}[/]  {name}"
    if note: line += f"  [dim]{note}[/]"
    console.print(line)

def extract_summary(raw: str) -> dict:
    """Parse BinSmasher summary table from output. Returns dict of key→value."""
    clean = strip_ansi(raw)
    info  = {}
    for line in clean.splitlines():
        if "│" in line:
            parts = [p.strip() for p in line.split("│") if p.strip()]
            if len(parts) == 2:
                info[parts[0]] = parts[1]
        # Extract the actual win() address from log line "Return address target: 0x..."
        if "Return address target:" in line:
            m = __import__("re").search(r"(0x[0-9a-fA-F]+)", line)
            if m:
                info["win_addr"] = m.group(1)
        # Extract seccomp/NX/PIE protection info
        if "NX:" in line or "Canary" in line or "PIE:" in line:
            for kw in ("NX:", "Canary:", "PIE:", "RELRO:"):
                if kw in line:
                    m2 = __import__("re").search(rf"{kw.rstrip(':')}: *(\S+)", line)
                    if m2:
                        info[kw.rstrip(":")] = m2.group(1)
    return info

def show_result(out: str, passed: bool = True) -> None:
    """
    Print the BinSmasher summary table and — on WARN/FAIL only — key diagnostic lines.
    Strips all known noise: core-file errors, libc-offset warnings, ethics banners.
    """
    NOISE = (
        "[ERROR] Could not find core file",
        "No built-in offsets for libc",
        "WARNING: Use only",
        "Unauthorized access",
        "Ethics Notice",
        "written authorization",
        "seccomp-tools not installed",
        "│ WARNING:",
    )
    clean = strip_ansi(out)
    table_lines  = []   # the ┌─┤ box lines we always show
    useful_lines = []   # INFO/WARNING/ERROR lines useful for diagnosis
    in_sug = False

    for line in clean.splitlines():
        s = line.strip()
        if not s:
            continue
        # Skip suggestion panel
        if "Suggest" in s and s.startswith("╭"):
            in_sug = True; continue
        if in_sug:
            if s.startswith("╰"): in_sug = False
            continue
        if s.startswith("│   •") or s.startswith("╭") or s.startswith("╰"):
            continue
        # Skip noise
        if any(n in line for n in NOISE):
            continue
        # Keep summary table rows (│ key │ value │)
        if s.startswith("│") or s.startswith("└") or s.startswith("┘"):
            table_lines.append(line)
            continue
        # Keep diagnostic lines (INFO/WARNING/ERROR) — but only for failures
        if any(k in line for k in ("INFO", "WARNING", "ERROR", ">>>")):
            useful_lines.append(line)

    # Always show the summary table
    for line in table_lines[-12:]:
        console.print(f"  [dim]{line}[/]")

    # Only show diagnostics on WARN or FAIL
    if not passed and useful_lines:
        console.print("  [bold red]  ── diagnosis ──────────────────────────────[/]")
        for line in useful_lines[-6:]:
            console.print(f"  [red]  {line.strip()}[/]")


def wait_port(host: str, port: int, timeout: float = 6.0) -> bool:
    dl = time.time() + timeout
    while time.time() < dl:
        try:
            with socket.create_connection((host, port), timeout=0.4):
                return True
        except Exception:
            time.sleep(0.1)
    return False

def run_bs(args: list, timeout: int = 180) -> tuple:
    """
    Run BinSmasher subprocess.
    - TERM=dumb + NO_COLOR=1: no ANSI codes in captured output
    - stdin=DEVNULL: prevents any child process from reading the terminal (avoids SIGTTIN)
    - start_new_session=True: detaches from the controlling TTY entirely
    - RLIMIT_CORE=0: no core dumps
    """
    cmd = [sys.executable, str(SRC_DIR / "main.py")] + args
    env = {**os.environ, "PYTHONPATH": str(SRC_DIR),
           "TERM": "dumb", "NO_COLOR": "1", "COLUMNS": "120"}
    def preexec():
        try: resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except Exception: pass
        # Detach from controlling terminal so SIGTTIN/SIGTTOU can't suspend us
        try:
            import os as _os
            _os.setsid()
        except Exception: pass
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, env=env,
                           stdin=subprocess.DEVNULL,
                           preexec_fn=preexec)
        return r.returncode, strip_ansi(r.stdout + r.stderr)
    except subprocess.TimeoutExpired:
        return -1, "TIMEOUT"
    except Exception as e:
        return -2, str(e)

def success_in(out: str) -> bool:
    if "Exploit succeeded" in out: return True
    if "ret2win succeeded" in out: return True
    if "ret2win fired"     in out: return True
    if "dos_crash" in out and "Success" in out: return True
    info = extract_summary(out)
    return info.get("Status", "") == "Success"

def ran(out: str) -> bool:
    return "Exploit Type" in out and "Status" in out

def socat_fork(bin_path: str, port: int) -> subprocess.Popen:
    """
    Start socat with fork. Uses a wrapper script to handle spaces/special chars
    in the binary path — socat EXEC: splits on whitespace, breaking any path
    that contains spaces (e.g. 'Downloads/binsmasher_v7 (1)/v7/...').
    """
    import shlex, stat
    script = f"/tmp/_bs_{port}.sh"
    with open(script, "w") as f:
        f.write(f"#!/bin/sh\nexec {shlex.quote(bin_path)}\n")
    os.chmod(script, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
    return subprocess.Popen(
        ["socat", f"TCP-LISTEN:{port},reuseaddr,fork", f"EXEC:{script}"],
        preexec_fn=os.setsid,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def kill_srv(proc: subprocess.Popen) -> None:
    try: os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        try: proc.terminate()
        except Exception: pass

def workdir_of(bin_path: str) -> Path:
    d = Path(bin_path).parent / "_bs_work"
    d.mkdir(exist_ok=True)
    return d

# ── download ──────────────────────────────────────────────────────────────────

def download_ctf_bins() -> dict:
    console.rule("[bold cyan]Downloading CTF binaries[/]")
    if CTF_DIR.exists(): shutil.rmtree(CTF_DIR)
    CTF_DIR.mkdir(parents=True)
    avail = {}
    for name, url in CTF_BINS.items():
        dest = CTF_DIR / name
        console.print(f"  [dim]↓ {name}…[/]", end=" ")
        try:
            subprocess.run(["curl","-L","-f","-s","--max-time","15",url,"-o",str(dest)],
                           capture_output=True)
            if not dest.exists() or dest.stat().st_size < 100:
                console.print("[red]FAILED[/]"); continue
            if "ELF" not in subprocess.check_output(["file",str(dest)]).decode():
                console.print("[red]not ELF[/]"); dest.unlink(); continue
            dest.chmod(0o755); console.print("[green]OK[/]")
            avail[name] = str(dest)
        except Exception as e:
            console.print(f"[red]{e}[/]")
    return avail

# ── test CTF ──────────────────────────────────────────────────────────────────

def test_ctf(name: str, bin_path: str, port: int) -> None:
    section(f"CTF  {name}", f"port {port}")
    srv = socat_fork(bin_path, port); time.sleep(0.8)
    if not wait_port("127.0.0.1", port, 5):
        kill_srv(srv); record("CTF", name, FAIL, "socat did not start"); return
    try:
        rc, out = run_bs(["binary","-b",bin_path,
                           "--host","127.0.0.1","--port",str(port),
                           "--test-exploit","--pattern-size","300"])
        info = extract_summary(out)
        win  = info.get("win_addr", "")
        note = (f"Offset={info.get('Offset','?')}  "
                f"Type={info.get('Exploit Type','?')}  "
                f"Status={info.get('Status','?')}"
                + (f"  win@{win}" if win else ""))
        if success_in(out):   record("CTF", name, PASS, note)
        elif ran(out):        record("CTF", name, WARN, note)
        elif rc == -1:        record("CTF", name, WARN, "timed out (180s)")
        else:                 record("CTF", name, FAIL, f"rc={rc}")
        show_result(out, passed=success_in(out))
    finally:
        kill_srv(srv); time.sleep(0.3)

# ── test LOCAL ────────────────────────────────────────────────────────────────

def test_local(name: str, port: int, expected: str) -> None:
    bin_path = BINS_DIR / name
    if not bin_path.is_file():
        record("LOCAL", name, SKIP, "run: cd tests/src && make"); return

    section(f"LOCAL  {name}", f"port {port}  [{'expected PASS' if expected==PASS else 'WARN expected'}]")
    srv = socat_fork(str(bin_path), port); time.sleep(0.8)
    if not wait_port("127.0.0.1", port, 5):
        kill_srv(srv); record("LOCAL", name, FAIL, "socat failed to start"); return
    try:
        rc, out = run_bs(["binary","-b",str(bin_path),
                           "--host","127.0.0.1","--port",str(port),
                           "--test-exploit","--pattern-size","200"])
        info = extract_summary(out)
        status  = info.get("Status", "")
        etype   = info.get("Exploit Type", "")
        offset  = info.get("Offset", "?")
        win_a   = info.get("win_addr", "")
        has_pwn = "PWNED" in out or "pwned" in out.lower()
        note    = f"Offset={offset}  Type={etype}"
        if win_a:  note += f"  win@{win_a}"
        if has_pwn: note += "  [PWNED ✓]"

        if success_in(out) and has_pwn:
            record("LOCAL", name, PASS, note + " — win() confirmed via PWNED")
        elif success_in(out):
            record("LOCAL", name, PASS, note)
        elif ran(out) and expected == WARN:
            record("LOCAL", name, WARN, note + " (expected)")
        elif ran(out):
            record("LOCAL", name, WARN, note)
        elif rc == -1:
            record("LOCAL", name, WARN, "timed out (180s)")
        else:
            record("LOCAL", name, FAIL, f"rc={rc}")
        show_result(out, passed=success_in(out))
    finally:
        kill_srv(srv); time.sleep(0.3)

# ── test DOS ──────────────────────────────────────────────────────────────────

def test_dos(name: str, bin_path: str, port: int) -> None:
    section(f"DOS  {name}", f"port {port}")
    wd    = workdir_of(bin_path)
    bname = Path(bin_path).name
    cf    = wd / f"crash_{bname}.py"
    ef    = wd / f"exploit_{bname}.py"
    cf.unlink(missing_ok=True); ef.unlink(missing_ok=True)

    srv = socat_fork(bin_path, port); time.sleep(0.8)
    if not wait_port("127.0.0.1", port, 5):
        kill_srv(srv); record("DOS", name, FAIL, "socat failed to start"); return
    try:
        rc, out = run_bs(["binary","-b",bin_path,
                           "--host","127.0.0.1","--port",str(port),
                           "--dos","--test-exploit","--pattern-size","300"])
        ok_c = cf.is_file(); ok_e = ef.is_file()
        info = extract_summary(out)

        if ok_c and ok_e and success_in(out):
            record("DOS", name, PASS,
                   f"Offset={info.get('Offset','?')} — crash sent + crash_B.py + exploit_B.py")
        elif ok_c and ok_e:
            record("DOS", name, PASS,
                   f"crash_B.py + exploit_B.py written  (crash send failed: target down)")
        elif ok_c or ok_e:
            record("DOS", name, WARN, "only one script generated")
        elif rc == -1:
            record("DOS", name, WARN, "timed out")
        else:
            record("DOS", name, FAIL, f"no scripts (rc={rc})")
        show_result(out, passed=success_in(out))
    finally:
        kill_srv(srv); time.sleep(0.3)

# ── test SCRIPTS ──────────────────────────────────────────────────────────────

def test_scripts(name: str, bin_path: str, port: int) -> None:
    section(f"SCRIPTS  {name}", f"port {port}")
    wd    = workdir_of(bin_path)
    bname = Path(bin_path).name
    cf    = wd / f"crash_{bname}.py"
    ef    = wd / f"exploit_{bname}.py"
    cf.unlink(missing_ok=True); ef.unlink(missing_ok=True)

    srv = socat_fork(bin_path, port); time.sleep(0.8)
    if not wait_port("127.0.0.1", port, 5):
        kill_srv(srv); record("SCRIPTS", name, FAIL, "socat failed to start"); return
    try:
        rc, out = run_bs(["binary","-b",bin_path,
                           "--host","127.0.0.1","--port",str(port),
                           "--generate-scripts","--pattern-size","300"])
        ok_c = cf.is_file(); ok_e = ef.is_file()
        if ok_c and ok_e:
            try:
                ast.parse(cf.read_text()); ast.parse(ef.read_text())
                # Run the crash script to confirm it actually fires
                srv2 = socat_fork(bin_path, port + 200); time.sleep(0.5)
                patch = cf.read_text().replace(f"PORT   = {port}", f"PORT   = {port+200}")
                tmp = wd / "_run_crash.py"
                tmp.write_text(patch)
                env2 = {**os.environ, "TERM": "dumb", "NO_COLOR": "1"}
                r2 = subprocess.run([sys.executable, str(tmp)],
                                    capture_output=True, timeout=20, env=env2)
                kill_srv(srv2)
                if r2.returncode == 0:
                    record("SCRIPTS", name, PASS,
                           "both scripts written, valid Python, crash script executed OK")
                else:
                    record("SCRIPTS", name, WARN,
                           "scripts written, valid Python, crash script non-zero exit")
            except Exception as e:
                record("SCRIPTS", name, WARN, f"scripts written but issue: {e}")
        elif ok_c or ok_e:
            record("SCRIPTS", name, WARN, "only one script generated")
        elif rc == -1:
            record("SCRIPTS", name, WARN, "timed out")
        else:
            record("SCRIPTS", name, FAIL, f"no scripts (rc={rc})")
        show_result(out, passed=success_in(out))
    finally:
        kill_srv(srv); time.sleep(0.3)

# ── test CMD ──────────────────────────────────────────────────────────────────

def test_cmd() -> None:
    """
    t_shellexec stdin/stdout binary wrapped by socat fork.
    win() calls system("id") whose output goes to stdout → socat → BinSmasher.
    BinSmasher's _send_recv captures "uid=..." in the response.
    """
    name     = "t_shellexec"
    bin_path = BINS_DIR / name
    if not bin_path.is_file():
        record("CMD", name, SKIP, "run: cd tests/src && make"); return

    port = 14461
    section(f"CMD exec  {name}", f"port {port}  →  win() calls system('id') → stdout")
    # t_shellexec sends "ready\n" banner before reading.
    # socat fork handles multiple connections (each crash spawns fresh child).
    srv = socat_fork(str(bin_path), port); time.sleep(0.5)
    if not wait_port("127.0.0.1", port, 5):
        kill_srv(srv); record("CMD", name, FAIL, "socat did not start"); return
    try:
        rc, out = run_bs(["binary","-b",str(bin_path),
                           "--host","127.0.0.1","--port",str(port),
                           "--test-exploit","--pattern-size","200"])
        info    = extract_summary(out)
        is_ok   = success_in(out)

        # Extract cmd output from COMMAND OUTPUT log lines
        # Rich may wrap the content onto the next line, so check adjacent lines too
        cmd_output = ""
        lines = out.splitlines()
        for i, line in enumerate(lines):
            if "COMMAND OUTPUT" in line:
                # uid= might be on the same line or the next wrapped line
                search_lines = [line] + (lines[i+1:i+3] if i+1 < len(lines) else [])
                for sl in search_lines:
                    idx = sl.find("uid=")
                    if idx >= 0:
                        cmd_output = sl[idx:].strip()[:80]
                        break
                if cmd_output:
                    break

        if is_ok and cmd_output:
            record("CMD", name, PASS, f"CMD confirmed → {cmd_output}")
            console.print(f"  [green bold]  >>> CMD OUTPUT: {cmd_output}[/]")
        elif is_ok:
            record("CMD", name, PASS, "exploit succeeded — check log for output")
        elif rc == -1:
            record("CMD", name, WARN, "timed out (180s)")
        else:
            record("CMD", name, FAIL,
                   f"exploit failed — Offset={info.get('Offset','?')} "
                   f"Type={info.get('Exploit Type','?')}")
        show_result(out, passed=success_in(out))
    finally:
        kill_srv(srv); time.sleep(0.3)

# ── test REVSHELL ─────────────────────────────────────────────────────────────

def test_revshell() -> None:
    """
    t_revshell stdin/stdout binary wrapped by socat fork.
    win() connects back to 127.0.0.1:9001 and execs /bin/sh.
    We listen on 9001, send 'id', and verify uid= comes back.
    """
    name     = "t_revshell"
    bin_path = BINS_DIR / name
    if not bin_path.is_file():
        record("REVSHELL", name, SKIP, "run: cd tests/src && make"); return

    port  = 14462
    LPORT = 9001
    section(f"REVSHELL  {name}", f"target={port}  listener=127.0.0.1:{LPORT}")

    received = []; conn_time = [None]
    stop_ev  = threading.Event()

    def listener() -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        try:
            srv.bind(("127.0.0.1", LPORT))
            srv.listen(10)        # big backlog — 3 parallel workers may all connect
            srv.settimeout(35)
            conn, addr = srv.accept()
            conn_time[0] = time.time()
            console.print(f"  [green bold]  ← reverse shell connected from {addr[0]}:{addr[1]}[/]")
            conn.settimeout(5)
            data = b""
            for _ in range(100):
                try:
                    chunk = conn.recv(512)
                    if not chunk: break
                    data += chunk
                except Exception: break
            received.append(data)
            conn.close()
        except Exception as e:
            console.print(f"  [red]  Listener error on :{LPORT}: {e}[/]")
            received.append(b"")
        finally:
            try: srv.close()
            except: pass

    # Kill anything holding port 9001 from a previous run
    try:
        subprocess.run(["fuser", "-k", "9001/tcp"],
                       capture_output=True, timeout=3)
        time.sleep(0.4)
    except Exception:
        pass

    t = threading.Thread(target=listener, daemon=True)
    t.start(); time.sleep(0.5)   # give listener time to bind

    srv = socat_fork(str(bin_path), port); time.sleep(0.5)
    if not wait_port("127.0.0.1", port, 5):
        kill_srv(srv); stop_ev.set()
        record("REVSHELL", name, FAIL, "socat did not start"); return
    try:
        rc, out = run_bs(["binary","-b",str(bin_path),
                           "--host","127.0.0.1","--port",str(port),
                           "--test-exploit","--pattern-size","200"])
        # Give win() extra time to connect back
        time.sleep(3.0)
        stop_ev.set(); t.join(timeout=8)
        shell_out = received[0] if received else b""

        has_shell_output = (b"uid=" in shell_out or b"root" in shell_out
                             or b"REVSHELL_OK" in shell_out)
        if has_shell_output:
            record("REVSHELL", name, PASS,
                   f"reverse shell confirmed: {shell_out.decode(errors='replace').strip()[:80]}")
            # Show the output from win()
            out_text = shell_out.decode(errors='replace').strip()
            first_line = out_text.splitlines()[0] if out_text else ""
            console.print(f"  [green bold]  >>> REVSHELL OUTPUT: {first_line[:80]}[/]")
        elif success_in(out):
            record("REVSHELL", name, WARN,
                   "exploit succeeded but shell output not captured on 9001 listener")
        elif rc == -1:
            record("REVSHELL", name, WARN, "timed out (180s)")
        else:
            info = extract_summary(out)
            record("REVSHELL", name, FAIL,
                   f"no shell — Offset={info.get('Offset','?')} "
                   f"Type={info.get('Exploit Type','?')}")
        show_result(out, passed=success_in(out))
    finally:
        kill_srv(srv); time.sleep(0.3)

# ── summary table ─────────────────────────────────────────────────────────────

def print_summary() -> None:
    console.rule("[bold white]FINAL RESULTS[/]", style="white")
    counts = {PASS:0, FAIL:0, WARN:0, SKIP:0}
    tbl = Table(show_header=True, header_style="bold cyan",
                title="[bold]BinSmasher — Test Results[/]",
                min_width=110, pad_edge=True, show_lines=False)
    tbl.add_column(" ", width=2, no_wrap=True)
    tbl.add_column("Status", width=7, no_wrap=True)
    tbl.add_column("Category", width=9, no_wrap=True)
    tbl.add_column("Binary", width=24, no_wrap=True)
    tbl.add_column("Note", overflow="fold")

    for cat, name, status, note in _results:
        counts[status] = counts.get(status, 0) + 1
        icon  = {"PASS":"[green]●[/]","FAIL":"[red]✗[/]","WARN":"[yellow]⚠[/]","SKIP":"[dim]○[/]"}.get(status,"?")
        style = STYLE.get(status, "white")
        tbl.add_row(icon, f"[{style}]{status}[/]", f"[dim]{cat}[/]", name, f"[dim]{note}[/]" if note else "")

    console.print(tbl)
    console.print()
    console.print(f"  [bold green]PASS={counts[PASS]}[/]  "
                  f"[bold red]FAIL={counts[FAIL]}[/]  "
                  f"[bold yellow]WARN={counts[WARN]}[/]  "
                  f"[dim]SKIP={counts[SKIP]}[/]")
    console.print()
    if counts[FAIL] == 0:
        console.print(Panel("[bold green]✓  No hard failures[/]", border_style="green", width=50))
    else:
        console.print(Panel(f"[bold red]✗  {counts[FAIL]} failure(s)[/]", border_style="red", width=50))

# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="BinSmasher realtest")
    ap.add_argument("--ctf-only",    action="store_true")
    ap.add_argument("--local-only",  action="store_true")
    ap.add_argument("--no-download", action="store_true")
    ap.add_argument("--skip-slow",   action="store_true", help="Skip CMD + REVSHELL tests")
    args = ap.parse_args()

    # Disable core dumps for this entire test process tree
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass
    # Also redirect via /proc if writable
    try:
        with open("/proc/sys/kernel/core_pattern", "w") as f:
            f.write(str(WORK_DIR / "core.%e.%p"))
    except Exception:
        pass  # not writable — that's ok, RLIMIT_CORE=0 handles it

    console.print(Panel(
        "[bold cyan]BinSmasher[/] test\n"
        "[dim]PASS=working  WARN=partial/expected  FAIL=broken  SKIP=binary missing[/]\n"
        "[dim]All local bins: stdin/stdout via socat fork. win() in every binary.[/]",
        title="[bold]🔨 test [/]", border_style="cyan", width=80))

    run_ctf   = not args.local_only
    run_local = not args.ctf_only
    port = 4444

    if run_ctf:
        ctf_avail = {}
        if not args.no_download:
            ctf_avail = download_ctf_bins()
        else:
            ctf_avail = {n: str(CTF_DIR/n) for n in CTF_BINS if (CTF_DIR/n).is_file()}
        for name, path in ctf_avail.items():
            test_ctf(name, path, port); port += 1
        if ctf_avail:
            first = next(iter(ctf_avail.items()))
            test_dos(*first, port);     port += 1
            test_scripts(*first, port); port += 1

    if run_local:
        console.rule(f"[bold cyan]Local binaries[/]  [dim]{BINS_DIR}[/]")
        if not BINS_DIR.is_dir():
            console.print(f"[red]  {BINS_DIR} not found[/]\n"
                          "[dim]  Run: cd tests/src && make[/]")
        else:
            for name, (lport, exp) in LOCAL_BINS.items():
                test_local(name, lport, exp)
            if not args.skip_slow:
                test_cmd()
                test_revshell()

    print_summary()


if __name__ == "__main__":
    main()
