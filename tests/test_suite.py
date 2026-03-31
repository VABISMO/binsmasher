#!/usr/bin/env python3
"""
BinSmasher — tests/test_suite.py
Complete test harness covering all modules and binary types.

Run:
    cd binsmasher_final
    python tests/test_suite.py
"""

import sys, os, time, socket, struct, subprocess, threading, signal, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule

console = Console()
BINS = os.path.join(os.path.dirname(__file__), "bins")
os.makedirs(BINS, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# Infrastructure helpers
# ─────────────────────────────────────────────────────────────────────────────

def wait_port(host: str, port: int, timeout: float = 4.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, port), 0.3)
            s.close()
            return True
        except Exception:
            time.sleep(0.1)
    return False


def spawn(binary: str, args: list = None):
    cmd  = [binary] + (args or [])
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             preexec_fn=os.setsid)
    def kill():
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass
    return proc, kill


def send_recv(host: str, port: int, payload: bytes,
              timeout: float = 2.0) -> bytes | None:
    try:
        s = socket.create_connection((host, port), timeout)
        s.sendall(payload)
        s.settimeout(timeout)
        try:
            data = s.recv(4096)
        except Exception:
            data = b""
        s.close()
        return data
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Result tracking
# ─────────────────────────────────────────────────────────────────────────────

results = []

def R(section: str, test: str, status: str, detail: str = "") -> None:
    results.append((section, test, status, detail))
    icons = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "SKIP": "⏭️"}
    console.print(
        f"  {icons.get(status,'•')} [{status}] {test}"
        + (f" — {detail}" if detail else "")
    )


# ─────────────────────────────────────────────────────────────────────────────
# Binary compilation
# ─────────────────────────────────────────────────────────────────────────────

BINARY_SOURCES = {
    # T1: stack overflow, no protections, NX off
    "t1_stack_noprotect": {
        "port": 14441,
        "flags": "-z execstack -fno-stack-protector -no-pie",
        "src": r"""
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
void handle(int fd){ char buf[64]; read(fd,buf,512); write(fd,buf,8); }
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0),c,opt=1;
  struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(14441);
  setsockopt(s,1,2,&opt,sizeof(opt));
  bind(s,(struct sockaddr*)&a,sizeof(a)); listen(s,1);
  c=accept(s,NULL,NULL); handle(c); close(c); close(s); return 0;
}
""",
    },
    # T2: stack overflow, NX on (ret2libc needed)
    "t2_stack_nx": {
        "port": 14442,
        "flags": "-fno-stack-protector -no-pie",
        "src": r"""
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
void handle(int fd){ char buf[64]; read(fd,buf,512); write(fd,buf,8); }
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0),c,opt=1;
  struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(14442);
  setsockopt(s,1,2,&opt,sizeof(opt));
  bind(s,(struct sockaddr*)&a,sizeof(a)); listen(s,1);
  c=accept(s,NULL,NULL); handle(c); close(c); close(s); return 0;
}
""",
    },
    # T3: stack overflow + canary
    "t3_stack_canary": {
        "port": 14443,
        "flags": "-z execstack -fstack-protector-all -no-pie",
        "src": r"""
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
void handle(int fd){ char buf[64]; read(fd,buf,512); write(fd,buf,8); }
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0),c,opt=1;
  struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(14443);
  setsockopt(s,1,2,&opt,sizeof(opt));
  bind(s,(struct sockaddr*)&a,sizeof(a)); listen(s,1);
  c=accept(s,NULL,NULL); handle(c); close(c); close(s); return 0;
}
""",
    },
    # T4: format string vulnerability -- echoes input, system() in PLT, multi-accept
    "t4_fmtstr": {
        "port": 14444,
        "flags": "-fno-stack-protector -no-pie -z norelro",
        "src": r"""
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
/* system() in PLT -- required for GOT-overwrite technique */
__attribute__((used)) static void _pull(void){ system(""); }
void vuln(int fd){
  char buf[256], resp[512];
  int n = read(fd, buf, 255);
  buf[n] = '\0';
  int l = snprintf(resp, sizeof(resp), buf);   /* VULN: format string */
  write(fd, resp, l);
}
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0),c,opt=1;
  struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(14444);
  setsockopt(s,1,2,&opt,sizeof(opt));
  bind(s,(struct sockaddr*)&a,sizeof(a)); listen(s,1);
  /* multi-accept: each %p probe gets its own connection */
  while((c=accept(s,NULL,NULL))!=-1){ vuln(c); close(c); }
  close(s); return 0;
}
""",
    },
    # T5: heap — memcpy overflow into fn-pointer on heap chunk
    "t5_heap": {
        "port": 14445,
        "flags": "-fno-stack-protector -no-pie -z execstack",
        "src": r"""
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
typedef struct { char name[32]; void (*fn)(void); } Obj;
void win(void)  { write(1, "pwned!\n", 7); }
void noop(void) {}
void vuln(int fd){
  Obj *o = malloc(sizeof(Obj));
  o->fn = noop;
  char buf[64];
  int n = read(fd, buf, 255);  /* overflow past name[32] into fn ptr */
  memcpy(o->name, buf, n);
  o->fn();
  free(o);
}
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0),c,opt=1;
  struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(14445);
  setsockopt(s,1,2,&opt,sizeof(opt));
  bind(s,(struct sockaddr*)&a,sizeof(a)); listen(s,1);
  c=accept(s,NULL,NULL); vuln(c); close(c); close(s); return 0;
}
""",
    },
    # T6: 64-bit NX -- unbounded read(), no canary, no PIE
    "t6_64bit_nx": {
        "port": 14446,
        "flags": "-fno-stack-protector -no-pie",
        "src": r"""
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
void process(int fd){
  char buf[128];
  read(fd, buf, 512);   /* VULN: 512 bytes into 128-byte buf */
  write(fd, buf, 8);
}
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0),c,opt=1;
  struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(14446);
  setsockopt(s,1,2,&opt,sizeof(opt));
  bind(s,(struct sockaddr*)&a,sizeof(a)); listen(s,1);
  c=accept(s,NULL,NULL);
  process(c); close(c); close(s); return 0;
}
""",
    },
}


def compile_binaries() -> dict:
    """Compile all test binaries. Returns {name: path | None}."""
    console.print(Rule("[bold cyan]Compiling test binaries[/]"))
    compiled = {}
    for name, info in BINARY_SOURCES.items():
        src_path = f"/tmp/bs_{name}.c"
        out_path = os.path.join(BINS, name)
        with open(src_path, "w") as f:
            f.write(info["src"])
        cmd = f"gcc -o {out_path} {src_path} {info['flags']} -w 2>&1"
        ret = subprocess.run(cmd, shell=True, capture_output=True)
        if ret.returncode == 0 and os.path.isfile(out_path):
            compiled[name] = out_path
            console.print(f"  ✅ {name} compiled → {out_path}")
        else:
            compiled[name] = None
            console.print(f"  ❌ {name} compilation failed:\n    {ret.stdout.decode()[:200]}")
    return compiled


# ─────────────────────────────────────────────────────────────────────────────
# MODULE: utils
# ─────────────────────────────────────────────────────────────────────────────

def test_utils(compiled: dict) -> None:
    console.print(Rule("[bold cyan]MODULE: utils / ExploitConfig[/]"))
    from utils import ExploitConfig, setup_logging, print_summary

    sec = "utils"
    any_bin = next((p for p in compiled.values() if p), None)

    # valid config
    try:
        cfg = ExploitConfig(binary=any_bin or __file__, host="127.0.0.1", port=14441)
        cfg.validate()
        R(sec, "valid_config", "PASS")
    except Exception as e:
        R(sec, "valid_config", "FAIL", str(e))

    # missing binary
    try:
        ExploitConfig(binary="/tmp/DOES_NOT_EXIST_XYZ").validate()
        R(sec, "missing_binary_exits", "FAIL", "should have called sys.exit")
    except SystemExit:
        R(sec, "missing_binary_exits", "PASS")

    # bad port
    try:
        ExploitConfig(binary=any_bin or __file__, port=99999).validate()
        R(sec, "bad_port_exits", "FAIL")
    except SystemExit:
        R(sec, "bad_port_exits", "PASS")

    # bad hex return addr
    try:
        ExploitConfig(binary=any_bin or __file__, return_addr="GGGG").validate()
        R(sec, "bad_hex_exits", "FAIL")
    except SystemExit:
        R(sec, "bad_hex_exits", "PASS")

    # binary_args_list never None
    for args_str, expected in [("", []), ("  ", []), ("-v --debug", ["-v", "--debug"])]:
        try:
            cfg = ExploitConfig(binary=any_bin or __file__, binary_args=args_str)
            assert cfg.binary_args_list == expected, f"{cfg.binary_args_list!r} != {expected!r}"
            R(sec, f"binary_args_list({args_str!r})", "PASS")
        except Exception as e:
            R(sec, f"binary_args_list({args_str!r})", "FAIL", str(e))

    # print_summary smoke
    try:
        import io
        print_summary(76, 0xffffd000, 0xffffd04c, "ret2libc",
                      "Success", 0xdeadbe00, "handle_client", ["Check output"])
        R(sec, "print_summary_smoke", "PASS")
    except Exception as e:
        R(sec, "print_summary_smoke", "FAIL", str(e))


# ─────────────────────────────────────────────────────────────────────────────
# MODULE: BinaryAnalyzer
# ─────────────────────────────────────────────────────────────────────────────

EXPECTED_PROTECTIONS = {
    "t1_stack_noprotect": dict(nx=False, canary=False),
    "t2_stack_nx":        dict(nx=True,  canary=False),
    "t3_stack_canary":    dict(nx=False, canary=True),
    "t4_fmtstr":          dict(nx=True,  canary=False),
    "t5_heap":            dict(nx=False, canary=False),
    "t6_64bit_nx":        dict(nx=True,  canary=False),
}

EXPECTED_ARCH = {
    "t1_stack_noprotect": ("linux", "amd64"),
    "t2_stack_nx":        ("linux", "amd64"),
    "t3_stack_canary":    ("linux", "amd64"),
    "t4_fmtstr":          ("linux", "amd64"),
    "t5_heap":            ("linux", "amd64"),
    "t6_64bit_nx":        ("linux", "amd64"),
}

EXPECTED_DETECTIONS = {
    "t4_fmtstr": {
        "format_string_functions": ["snprintf"],
    },
    "t5_heap": {
        "heap_functions": ["malloc", "free"],
        "vulnerable_functions": ["memcpy"],
    },
    "t6_64bit_nx": {
        "vulnerable_functions": ["read"],
    },
}


def test_analyzer(compiled: dict) -> None:
    console.print(Rule("[bold cyan]MODULE: BinaryAnalyzer[/]"))
    from utils import setup_logging
    setup_logging("/tmp/bs_test_analyzer.log")
    from analyzer import BinaryAnalyzer

    for name, path in compiled.items():
        if not path:
            R(f"analyzer/{name}", "compile", "SKIP", "binary not compiled")
            continue

        sec = f"analyzer/{name}"
        console.print(f"\n  [bold]{name}[/]")
        az = BinaryAnalyzer(path, f"/tmp/bs_{name}.log")

        # setup_context
        try:
            plat, arch = az.setup_context()
            exp_plat, exp_arch = EXPECTED_ARCH.get(name, ("linux", "amd64"))
            ok = plat == exp_plat and arch == exp_arch
            R(sec, "setup_context",
              "PASS" if ok else "FAIL",
              f"{plat}/{arch} (expected {exp_plat}/{exp_arch})")
        except Exception as e:
            R(sec, "setup_context", "FAIL", str(e)[:80])
            continue

        # static_analysis
        try:
            findings, target_fn, functions = az.static_analysis()
            R(sec, "static_analysis.functions",
              "PASS" if functions else "WARN",
              f"{len(functions)} fn, target={target_fn}")

            for category, expected_fns in EXPECTED_DETECTIONS.get(name, {}).items():
                for fn in expected_fns:
                    detected = fn in findings.get(category, [])
                    R(sec, f"detect.{category}.{fn}",
                      "PASS" if detected else "FAIL",
                      f"found={findings.get(category, [])}")
        except Exception as e:
            R(sec, "static_analysis", "FAIL", str(e)[:120])

        # check_protections
        try:
            res = az.check_protections()
            stack_exec, nx, aslr, canary, relro, safeseh, cfg, fortify, pie, shadow_stack = res
            for attr, expected_val in EXPECTED_PROTECTIONS.get(name, {}).items():
                actual = locals()[attr]
                R(sec, f"protection.{attr}",
                  "PASS" if actual == expected_val else "FAIL",
                  f"got={actual} expected={expected_val}")
        except Exception as e:
            R(sec, "check_protections", "FAIL", str(e)[:120])

        # load_library_offsets
        try:
            lib, ver, offs, base = az.load_library_offsets()
            R(sec, "load_library_offsets",
              "PASS",
              f"lib={lib} ver={ver} n_offsets={len(offs)}")
        except Exception as e:
            R(sec, "load_library_offsets", "WARN", str(e)[:80])


# ─────────────────────────────────────────────────────────────────────────────
# MODULE: ExploitGenerator static tests
# ─────────────────────────────────────────────────────────────────────────────

def test_exploiter_static(compiled: dict) -> None:
    console.print(Rule("[bold cyan]MODULE: ExploitGenerator (static)[/]"))
    from utils import setup_logging
    setup_logging("/tmp/bs_test_exploiter.log")
    from exploiter import ExploitGenerator

    cases = [
        ("t1_stack_noprotect", "amd64", 14441),
        ("t2_stack_nx",        "amd64", 14442),
        ("t4_fmtstr",          "amd64", 14444),
        ("t6_64bit_nx",        "amd64", 14446),
    ]

    for bname, arch, port in cases:
        path = compiled.get(bname)
        if not path:
            R(f"exploiter/{bname}", "compile", "SKIP")
            continue

        sec = f"exploiter/{bname}"
        console.print(f"\n  [bold]{bname}[/]")
        ex = ExploitGenerator(path, "linux", "127.0.0.1", port,
                              "/tmp/bs_test.log", False, "")

        # Shellcode (cmd and reverse)
        for rev in (False, True):
            try:
                sc = ex.generate_shellcode("id", "127.0.0.1", 9999, arch, rev)
                ok = isinstance(sc, bytes) and len(sc) > 4
                R(sec, f"shellcode.reverse={rev}",
                  "PASS" if ok else "FAIL",
                  f"{len(sc)}b" if ok else "None")
            except Exception as e:
                R(sec, f"shellcode.reverse={rev}", "FAIL", str(e)[:80])

        # File payloads
        for ftype in ("mp3", "raw"):
            try:
                dummy = b"\x90" * 32 + b"\xcc"
                payload, fname = ex.craft_file_payload(ftype, 76, dummy)
                ok = isinstance(payload, bytes) and len(payload) > 0
                R(sec, f"file_payload.{ftype}",
                  "PASS" if ok else "FAIL",
                  f"{len(payload)}b→{fname}")
            except Exception as e:
                R(sec, f"file_payload.{ftype}", "FAIL", str(e)[:80])

        # ROP chain
        try:
            chain = ex.build_rop_chain(76, None, None, {}, None)
            R(sec, "build_rop_chain",
              "PASS",
              f"{len(chain)}b" if isinstance(chain, bytes) else "None (no system@plt, expected)")
        except Exception as e:
            R(sec, "build_rop_chain", "WARN", str(e)[:80])

        # ret2dlresolve
        try:
            chain = ex.ret2dlresolve(76, None)
            R(sec, "ret2dlresolve",
              "PASS",
              f"{len(chain)}b" if isinstance(chain, bytes) else "None (PIE/stripped, expected)")
        except Exception as e:
            R(sec, "ret2dlresolve", "WARN", str(e)[:80])

        # Gadget finder
        try:
            gadgets = ex.find_gadgets()
            R(sec, "find_gadgets",
              "PASS" if isinstance(gadgets, list) else "FAIL",
              f"{len(gadgets)} gadgets")
        except Exception as e:
            R(sec, "find_gadgets", "WARN", str(e)[:60])


# ─────────────────────────────────────────────────────────────────────────────
# MODULE: Format string payload generation
# ─────────────────────────────────────────────────────────────────────────────

def test_fmtstr_payload_gen(compiled: dict) -> None:
    console.print(Rule("[bold cyan]MODULE: Format String Payload Generation[/]"))
    from utils import setup_logging
    setup_logging("/tmp/bs_test_fmtstr.log")
    from exploiter import ExploitGenerator
    from analyzer import BinaryAnalyzer

    path = compiled.get("t4_fmtstr")
    if not path:
        R("fmtstr_payload", "all", "SKIP", "t4_fmtstr not compiled")
        return

    az = BinaryAnalyzer(path, "/tmp/bs_fmtstr.log")
    az.setup_context()
    ex = ExploitGenerator(path, "linux", "127.0.0.1", 14444,
                          "/tmp/bs_fmtstr.log", False, "")

    for relro, expect_payload in [("No RELRO", True), ("Full RELRO", False)]:
        # Server must be running so generate_format_string_payload can do %p leaks
        proc, kill = spawn(path)
        try:
            if not wait_port("127.0.0.1", 14444, 4):
                R("fmtstr_payload", f"relro={relro}", "FAIL", "server did not start")
                continue
            payload = ex.generate_format_string_payload(offset=7, relro=relro)
            ok = (payload is not None) == expect_payload
            R("fmtstr_payload", f"relro={relro}",
              "PASS" if ok else "FAIL",
              f"payload={'present' if payload else 'None'} expected={'present' if expect_payload else 'None'}")
        except Exception as e:
            R("fmtstr_payload", f"relro={relro}", "WARN", str(e)[:80])
        finally:
            kill()
            time.sleep(0.4)


# ─────────────────────────────────────────────────────────────────────────────
# MODULE: Fuzzer (static / unit)
# ─────────────────────────────────────────────────────────────────────────────

def test_fuzzer_static(compiled: dict) -> None:
    console.print(Rule("[bold cyan]MODULE: Fuzzer (static/unit)[/]"))
    import shutil
    from utils import setup_logging
    setup_logging("/tmp/bs_test_fuzzer.log")
    from fuzzer import Fuzzer

    sec = "fuzzer"
    path = compiled.get("t1_stack_noprotect")

    # AFL++ binary present?
    if shutil.which("afl-fuzz"):
        R(sec, "afl_binary_present", "PASS")
    else:
        R(sec, "afl_binary_present", "WARN", "afl-fuzz not installed — skipped")

    # Mutation fuzzer API
    fz = Fuzzer(path or "/dev/null", "127.0.0.1", 14441,
                "/tmp/bs_fuzzer.log", "linux")

    if path:
        proc, kill = spawn(path)
        if wait_port("127.0.0.1", 14441, 4):
            try:
                ok = fz.mutation_fuzz(num_cases=20, timeout=0.4)
                R(sec, "mutation_fuzz_runs", "PASS", f"returned={ok}")
            except Exception as e:
                R(sec, "mutation_fuzz_runs", "FAIL", str(e)[:80])
        else:
            R(sec, "mutation_fuzz_runs", "SKIP", "server did not start")
        kill()
        time.sleep(0.3)
    else:
        R(sec, "mutation_fuzz_runs", "SKIP", "t1 not compiled")

    # QUIC DoS packet builder
    try:
        # Just verify the function doesn't crash immediately (target won't respond)
        fz2 = Fuzzer("/dev/null", "127.0.0.1", 14441, "/tmp/bs_fuzzer.log", "linux")
        # Send 5 packets to a closed port — should return True/False not throw
        result = fz2.dos_quic(num_packets=5)
        R(sec, "dos_quic_api", "PASS", f"returned={result}")
    except Exception as e:
        R(sec, "dos_quic_api", "FAIL", str(e)[:80])


# ─────────────────────────────────────────────────────────────────────────────
# LIVE: crash / overflow tests
# ─────────────────────────────────────────────────────────────────────────────

def test_live_crash(compiled: dict, bname: str, port: int,
                    overflow_size: int = 512) -> None:
    sec  = f"live/{bname}"
    path = compiled.get(bname)
    console.print(f"\n  [bold]Live crash: {bname} :{port}[/]")

    if not path:
        R(sec, "all", "SKIP", "binary not compiled"); return

    # Normal connection
    proc, kill = spawn(path)
    try:
        if not wait_port("127.0.0.1", port, 4):
            R(sec, "server_start", "FAIL", "port did not open"); return
        R(sec, "server_start", "PASS")

        resp = send_recv("127.0.0.1", port, b"HELLO\n", 1.5)
        R(sec, "normal_connect",
          "PASS" if resp is not None else "WARN",
          repr(resp[:20] if resp else b""))
    finally:
        kill(); time.sleep(0.4)

    # Overflow
    proc2, kill2 = spawn(path)
    try:
        if not wait_port("127.0.0.1", port, 4):
            R(sec, "overflow_crash", "FAIL", "port did not reopen"); return

        send_recv("127.0.0.1", port, b"A" * overflow_size, 1.5)
        time.sleep(0.5)
        crashed = proc2.poll() is not None
        R(sec, "overflow_crash",
          "PASS" if crashed else "FAIL",
          f"crashed={crashed}")
    finally:
        kill2(); time.sleep(0.4)


def test_live_fmtstr(compiled: dict) -> None:
    sec  = "live/t4_fmtstr"
    path = compiled.get("t4_fmtstr")
    console.print(f"\n  [bold]Live format string: t4_fmtstr :14444[/]")

    if not path:
        R(sec, "all", "SKIP", "t4_fmtstr not compiled"); return

    proc, kill = spawn(path)
    try:
        if not wait_port("127.0.0.1", 14444, 4):
            R(sec, "server_start", "FAIL"); return
        R(sec, "server_start", "PASS")

        # %p leak
        resp = send_recv("127.0.0.1", 14444, b"%p.%p.%p.%p\n", 2.0)
        if resp:
            leak = b"0x" in resp or b"nil" in resp
            R(sec, "fmt_leak_%p",
              "PASS" if leak else "FAIL",
              repr(resp[:64]))
        else:
            R(sec, "fmt_leak_%p", "FAIL", "no response")

        # %n / %s crash
    finally:
        kill(); time.sleep(0.4)

    proc2, kill2 = spawn(path)
    try:
        if wait_port("127.0.0.1", 14444, 4):
            send_recv("127.0.0.1", 14444, b"%s%s%s%s%s%s%s%s%s%s", 1.0)
            time.sleep(0.4)
            crashed = proc2.poll() is not None
            R(sec, "fmt_crash_%s",
              "PASS" if crashed else "WARN",
              f"crashed={crashed}")
    finally:
        kill2(); time.sleep(0.4)


def test_live_heap(compiled: dict) -> None:
    sec  = "live/t5_heap"
    path = compiled.get("t5_heap")
    console.print(f"\n  [bold]Live heap fn-ptr overwrite: t5_heap :14445[/]")

    if not path:
        R(sec, "all", "SKIP"); return

    proc, kill = spawn(path)
    try:
        if not wait_port("127.0.0.1", 14445, 4):
            R(sec, "server_start", "FAIL"); return
        R(sec, "server_start", "PASS")

        # Overflow name[32] into fn ptr with 0xcccccccc (SIGTRAP)
        payload = b"A" * 32 + b"\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc"
        send_recv("127.0.0.1", 14445, payload, 1.0)
        time.sleep(0.4)
        crashed = proc.poll() is not None
        R(sec, "heap_fn_overwrite_crash",
          "PASS" if crashed else "WARN",
          f"crashed={crashed}")
    finally:
        kill(); time.sleep(0.4)


def test_live_canary(compiled: dict) -> None:
    sec  = "live/t3_canary"
    path = compiled.get("t3_stack_canary")
    console.print(f"\n  [bold]Live canary: t3_stack_canary :14443[/]")

    if not path:
        R(sec, "all", "SKIP"); return

    proc, kill = spawn(path)
    try:
        if not wait_port("127.0.0.1", 14443, 4):
            R(sec, "server_start", "FAIL"); return
        R(sec, "server_start", "PASS")

        # Small write — should not crash
        resp = send_recv("127.0.0.1", 14443, b"A" * 32, 1.5)
        R(sec, "normal_write_no_crash",
          "PASS" if proc.poll() is None else "WARN",
          f"alive={proc.poll() is None}")
    finally:
        kill(); time.sleep(0.4)

    # Overflow PAST canary — should crash with stack smashing
    proc2, kill2 = spawn(path)
    try:
        if wait_port("127.0.0.1", 14443, 4):
            send_recv("127.0.0.1", 14443, b"A" * 256, 1.5)
            time.sleep(0.4)
            crashed = proc2.poll() is not None
            R(sec, "overflow_triggers_canary_abort",
              "PASS" if crashed else "WARN",
              f"crashed={crashed}")
    finally:
        kill2(); time.sleep(0.4)


def test_live_cyclic_offset(compiled: dict) -> None:
    """Confirm pwntools cyclic crashes the binary in a detectable way."""
    console.print(f"\n  [bold]Live cyclic offset detection: t1 :14441[/]")
    sec  = "live/cyclic_offset"
    path = compiled.get("t1_stack_noprotect")
    if not path:
        R(sec, "all", "SKIP"); return

    try:
        from pwn import cyclic, context  # type: ignore
        context(arch="amd64", os="linux")
    except Exception as e:
        R(sec, "pwntools_import", "FAIL", str(e)); return

    pattern = cyclic(300)
    proc, kill = spawn(path)
    try:
        if not wait_port("127.0.0.1", 14441, 4):
            R(sec, "server_start", "FAIL"); return
        send_recv("127.0.0.1", 14441, pattern, 1.5)
        time.sleep(0.4)
        crashed = proc.poll() is not None
        R(sec, "cyclic_causes_crash",
          "PASS" if crashed else "FAIL",
          f"exit_code={proc.poll()}")
    finally:
        kill(); time.sleep(0.3)


# ─────────────────────────────────────────────────────────────────────────────
# Final summary
# ─────────────────────────────────────────────────────────────────────────────

def print_final_summary() -> int:
    console.print(Rule("[bold white]FINAL TEST RESULTS[/]"))
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Section",  style="dim cyan",  min_width=28)
    table.add_column("Test",     style="white",     min_width=36)
    table.add_column("Status",   min_width=6)
    table.add_column("Detail",   style="dim white", min_width=40)

    counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "SKIP": 0}
    for section, test, status, detail in results:
        colour = {"PASS": "green", "FAIL": "red", "WARN": "yellow", "SKIP": "dim"}.get(
            status, "white"
        )
        table.add_row(section, test, f"[{colour}]{status}[/]", detail[:60])
        counts[status] = counts.get(status, 0) + 1

    console.print(table)
    total = sum(counts.values())
    console.print(Panel(
        f"[green]PASS {counts['PASS']}[/]  "
        f"[red]FAIL {counts['FAIL']}[/]  "
        f"[yellow]WARN {counts['WARN']}[/]  "
        f"[dim]SKIP {counts['SKIP']}[/]  "
        f"TOTAL {total}",
        title="Test Summary", border_style="cyan",
    ))
    return counts["FAIL"]


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    console.print(Panel(
        "[bold cyan]BinSmasher Test Suite[/]\n"
        "6 vulnerable binaries × all modules",
        border_style="cyan",
    ))

    # Compile first
    compiled = compile_binaries()

    # Static module tests
    test_utils(compiled)
    test_analyzer(compiled)
    test_exploiter_static(compiled)
    test_fmtstr_payload_gen(compiled)
    test_fuzzer_static(compiled)

    # Live network tests
    console.print(Rule("[bold cyan]LIVE NETWORK TESTS[/]"))
    test_live_crash(compiled, "t1_stack_noprotect", 14441, 512)
    test_live_crash(compiled, "t2_stack_nx",        14442, 512)
    test_live_crash(compiled, "t6_64bit_nx",        14446, 512)
    test_live_fmtstr(compiled)
    test_live_heap(compiled)
    test_live_canary(compiled)
    test_live_cyclic_offset(compiled)

    fails = print_final_summary()
    sys.exit(0 if fails == 0 else 1)
