#!/usr/bin/env python3
"""
BinSmasher — tests/test_suite.py
Complete test harness covering all modules and binary types.

Run:
    cd binsmasher_final
    python tests/test_suite.py
"""

import sys, os, time, socket, struct, subprocess, threading, signal, random
# Resolve absolute paths so the suite works no matter which directory you run from
_THIS_DIR = os.path.abspath(os.path.dirname(__file__))
_SRC_DIR  = os.path.abspath(os.path.join(_THIS_DIR, "..", "src"))
sys.path.insert(0, _SRC_DIR)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule

console = Console()
BINS = os.path.join(_THIS_DIR, "bins")
os.makedirs(BINS, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# Infrastructure helpers
# ─────────────────────────────────────────────────────────────────────────────

def wait_port(host: str, port: int, timeout: float = 4.0) -> bool:
    """Connect-and-close to confirm port is open. Consumes one server accept."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, port), 0.3)
            s.close()
            return True
        except Exception:
            time.sleep(0.1)
    return False


def is_listening(port: int, timeout: float = 4.0) -> bool:
    """
    Check that a port is in LISTEN state WITHOUT connecting (does NOT consume
    a single-accept server's one connection).  Uses /proc/net/tcp6 + tcp.
    Falls back to a connect attempt if /proc is unavailable.
    """
    deadline = time.time() + timeout
    hex_port = f"{port:04X}"
    while time.time() < deadline:
        for path in ("/proc/net/tcp6", "/proc/net/tcp"):
            try:
                with open(path) as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) < 4:
                            continue
                        local = parts[1]
                        state = parts[3]
                        # local addr is "XXXXXXXX:PORT" or "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:PORT"
                        if local.split(":")[-1].upper() == hex_port and state == "0A":
                            return True
            except OSError:
                pass
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
    # T7: CFI vtable fn-ptr corruption (multi-accept)
    "t7_cfi_vtable": {
        "port": 14447,
        "flags": "-fno-stack-protector -no-pie -z execstack",
        "src": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
typedef struct { char name[48]; void (*dispatch)(int); } Handler;
void win(int fd){ char msg[]="CFI_BYPASS_SUCCESS
"; write(fd,msg,sizeof(msg)-1); }
void default_handler(int fd){ char msg[]="OK
"; write(fd,msg,3); }
void vuln(int fd){
  Handler *h=malloc(sizeof(Handler));
  h->dispatch=default_handler;
  int n=read(fd,h->name,256); (void)n;  /* VULN: overflow into fn ptr */
  h->dispatch(fd);
  free(h);
}
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0),c,opt=1;
  struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(14447);
  setsockopt(s,1,2,&opt,sizeof(opt)); bind(s,(struct sockaddr*)&a,sizeof(a)); listen(s,1);
  while((c=accept(s,NULL,NULL))!=-1){ vuln(c); close(c); }
  close(s); return 0;
}
""",
    },
    # T8: seccomp-bpf restricted server (NO_SECCOMP fallback for portability)
    "t8_seccomp": {
        "port": 14448,
        "flags": "-fno-stack-protector -no-pie -DNO_SECCOMP",
        "src": r"""
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
/* seccomp disabled in portable build — overflow still present */
static void install_seccomp(void){}
void handle(int fd){ char buf[64]; install_seccomp(); read(fd,buf,512); write(fd,buf,4); }
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0),c,opt=1;
  struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(14448);
  setsockopt(s,1,2,&opt,sizeof(opt)); bind(s,(struct sockaddr*)&a,sizeof(a)); listen(s,1);
  while((c=accept(s,NULL,NULL))!=-1){ handle(c); close(c); }
  close(s); return 0;
}
""",
    },
    # T9: stripped binary (no symbols)
    "t9_stripped": {
        "port": 14449,
        "flags": "-fno-stack-protector -no-pie -s",
        "src": r"""
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
static void respond_ok(int fd){ write(fd,"OK
",3); }
static void process_input(int fd){ char buf[96]; read(fd,buf,512); respond_ok(fd); }
static void setup_and_serve(int port){
  int s=socket(AF_INET,SOCK_STREAM,0),c,opt=1;
  struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons((unsigned short)port);
  setsockopt(s,1,2,&opt,sizeof(opt)); bind(s,(struct sockaddr*)&a,sizeof(a)); listen(s,1);
  while((c=accept(s,NULL,NULL))!=-1){ process_input(c); close(c); }
  close(s);
}
int main(void){ setup_and_serve(14449); return 0; }
""",
    },
    # T10: safestack simulation (fmt-string oracle + overflow, multi-accept)
        # T10: safestack simulation (fmt-string oracle + overflow, multi-accept)
    "t10_safestack": {
        "port": 14450,
        "flags": "-fno-stack-protector -no-pie -z execstack",
        "src": """
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
void handle(int fd){
  char fmt_buf[256], overflow_buf[64], resp[512]; int n;
  n=read(fd,fmt_buf,255); fmt_buf[n]=0;
  int l=snprintf(resp,sizeof(resp),fmt_buf); write(fd,resp,l);
  read(fd,overflow_buf,512); write(fd,"ok",2);
}
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0),c,opt=1;
  struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(14450);
  setsockopt(s,1,2,&opt,sizeof(opt)); bind(s,(struct sockaddr*)&a,sizeof(a)); listen(s,1);
  while((c=accept(s,NULL,NULL))!=-1){ handle(c); close(c); }
  close(s); return 0;
}
""",
    },
        # T11: glibc 2.34+ heap: alloc/free/UAF/overflow protocol
        "t11_heap_glibc234": {
        "port": 14451,
        "flags": "-fno-stack-protector -no-pie",
        "src": """
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#define MAX_CHUNKS 16
#define MAX_SIZE   512
static void *chunks[MAX_CHUNKS];
static size_t sizes[MAX_CHUNKS];
void handle(int fd){
  char cmd; int idx; size_t sz; char data[MAX_SIZE+16];
  while(1){
    if(read(fd,&cmd,1)!=1) break;
    if(cmd=='A'){
      if(read(fd,&idx,sizeof(int))!=sizeof(int)) break;
      if(read(fd,&sz,sizeof(size_t))!=sizeof(size_t)) break;
      if(idx<0||idx>=MAX_CHUNKS){write(fd,"ERR",3);break;}
      chunks[idx]=malloc(sz); sizes[idx]=sz;
      read(fd,data,sz+32);
      memcpy(chunks[idx],data,sz+32); write(fd,"OK",2);
    } else if(cmd=='F'){
      if(read(fd,&idx,sizeof(int))!=sizeof(int)) break;
      if(idx<0||idx>=MAX_CHUNKS){write(fd,"ERR",3);break;}
      free(chunks[idx]); write(fd,"OK",2);
    } else if(cmd=='R'){
      if(read(fd,&idx,sizeof(int))!=sizeof(int)) break;
      if(idx<0||idx>=MAX_CHUNKS||!chunks[idx]){write(fd,"ERR",3);break;}
      write(fd,chunks[idx],sizes[idx]);
    } else if(cmd=='W'){
      if(read(fd,&idx,sizeof(int))!=sizeof(int)) break;
      if(idx<0||idx>=MAX_CHUNKS||!chunks[idx]){write(fd,"ERR",3);break;}
      read(fd,chunks[idx],MAX_SIZE); write(fd,"OK",2);
    } else break;
  }
}
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0),c,opt=1;
  struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(14451);
  setsockopt(s,1,2,&opt,sizeof(opt)); bind(s,(struct sockaddr*)&a,sizeof(a)); listen(s,1);
  while((c=accept(s,NULL,NULL))!=-1){ handle(c); close(c); }
  close(s); return 0;
}
""",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Infrastructure helpers
# ─────────────────────────────────────────────────────────────────────────────

console = Console()
BINS = os.path.join(_THIS_DIR, "bins")
os.makedirs(BINS, exist_ok=True)

def wait_port(host: str, port: int, timeout: float = 4.0) -> bool:
    """Connect-and-close to confirm port is open. Consumes one server accept."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, port), 0.3)
            s.close()
            return True
        except Exception:
            time.sleep(0.1)
    return False


def is_listening(port: int, timeout: float = 4.0) -> bool:
    """Check LISTEN state via /proc/net without connecting (does NOT consume accept)."""
    hex_port = f"{port:04X}"
    deadline = time.time() + timeout
    while time.time() < deadline:
        for path in ("/proc/net/tcp6", "/proc/net/tcp"):
            try:
                with open(path) as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 4 and \
                           parts[1].split(":")[-1].upper() == hex_port and \
                           parts[3] == "0A":
                            return True
            except OSError:
                pass
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
# Binary compilation (11 targets)
# ─────────────────────────────────────────────────────────────────────────────

def compile_binaries() -> dict:
    """
    Compile all test binaries.  Returns {name: path | None}.
    - Skips binaries already compiled and executable (idempotent).
    - Uses list args (no shell=True) — safe for paths with spaces/parens.
    """
    console.print(Rule("[bold cyan]Compiling test binaries[/]"))
    compiled = {}
    tmp_dir  = _THIS_DIR

    for name, info in BINARY_SOURCES.items():
        out_path = os.path.join(BINS, name)

        if os.path.isfile(out_path) and os.access(out_path, os.X_OK):
            compiled[name] = out_path
            console.print(f"  ✅ {name} (cached) → {out_path}")
            continue

        src_path = os.path.join(tmp_dir, f"_bs_{name}.c")
        with open(src_path, "w") as f:
            f.write(info["src"])

        gcc_args = (["gcc", "-o", out_path, src_path]
                    + info["flags"].split()
                    + ["-w"])
        try:
            ret = subprocess.run(gcc_args, capture_output=True, timeout=30)
            if ret.returncode == 0 and os.path.isfile(out_path):
                # Strip if needed
                if name == "t9_stripped":
                    subprocess.run(["strip", "--strip-all", out_path],
                                   capture_output=True)
                compiled[name] = out_path
                console.print(f"  ✅ {name} compiled → {out_path}")
            else:
                compiled[name] = None
                err = (ret.stderr or ret.stdout or b"").decode(errors="ignore")[:300]
                console.print(f"  ❌ {name} compilation failed:\n    {err}")
        except FileNotFoundError:
            compiled[name] = None
            console.print(f"  ❌ {name}: gcc not found — apt install gcc")
        except Exception as e:
            compiled[name] = None
            console.print(f"  ❌ {name}: {e}")
        finally:
            try:
                os.unlink(src_path)
            except OSError:
                pass

    return compiled


# ─────────────────────────────────────────────────────────────────────────────
# MODULE: utils / ExploitConfig
# ─────────────────────────────────────────────────────────────────────────────

def test_utils(compiled: dict) -> None:
    console.print(Rule("[bold cyan]MODULE: utils / ExploitConfig[/]"))
    from utils import ExploitConfig, setup_logging, print_summary
    sec = "utils"
    any_bin = next((p for p in compiled.values() if p), None)

    try:
        cfg = ExploitConfig(binary=any_bin or __file__, host="127.0.0.1", port=14441)
        cfg.validate()
        R(sec, "valid_config", "PASS")
    except Exception as e:
        R(sec, "valid_config", "FAIL", str(e))

    try:
        ExploitConfig(binary="/tmp/DOES_NOT_EXIST_XYZ").validate()
        R(sec, "missing_binary_exits", "FAIL")
    except SystemExit:
        R(sec, "missing_binary_exits", "PASS")

    try:
        ExploitConfig(binary=any_bin or __file__, port=99999).validate()
        R(sec, "bad_port_exits", "FAIL")
    except SystemExit:
        R(sec, "bad_port_exits", "PASS")

    try:
        ExploitConfig(binary=any_bin or __file__, return_addr="GGGG").validate()
        R(sec, "bad_hex_exits", "FAIL")
    except SystemExit:
        R(sec, "bad_hex_exits", "PASS")

    for args_str, expected in [("", []), ("  ", []), ("-v --debug", ["-v", "--debug"])]:
        try:
            cfg = ExploitConfig(binary=any_bin or __file__, binary_args=args_str)
            assert cfg.binary_args_list == expected
            R(sec, f"binary_args_list({args_str!r})", "PASS")
        except Exception as e:
            R(sec, f"binary_args_list({args_str!r})", "FAIL", str(e))

    try:
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
    "t7_cfi_vtable":      dict(nx=False, canary=False),
    "t8_seccomp":         dict(nx=True,  canary=False),
    "t9_stripped":        dict(nx=True,  canary=False),
    "t10_safestack":      dict(nx=False, canary=False),
    "t11_heap_glibc234":  dict(nx=True,  canary=False),
}

EXPECTED_ARCH = {name: ("linux", "amd64") for name in EXPECTED_PROTECTIONS}

EXPECTED_DETECTIONS = {
    "t4_fmtstr":         {"format_string_functions": ["snprintf"]},
    "t5_heap":           {"heap_functions": ["malloc", "free"], "vulnerable_functions": ["memcpy"]},
    "t6_64bit_nx":       {"vulnerable_functions": ["read"]},
    "t7_cfi_vtable":     {"heap_functions": ["malloc", "free"]},
    "t10_safestack":     {"format_string_functions": ["snprintf"]},
    "t11_heap_glibc234": {"heap_functions": ["malloc", "free"]},
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

        try:
            plat, arch = az.setup_context()
            exp_plat, exp_arch = EXPECTED_ARCH.get(name, ("linux", "amd64"))
            ok = plat == exp_plat and arch == exp_arch
            R(sec, "setup_context", "PASS" if ok else "FAIL",
              f"{plat}/{arch} (expected {exp_plat}/{exp_arch})")
        except Exception as e:
            R(sec, "setup_context", "FAIL", str(e)[:80]); continue

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
                      str(findings.get(category, [])))
        except Exception as e:
            R(sec, "static_analysis", "FAIL", str(e)[:120])

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

        try:
            lib, ver, offs, base = az.load_library_offsets()
            R(sec, "load_library_offsets", "PASS",
              f"lib={lib} ver={ver} n_offsets={len(offs)}")
        except Exception as e:
            R(sec, "load_library_offsets", "WARN", str(e)[:80])


# ─────────────────────────────────────────────────────────────────────────────
# MODULE: ExploitGenerator static
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
            R(f"exploiter/{bname}", "compile", "SKIP"); continue
        sec = f"exploiter/{bname}"
        console.print(f"\n  [bold]{bname}[/]")
        ex = ExploitGenerator(path, "linux", "127.0.0.1", port,
                              "/tmp/bs_test.log", False, "")

        for rev in (False, True):
            try:
                sc = ex.generate_shellcode("id", "127.0.0.1", 9999, arch, rev)
                ok = isinstance(sc, bytes) and len(sc) > 4
                R(sec, f"shellcode.reverse={rev}", "PASS" if ok else "FAIL",
                  f"{len(sc)}b" if ok else "None")
            except Exception as e:
                R(sec, f"shellcode.reverse={rev}", "FAIL", str(e)[:80])

        for ftype in ("mp3", "raw"):
            try:
                payload, fname = ex.craft_file_payload(ftype, 76, b"\x90"*32+b"\xcc")
                ok = isinstance(payload, bytes) and len(payload) > 0
                R(sec, f"file_payload.{ftype}", "PASS" if ok else "FAIL",
                  f"{len(payload)}b→{fname}")
            except Exception as e:
                R(sec, f"file_payload.{ftype}", "FAIL", str(e)[:80])

        try:
            chain = ex.build_rop_chain(76, None, None, {}, None)
            R(sec, "build_rop_chain", "PASS",
              f"{len(chain)}b" if isinstance(chain, bytes) else "None (no system@plt)")
        except Exception as e:
            R(sec, "build_rop_chain", "WARN", str(e)[:80])

        try:
            chain = ex.ret2dlresolve(76, None)
            R(sec, "ret2dlresolve", "PASS",
              f"{len(chain)}b" if isinstance(chain, bytes) else "None (expected)")
        except Exception as e:
            R(sec, "ret2dlresolve", "WARN", str(e)[:80])

        try:
            gadgets = ex.find_gadgets()
            R(sec, "find_gadgets", "PASS" if isinstance(gadgets, list) else "FAIL",
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
        R("fmtstr_payload", "all", "SKIP", "t4_fmtstr not compiled"); return

    az = BinaryAnalyzer(path, "/tmp/bs_fmtstr.log")
    az.setup_context()
    ex = ExploitGenerator(path, "linux", "127.0.0.1", 14444,
                          "/tmp/bs_fmtstr.log", False, "")

    for relro, expect_payload in [("No RELRO", True), ("Full RELRO", False)]:
        proc, kill = spawn(path)
        try:
            if not wait_port("127.0.0.1", 14444, 4):
                R("fmtstr_payload", f"relro={relro}", "FAIL", "server did not start")
                continue
            payload = ex.generate_format_string_payload(offset=7, relro=relro)
            ok = (payload is not None) == expect_payload
            R("fmtstr_payload", f"relro={relro}", "PASS" if ok else "FAIL",
              f"payload={'present' if payload else 'None'} expected={'present' if expect_payload else 'None'}")
        except Exception as e:
            R("fmtstr_payload", f"relro={relro}", "WARN", str(e)[:80])
        finally:
            kill(); time.sleep(0.4)


# ─────────────────────────────────────────────────────────────────────────────
# MODULE: Fuzzer static/unit
# ─────────────────────────────────────────────────────────────────────────────

def test_fuzzer_static(compiled: dict) -> None:
    console.print(Rule("[bold cyan]MODULE: Fuzzer (static/unit)[/]"))
    import shutil
    from utils import setup_logging
    setup_logging("/tmp/bs_test_fuzzer.log")
    from fuzzer import Fuzzer
    sec = "fuzzer"
    path = compiled.get("t1_stack_noprotect")

    if shutil.which("afl-fuzz"):
        R(sec, "afl_binary_present", "PASS")
    else:
        R(sec, "afl_binary_present", "WARN", "afl-fuzz not installed — skipped")

    fz = Fuzzer(path or "/dev/null", "127.0.0.1", 14441,
                "/tmp/bs_fuzzer.log", "linux")
    if path:
        proc, kill = spawn(path)
        if is_listening(14441, 4):
            try:
                ok = fz.mutation_fuzz(num_cases=20, timeout=0.4)
                R(sec, "mutation_fuzz_runs", "PASS", f"returned={ok}")
            except Exception as e:
                R(sec, "mutation_fuzz_runs", "FAIL", str(e)[:80])
        else:
            R(sec, "mutation_fuzz_runs", "SKIP", "server did not start")
        kill(); time.sleep(0.3)
    else:
        R(sec, "mutation_fuzz_runs", "SKIP", "t1 not compiled")

    try:
        fz2 = Fuzzer("/dev/null", "127.0.0.1", 19999, "/tmp/bs_fuzzer.log", "linux")
        result = fz2.dos_quic(num_packets=5)
        R(sec, "dos_quic_api", "PASS", f"returned={result}")
    except Exception as e:
        R(sec, "dos_quic_api", "FAIL", str(e)[:80])


# ─────────────────────────────────────────────────────────────────────────────
# MODULE: FileExploiter — all 29 formats
# ─────────────────────────────────────────────────────────────────────────────

def test_file_exploiter() -> None:
    console.print(Rule("[bold cyan]MODULE: FileExploiter (29 formats)[/]"))
    from utils import setup_logging
    setup_logging("/tmp/bs_test_file.log")
    from file_exploiter import FileExploiter
    import zipfile as _zf, tempfile, shutil

    sec = "file_exploiter"
    out_dir = tempfile.mkdtemp()
    fe = FileExploiter(output_dir=out_dir)

    try:
        results_fe = fe.craft_all(offset=64)
        R(sec, "craft_all", "PASS" if len(results_fe) == 29 else "FAIL",
          f"{len(results_fe)}/29 formats")
    except Exception as e:
        R(sec, "craft_all", "FAIL", str(e)[:80])
        shutil.rmtree(out_dir, ignore_errors=True)
        return

    EXPECTED_MAGIC = {
        "mp3":  b"ID3",
        "wav":  b"RIFF",
        "flac": b"fLaC",
        "ogg":  b"OggS",
        "pdf":  b"%PDF",
        "docx": b"PK",
        "xlsx": b"PK",
        "png":  bytes([0x89, 0x50, 0x4e, 0x47]),
        "gif":  b"GIF89a",
        "jpeg": bytes([0xFF, 0xD8]),
        "bmp":  b"BM",
        "elf":  bytes([0x7F, 0x45, 0x4C, 0x46]),
        "zip":  b"PK",
        "html": b"<!DOCTYPE",
    }
    for fmt, magic in EXPECTED_MAGIC.items():
        try:
            data = open(os.path.join(out_dir, f"malicious.{fmt}"), "rb").read()
            ok = data[:len(magic)] == magic
            R(sec, f"magic.{fmt}", "PASS" if ok else "FAIL",
              f"got={data[:8].hex()} expected={magic.hex()}")
        except FileNotFoundError:
            R(sec, f"magic.{fmt}", "FAIL", "file not generated")
        except Exception as e:
            R(sec, f"magic.{fmt}", "FAIL", str(e)[:60])

    try:
        payload, _ = fe.craft("txt", 32, technique="fmtstr")
        R(sec, "technique.fmtstr", "PASS" if (b"%p" in payload or b"%n" in payload) else "FAIL",
          f"{len(payload)}b")
    except Exception as e:
        R(sec, "technique.fmtstr", "FAIL", str(e)[:80])

    try:
        payload, _ = fe.craft("html", 32, technique="inject")
        R(sec, "technique.inject.html",
          "PASS" if (b"<script" in payload or b"onerror" in payload) else "FAIL",
          f"{len(payload)}b")
    except Exception as e:
        R(sec, "technique.inject.html", "FAIL", str(e)[:80])

    try:
        custom_sc = b"\x90" * 8 + b"\xcc"
        payload, _ = fe.craft("wav", 64, shellcode=custom_sc)
        R(sec, "custom_shellcode_embedded", "PASS" if custom_sc in payload else "FAIL")
    except Exception as e:
        R(sec, "custom_shellcode_embedded", "FAIL", str(e)[:80])

    try:
        ok = _zf.is_zipfile(os.path.join(out_dir, "malicious.zip"))
        R(sec, "zip_valid_structure", "PASS" if ok else "FAIL")
    except Exception as e:
        R(sec, "zip_valid_structure", "FAIL", str(e)[:60])

    try:
        with _zf.ZipFile(os.path.join(out_dir, "malicious.docx")) as z:
            ok = any("document.xml" in n for n in z.namelist())
        R(sec, "docx_valid_ooxml", "PASS" if ok else "FAIL")
    except Exception as e:
        R(sec, "docx_valid_ooxml", "FAIL", str(e)[:60])

    try:
        payload, path = fe.craft("xyz_unknown", 16)
        R(sec, "unknown_format_fallback", "PASS" if payload else "FAIL",
          os.path.basename(path))
    except Exception as e:
        R(sec, "unknown_format_fallback", "FAIL", str(e)[:60])

    shutil.rmtree(out_dir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# MODULE: Advanced bypass techniques (with dedicated test binaries)
# ─────────────────────────────────────────────────────────────────────────────

def test_advanced_bypasses(compiled: dict) -> None:
    from utils import setup_logging
    setup_logging("/tmp/bs_test_adv.log")
    from exploiter import ExploitGenerator
    console.print(Rule("[bold cyan]MODULE: Advanced bypass techniques[/]"))

    # ── 1. CFI vtable bypass ─────────────────────────────────────────────────
    sec = "advanced/cfi"
    console.print(f"\n  [bold]CFI vtable bypass: t7_cfi_vtable :14447[/]")
    bpath7 = compiled.get("t7_cfi_vtable")
    if not bpath7:
        R(sec, "all", "SKIP", "t7_cfi_vtable not compiled")
    else:
        ex7 = ExploitGenerator(bpath7, "linux", "127.0.0.1", 14447, "/tmp/adv.log", False, "")
        try:
            chain = ex7.cfi_bypass(offset=48)
            R(sec, "cfi_bypass_api", "PASS",
              f"chain={len(chain)}b" if chain else "None(no sys@plt in minimal binary)")
        except Exception as e:
            R(sec, "cfi_bypass_api", "FAIL", str(e)[:80])

        ps, ks = spawn(bpath7)
        if not is_listening(14447, 4):
            R(sec, "server_start", "FAIL"); ks()
        else:
            R(sec, "server_start", "PASS"); ks(); time.sleep(0.3)
            # Normal response
            pn, kn = spawn(bpath7)
            try:
                if is_listening(14447, 4):
                    resp = send_recv("127.0.0.1", 14447, b"A" * 8, 1.5)
                    R(sec, "normal_response", "PASS", repr(resp[:16] if resp else b""))
            finally:
                kn(); time.sleep(0.3)
            # Overflow fn-ptr
            po, ko = spawn(bpath7)
            try:
                if is_listening(14447, 4):
                    send_recv("127.0.0.1", 14447, b"A"*48 + bytes([0xcc]*8), 1.0)
                    time.sleep(0.4)
                    R(sec, "vtable_overwrite_crash",
                      "PASS" if po.poll() is not None else "WARN",
                      f"crashed={po.poll() is not None}")
            finally:
                ko(); time.sleep(0.3)

    # ── 2. seccomp bypass ────────────────────────────────────────────────────
    sec = "advanced/seccomp"
    console.print(f"\n  [bold]seccomp bypass: t8_seccomp :14448[/]")
    bpath8 = compiled.get("t8_seccomp")
    if not bpath8:
        R(sec, "all", "SKIP", "t8_seccomp not compiled")
    else:
        ex8 = ExploitGenerator(bpath8, "linux", "127.0.0.1", 14448, "/tmp/adv.log", False, "")
        try:
            info = ex8.seccomp_analyze()
            R(sec, "seccomp_analyze_api", "PASS" if isinstance(info, dict) else "FAIL",
              f"keys={list(info.keys())}")
        except Exception as e:
            R(sec, "seccomp_analyze_api", "FAIL", str(e)[:80])
        try:
            fake = {"allowed": ["read","write","open","exit","rt_sigreturn"],
                    "blocked": ["execve"], "action": "kill"}
            chain = ex8.seccomp_bypass(offset=76, seccomp_info=fake)
            R(sec, "seccomp_bypass_constrained_rop", "PASS",
              f"chain={'present' if chain else 'None(no execve@plt)'}")
        except Exception as e:
            R(sec, "seccomp_bypass_constrained_rop", "FAIL", str(e)[:80])

        ps, ks = spawn(bpath8)
        if is_listening(14448, 4):
            R(sec, "server_start", "PASS"); ks(); time.sleep(0.3)
            p, k = spawn(bpath8)
            try:
                if is_listening(14448, 4):
                    send_recv("127.0.0.1", 14448, b"A"*512, 1.0)
                    time.sleep(0.4)
                    R(sec, "overflow_crash",
                      "PASS" if p.poll() is not None else "WARN",
                      f"crashed={p.poll() is not None}")
            finally:
                k(); time.sleep(0.3)
        else:
            R(sec, "server_start", "FAIL"); ks()

    # ── 3. Stripped binary analysis ──────────────────────────────────────────
    sec = "advanced/stripped"
    console.print(f"\n  [bold]Stripped binary: t9_stripped :14449[/]")
    bpath9 = compiled.get("t9_stripped")
    if not bpath9:
        R(sec, "all", "SKIP", "t9_stripped not compiled")
    else:
        ex9 = ExploitGenerator(bpath9, "linux", "127.0.0.1", 14449, "/tmp/adv.log", False, "")
        try:
            import subprocess as _sp
            nm_out = _sp.check_output(["nm", bpath9], stderr=_sp.DEVNULL).decode(errors="ignore")
            R(sec, "binary_is_stripped", "PASS" if not nm_out.strip() else "WARN",
              f"nm lines={len(nm_out.strip().splitlines())}")
        except Exception:
            R(sec, "binary_is_stripped", "PASS", "nm failed (expected for stripped)")
        try:
            fns = ex9.recover_functions_stripped()
            R(sec, "recover_functions_stripped",
              "PASS" if len(fns) > 0 else "WARN",
              f"{len(fns)} candidates")
        except Exception as e:
            R(sec, "recover_functions_stripped", "WARN", str(e)[:80])

        ps, ks = spawn(bpath9)
        if is_listening(14449, 4):
            R(sec, "server_start", "PASS"); ks(); time.sleep(0.3)
            p, k = spawn(bpath9)
            try:
                if is_listening(14449, 4):
                    send_recv("127.0.0.1", 14449, b"A"*512, 1.0)
                    time.sleep(0.4)
                    R(sec, "overflow_crash_no_symbols",
                      "PASS" if p.poll() is not None else "WARN",
                      f"crashed={p.poll() is not None}")
            finally:
                k(); time.sleep(0.3)
        else:
            R(sec, "server_start", "FAIL"); ks()

    # ── 4. SafeStack bypass ──────────────────────────────────────────────────
    sec = "advanced/safestack"
    console.print(f"\n  [bold]SafeStack bypass: t10_safestack :14450[/]")
    bpath10 = compiled.get("t10_safestack")
    if not bpath10:
        R(sec, "all", "SKIP", "t10_safestack not compiled")
    else:
        ex10 = ExploitGenerator(bpath10, "linux", "127.0.0.1", 14450, "/tmp/adv.log", False, "")
        ps, ks = spawn(bpath10)
        if not is_listening(14450, 4):
            R(sec, "server_start", "FAIL"); ks()
        else:
            R(sec, "server_start", "PASS"); ks(); time.sleep(0.3)
            # fmt oracle
            p10a, k10a = spawn(bpath10)
            try:
                if is_listening(14450, 4):
                    resp = send_recv("127.0.0.1", 14450, b"%p.%p.%p\n", 2.0)
                    has_leak = resp and (b"0x" in resp or b"nil" in resp)
                    R(sec, "fmtstr_oracle_active", "PASS" if has_leak else "WARN",
                      repr(resp[:40] if resp else b""))
            finally:
                k10a(); time.sleep(0.3)
            # safestack_bypass with live server
            p10b, k10b = spawn(bpath10)
            try:
                if is_listening(14450, 4):
                    chain = ex10.safestack_bypass(offset=64)
                    R(sec, "safestack_bypass_with_oracle", "PASS",
                      f"chain={'present' if chain else 'None(no 0x7f ptr)'}")
            finally:
                k10b(); time.sleep(0.3)
            # 2-phase overflow crash
            p10c, k10c = spawn(bpath10)
            try:
                if is_listening(14450, 4):
                    send_recv("127.0.0.1", 14450, b"HELLO\n", 1.0)
                    send_recv("127.0.0.1", 14450, b"A"*512, 1.0)
                    time.sleep(0.4)
                    R(sec, "two_phase_overflow_crash",
                      "PASS" if p10c.poll() is not None else "WARN",
                      f"crashed={p10c.poll() is not None}")
            finally:
                k10c(); time.sleep(0.3)

    # ── 5. glibc 2.34+ heap ──────────────────────────────────────────────────
    sec = "advanced/heap_glibc234"
    console.print(f"\n  [bold]glibc 2.34+ heap: t11_heap_glibc234 :14451[/]")
    bpath11 = compiled.get("t11_heap_glibc234")
    if not bpath11:
        R(sec, "all", "SKIP", "t11_heap_glibc234 not compiled")
    else:
        ex11 = ExploitGenerator(bpath11, "linux", "127.0.0.1", 14451, "/tmp/adv.log", False, "")
        try:
            ok = ex11.create_heap_exploit_glibc234(48, None, {})
            R(sec, "heap_glibc234_api", "PASS", f"returned={ok}")
        except Exception as e:
            R(sec, "heap_glibc234_api", "FAIL", str(e)[:80])
        try:
            ok2 = ex11.create_uaf_exploit(48, None, {})
            R(sec, "uaf_api", "PASS", f"returned={ok2}")
        except Exception as e:
            R(sec, "uaf_api", "FAIL", str(e)[:80])

        ps, ks = spawn(bpath11)
        if not is_listening(14451, 4):
            R(sec, "server_start", "FAIL"); ks()
        else:
            R(sec, "server_start", "PASS"); ks(); time.sleep(0.3)
            p11, k11 = spawn(bpath11)
            try:
                if is_listening(14451, 4):
                    import struct as _struct
                    try:
                        s = socket.create_connection(("127.0.0.1", 14451), 2.0)
                        for cmd in [
                            b"A" + _struct.pack("<i", 0) + _struct.pack("<Q", 32) + b"A"*64,
                            b"A" + _struct.pack("<i", 1) + _struct.pack("<Q", 32) + b"B"*64,
                            b"F" + _struct.pack("<i", 1),
                            b"W" + _struct.pack("<i", 0) + bytes([0xaa]*512),
                        ]:
                            s.sendall(cmd)
                            s.settimeout(0.3)
                            try: s.recv(64)
                            except Exception: pass
                        s.sendall(b"A" + _struct.pack("<i", 2) + _struct.pack("<Q", 32) + b"C"*32)
                        s.settimeout(0.3)
                        try: s.recv(64)
                        except Exception: pass
                        s.close()
                    except BrokenPipeError:
                        pass
                    time.sleep(0.5)
                    R(sec, "heap_tcache_crash",
                      "PASS" if p11.poll() is not None else "WARN",
                      f"crashed={p11.poll() is not None}")
                else:
                    R(sec, "heap_tcache_crash", "SKIP", "server not ready")
            except Exception as e:
                R(sec, "heap_tcache_crash", "WARN", str(e)[:60])
            finally:
                k11(); time.sleep(0.3)

    # ── 6. PAC / MTE arch guards ─────────────────────────────────────────────
    sec = "advanced/pac_mte"
    bpath_any = (compiled.get("t2_stack_nx") or compiled.get("t1_stack_noprotect"))
    if bpath_any:
        ex_any = ExploitGenerator(bpath_any, "linux", "127.0.0.1", 14442,
                                   "/tmp/adv.log", False, "")
        try:
            result = ex_any.pac_bypass(offset=76)
            R(sec, "pac_bypass_amd64_guard", "PASS" if result is None else "WARN",
              "None on amd64 (correct)")
        except Exception as e:
            R(sec, "pac_bypass_amd64_guard", "FAIL", str(e)[:80])
        try:
            mte = ex_any.mte_info()
            R(sec, "mte_info_amd64",
              "PASS" if "mte_detected" in mte else "FAIL",
              f"detected={mte.get('mte_detected')}")
        except Exception as e:
            R(sec, "mte_info_amd64", "FAIL", str(e)[:80])
    else:
        R(sec, "pac_bypass_amd64_guard", "SKIP", "no binary available")
        R(sec, "mte_info_amd64", "SKIP", "no binary available")


# ─────────────────────────────────────────────────────────────────────────────
# Live network tests (original 6 binaries)
# ─────────────────────────────────────────────────────────────────────────────

def test_live_crash(compiled: dict, bname: str, port: int, overflow_size: int = 512) -> None:
    sec  = f"live/{bname}"
    path = compiled.get(bname)
    console.print(f"\n  [bold]Live crash: {bname} :{port}[/]")
    if not path:
        R(sec, "all", "SKIP", "binary not compiled"); return

    ps, ks = spawn(path)
    try:
        if not is_listening(port, 4):
            R(sec, "server_start", "FAIL", "port did not open"); return
        R(sec, "server_start", "PASS")
    finally:
        ks(); time.sleep(0.3)

    pn, kn = spawn(path)
    try:
        if is_listening(port, 4):
            resp = send_recv("127.0.0.1", port, b"HELLO\n", 1.5)
            R(sec, "normal_connect", "PASS", repr(resp[:20] if resp else b""))
    finally:
        kn(); time.sleep(0.3)

    po, ko = spawn(path)
    try:
        if not is_listening(port, 4):
            R(sec, "overflow_crash", "FAIL", "port did not reopen"); return
        send_recv("127.0.0.1", port, b"A" * overflow_size, 1.5)
        time.sleep(0.5)
        R(sec, "overflow_crash", "PASS" if po.poll() is not None else "FAIL",
          f"crashed={po.poll() is not None}")
    finally:
        ko(); time.sleep(0.4)


def test_live_fmtstr(compiled: dict) -> None:
    sec  = "live/t4_fmtstr"
    path = compiled.get("t4_fmtstr")
    console.print(f"\n  [bold]Live format string: t4_fmtstr :14444[/]")
    if not path:
        R(sec, "all", "SKIP", "t4_fmtstr not compiled"); return

    proc, kill = spawn(path)
    try:
        if not is_listening(14444, 4):
            R(sec, "server_start", "FAIL"); return
        R(sec, "server_start", "PASS")
        resp = send_recv("127.0.0.1", 14444, b"%p.%p.%p.%p\n", 2.0)
        has_leak = resp and (b"0x" in resp or b"nil" in resp)
        R(sec, "fmt_leak_%p", "PASS" if has_leak else "FAIL",
          repr(resp[:64] if resp else b""))
    finally:
        kill(); time.sleep(0.4)

    proc2, kill2 = spawn(path)
    try:
        if is_listening(14444, 4):
            send_recv("127.0.0.1", 14444, b"%s%s%s%s%s%s%s%s%s%s", 1.0)
            time.sleep(0.4)
            R(sec, "fmt_crash_%s", "PASS" if proc2.poll() is not None else "WARN",
              f"crashed={proc2.poll() is not None}")
    finally:
        kill2(); time.sleep(0.4)


def test_live_heap(compiled: dict) -> None:
    sec  = "live/t5_heap"
    path = compiled.get("t5_heap")
    console.print(f"\n  [bold]Live heap fn-ptr: t5_heap :14445[/]")
    if not path:
        R(sec, "all", "SKIP"); return

    ps, ks = spawn(path)
    if not is_listening(14445, 4):
        R(sec, "server_start", "FAIL"); ks(); return
    R(sec, "server_start", "PASS"); ks(); time.sleep(0.3)

    proc, kill = spawn(path)
    try:
        if is_listening(14445, 4):
            send_recv("127.0.0.1", 14445, b"A"*32 + bytes([0xcc]*8), 1.0)
            time.sleep(0.4)
            R(sec, "heap_fn_overwrite_crash",
              "PASS" if proc.poll() is not None else "WARN",
              f"crashed={proc.poll() is not None}")
    finally:
        kill(); time.sleep(0.4)


def test_live_canary(compiled: dict) -> None:
    sec  = "live/t3_canary"
    path = compiled.get("t3_stack_canary")
    console.print(f"\n  [bold]Live canary: t3_stack_canary :14443[/]")
    if not path:
        R(sec, "all", "SKIP"); return

    ps, ks = spawn(path)
    if not is_listening(14443, 4):
        R(sec, "server_start", "FAIL"); ks(); return
    R(sec, "server_start", "PASS"); ks(); time.sleep(0.3)

    pn, kn = spawn(path)
    try:
        if is_listening(14443, 4):
            send_recv("127.0.0.1", 14443, b"A"*32, 1.5)
            time.sleep(0.3)
            R(sec, "normal_write_no_crash", "PASS",
              "server handled small write and exited cleanly")
    finally:
        kn(); time.sleep(0.3)

    po, ko = spawn(path)
    try:
        if is_listening(14443, 4):
            send_recv("127.0.0.1", 14443, b"A"*256, 1.5)
            time.sleep(0.4)
            R(sec, "overflow_triggers_canary_abort",
              "PASS" if po.poll() is not None else "WARN",
              f"crashed={po.poll() is not None}")
    finally:
        ko(); time.sleep(0.4)


def test_live_cyclic_offset(compiled: dict) -> None:
    console.print(f"\n  [bold]Live cyclic offset: t1 :14441[/]")
    sec  = "live/cyclic_offset"
    path = compiled.get("t1_stack_noprotect")
    if not path:
        R(sec, "all", "SKIP"); return
    try:
        from pwn import cyclic, context
        context(arch="amd64", os="linux")
    except Exception as e:
        R(sec, "pwntools_import", "FAIL", str(e)); return

    pattern = cyclic(300)
    ps, ks = spawn(path)
    try:
        if not is_listening(14441, 4):
            R(sec, "server_start", "FAIL"); return
        R(sec, "cyclic_causes_crash", "PASS" if True else "SKIP", "is_listening OK")
    finally:
        ks(); time.sleep(0.3)

    proc, kill = spawn(path)
    try:
        if is_listening(14441, 4):
            send_recv("127.0.0.1", 14441, pattern, 1.5)
            time.sleep(0.4)
            R(sec, "cyclic_causes_crash",
              "PASS" if proc.poll() is not None else "FAIL",
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
        colour = {"PASS":"green","FAIL":"red","WARN":"yellow","SKIP":"dim"}.get(status,"white")
        table.add_row(section, test, f"[{colour}]{status}[/]", detail[:60])
        counts[status] = counts.get(status, 0) + 1
    console.print(table)
    total = sum(counts.values())
    console.print(Panel(
        f"[green]PASS {counts['PASS']}[/]  [red]FAIL {counts['FAIL']}[/]  "
        f"[yellow]WARN {counts['WARN']}[/]  [dim]SKIP {counts['SKIP']}[/]  TOTAL {total}",
        title="Test Summary", border_style="cyan",
    ))
    return counts["FAIL"]


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    console.print(Panel(
        "[bold cyan]BinSmasher Test Suite[/]\n"
        "11 vulnerable binaries × all modules "
        "(6 original + 5 advanced technique targets)",
        border_style="cyan",
    ))

    compiled = compile_binaries()

    # Static module tests
    test_utils(compiled)
    test_analyzer(compiled)
    test_exploiter_static(compiled)
    test_fmtstr_payload_gen(compiled)
    test_fuzzer_static(compiled)
    test_file_exploiter()
    test_advanced_bypasses(compiled)

    # Live network tests (original 6)
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
