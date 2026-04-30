# BinSmasher 🔨

**Production-Ready Binary Exploitation Framework**

<img width="1024" height="1024" alt="BinSmasher Logo" src="https://github.com/user-attachments/assets/66969605-fcae-48b9-9096-350778bdab99" />

> **Authorized use only**: CTF competitions, penetration testing, security research  
> **Unauthorized access to systems you do not own is illegal.**

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔍 **Auto-Detection** | Automatically detects vulnerability type, protections, win functions, and exploit strategy |
| 🎯 **43+ Techniques** | ret2win, ret2libc, ROP, SROP, ORW, heap, format string, FSOP, ASLR bypass, etc. |
| 🛡️ **Protection Bypass** | PIE, NX, ASLR, canary, RELRO, seccomp, CFI, SafeSEH |
| 📊 **Binary Analysis** | Static analysis, gadget finding, libc fingerprinting, seccomp parsing |
| ⚙️ **Fully Configurable** | Custom win function names, offset ranges, and exploit parameters via CLI |
| 🔗 **Network Ready** | TCP, UDP, HTTP, TLS support with adaptive timeouts |
| 🧪 **Test Suite** | 245+ unit tests, 25+ integration tests, comprehensive coverage |
| 📝 **Auto-Generated** | Exploit scripts, GDB scripts, crash scripts, CTF writeups |
| 🔧 **Extensible** | Modular mixin architecture (25 mixins), easy to add new techniques |

---

## 🚀 Quick Start

```bash
# System dependencies
sudo apt-get install -y python3 python3-pip gdb radare2 socat \
    binutils file patchelf checksec

# Python dependencies
pip install pwntools rich boofuzz frida-tools ropper

# Optional: angr symbolic execution (large)
pip install angr

# Optional: AFL++ coverage fuzzing
sudo apt-get install -y afl++

# Optional: one_gadget (Ruby gem)
gem install one_gadget
```

### Install as global command

```bash
git clone https://github.com/your-org/binsmasher
cd binsmasher
pip install -e .
binsmasher --help
```

### Docker

```bash
docker build -t binsmasher .
docker run --rm -it --network host --cap-add SYS_PTRACE \
  -v $(pwd):/workspace binsmasher binary --help
```

---

## Quick Start

```bash
# Run directly (no install)
python3 src/main.py binary -b ./vuln --host 127.0.0.1 --port 4444 -t

# Installed command
binsmasher binary -b ./vuln --host 127.0.0.1 --port 4444 -t

# Auto-detect vuln type, use adaptive timeouts, generate solve template
binsmasher binary -b ./vuln --host ctf.io --port 4444 \
  --detect-vuln --adaptive-timeout --template -t
```

---

## Architecture

```
binsmasher/
├── src/
│   ├── main.py                       # Entry point & CLI
│   ├── binsmasher_main.py            # pip console-script shim
│   │
│   ├── utils/
│   │   ├── config.py                 # ExploitConfig dataclass
│   │   ├── display.py                # Rich summary table
│   │   ├── logging_setup.py          # Dual-sink logging
│   │   ├── _process.py               # Core-dump isolation (/tmp/binsmasher_*)
│   │   ├── adaptive_timeout.py       # RTT-based timeout scaling
│   │   ├── json_output.py            # JSON/Markdown structured output
│   │   ├── progress.py               # Rich progress bars, noise suppression
│   │   └── writeup.py                # CTF writeup generator
│   │
│   ├── analyzer/
│   │   ├── static.py                 # r2 static analysis (cached)
│   │   ├── protections.py            # checksec-based protection detection
│   │   ├── binary_info.py            # Correct ELF-header detection (ET_DYN/PIE, GNU_STACK/NX)
│   │   ├── dynamic.py                # Frida instrumentation
│   │   ├── library.py                # libc offset loading, libc.rip queries
│   │   ├── seccomp.py                # seccomp-tools integration
│   │   ├── seccomp_parser.py         # Seccomp detection without seccomp-tools (pure Python)
│   │   ├── recovery.py               # Stripped binary recovery
│   │   ├── cache.py                  # SHA256 analysis cache (~/.binsmasher_cache/)
│   │   ├── angr_analysis.py          # angr symbolic path exploration
│   │   ├── vuln_detect.py            # Automatic vulnerability type detection
│   │   ├── libc_db.py                # Local libc database (9 versions, no internet)
│   │   └── libc_fingerprint.py       # Multi-symbol libc fingerprinting
│   │
│   ├── exploiter/
│   │   ├── connection.py             # TCP/UDP connection management
│   │   ├── offset.py                 # Offset detection (corefile/GDB/remote bisect)
│   │   ├── rop_chains.py             # ret2win, ret2libc, SROP, ORW, ret2dlresolve
│   │   ├── heap.py                   # Basic heap: UAF, fastbin, tcache
│   │   ├── heap_advanced.py          # tcache+safe-linking, House of Apple2, DynELF
│   │   ├── heap_groom.py             # Heap grooming, spray, off-by-one/null, ret2mprotect
│   │   ├── gadgets.py                # ROPgadget/ropper, one_gadget
│   │   ├── shellcode.py              # Shellcode + XOR encoding
│   │   ├── format_string.py          # Basic format string (Partial RELRO)
│   │   ├── format_string_advanced.py # Full RELRO bypass, PIE-aware, stack write
│   │   ├── windows.py                # SafeSEH, CFG, CFI bypass
│   │   ├── scripts.py                # Script generation (crash/exploit/GDB)
│   │   ├── orchestrator.py           # create_exploit: master TCP strategy selector
│   │   ├── multistage.py             # Two-stage TCP (leak GOT → ret2system)
│   │   ├── interactive.py            # Interactive shell + solve template
│   │   ├── brute_aslr.py             # ASLR brute (PIE base / libc / partial overwrite)
│   │   ├── aslr_bypass.py            # Automatic ASLR/PIE bypass (fmtstr leak, libc ID)
│   │   ├── win_detector.py           # Automatic win function detection (39+ patterns)
│   │   ├── i386.py                   # Correct 32-bit ROP chains (cdecl, int 0x80, SROP)
│   │   ├── arm64.py                  # AArch64 exploit primitives (svc, SROP, gadgets)
│   │   ├── fsop.py                   # FSOP for glibc 2.34+ (House of Banana/Emma/Kiwi)
│   │   ├── canary_leak.py            # Canary leak without fork-server
│   │   ├── session.py                # Stateful menu/login service interaction
│   │   ├── udp_strategies.py         # UDP+spawn exploit engine (A–F)
│   │   └── http_strategies.py        # HTTP+spawn exploit engine (A–E)
│   │
│   ├── fuzzer/
│   │   ├── afl.py                    # AFL++ coverage fuzzing
│   │   ├── boofuzz_fuzz.py           # boofuzz network fuzzing
│   │   ├── mutation.py               # Built-in mutation fuzzer
│   │   ├── udp.py                    # UDP offset detection (bisect + corefile)
│   │   ├── http.py                   # HTTP payload template + offset detection
│   │   ├── template_utils.py         # Protocol-agnostic {PAYLOAD} substitution + Content-Length
│   │   ├── core_analysis.py          # Core dump analysis
│   │   ├── gdb_scripts.py            # GDB script generation (pwndbg/peda/vanilla)
│   │   ├── offset_roto.py            # ROTO heuristic, SIGFAULT analysis
│   │   └── solana.py                 # Solana/Agave SVM fuzzing
│   │
│   └── file_exploiter/
│       ├── audio.py                  # MP3, WAV, FLAC, OGG, AAC
│       ├── documents.py              # PDF, DOC, DOCX, XLS, XLSX, RTF
│       ├── web.py                    # JSON, XML, HTML, SVG, TXT, CSV
│       ├── images.py                 # BMP, PNG, GIF, JPEG
│       ├── scripts_fmt.py            # PY, JS, PHP, LUA, RB
│       └── archives.py               # ZIP, TAR, ELF, RAW
│
├── binsmasher/
│   └── __init__.py                   # Python library API (BinSmasher class)
│
├── tests/
│   ├── test_suite.py                 # Integration test runner
│   ├── test_new_features.py          # Unit/integration tests for new modules
│   ├── bins/                         # Compiled test binaries
│   └── src/                          # 13 C test sources + Makefile
│
├── Dockerfile
├── docker-compose.yml
├── setup.py
└── pyproject.toml
```

---

## Subcommands

```bash
binsmasher binary   [options]   # ELF/PE binary exploitation
binsmasher file     [options]   # Malicious file generation
binsmasher solana   [options]   # Agave/Solana SVM auditing
```

---

## binary — Full Reference

### Basic Options

| Flag | Default | Description |
|---|---|---|
| `-b`, `--binary` | required | Path to target binary |
| `-c`, `--cmd` | `id` | Command for shellcode payloads |
| `-p`, `--pattern-size` | `200` | Initial cyclic pattern size |
| `-r`, `--return-addr` | auto | Hex return address (skips auto-detection) |
| `--return-offset` | `80` | Bytes from stack addr to return addr |
| `-t`, `--test-exploit` | off | Fire exploit and verify RCE |
| `-l`, `--log-file` | auto `/tmp` | Log file path |

### Network Options

| Flag | Default | Description |
|---|---|---|
| `--host` | `localhost` | Target host |
| `--port` | `4444` | Target port |
| `--tls` | off | Use TLS/SSL |
| `--output-ip` | `127.0.0.1` | Listener IP for callback/revshell |
| `--output-port` | `6666` | Listener port for callback/revshell |

### Payload Options

| Flag | Default | Description |
|---|---|---|
| `--reverse-shell` | off | Reverse shell payload |
| `--file-input` | — | Embed shellcode in `mp3` or `raw` file |
| `--binary-args` | `""` | Arguments to pass to spawned binary |
| `--payload-data` | — | Custom payload template (`{PAYLOAD}` placeholder for injection) |
| `--udp` | off | Send `--payload-data` via UDP |
| `--http` | off | HTTP mode: send payload as HTTP request (e.g. `--http "POST /submit"`) |
| `--spawn-target` | off | Spawn binary locally for crash detection |
| `--bad-bytes` | `""` | Hex bytes to avoid in exploit addresses (e.g. `0a0d` for SIP) |
| `--menu-script` | — | JSON interaction script for menu-based services |
| `--pre-send` | — | Hex bytes to send before exploit payload |

### Fuzzing Options

| Flag | Default | Description |
|---|---|---|
| `--fuzz` | off | boofuzz network fuzzer |
| `--mutation-fuzz` | off | Built-in mutation fuzzer |
| `--afl-fuzz` | off | AFL++ coverage fuzzing |
| `--afl-timeout` | `60` | AFL++ runtime (seconds) |
| `--frida` | off | Frida dynamic instrumentation |
| `--protocol` | `raw` | Protocol hint for boofuzz |

### Exploit Techniques

| Flag | Default | Description |
|---|---|---|
| `--detect-vuln` | off | Auto-detect vulnerability type (STACK_OVERFLOW, FORMAT_STRING, HEAP_OVERFLOW, UAF, INTEGER_OVERFLOW) |
| `--multistage` | off | Two-stage TCP: leak GOT address → compute libc base → ret2system |
| `--multisym-leak` | off | Leak 3 GOT symbols simultaneously for precise libc fingerprinting |
| `--brute-aslr` | off | Brute-force ASLR without a leak |
| `--brute-attempts` | `256` | Max ASLR brute attempts |
| `--srop` | off | Force SROP chain (Sigreturn-Oriented Programming) |
| `--orw` | off | Force ORW chain (open/read/write flag — seccomp bypass) |
| `--flag-path` | `/flag` | Flag file path for ORW chain |
| `--win-names` | `win,flag,shell...` | Comma-separated list of win function names to detect |
| `--offset-min` | `8` | Minimum offset to try for brute force |
| `--offset-max` | `520` | Maximum offset to try for brute force |
| `--offset-step` | `8` | Step size for offset brute force |
| `--ret2mprotect` | off | Force ret2mprotect (make memory executable, inject shellcode) |
| `--off-by-one` | off | Detect and exploit off-by-one / off-by-null heap overflows |
| `--angr` | off | Use angr symbolic execution to find win() path |
| `--interactive` | off | Drop to interactive shell after successful exploit |
| `--template` | off | Generate a complete `solve_BINARY.py` template |
| `--debug` | off | Launch binary under GDB/pwndbg |

### Heap Options

| Flag | Default | Description |
|---|---|---|
| `--heap-exploit` | off | Basic heap exploitation (UAF, fastbin dup, tcache basic) |
| `--heap-advanced` | off | Advanced heap: tcache safe-linking bypass, House of Apple2, DynELF, malloc/free hook |
| `--largebin-attack` | off | Largebin attack (glibc ≥ 2.28) |
| `--stack-pivot` | off | Stack pivot chain via `leave; ret` |
| `--privilege-escalation` | off | Post-exploit privilege escalation attempt |

### Output Options

| Flag | Default | Description |
|---|---|---|
| `--print-json` | off | Print complete result as JSON to stdout |
| `--output-json PATH` | — | Write JSON result to file |
| `--output-markdown` | off | Write Markdown summary to `_bs_work/` |
| `--writeup` | off | Generate full CTF-style writeup |
| `--generate-scripts` | off | Write `crash_BINARY.py` and `exploit_BINARY.py` |
| `--dos` | off | Crash-only mode: find offset, fire crash payload, generate scripts |

### Advanced / Misc

| Flag | Default | Description |
|---|---|---|
| `--adaptive-timeout` | off | Scale all timeouts based on measured RTT to target |
| `--clear-cache` | off | Clear analysis cache for this binary |
| `--no-cache` | off | Disable analysis cache for this run |
| `--gdb-mode` | `pwndbg` | GDB script style: `pwndbg`, `peda`, `vanilla` |
| `--safeseh-bypass` | off | SafeSEH bypass (Windows) |
| `--cfi-bypass` | off | CFI bypass via valid-target pivot |
| `--quiet` | off | Suppress all output except final result |
| `--verbose` | off | Show debug-level output |

---

## Win Function Detection

BinSmasher automatically detects win functions using 39+ built-in patterns:

```
win, flag, shell, backdoor, secret, easy, print_flag, cat_flag,
get_flag, read_flag, show_flag, get_shell, give_shell, spawn_shell,
drop_shell, spawn, pwned, success, solve, victory, solved, system,
exec_shell, do_shell, run_shell, win_func, flag_func, shell_func,
getFlag, getShell, hidden, debug, admin, root, priv, func1, func_win, pwn, ret
```

### Custom Win Functions

Override with `--win-names` for binaries with non-standard naming:

```bash
# Binary has function "capture_flag()" instead of "win()"
binsmasher binary -b ./custom --host 127.0.0.1 --port 4444 \
  --win-names "capture_flag,steal_flag,get_flag" -t
```

### How It Works

1. **Symbol table lookup** — Searches ELF symbols for matching names
2. **Pattern matching** — Checks prefixes, suffixes, and exact matches
3. **Disassembly analysis** — Analyzes function code for shell/flag indicators
4. **String detection** — Looks for `/bin/sh`, `flag{`, `PWNED` in binary strings

---

## Exploit Techniques — TCP Mode

| # | Technique | Trigger |
|---|---|---|
| 0 | **ret2win** | Win/flag/shell symbol found in binary |
| 1 | **two-stage ret2libc** | `--multistage` or ASLR+NX |
| 2 | **ret2csu leak** | No `pop rdi` gadget available |
| 3 | **write-syscall leak** | No PLT leak function |
| 4 | **Canary leak (fmtstr)** | Format string detected, canary present |
| 5 | **Canary leak (stack read)** | Service echoes more bytes than sent |
| 6 | **Canary brute (fork)** | Fork-server detected |
| 7 | **ret2system ROP** | NX on, libc base known |
| 8 | **ret2csu** | No `pop rdi`, libc base known |
| 9 | **SROP** | `--srop` or `syscall;ret` available |
| 10 | **ORW** | `--orw` or seccomp blocks execve |
| 11 | **Format string (Partial RELRO)** | printf detected, GOT writable |
| 12 | **Format string (Full RELRO)** | printf detected, Full RELRO — writes to stack return address |
| 13 | **Shellcode** | NX disabled |
| 14 | **ret2libc static** | NX on, no ASLR |
| 15 | **ret2dlresolve** | No libc leak, no PLT |
| 16 | **tcache poisoning** | `--heap-advanced`, glibc 2.31+ |
| 17 | **tcache + safe-linking bypass** | `--heap-advanced`, glibc 2.32+ |
| 18 | **House of Apple2** | `--heap-advanced`, glibc 2.34+ |
| 19 | **House of Banana** | `--heap-advanced`, glibc 2.34+ (`dl_fini`) |
| 20 | **House of Emma** | `--heap-advanced`, glibc 2.34+ (`_IO_cookie`) |
| 21 | **House of Kiwi** | `--heap-advanced`, glibc 2.34+ (`malloc_assert`) |
| 22 | **FSOP via exit()** | `--heap-advanced`, exit triggers `_IO_flush_all_lockp` |
| 23 | **malloc/free hook overwrite** | `--heap-advanced`, glibc < 2.34 |
| 24 | **DynELF** | `--heap-advanced`, arbitrary read primitive |
| 25 | **Brute PIE base** | `--brute-aslr`, win() present, PIE on |
| 26 | **Brute libc base** | `--brute-aslr`, one_gadget known |
| 27 | **Partial overwrite** | `--brute-aslr`, 12-bit fixed, 16 attempts |
| 28 | **ret2mprotect** | `--ret2mprotect`, no system() available |
| 29 | **Off-by-one/null** | `--off-by-one`, heap overlap |
| 30 | **i386 ret2libc** | 32-bit binary, cdecl stack args |
| 31 | **i386 execve int 0x80** | 32-bit, `int 0x80` gadget found |
| 32 | **i386 SROP** | 32-bit, `SYS_sigreturn=119` |
| 33 | **AArch64 ret2win** | ARM64 binary, LR overwrite |
| 34 | **AArch64 ret2system** | ARM64, x0 gadget + system() |
| 35 | **AArch64 execve svc** | ARM64, `x8=221, svc #0` |
| 36 | **AArch64 SROP** | ARM64, `SYS_rt_sigreturn=139` |
| 37 | **one_gadget** | one_gadget installed, libc known |
| 38 | **CFI bypass** | `--cfi-bypass` |
| 39 | **SafeSEH bypass** | `--safeseh-bypass`, Windows |
| 40 | **Stack pivot** | `--stack-pivot`, `leave; ret` found |
| 41 | **Largebin attack** | `--largebin-attack`, glibc ≥ 2.28 |
| 42 | **Format string leak** | Auto-detect fmtstr vuln, leak libc/stack addresses |
| 43 | **PIE base calc** | Calculate PIE base from leaked code pointer |
| 44 | **Win function detection** | Auto-detect 39+ win function patterns, configurable via CLI |

---

## Exploit Techniques — UDP+Spawn Mode

Activated with `--payload-data` + `--udp` + `--spawn-target`.

| Strategy | Name | Viable when |
|---|---|---|
| A | **ret2system ROP** | `ret_offset + 24 < min_crash`, `pop rdi` available |
| A* | **ret2csu fallback** | As above, no `pop rdi` — uses `__libc_csu_init` |
| B | **SROP** | `syscall;ret` + `pop rax;ret`, frame fits in payload |
| C | **GOT overwrite** | Pointer-overwrite crash pattern detected |
| D | **ret2win** | Win symbol found, `ret_offset + 8 < min_crash` |
| E | **one_gadget** | `one_gadget` installed, no bad bytes |
| F | **ORW** | `--orw` flag, execve blocked by seccomp |

---

## Exploit Techniques — HTTP+Spawn Mode

Activated with `--payload-data` + `--http` + `--spawn-target`.

Same strategy cascade as UDP (A–E), but delivers exploits via HTTP over TCP.

| Strategy | Name | Viable when |
|---|---|---|
| A | **ret2system ROP** | Stack overflow, `pop rdi` available |
| B | **SROP** | `syscall;ret` + `pop rax;ret` |
| C | **ret2win** | Win symbol found |
| D | **one_gadget** | `one_gadget` installed |
| E | **ORW** | `--orw` flag, seccomp detected |

---

## Custom Payload Mode — HTTP

Use `--http` to send payloads as HTTP requests. Works with or without `--spawn-target`.

### HTTP with spawn (offset detection + auto exploit)

```bash
# Template with {PAYLOAD} placeholder — auto-detects injection point
binsmasher binary -b ./http_vuln \
  --host 127.0.0.1 --port 8080 \
  --http "POST /submit" \
  --payload-data 'username=AAAA&data={PAYLOAD}' \
  --spawn-target -t

# Full HTTP template — Content-Length auto-recalculated
binsmasher binary -b ./http_vuln \
  --host 127.0.0.1 --port 8080 \
  --http --spawn-target \
  --payload-data "$(cat http_template.txt)" -t
```

### HTTP raw send (no spawn, no offset detection)

```bash
binsmasher binary -b ./http_vuln \
  --host 127.0.0.1 --port 8080 \
  --http "POST /login" \
  --payload-data 'user=admin&data={PAYLOAD}'
```

When `--payload-data` already contains HTTP framing (starts with `POST`, `GET`, etc.), BinSmasher sends it as-is. Otherwise it wraps the body in HTTP/1.1 framing with `Content-Length` and `Connection: close`.

### HTTP template example

```
POST /vuln HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 8

data={PAYLOAD}
```

`Content-Length` is automatically recalculated after `{PAYLOAD}` substitution.

| Strategy | Name | Viable when |
|---|---|---|
| A | **ret2system ROP** | `ret_offset + 24 < min_crash`, `pop rdi` available |
| A* | **ret2csu fallback** | As above, no `pop rdi` — uses `__libc_csu_init` |
| B | **SROP** | `syscall;ret` + `pop rax;ret`, frame fits in payload |
| C | **GOT overwrite** | Pointer-overwrite crash pattern detected |
| D | **ret2win** | Win symbol found, `ret_offset + 8 < min_crash` |
| E | **one_gadget** | `one_gadget` installed, no bad bytes |
| F | **ORW** | `--orw` flag, execve blocked by seccomp |

---

## Custom Payload Mode — Deep Dive

### Flow

```
1. BISECT      Find min crash size by probing [8, 16, 32 … 4096] bytes + bisect
2. COREDUMP    Inject cyclic(min_crash), collect core → extract RIP → stack scan
3. BASES       Read PIE base + libc base from /proc/PID/maps
4. EXPLOIT     Try strategies A→F, spawn fresh binary per attempt (clean ASLR)
```

### Payload Template

Use `{PAYLOAD}` as injection point. `Content-Length` is auto-recalculated.

```
INVITE sip:target@127.0.0.1 SIP/2.0
...
Content-Length: {CONTENT_LENGTH}
a=ice-ufrag:{PAYLOAD}
```

### Bad Bytes

| Protocol | `--bad-bytes` |
|---|---|
| Raw TCP/UDP | *(empty)* |
| SIP/HTTP headers | `0a0d` |
| Null-terminated string | `00` |
| C string + newline | `000a0d` |

---

## Menu-based Services

For CTF binaries with menus (alloc/free/edit/show/exit), use `--menu-script`:

```bash
binsmasher binary -b ./heap_menu --host 127.0.0.1 --port 4444 -t \
  --menu-script '[{"recv_until":"> "},{"send_line":"1"},{"recv_until":"size: "},{"send_line":"32"},{"recv_until":"> "},{"send_line":"3"},{"recv_until":"data: "}]'
```

---

## Python API

```python
from binsmasher import BinSmasher
from exploiter import ExploitGenerator, DEFAULT_WIN_PATTERNS

# Analyze with default settings
bs = BinSmasher("./vuln", host="ctf.io", port=4444)
bs.analyze()
bs.detect_vuln()

# Find offset + canary
offset = bs.find_offset()
canary = bs.leak_canary()   # tries fmtstr, stack read, fork brute

# Build and send exploit
chain = bs.build_rop("auto")   # auto-selects: win → system → srop → execve
bs.send(chain)
bs.interactive()

# Two-stage
ok, etype = bs.multistage()

# Output
bs.template()          # → solve_vuln.py
bs.save_json()         # → result.json
bs.save_writeup()      # → writeup_vuln.md

# === Advanced: Custom win function detection ===

# Use ExploitGenerator directly with custom parameters
eg = ExploitGenerator(
    binary="./custom_chall",
    platform="linux",
    host="ctf.io",
    port=4444,
    log_file="/tmp/bs.log",
    tls=False,
    binary_args="",
    win_names=["get_flag", "print_flag", "solve"],  # Custom win function names
    offset_range=(16, 256, 16)  # Custom offset range: min, max, step
)

# Check default win patterns (39+ built-in)
print(DEFAULT_WIN_PATTERNS)
# ['win', 'flag', 'shell', 'backdoor', 'secret', 'easy', ...]
```

---

## file — Malicious File Generation

```bash
binsmasher file --format mp3 --offset 256 --technique overflow -o ./payloads/
binsmasher file --all-formats --offset 512 -o ./payloads/
```

| Category | Formats |
|---|---|
| Audio | `mp3`, `wav`, `flac`, `ogg`, `aac` |
| Documents | `pdf`, `doc`, `docx`, `xls`, `xlsx`, `rtf`, `txt`, `csv` |
| Web/Data | `json`, `xml`, `html`, `svg` |
| Images | `bmp`, `png`, `gif`, `jpeg` |
| Code | `py`, `js`, `php`, `lua`, `rb` |
| Archives/Binary | `zip`, `tar`, `elf`, `raw` |

---

## solana — Agave / Solana SVM Auditing

```bash
binsmasher solana --rpc http://localhost:8899 \
  --source-path ./agave/src --exploit-type svm-bpf
```

| `--exploit-type` | Description |
|---|---|
| `svm-bpf` | BPF verifier bypass |
| `deser` | Account deserialization vulnerability |
| `dos-quic` | QUIC connection denial of service |
| `snapshot-assert` | Snapshot loading assertion panic |

---

## Usage Examples

### CTF — ret2win (simplest case)

```bash
binsmasher binary -b ./pwn1 --host 127.0.0.1 --port 1337 -t
```

### CTF — Auto-detect vuln, adaptive timeout

```bash
binsmasher binary -b ./unknown --host ctf.example.com --port 4444 \
  --detect-vuln --adaptive-timeout -t
```

### CTF — ASLR + NX + PIE, two-stage leak

```bash
binsmasher binary -b ./hard_pwn --host 127.0.0.1 --port 9001 \
  --multistage -t --interactive
```

### CTF — Format string, Full RELRO

```bash
binsmasher binary -b ./fmtstr_chal --host 127.0.0.1 --port 5555 -t
# Automatically uses stack return-address write when Full RELRO detected
```

### CTF — Heap challenge (glibc 2.35, no hooks)

```bash
binsmasher binary -b ./heap_chal --host 127.0.0.1 --port 7777 \
  --heap-advanced -t
# Auto-selects: House of Apple2 (glibc 2.34+) or tcache+hook (< 2.34)
```

### CTF — Brute ASLR without leak

```bash
binsmasher binary -b ./pie_binary --host ctf.io --port 4444 \
  --brute-aslr --brute-attempts 512 -t
```

### CTF — ARM64 binary

```bash
binsmasher binary -b ./arm64_chal --host 127.0.0.1 --port 4444 -t
# Detects AArch64 and uses ARM64-specific ROP chains automatically
```

### CTF — Seccomp sandbox, ORW

```bash
binsmasher binary -b ./sandboxed --host 127.0.0.1 --port 8888 \
  --detect-vuln --flag-path /home/ctf/flag.txt -t
# Detects seccomp, auto-enables --orw using only allowed syscalls
```

### CTF — Canary without fork-server

```bash
binsmasher binary -b ./canary_chal --host 127.0.0.1 --port 3333 -t
# Tries: format string leak → stack read → printf leak → fork brute
```

### CTF — Generate solve template

```bash
binsmasher binary -b ./challenge --host 127.0.0.1 --port 1337 \
  --template --writeup --generate-scripts -t
```

### CTF — Remote with high latency + multi-symbol fingerprint

```bash
binsmasher binary -b ./challenge --host ctf.example.com --port 1337 \
  --adaptive-timeout --multistage --multisym-leak \
  --output-json result.json -t
```

### Pentest — SIP/UDP service

```bash
cat > invite.txt << 'EOF'
INVITE sip:target@127.0.0.1 SIP/2.0
Content-Type: application/sdp
Content-Length: {CONTENT_LENGTH}

a=ice-ufrag:{PAYLOAD}
EOF

binsmasher binary -b /path/to/sip_server \
  --host 127.0.0.1 --port 5060 \
  --udp --spawn-target \
  --bad-bytes 0a0d \
  --adaptive-timeout \
  --payload-data "$(cat invite.txt)"
```

### CTF — HTTP service with exploit

```bash
# Auto-detect offset and exploit via HTTP POST
binsmasher binary -b ./http_vuln \
  --host 127.0.0.1 --port 8080 \
  --http "POST /submit" \
  --payload-data 'user=AAAA&data={PAYLOAD}' \
  --spawn-target -t

# Full HTTP template with headers
cat > http_template.txt << 'EOF'
POST /vuln HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 8

data={PAYLOAD}
EOF

binsmasher binary -b ./http_vuln \
  --host 127.0.0.1 --port 8080 \
  --http --spawn-target \
  --payload-data "$(cat http_template.txt)" -t
```

### Menu binary (heap CTF)

```bash
binsmasher binary -b ./heap_menu --host 127.0.0.1 --port 4444 \
  --heap-advanced -t \
  --menu-script '[
    {"recv_until": "> "},
    {"send_line": "1"},
    {"recv_until": "size: "},
    {"send_line": "32"}
  ]'
```

---

## Running the Test Suite

```bash
# 1. Compile test binaries
cd tests/src && make && cd ../..

# 2. Fast local tests (skip slow CMD/REVSHELL)
python tests/test_suite.py --local-only --skip-slow

# 3. Full local tests
python tests/test_suite.py --local-only

# 4. Full suite + CTF binary downloads
python tests/test_suite.py

# 5. New feature unit/integration tests
python tests/test_new_features.py
```

### Expected results

| Binary | Status | Technique |
|---|---|---|
| t1_stack_noprotect | ✅ PASS | ret2win — NX off |
| t2_stack_nx | ✅ PASS | ret2win — NX on |
| t3_stack_canary | ✅ PASS | ret2win (canary detected) |
| t4_fmtstr | ✅ PASS | ret2win via format string binary |
| t5_heap | ✅ PASS | ret2win via heap binary |
| t6_64bit_nx | ✅ PASS | ret2win — 64-bit NX |
| t7_cfi_vtable | ✅ PASS | ret2win — vtable binary |
| t8_seccomp | ✅ PASS | ret2win — seccomp binary |
| t9_stripped | ⚠️ WARN | No symbols — expected |
| t10_safestack | ✅ PASS | ret2win |
| t11_heap_glibc234 | ✅ PASS | ret2win — glibc 2.34+ |
| t_shellexec | ✅ PASS | win() → system("id") |
| t_revshell | ✅ PASS | win() → connect-back shell |

---

## Known Limitations

### Automatic Exploitation
- **PIE + ASLR without leak**: Requires address leak in banner/output. Use `--brute-aslr` for fork servers.
- **Stripped binaries**: No symbols = no automatic win detection. Use `--win-names` if you know the function.
- **Menu-based services**: Requires `--menu-script` JSON for navigation.
- **Heap with complex menus**: Partial automation; some interaction may be manual.

### Technical Constraints
- **UDP+spawn**: Single-stage only. ret2plt+leak, DynELF, format string leak require receive channel.
- **Copy crash constraint**: If `ret_addr_offset + chain_len >= min_crash`, that overflow cannot be exploited.
- **Windows**: SafeSEH/CFG detection works; exploitation is partially implemented.
- **Kernel exploits**: Not in scope (`/dev/ptmx`, `userfaultfd`, heap spray).
- **ARM64 gadget search**: Depends on ROPgadget or ropper being installed.
- **angr**: Requires separate installation (`pip install angr`), large dependency.

### What Works Automatically
| Binary Type | Success Rate | Notes |
|-------------|---------------|-------|
| ret2win (symbols) | ✅ 100% | Auto-detects 39+ win patterns |
| NX + canary (banner leak) | ✅ 100% | Parses `COOKIE:0x...` from banner |
| Format string | ✅ 95% | Partial/Full RELRO supported |
| PIE + leak in output | ✅ 90% | Same-connection exploit |
| ret2libc (libc known) | ✅ 85% | Requires libc identification |
| Heap basic | ✅ 80% | UAF, fastbin, tcache |
| Heap advanced | ⚠️ 60% | House of Apple2, FSOP |
| PIE + ASLR (no leak) | ⚠️ 30% | Fork-server brute only |
| Stripped | ❌ 10% | Needs `--win-names` or angr |

---

## Dependencies

| Tool | Required | Purpose |
|---|---|---|
| `python3` ≥ 3.9 | Yes | Runtime |
| `pwntools` | Yes | Exploit primitives, ROP, ELF, DynELF |
| `radare2` | Yes | Static analysis, gadget finding |
| `gdb` | Recommended | Offset detection, corefile analysis |
| `socat` | Yes (tests) | TCP→stdin for test suite |
| `one_gadget` | Recommended | one_gadget libc magic gadgets |
| `AFL++` | Optional | Coverage fuzzing (`--afl-fuzz`) |
| `frida` | Optional | Dynamic instrumentation (`--frida`) |
| `boofuzz` | Optional | Network fuzzing (`--fuzz`) |
| `angr` | Optional | Symbolic execution (`--angr`) |
| `checksec` | Optional | Better protection detection |
| `patchelf` | Optional | Binary patching for local libc |
| `seccomp-tools` | Optional | Seccomp filter analysis (Ruby gem) |

---

## CVE Scanner — `binscan`

<img width="1770" height="942" alt="image" src="https://github.com/user-attachments/assets/feacfd20-d743-4e29-96c4-42f9148ab327" />

**Static-only binary vulnerability scanner for responsible disclosure.**

Installed as the `binscan` command via `pip install`.

```bash
# Scan default paths (/usr/bin, /usr/sbin, /lib/modules)
binscan

# Scan specific directories
binscan /usr/sbin /opt/binaries

# Audit a single binary
binscan --single /tmp/vuln_binary

# Custom output directory (default: ~/binscan_reports)
binscan /usr/bin -o ~/my_reports

# High-confidence only, verbose
binscan --single ./target --confidence CONFIRMED -v

# Skip taint analysis, threshold 100
binscan /usr/bin /sbin --threshold 100 --no-taint

# Skip HTML report generation
binscan /usr/bin --no-html
```

### Options

| Flag | Default | Description |
|---|---|---|
| `paths` | `/usr/bin /usr/sbin /lib/modules` | Directories or files to scan |
| `-o`, `--output-dir` | `~/binscan_reports` | Output directory for reports |
| `--threshold` | `50` | Minimum risk score to include a binary |
| `-v`, `--verbose` | off | Enable debug logging |
| `--single BINARY` | — | Audit a single binary file |
| `--no-taint` | off | Disable taint / data-flow analysis |
| `--confidence` | `PROBABLE` | Minimum confidence: `CONFIRMED`, `PROBABLE`, `UNCONFIRMED` |
| `--no-html` | off | Skip HTML report generation |

### Output

Reports are saved to `~/binscan_reports` (or custom `-o` path):

| File | Description |
|---|---|
| `cve_audit_all_*.json` | All findings as JSON |
| `cve_audit_confirmed_high_*.json` | CONFIRMED + High/Critical only |
| `cve_audit_probable_high_*.json` | PROBABLE + High/Critical only |
| `cve_mitre_*.md` | MITRE CVE submission templates (Markdown) |
| `cve_mitre_json_*.json` | MITRE CVE 5.0 JSON templates |
| `cve_audit_*.html` | Interactive HTML report with filters |

Detects 25+ dangerous functions, applies taint analysis, generates CVSS-scored HTML/JSON/MITRE CVE output.

---

## Contributing

Contributions are welcome. Open an issue or submit a pull request.

Priority areas:
- Kernel exploit primitives (`modprobe_path`, `commit_creds`, `msg_msg`)
- CTF platform integration (`pwn.college`, `HTB`, `pwnable.kr`)
- ARM64 gadget search improvements (PAC bypass)
- More libc versions in local database

---

## Donations

If BinSmasher has been useful in your research or competitions:

**ETH** — `0xD773B73C7ea4862020b7B5B58f31Ea491f5a9bA3`

**BTC** — `bc1ql6qvsk67hl5vz346kx4gueqjhp6me9ss8eflgt`

**SOL** — `GYBiTvVbPvPJP7ZK5oaqc9w6UtHvd6NkhSPP2UBhDvfh`

---

## Authors

**AncientEncoder**

**A. Canto** — InsecureWorld

**V. Nos** — Cryptocalypse

BinSmasher Team
