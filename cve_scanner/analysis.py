#!/usr/bin/env python3
"""
analysis.py — Binary analysis functions for BinSmasher CVE Auditor.

Handles: architecture detection, protection checks, symbol extraction,
FORTIFY detection, rodata analysis, RPATH checks, kernel module analysis,
system version extraction, Linux capabilities, seccomp, and more.
"""

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

from catalog import FORTIFY_MAP, KNOWN_CVES


# ── Shell helper ───────────────────────────────────────────────────────────────

def _run(cmd: list, timeout: int = 20) -> str:
    """Run a command and return its stdout, ignoring errors."""
    try:
        return subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, timeout=timeout
        ).decode(errors="ignore")
    except Exception:
        return ""


# ── File hashing ───────────────────────────────────────────────────────────────

def file_hashes(path: str) -> tuple[str, str]:
    """Return (md5, sha256) hex digests for a file."""
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha.update(chunk)
    return md5.hexdigest(), sha.hexdigest()


# ── Architecture detection ────────────────────────────────────────────────────

def detect_arch(path: str) -> tuple[str, int, str]:
    """Return (arch, bits, platform) for a binary."""
    out    = _run(["file", path]).lower()
    arch   = "unknown"
    bits   = 64
    plat   = "linux"
    if "32-bit"  in out: bits = 32
    if "64-bit"  in out: bits = 64
    if "x86-64"  in out or "x86_64" in out: arch = "x86_64"
    elif "80386" in out or "i386"   in out:  arch = "i386"
    elif "aarch64" in out:                    arch = "aarch64"
    elif "arm"     in out:                    arch = "arm"
    elif "mips"    in out:                    arch = "mips"
    elif "riscv"   in out:                    arch = "riscv"
    if "pe32"    in out: plat = "windows"
    elif "mach-o" in out: plat = "macos"
    elif "elf" not in out: plat = "unknown"
    return arch, bits, plat


# ── Protection detection ───────────────────────────────────────────────────────

def check_protections(path: str, platform: str) -> dict:
    """
    Detect binary protections: NX, PIE, canary, RELRO, FORTIFY,
    shadow stack, stack-executable, ASLR.
    Uses checksec (json) then readelf/nm fallback.
    """
    result = dict(
        nx=False, pie=False, canary=False,
        relro="None", fortify=False,
        shadow_stack=False, stack_exec=True, aslr=False,
    )

    # ── Try checksec JSON ──────────────────────────────────────────────────
    if shutil.which("checksec"):
        cs = _run(["checksec", f"--file={path}", "--output=json"])
        if not cs:
            cs = _run(["checksec", "--file", path, "--output=json"])
        if cs:
            try:
                data  = json.loads(cs)
                entry = data.get(path, next(iter(data.values()), {}))
                def _yn(k): return str(entry.get(k, "no")).lower()

                result["nx"]      = _yn("nx")    in ("yes", "true", "enabled")
                result["canary"]  = _yn("canary") in ("yes", "found", "true")
                result["fortify"] = _yn("fortify_source") in ("yes", "true", "enabled")

                pie_raw = _yn("pie")
                result["pie"]  = pie_raw in ("yes", "true", "pie", "enabled")
                result["aslr"] = result["pie"]

                relro_raw = _yn("relro")
                if   "full"    in relro_raw: result["relro"] = "Full"
                elif "partial" in relro_raw: result["relro"] = "Partial"
                else:                         result["relro"] = "None"

                result["stack_exec"] = not result["nx"]
                return result
            except Exception:
                pass

    # ── readelf / nm fallback ─────────────────────────────────────────────
    ph  = _run(["readelf", "-W", "-l", path])
    hdr = _run(["readelf", "-h", path])
    dyn = _run(["readelf", "-d", path])
    nm  = _run(["nm", "-D", "--undefined-only", path])
    sym = _run(["readelf", "-s", "--wide", path])

    # NX / stack executable
    for line in ph.splitlines():
        if "GNU_STACK" in line:
            result["stack_exec"] = ("RWE" in line or "rwx" in line.lower())
            result["nx"] = not result["stack_exec"]
            break

    # PIE / ASLR
    result["pie"]  = "DYN" in hdr
    result["aslr"] = result["pie"]

    # Stack canary
    result["canary"] = (
        "__stack_chk_fail" in nm or
        "__stack_chk_fail" in sym or
        "__stack_chk_guard" in nm
    )

    # RELRO
    if "GNU_RELRO" in ph and "BIND_NOW" in dyn:
        result["relro"] = "Full"
    elif "GNU_RELRO" in ph:
        result["relro"] = "Partial"

    # FORTIFY
    result["fortify"] = (
        "_chk@" in nm or
        "__sprintf_chk" in sym or
        "__printf_chk" in sym or
        "__read_chk" in sym
    )

    # Shadow stack / CET
    if "GNU_PROPERTY" in ph:
        prop = _run(["readelf", "-n", path])
        result["shadow_stack"] = ("IBT" in prop or "SHSTK" in prop)

    return result


# ── Symbol extraction ─────────────────────────────────────────────────────────

# Module-level disassembly cache keyed by binary path
_DISASM_CACHE: dict = {}

def _get_disasm(path: str) -> str:
    """Return cached objdump output for path, running it once if needed."""
    if path not in _DISASM_CACHE:
        _DISASM_CACHE[path] = _run(["objdump", "-d", "--wide", path])
    return _DISASM_CACHE[path]


def get_imported_symbols(path: str) -> list[str]:
    """Extract all imported (undefined/dynamic) symbols from a binary."""
    syms: set = set()

    # nm dynamic imports
    out = _run(["nm", "-D", "--undefined-only", path])
    for line in out.splitlines():
        parts = line.strip().split()
        if parts:
            syms.add(parts[-1])

    # readelf imports (UND entries)
    out2 = _run(["readelf", "--syms", "--wide", path])
    for line in out2.splitlines():
        if "UND" in line:
            m = re.search(r"\s(\w[\w@.]+)$", line)
            if m:
                syms.add(m.group(1))

    # objdump PLT stubs
    out3 = _run(["objdump", "-d", "--wide", path])
    for m in re.finditer(r"<(\w+)@plt>", out3):
        syms.add(m.group(1))

    return sorted(filter(None, syms))


# ── Strings of interest ───────────────────────────────────────────────────────

def get_strings_of_interest(path: str) -> list[str]:
    """Extract suspicious strings from a binary."""
    patterns = [
        r"/bin/sh", r"/bin/bash", r"/bin/dash",
        r"system\b", r"exec\b",
        r"password", r"passwd", r"secret", r"token",
        r"debug", r"backdoor", r"admin", r"root",
        r"http://", r"https://",
        r"\$\(", r"`",
        r"%s.*%s.*%s", r"%n",
        r"chmod\s+[0-9]", r"sudo\b",
        r"\bAWS\b.*\bkey\b", r"\bAKIA[0-9A-Z]{16}\b",
        r"\bPRIVATE KEY\b", r"\bBEGIN RSA\b",
        r"\bBEGIN PGP\b",
    ]
    raw   = _run(["strings", "-n", "6", path])
    found = []
    for line in raw.splitlines():
        for p in patterns:
            if re.search(p, line, re.IGNORECASE):
                found.append(line.strip()[:120])
                break
    return list(dict.fromkeys(found))[:50]


# ── Vulnerable function address finding ────────────────────────────────────────

def find_vuln_addresses(path: str, fn_name: str) -> list[str]:
    """Find call site addresses for a function in binary disassembly."""
    addrs = []
    out   = _get_disasm(path)
    pat   = re.compile(
        r"^\s*([0-9a-f]+):\s+.*<" + re.escape(fn_name) + r"(?:@plt|@got)?>",
        re.MULTILINE
    )
    for m in pat.finditer(out):
        addrs.append("0x" + m.group(1))
    return addrs[:15]


# ── Disassembly context ────────────────────────────────────────────────────────

def get_disasm_context(path: str, fn: str) -> list[str]:
    """Try radare2, fall back to cached objdump snippet."""
    if shutil.which("r2"):
        cmd = f"aaa; axt sym.imp.{fn}~[0]"
        out = _run(["r2", "-q", "-e", "scr.color=false", "-c", cmd, path], timeout=25)
        lines = [l.strip() for l in out.splitlines()[:10] if l.strip() and not l.startswith("[")]
        if lines:
            return lines

    # Fallback: use cached objdump
    out   = _get_disasm(path)
    pat   = re.compile(r"^\s*([0-9a-f]+):\s+.*<" + re.escape(fn) + r"(?:@plt)?>", re.M)
    lines = []
    for m in pat.finditer(out):
        start  = max(0, out.rfind("\n", 0, m.start()))
        chunk  = out[max(0, start - 600): m.end() + 200]
        for l in chunk.splitlines()[-8:]:
            if l.strip():
                lines.append(l.strip()[:100])
        if lines:
            break
    return lines[:8]


# ── SUID/SGID check ────────────────────────────────────────────────────────────

def suid_sgid_check(path: str) -> tuple[bool, bool, str, str]:
    """Return (is_suid, is_sgid, owner, permissions) for a file."""
    try:
        st     = os.stat(path)
        suid   = bool(st.st_mode & stat.S_ISUID)
        sgid   = bool(st.st_mode & stat.S_ISGID)
        import pwd
        try:    owner = pwd.getpwuid(st.st_uid).pw_name
        except: owner = str(st.st_uid)
        perms  = oct(st.st_mode)[-4:]
        return suid, sgid, owner, perms
    except Exception:
        return False, False, "unknown", "0000"


# ── FORTIFY symbol detection ──────────────────────────────────────────────────

def check_fortify_symbols(path: str) -> set[str]:
    """Return set of base function names that have FORTIFY _chk variants linked."""
    chk_syms: set = set()
    out  = _run(["nm", "-D", path])
    out2 = _run(["readelf", "-s", "--wide", path])
    combined = out + "\n" + out2

    for chk_sym, base_fn in FORTIFY_MAP.items():
        if chk_sym in combined:
            chk_syms.add(base_fn)
    return chk_syms


# ── FORTIFY source level detection ────────────────────────────────────────────

def detect_fortify_level(path: str) -> int:
    """
    Detect the FORTIFY_SOURCE level compiled into the binary.
    Returns 0 (none), 1, or 2.
    Checks for _FORTIFY_SOURCE strings and the number of _chk symbols.
    """
    strings_out = _run(["strings", path])
    # Check for explicit level markers
    if "_FORTIFY_SOURCE=2" in strings_out:
        return 2
    if "_FORTIFY_SOURCE=1" in strings_out:
        return 1
    # Check for _chk symbols — if many are present, likely level 2
    chk_count = sum(1 for sym in FORTIFY_MAP if sym in strings_out)
    if chk_count >= 6:
        return 2
    if chk_count >= 1:
        return 1
    return 0


# ── rodata format string safety analysis ──────────────────────────────────────

def analyze_rodata_format_strings(path: str) -> bool:
    """
    Check if format strings in rodata contain dangerous specifiers (%n, stacked %s).
    Returns True if ALL format strings appear safe (constant format strings only).
    Returns False if any dangerous format specifier pattern is found.
    """
    rodata = _run(["objdump", "-s", "-j", ".rodata", path])
    if not rodata:
        rodata = _run(["objdump", "-s", "-j", ".data", path])
    if not rodata:
        return False  # Can't analyze — assume unsafe

    # Extract readable strings from hex dump
    strings = re.findall(r'[a-zA-Z0-9_\-\./ ]{%4,}', rodata)

    has_pct_n = False
    has_stacked_s = False

    for s in strings:
        if re.search(r'%[^%]*n', s):
            has_pct_n = True
        if re.search(r'%s.*%s.*%s', s):
            has_stacked_s = True

    return not (has_pct_n or has_stacked_s)


# ── RPATH / RUNPATH analysis ─────────────────────────────────────────────────

def check_rpath(path: str) -> list[str]:
    """Check for insecure RPATH/RUNPATH entries."""
    findings = []
    dyn = _run(["readelf", "-d", path])

    for line in dyn.splitlines():
        if "RPATH" in line or "RUNPATH" in line:
            m = re.search(r'\(.*:\s*(.+)\)', line)
            if m:
                rpath_val = m.group(1).strip()
                if rpath_val == "":
                    findings.append(f"Empty RPATH — may inherit LD_LIBRARY_PATH")
                elif rpath_val.startswith("/tmp") or rpath_val.startswith("/var/tmp"):
                    findings.append(f"RPATH points to world-writable dir: {rpath_val}")
                elif rpath_val == "." or rpath_val.startswith("./"):
                    findings.append(f"Relative RPATH (cwd-dependent): {rpath_val}")
                elif rpath_val.startswith("/home") or not rpath_val.startswith("/"):
                    findings.append(f"Suspicious RPATH: {rpath_val}")
                else:
                    findings.append(f"RPATH set: {rpath_val}")
    return findings


# ── Kernel module analysis ────────────────────────────────────────────────────

def is_kernel_module(path: str) -> bool:
    """Check if an ELF binary is a kernel module (.ko)."""
    out = _run(["readelf", "-S", path])
    return ".modinfo" in out or ".gnu.linkonce.this_module" in out


def extract_modinfo(path: str) -> dict:
    """Extract kernel module metadata from .modinfo section."""
    info = {}
    out = _run(["modinfo", path])
    if not out:
        raw = _run(["objdump", "-s", "-j", ".modinfo", path])
        text = re.sub(r'[^[:print:]]', '', raw)
        for m in re.finditer(r'(\w+)=(\S+)', text):
            info[m.group(1)] = m.group(2)

    for line in out.splitlines():
        m = re.match(r'^(\w+):\s+(.+)$', line.strip())
        if m:
            info[m.group(1).lower()] = m.group(2).strip()
    return info


# ── System version / known CVE extraction ─────────────────────────────────────

def get_system_versions() -> dict:
    """Extract kernel, glibc, and distribution versions for CVE matching."""
    versions = {}

    # Kernel version
    uname_out = _run(["uname", "-r"])
    if uname_out:
        versions["kernel"] = uname_out.strip()

    # glibc version from ldd
    ldd_out = _run(["ldd", "--version"])
    m = re.search(r'(\d+\.\d+(?:\.\d+)?)', ldd_out)
    if m:
        versions["glibc"] = m.group(1)

    # Distribution
    for rel_file in ["/etc/os-release", "/usr/lib/os-release"]:
        if os.path.isfile(rel_file):
            try:
                content = Path(rel_file).read_text()
                for key in ["VERSION_ID", "VERSION"]:
                    kv = re.search(rf'^{key}="?([^"\n]+)"?', content, re.M)
                    if kv:
                        versions[f"dist_{key.lower()}"] = kv.group(1)
            except Exception:
                pass

    # ASLR system-wide status
    try:
        aslr = Path("/proc/sys/kernel/randomize_va_space").read_text().strip()
        versions["aslr_system"] = aslr  # 0=off, 1=conservative, 2=full
    except Exception:
        versions["aslr_system"] = "unknown"

    return versions


def match_version_cves(component: str, version: str) -> list[dict]:
    """Match a component version against known CVE database."""
    hits = []
    cves = KNOWN_CVES.get(component, [])
    if not version:
        return hits
    try:
        from packaging.version import Version as V
        v_installed = V(version)
    except Exception:
        # Fallback: simple numeric comparison
        def V(x):
            parts = x.split(".")
            return [int(p) for p in parts if p.isdigit()]
        v_installed = V(version)

    for cve in cves:
        for ver_op, *ver_vals in cve.get("ver_range", []):
            for ver_val in ver_vals if ver_vals else [ver_op]:
                try:
                    v_threshold = V(ver_val) if not isinstance(V("1.0"), list) else V(ver_val)
                    if ver_op == "<" and v_installed < v_threshold:
                        hits.append(cve)
                except Exception:
                    pass
    return hits


# ── Linux capabilities check ──────────────────────────────────────────────────

def check_linux_capabilities(path: str) -> tuple[bool, list[str]]:
    """
    Check for Linux capabilities set on a binary using getcap.
    Returns (has_caps, list_of_capability_strings).
    """
    caps: list[str] = []
    out = _run(["getcap", path])
    if not out:
        return False, caps
    # Typical output: "/path/to/binary = cap_setuid,cap_net_raw+eip"
    m = re.search(r'=\s*(.+)', out)
    if m:
        cap_str = m.group(1).strip()
        # Split capabilities and clean
        for cap in re.split(r'[,+\s]+', cap_str):
            cap = cap.strip().lower()
            if cap and cap != "empty":
                caps.append(cap)
    return bool(caps), caps


# ── Stack clash protection detection ──────────────────────────────────────────

def check_stack_clash_protection(path: str) -> bool:
    """
    Check if the binary was compiled with -fstack-clash-protection.
    Detects via readelf notes (GCC stack clash probe markers).
    """
    # Check for -fstack-clash-protection compiled binaries
    # GCC adds .note.gnu.property with stack clash probe markers
    out = _run(["readelf", "-n", path])
    if "GNU_PROPERTY" in out:
        return True
    # Check for probe-loop patterns in disassembly (xor + probe sequence)
    disasm = _get_disasm(path)
    # Stack clash protection generates "or" instructions for probing
    # This is a heuristic — presence of stack probing instructions
    probe_patterns = re.findall(r'\bor\b.*%[er]sp', disasm)
    return len(probe_patterns) > 0


# ── Symbol version detection ───────────────────────────────────────────────────

def detect_symbol_versions(path: str) -> dict:
    """
    Detect GLIBC and other library version requirements from symbol versioning.
    Returns dict like {"GLIBC_2.34": ["memcpy", "strcpy"], "GLIBC_2.17": ["clock_gettime"]}.
    """
    versions: dict = {}
    out = _run(["readelf", "-V", path])
    if not out:
        return versions

    current_version = None
    for line in out.splitlines():
        # Parse version definition sections
        m = re.match(r'\s*\d+:\s+\w+\s+.*\((GLIBC_\d+[\.\d]*|.*?\d+[\.\d]*)\)', line)
        if m:
            ver = m.group(1)
            versions.setdefault(ver, [])
        # Parse symbol version requirements
        m2 = re.match(r'\s*(\S+)\s+.*\((GLIBC_\d+[\.\d]*)\)', line)
        if m2:
            sym = m2.group(1)
            ver = m2.group(2)
            versions.setdefault(ver, [])
            if sym and sym not in versions[ver]:
                versions[ver].append(sym)

    # Also try objdump -T for versioned symbols
    out2 = _run(["objdump", "-T", path])
    for line in out2.splitlines():
        m = re.search(r'\((GLIBC_\d+[\.\d]*)\)', line)
        if m:
            ver = m.group(1)
            versions.setdefault(ver, [])

    return versions


# ── Seccomp status check ──────────────────────────────────────────────────────

def check_seccomp() -> str:
    """
    Check system-wide seccomp status.
    Returns "strict", "filter", "disabled", or "unknown".
    """
    # Check /proc/sys/kernel/seccomp if available
    try:
        seccomp = Path("/proc/sys/kernel/seccomp").read_text().strip()
        if seccomp == "2":
            return "strict"
        elif seccomp == "1":
            return "filter"
        elif seccomp == "0":
            return "disabled"
    except Exception:
        pass

    # Check if seccomp is compiled in kernel
    config = _run(["grep", "-c", "CONFIG_SECCOMP=y", "/boot/config-" + _run(["uname", "-r"]).strip()])
    if config.strip().isdigit() and int(config.strip()) > 0:
        return "filter"

    return "unknown"


# ── PLT/GOT analysis ─────────────────────────────────────────────────────────

def analyze_plt_got(path: str) -> dict:
    """
    Analyze PLT/GOT entries for potential hijacking vectors.
    Returns dict with counts and lazy binding status.
    """
    result = {
        "plt_count": 0,
        "got_count": 0,
        "lazy_binding": False,
        "full_relro": False,
    }

    # PLT entries
    plt_out = _run(["objdump", "-d", "-j", ".plt", path])
    result["plt_count"] = len(re.findall(r'<.*@plt>:', plt_out))

    # GOT entries
    got_out = _run(["readelf", "-r", path])
    result["got_count"] = len(re.findall(r'GLOB_DAT|JUMP_SLOT', got_out))

    # Check for BIND_NOW (no lazy binding)
    dyn_out = _run(["readelf", "-d", path])
    result["lazy_binding"] = "BIND_NOW" not in dyn_out and "FLAGS_1" not in dyn_out
    result["full_relro"] = "BIND_NOW" in dyn_out

    return result


# ── Dead code detection (PLT-only imports with no call sites) ──────────────────

def detect_dead_imports(path: str, imported_symbols: list[str]) -> set[str]:
    """
    Detect imported symbols that appear in PLT but are never referenced
    from .text sections. These are likely dead code / dependency-only imports
    and should be deprioritized to reduce false positives.
    """
    disasm = _get_disasm(path)

    # Find the .text section boundaries
    text_start = None
    text_end = None
    for line in disasm.splitlines():
        m = re.match(r'^\s*([0-9a-f]+)\s+<\.text>', line)
        if m and text_start is None:
            text_start = int(m.group(1), 16)
        # After .text section, next section starts

    live_symbols: set[str] = set()

    # Check which imported symbols have call references in .text
    for sym in imported_symbols:
        canonical = re.split(r"[@\+]", sym)[0].strip("_ \t").lower()
        # Look for call/jmp instructions referencing this symbol
        call_pat = re.compile(
            r'call[q]?\s+[0-9a-f]+\s+<' + re.escape(sym.split('@')[0]) + r'@plt>',
            re.IGNORECASE
        )
        if call_pat.search(disasm):
            live_symbols.add(canonical)

    # Symbols in imported_symbols but not in live_symbols are potentially dead
    all_canonical = {re.split(r"[@\+]", s)[0].strip("_ \t").lower() for s in imported_symbols}
    return all_canonical - live_symbols