#!/usr/bin/env python3
"""
cve_scan.py  v3  —  BinSmasher CVE Auditor
═══════════════════════════════════════════
Static-only binary vulnerability scanner for responsible disclosure.

Outputs
───────
  • cve_reports/
      ├── cve_audit_<ts>.html           — Full interactive report (search + filters)
      ├── cve_audit_all_<ts>.json       — All findings
      ├── cve_audit_confirmed_high_<ts>.json  — CONFIRMED + High/Critical only
      ├── cve_audit_probable_high_<ts>.json   — PROBABLE  + High/Critical only
      └── cve_mitre_<ts>.md             — MITRE CVE submission templates (High/Critical + CONFIRMED)

Usage
─────
  python3 cve_scan.py [paths…] [options]

  -o / --output-dir    Output directory (default: ./cve_reports)
  --threshold          Minimum risk score to include binary (default: 50)
  -v / --verbose       Debug logging
  --single BINARY      Audit a single binary
  --no-taint           Skip taint analysis
  --confidence         Minimum confidence filter: CONFIRMED|PROBABLE|UNCONFIRMED
"""

# ── stdlib ───────────────────────────────────────────────────────────────────
import os, re, sys, json, stat, time, shutil, hashlib, logging, argparse, subprocess
from pathlib import Path
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

# ── Taint analysis ────────────────────────────────────────────────────────────
try:
    from taint_analyzer import enrich_vuln_points
    HAS_TAINT = True
except ImportError:
    HAS_TAINT = False

# ── Rich UI ───────────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.logging import RichHandler
    from rich.panel import Panel
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console(highlight=False) if RICH else None

def rprint(msg: str) -> None:
    if RICH:
        console.print(msg)
    else:
        print(re.sub(r"\[/?[a-zA-Z_ ]+\]", "", msg))

# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class VulnPoint:
    vuln_id:        str
    category:       str
    cwe:            str
    function_name:  str
    location:       str
    description:    str
    severity:       str
    cvss_base:      float
    evidence:       list  = field(default_factory=list)
    mitigation:     str   = ""
    affected_binary: str  = ""
    binary_hash:    str   = ""
    confidence:     str   = "PROBABLE"
    call_sites:     list  = field(default_factory=list)


@dataclass
class BinaryReport:
    binary_path:      str
    binary_name:      str
    binary_hash_md5:  str
    binary_hash_sha256: str
    file_size:        int
    arch:             str
    bits:             int
    platform:         str
    is_suid:          bool
    is_sgid:          bool
    owner:            str
    permissions:      str
    # Protections
    nx:               bool
    pie:              bool
    canary:           bool
    relro:            str
    fortify:          bool
    shadow_stack:     bool
    stack_exec:       bool
    aslr:             bool
    # Findings
    vuln_points:      list  = field(default_factory=list)
    imported_libs:    list  = field(default_factory=list)
    strings_of_interest: list = field(default_factory=list)
    risk_score:       int   = 0
    audit_timestamp:  str   = ""


# ── Vulnerability catalogue ───────────────────────────────────────────────────

VULN_CATALOG = {
    # Unbounded / dangerous input
    "gets":     ("BufferOverflow",   "CWE-120", "Unbounded stack buffer overflow via gets()",                       9.8),
    "strcpy":   ("BufferOverflow",   "CWE-120", "Unchecked string copy — potential stack overflow",                 8.1),
    "strcat":   ("BufferOverflow",   "CWE-120", "Unchecked string concatenation — heap/stack overflow",             7.5),
    "sprintf":  ("BufferOverflow",   "CWE-134", "Unchecked sprintf — format/buffer overflow",                       7.5),
    "vsprintf": ("BufferOverflow",   "CWE-134", "Unchecked vsprintf — format/buffer overflow",                      7.5),
    "scanf":    ("BufferOverflow",   "CWE-120", "Unchecked scanf input — stack overflow",                           8.1),
    "sscanf":   ("BufferOverflow",   "CWE-120", "Unchecked sscanf — buffer overflow",                               7.5),
    "read":     ("BufferOverflow",   "CWE-122", "read() without size validation — heap/stack overflow",             7.5),
    "fread":    ("BufferOverflow",   "CWE-122", "fread() without bounds check — heap overflow",                     7.2),
    "recv":     ("BufferOverflow",   "CWE-122", "Network recv() without size validation — heap overflow",           9.1),
    "memcpy":   ("BufferOverflow",   "CWE-122", "memcpy without destination size check",                            7.5),
    "memmove":  ("BufferOverflow",   "CWE-122", "memmove without destination size check",                           7.2),
    # Off-by-one
    "strncpy":  ("OffByOne",         "CWE-193", "strncpy may not null-terminate — off-by-one",                      6.5),
    "strncat":  ("OffByOne",         "CWE-193", "strncat misuse — off-by-one on null terminator",                   6.5),
    # Format string
    "printf":   ("FormatString",     "CWE-134", "Uncontrolled format string — memory read/write primitive",         9.8),
    "fprintf":  ("FormatString",     "CWE-134", "Uncontrolled fprintf format string",                               8.5),
    "snprintf": ("FormatString",     "CWE-134", "Potential format string if format arg is user-controlled",         7.5),
    "dprintf":  ("FormatString",     "CWE-134", "dprintf format string — potential arbitrary write",                8.5),
    "syslog":   ("FormatString",     "CWE-134", "syslog format string — potential log injection / write",           7.2),
    # Memory management
    "malloc":   ("MemoryMgmt",       "CWE-789", "malloc result unchecked — null dereference / heap misuse",        5.5),
    "free":     ("UseAfterFree",     "CWE-416", "free() — potential double-free or use-after-free",                8.1),
    "realloc":  ("MemoryMgmt",       "CWE-789", "realloc — size confusion / heap overflow possible",               7.2),
    "calloc":   ("MemoryMgmt",       "CWE-789", "calloc — integer overflow in size × count",                       7.2),
    # Command injection
    "system":   ("CommandInjection", "CWE-78",  "system() call — OS command injection if input reaches it",        9.8),
    "popen":    ("CommandInjection", "CWE-78",  "popen() — OS command injection vector",                           9.8),
    "execve":   ("CommandInjection", "CWE-78",  "execve() — arbitrary code execution if args are user-tainted",    9.8),
    "execl":    ("CommandInjection", "CWE-78",  "execl() — command injection vector",                              9.8),
    "execlp":   ("CommandInjection", "CWE-78",  "execlp() — PATH injection possible",                              9.1),
    # Dynamic loading
    "dlopen":   ("DynamicLoad",      "CWE-114", "dlopen() — dynamic library injection",                            8.5),
    # Privilege
    "setuid":   ("PrivEsc",          "CWE-250",
               "setuid() — privilege manipulation. NOTE: may be legitimate "
               "privilege dropping (setuid(nobody)) — verify the argument. "
               "Only a vulnerability if called with uid=0 or attacker-controlled arg.",
               8.8),
    "setgid":   ("PrivEsc",          "CWE-250",
               "setgid() — privilege manipulation. NOTE: may be legitimate "
               "privilege dropping — verify the argument.",
               8.5),
}

SEVERITY_THRESHOLDS = [
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.0, "Low"),
]

def cvss_to_severity(score: float) -> str:
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "Informational"

def adjust_cvss(base: float, nx: bool, pie: bool, canary: bool, is_suid: bool) -> float:
    score = base
    if nx:      score -= 0.8
    if pie:     score -= 0.6
    if canary:  score -= 0.5
    if not is_suid: score -= 0.3
    return round(max(score, 1.0), 1)


# ── Static analysis helpers ───────────────────────────────────────────────────

def _run(cmd: list, timeout: int = 20) -> str:
    try:
        return subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, timeout=timeout
        ).decode(errors="ignore")
    except Exception:
        return ""

def file_hashes(path: str) -> tuple[str, str]:
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk); sha.update(chunk)
    return md5.hexdigest(), sha.hexdigest()

def detect_arch(path: str) -> tuple[str, int, str]:
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


def check_protections(path: str, platform: str) -> dict:
    """
    Returns a dict with keys:
      nx, pie, canary, relro, fortify, shadow_stack, stack_exec, aslr
    Uses checksec (json), then readelf/nm fallback — matches analyzer.py logic.
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

                # stack_exec
                stack_raw = _yn("nx")
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
    # GNU_RELRO appears in PROGRAM HEADERS (readelf -l → stored in `ph`),
    # NOT in the dynamic section (readelf -d → stored in `dyn`).
    # Full RELRO = GNU_RELRO in program headers AND BIND_NOW in dynamic section.
    # Partial RELRO = GNU_RELRO in program headers only.
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


def get_imported_symbols(path: str) -> list[str]:
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


def get_strings_of_interest(path: str) -> list[str]:
    patterns = [
        r"/bin/sh", r"/bin/bash", r"/bin/dash",
        r"system\b", r"exec\b",
        r"password", r"passwd", r"secret", r"token",
        r"debug", r"backdoor", r"admin", r"root",
        r"http://", r"https://",
        r"\$\(", r"`",
        r"%s.*%s.*%s", r"%n",
        r"chmod\s+[0-9]", r"sudo\b",
    ]
    raw   = _run(["strings", "-n", "6", path])
    found = []
    for line in raw.splitlines():
        for p in patterns:
            if re.search(p, line, re.IGNORECASE):
                found.append(line.strip()[:120])
                break
    return list(dict.fromkeys(found))[:50]


# Module-level disassembly cache keyed by binary path — avoids repeated objdump calls
_DISASM_CACHE: dict = {}

def _get_disasm(path: str) -> str:
    """Return cached objdump output for path, running it once if needed."""
    if path not in _DISASM_CACHE:
        _DISASM_CACHE[path] = _run(["objdump", "-d", "--wide", path])
    return _DISASM_CACHE[path]


def find_vuln_addresses(path: str, fn_name: str) -> list[str]:
    addrs = []
    out   = _get_disasm(path)
    pat   = re.compile(
        r"^\s*([0-9a-f]+):\s+.*<" + re.escape(fn_name) + r"(?:@plt|@got)?>",
        re.MULTILINE
    )
    for m in pat.finditer(out):
        addrs.append("0x" + m.group(1))
    return addrs[:15]


def suid_sgid_check(path: str) -> tuple[bool, bool, str, str]:
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


def get_disasm_context(path: str, fn: str) -> list[str]:
    """Try radare2, fall back to cached objdump snippet."""
    if shutil.which("r2"):
        cmd = f"aaa; axt sym.imp.{fn}~[0]"
        out = _run(["r2", "-q", "-e", "scr.color=false", "-c", cmd, path], timeout=25)
        lines = [l.strip() for l in out.splitlines()[:10] if l.strip() and not l.startswith("[")]
        if lines:
            return lines

    # Fallback: use cached objdump (already run by find_vuln_addresses)
    out   = _get_disasm(path)
    pat   = re.compile(r"^\s*([0-9a-f]+):\s+.*<" + re.escape(fn) + r"(?:@plt)?>", re.M)
    lines = []
    for m in pat.finditer(out):
        # grab 5 lines of context before call
        start  = max(0, out.rfind("\n", 0, m.start()))
        chunk  = out[max(0, start - 600): m.end() + 200]
        for l in chunk.splitlines()[-8:]:
            if l.strip():
                lines.append(l.strip()[:100])
        if lines:
            break
    return lines[:8]


def _ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


# ── Mitigation hints ──────────────────────────────────────────────────────────

MITIGATIONS = {
    "gets":     "Replace gets() with fgets(buf, sizeof(buf), stdin).",
    "strcpy":   "Replace strcpy() with strlcpy() or snprintf().",
    "strcat":   "Replace strcat() with strlcat().",
    "sprintf":  "Replace sprintf() with snprintf() with explicit size.",
    "vsprintf": "Replace vsprintf() with vsnprintf().",
    "scanf":    "Use scanf(\"%Ns\", buf) with explicit field width N.",
    "printf":   "Always pass a literal format string: printf(\"%s\", user_input).",
    "system":   "Avoid system(). Use execve() with a fixed path and validated args.",
    "popen":    "Validate and sanitise input before passing to popen().",
    "execve":   "Validate all arguments; avoid user-controlled path components.",
    "recv":     "Always pass sizeof(buf) as the length argument to recv().",
    "read":     "Validate buffer size before calling read().",
    "fread":    "Verify element count × size does not exceed destination buffer.",
    "memcpy":   "Check destination size before calling memcpy().",
    "free":     "Set pointer to NULL after free(); audit for double-free / UAF.",
    "malloc":   "Always check malloc() return value for NULL before use.",
}

def _mitigation(fn: str, prot: dict) -> str:
    base  = MITIGATIONS.get(fn, f"Audit all uses of {fn}() and validate inputs.")
    flags = []
    if not prot.get("nx"):     flags.append("enable NX/DEP (-Wl,-z,noexecstack)")
    if not prot.get("pie"):    flags.append("compile with -fPIE -pie")
    if not prot.get("canary"): flags.append("enable stack canaries (-fstack-protector-strong)")
    if prot.get("relro") == "None": flags.append("enable RELRO (-Wl,-z,relro,-z,now)")
    if flags:
        base += f" Compiler hardening: {', '.join(flags)}."
    return base


# ── Core auditor ──────────────────────────────────────────────────────────────

class CVEAuditor:

    def __init__(
        self,
        search_paths:   list,
        output_dir:     str,
        threshold_score: int,
        verbose:        bool,
        taint:          bool = True,
        min_confidence: str  = "PROBABLE",
    ) -> None:
        self.search_paths   = search_paths
        self.output_dir     = Path(output_dir)
        self.threshold      = threshold_score
        self.verbose        = verbose
        self.taint          = taint and HAS_TAINT
        self.min_confidence = min_confidence
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._counter       = 0

        level   = logging.DEBUG if verbose else logging.INFO
        handlers = (
            [RichHandler(console=console, markup=True, rich_tracebacks=False, show_path=False)]
            if RICH else [logging.StreamHandler()]
        )
        logging.basicConfig(level=level, handlers=handlers, format="%(message)s")
        self.log = logging.getLogger("cve_auditor")

    # ── Internal helpers ──────────────────────────────────────────────────

    def _is_elf(self, path: str) -> bool:
        try:
            if not os.path.isfile(path) or os.path.islink(path):
                return False
            with open(path, "rb") as f:
                return f.read(4) == b"\x7fELF"
        except (PermissionError, OSError):
            return False

    def _next_id(self) -> str:
        self._counter += 1
        return f"AUDIT-{self._counter:04d}"

    # ── Binary audit ──────────────────────────────────────────────────────

    def audit_binary(self, path: str) -> Optional[BinaryReport]:
        try:
            return self._audit(path)
        except Exception as exc:
            self.log.debug(f"audit failed {path}: {exc}")
            return None

    def _audit(self, path: str) -> Optional[BinaryReport]:
        arch, bits, platform = detect_arch(path)
        md5h, sha256h        = file_hashes(path)
        st                   = os.stat(path)
        suid, sgid, owner, perms = suid_sgid_check(path)
        prot = check_protections(path, platform)

        report = BinaryReport(
            binary_path=path,
            binary_name=os.path.basename(path),
            binary_hash_md5=md5h,
            binary_hash_sha256=sha256h,
            file_size=st.st_size,
            arch=arch, bits=bits, platform=platform,
            is_suid=suid, is_sgid=sgid,
            owner=owner, permissions=perms,
            nx=prot["nx"], pie=prot["pie"],
            canary=prot["canary"], relro=prot["relro"],
            fortify=prot["fortify"], shadow_stack=prot["shadow_stack"],
            stack_exec=prot["stack_exec"], aslr=prot["aslr"],
            imported_libs=get_imported_symbols(path),
            strings_of_interest=get_strings_of_interest(path),
            audit_timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # ── Match imported symbols against catalogue ──────────────────
        seen_canonical: set = set()
        for sym in report.imported_libs:
            # Normalise: strip version / decoration  e.g.  gets@GLIBC_2.2.5 → gets
            canonical = re.split(r"[@\+]", sym)[0].strip("_ \t").lower()
            if canonical not in VULN_CATALOG:
                continue
            if canonical in seen_canonical:
                continue   # deduplicate
            seen_canonical.add(canonical)

            category, cwe, desc, base_cvss = VULN_CATALOG[canonical]
            adjusted  = adjust_cvss(base_cvss, prot["nx"], prot["pie"], prot["canary"], suid)
            sites     = find_vuln_addresses(path, canonical)
            evidence  = [f"Imported symbol: {sym}"]
            if sites:
                evidence.append(f"Call sites: {', '.join(sites)}")

            if shutil.which("r2") or True:   # always try objdump context
                ctx = get_disasm_context(path, canonical)
                if ctx:
                    evidence += [f"Disasm context: {l}" for l in ctx]

            vp = VulnPoint(
                vuln_id=self._next_id(),
                category=category,
                cwe=cwe,
                function_name=canonical,
                location=sites[0] if sites else "dynamic import",
                description=desc,
                severity=cvss_to_severity(adjusted),
                cvss_base=adjusted,
                evidence=evidence,
                mitigation=_mitigation(canonical, prot),
                affected_binary=path,
                binary_hash=sha256h,
                call_sites=sites,
            )
            report.vuln_points.append(vp)

        # ── SUID/SGID privilege escalation ────────────────────────────
        if (suid or sgid) and report.vuln_points:
            suid_vp = VulnPoint(
                vuln_id=self._next_id(),
                category="PrivilegeEscalation",
                cwe="CWE-250",
                function_name="setuid/suid_bit",
                location=path,
                description=(
                    f"Binary has SUID{'G' if sgid else ''} bit set AND "
                    f"dangerous functions: "
                    f"{[v.function_name for v in report.vuln_points]}"
                ),
                severity="Critical",
                cvss_base=9.3,
                evidence=[
                    f"SUID: {suid}, SGID: {sgid}",
                    f"Owner: {owner}, Permissions: {perms}",
                    f"Dangerous imports: {[v.function_name for v in report.vuln_points]}",
                ],
                mitigation="Remove SUID/SGID bit unless strictly necessary.",
                affected_binary=path,
                binary_hash=sha256h,
                confidence="CONFIRMED",
            )
            report.vuln_points.insert(0, suid_vp)

        # ── Taint analysis ────────────────────────────────────────────
        if self.taint and report.vuln_points:
            self.log.debug(f"  → Running taint analysis on {path}…")
            report.vuln_points = enrich_vuln_points(
                report.vuln_points, path, arch, bits,
                min_confidence=self.min_confidence,
            )

        # ── Risk score ────────────────────────────────────────────────
        if report.vuln_points:
            score  = sum(int(v.cvss_base * 10) for v in report.vuln_points)
            score += 200 if suid else 0
            score += 100 if not prot["nx"] else 0
            score += 80  if not prot["pie"] else 0
            score += 60  if not prot["canary"] else 0
            score += 40  if prot["relro"] == "None" else 0
            report.risk_score = score

        return report

    # ── Scanning ──────────────────────────────────────────────────────────

    def scan(self) -> list:
        binaries = []
        for sp in self.search_paths:
            if not os.path.exists(sp):
                self.log.warning(f"Path does not exist: {sp}")
                continue
            if os.path.isfile(sp) and self._is_elf(sp):
                binaries.append(sp)
                continue
            for root, dirs, files in os.walk(sp, followlinks=False):
                # Skip irrelevant dirs
                dirs[:] = [d for d in dirs
                           if d not in ("proc", "sys", "dev", "run")]
                for name in files:
                    fp = os.path.join(root, name)
                    if self._is_elf(fp):
                        binaries.append(fp)

        # Deduplicate
        binaries = sorted(set(binaries))
        self.log.info(f"Found {len(binaries)} ELF binaries to audit")

        reports = []
        total   = len(binaries)
        for i, bp in enumerate(binaries, 1):
            rprint(f"[dim]({i}/{total})[/] Auditing [cyan]{bp}[/] …")
            report = self.audit_binary(bp)
            if report and report.vuln_points and report.risk_score >= self.threshold:
                reports.append(report)
                self._print_table(report)

        return reports

    # ── Terminal table ────────────────────────────────────────────────────

    def _print_table(self, r: BinaryReport) -> None:
        if not RICH:
            print(f"\n{'='*70}")
            print(f"{r.binary_path}  Score: {r.risk_score}")
            print(f"  NX:{r.nx} PIE:{r.pie} Canary:{r.canary} RELRO:{r.relro}")
            print(f"{'='*70}")
            for v in r.vuln_points:
                print(f"  [{v.confidence:12}] {v.function_name:12} {v.cwe:10} {v.severity:8} CVSS:{v.cvss_base}")
            return

        t = Table(
            title=f"[bold red]{r.binary_name}[/]  Risk:[yellow]{r.risk_score}[/]"
                  f"  NX:[{'green' if r.nx else 'red'}]{r.nx}[/]"
                  f"  PIE:[{'green' if r.pie else 'red'}]{r.pie}[/]"
                  f"  Canary:[{'green' if r.canary else 'red'}]{r.canary}[/]"
                  f"  RELRO:[{'green' if r.relro=='Full' else 'yellow' if r.relro=='Partial' else 'red'}]{r.relro}[/]",
            show_lines=True,
            box=box.ROUNDED,
        )
        t.add_column("ID",           style="dim",     width=11)
        t.add_column("Confidence",   style="bold",    width=13)
        t.add_column("Category",     style="cyan",    width=20)
        t.add_column("CWE",          style="magenta", width=10)
        t.add_column("Function",                      width=12)
        t.add_column("Location",     style="dim",     width=14)
        t.add_column("CVSS",         style="yellow",  width=6)
        t.add_column("Severity",                      width=10)

        SEV_COLOR  = {"Critical": "bold red", "High": "red", "Medium": "yellow", "Low": "green"}
        CONF_COLOR = {"CONFIRMED": "bold green", "PROBABLE": "yellow", "UNCONFIRMED": "dim"}

        for v in r.vuln_points:
            cc = CONF_COLOR.get(v.confidence, "white")
            sc = SEV_COLOR.get(v.severity,    "white")
            t.add_row(
                v.vuln_id,
                f"[{cc}]{v.confidence}[/]",
                v.category,
                v.cwe,
                v.function_name,
                v.location[:13],
                str(v.cvss_base),
                f"[{sc}]{v.severity}[/]",
            )
        console.print(t)

    # ── Export: JSON (all) ────────────────────────────────────────────────

    def export_json_all(self, reports: list) -> Path:
        path = self.output_dir / f"cve_audit_all_{_ts()}.json"
        path.write_text(json.dumps([asdict(r) for r in reports], indent=2))
        self.log.info(f"JSON (all)      → {path}")
        return path

    # ── Export: JSON (CONFIRMED + High/Critical) ──────────────────────────

    def export_json_confirmed_high(self, reports: list) -> Path:
        out = []
        for r in reports:
            vps = [
                v for v in r.vuln_points
                if v.confidence == "CONFIRMED"
                and v.severity in ("Critical", "High")
            ]
            if vps:
                d = asdict(r)
                d["vuln_points"] = [asdict(v) for v in vps]
                out.append(d)
        path = self.output_dir / f"cve_audit_confirmed_high_{_ts()}.json"
        path.write_text(json.dumps(out, indent=2))
        self.log.info(f"JSON (confirmed+high) → {path}")
        return path

    # ── Export: JSON (PROBABLE + High/Critical) ───────────────────────────

    def export_json_probable_high(self, reports: list) -> Path:
        out = []
        for r in reports:
            vps = [
                v for v in r.vuln_points
                if v.confidence == "PROBABLE"
                and v.severity in ("Critical", "High")
            ]
            if vps:
                d = asdict(r)
                d["vuln_points"] = [asdict(v) for v in vps]
                out.append(d)
        path = self.output_dir / f"cve_audit_probable_high_{_ts()}.json"
        path.write_text(json.dumps(out, indent=2))
        self.log.info(f"JSON (probable+high)  → {path}")
        return path

    # ── Export: MITRE CVE submission templates ────────────────────────────

    def export_mitre_templates(self, reports: list) -> Path:
        """
        Generates MITRE CVE 5.0 JSON submission templates for every
        CONFIRMED + High/Critical finding.
        """
        entries = []
        ts_now  = datetime.now(timezone.utc).isoformat()

        for r in reports:
            for v in r.vuln_points:
                if v.confidence != "CONFIRMED":
                    continue
                if v.severity not in ("Critical", "High"):
                    continue

                # Build CVE JSON 5.0 skeleton
                entry = {
                    "dataType":    "CVE_RECORD",
                    "dataVersion": "5.0",
                    "cveMetadata": {
                        "cveId":          f"CVE-PENDING-{v.vuln_id}",
                        "assignerOrgId":  "YOUR-ORG-UUID",
                        "assignerShortName": "YourOrg",
                        "state":          "PUBLISHED",
                        "dateReserved":   ts_now,
                        "datePublished":  ts_now,
                        "dateUpdated":    ts_now,
                    },
                    "containers": {
                        "cna": {
                            "providerMetadata": {
                                "orgId":       "YOUR-ORG-UUID",
                                "shortName":   "YourOrg",
                                "dateUpdated": ts_now,
                            },
                            "title": (
                                f"{v.category} in {r.binary_name} via {v.function_name}()"
                            ),
                            "descriptions": [
                                {
                                    "lang":  "en",
                                    "value": (
                                        f"{v.description}. "
                                        f"Found in binary '{r.binary_name}' "
                                        f"(SHA-256: {r.binary_hash_sha256}) "
                                        f"at address {v.location}. "
                                        f"Binary protections: "
                                        f"NX={r.nx}, PIE={r.pie}, "
                                        f"Canary={r.canary}, RELRO={r.relro}."
                                    ),
                                }
                            ],
                            "affected": [
                                {
                                    "vendor":    "UNKNOWN — to be identified",
                                    "product":   r.binary_name,
                                    "versions":  [
                                        {
                                            "version":       "unknown",
                                            "status":        "affected",
                                            "versionType":   "custom",
                                        }
                                    ],
                                    "defaultStatus": "affected",
                                }
                            ],
                            "problemTypes": [
                                {
                                    "descriptions": [
                                        {
                                            "type":        "CWE",
                                            "cweId":       v.cwe,
                                            "lang":        "en",
                                            "description": v.description,
                                        }
                                    ]
                                }
                            ],
                            "metrics": [
                                {
                                    "format":   "CVSS",
                                    "scenarios": [
                                        {"lang": "en", "value": "GENERAL"}
                                    ],
                                    "cvssV3_1": {
                                        "version":             "3.1",
                                        "baseScore":           v.cvss_base,
                                        "baseSeverity":        v.severity.upper(),
                                        "vectorString":        _cvss_vector(v),
                                        "attackVector":        "NETWORK" if v.category in ("BufferOverflow","CommandInjection","FormatString") else "LOCAL",
                                        "attackComplexity":    "LOW",
                                        "privilegesRequired":  "NONE",
                                        "userInteraction":     "NONE",
                                        "scope":               "UNCHANGED",
                                        "confidentialityImpact": "HIGH",
                                        "integrityImpact":     "HIGH",
                                        "availabilityImpact":  "HIGH",
                                    },
                                }
                            ],
                            "references": [
                                {
                                    "url":  "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-PENDING",
                                    "name": "MITRE CVE Pending",
                                    "tags": ["vendor-advisory"],
                                },
                                {
                                    "url":  f"https://cwe.mitre.org/data/definitions/{v.cwe.replace('CWE-','')}.html",
                                    "name": f"{v.cwe} Reference",
                                    "tags": ["technical-description"],
                                },
                            ],
                            "timeline": [
                                {"time": ts_now, "lang": "en", "value": "Vulnerability discovered via automated static analysis"},
                                {"time": ts_now, "lang": "en", "value": "CVE reserved / pending assignment"},
                            ],
                            "solutions": [
                                {"lang": "en", "value": v.mitigation}
                            ],
                            "workarounds": [
                                {"lang": "en", "value": "Apply compiler hardening flags and restrict binary permissions."}
                            ],
                            "credits": [
                                {
                                    "lang":  "en",
                                    "value": "Discovered using BinSmasher CVE Auditor (static analysis)",
                                    "type":  "finder",
                                }
                            ],
                            "source": {
                                "discovery":      "INTERNAL",
                                "tool":           "BinSmasher CVE Auditor v3",
                                "binaryHash":     r.binary_hash_sha256,
                                "auditId":        v.vuln_id,
                                "taintConfidence": v.confidence,
                                "callSites":      v.call_sites,
                                "evidence":       v.evidence,
                            },
                        }
                    },
                }
                entries.append(entry)

        # Also generate a Markdown summary for human reading
        lines = [
            "# MITRE CVE Submission Report — BinSmasher CVE Auditor v3\n",
            f"Generated: {ts_now}\n",
            f"Scope: CONFIRMED + High/Critical findings only\n",
            "---\n",
        ]
        for e in entries:
            cna = e["containers"]["cna"]
            m   = cna["metrics"][0]["cvssV3_1"]
            lines += [
                f"\n## {e['cveMetadata']['cveId']}  —  {cna['title']}\n",
                f"\n### Vulnerability Description\n",
                f"{cna['descriptions'][0]['value']}\n",
                f"\n### CVSS 3.1\n",
                f"- Base Score: **{m['baseScore']}** ({m['baseSeverity']})\n",
                f"- Vector:     `{m['vectorString']}`\n",
                f"- Attack Vector: {m['attackVector']}\n",
                f"\n### Weakness Classification\n",
                f"- {cna['problemTypes'][0]['descriptions'][0]['cweId']}: "
                f"{cna['problemTypes'][0]['descriptions'][0]['description']}\n",
                f"\n### Affected Product\n",
                f"- Binary: `{cna['affected'][0]['product']}`\n",
                f"\n### Evidence\n",
            ]
            for ev in cna["source"].get("evidence", []):
                lines.append(f"- `{ev}`\n")
            lines += [
                f"\n### Solution\n",
                f"{cna['solutions'][0]['value']}\n",
                f"\n### References\n",
            ]
            for ref in cna["references"]:
                lines.append(f"- [{ref['name']}]({ref['url']})\n")
            lines.append("\n---\n")

        # Write JSON templates
        json_path = self.output_dir / f"cve_mitre_json_{_ts()}.json"
        json_path.write_text(json.dumps(entries, indent=2))

        # Write markdown
        md_path = self.output_dir / f"cve_mitre_{_ts()}.md"
        md_path.write_text("".join(lines))

        self.log.info(f"MITRE templates → {md_path} + {json_path}")
        return md_path

    # ── Export: HTML report ───────────────────────────────────────────────

    def export_html(self, reports: list) -> Path:
        path = self.output_dir / f"cve_audit_{_ts()}.html"
        path.write_text(_render_html(reports))
        self.log.info(f"HTML report     → {path}")
        return path


# ── CVSS vector helper ────────────────────────────────────────────────────────

def _cvss_vector(v: VulnPoint) -> str:
    av = "N" if v.category in ("BufferOverflow", "CommandInjection", "FormatString") else "L"
    return f"CVSS:3.1/AV:{av}/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


# ── HTML report renderer ──────────────────────────────────────────────────────

def _render_html(reports: list) -> str:  # noqa: C901
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Collect all vuln points for global stats
    all_vps = [vp for r in reports for vp in r.vuln_points]
    total_confirmed = sum(1 for v in all_vps if v.confidence == "CONFIRMED")
    total_probable  = sum(1 for v in all_vps if v.confidence == "PROBABLE")
    total_critical  = sum(1 for v in all_vps if v.severity == "Critical")
    total_high      = sum(1 for v in all_vps if v.severity == "High")

    sev_color = {
        "Critical": "#ff2d55",
        "High":     "#ff9f0a",
        "Medium":   "#ffd60a",
        "Low":      "#30d158",
    }
    conf_color = {
        "CONFIRMED":   "#30d158",
        "PROBABLE":    "#ffd60a",
        "UNCONFIRMED": "#636366",
    }

    # ── per-report rows ───────────────────────────────────────────────────
    report_rows = []
    for r in reports:
        for v in r.vuln_points:
            ev_html = "".join(
                f'<div class="ev-item">{_he(e)}</div>'
                for e in v.evidence
            )
            sites_html = ", ".join(v.call_sites) if v.call_sites else v.location

            report_rows.append(f"""
<tr
  data-binary="{_he(r.binary_name)}"
  data-confidence="{v.confidence}"
  data-severity="{v.severity}"
  data-category="{v.category}"
  data-cwe="{v.cwe}"
  data-function="{v.function_name}"
>
  <td><span class="badge-id">{_he(v.vuln_id)}</span></td>
  <td>
    <span class="badge-conf" style="--c:{conf_color.get(v.confidence,'#888')}">{v.confidence}</span>
  </td>
  <td>
    <strong>{_he(r.binary_name)}</strong>
    <div class="meta">
      {_he(r.arch)} · {r.bits}-bit · {_he(r.platform)}<br>
      MD5: <code>{r.binary_hash_md5}</code>
    </div>
  </td>
  <td>
    <span class="cat-tag">{_he(v.category)}</span>
  </td>
  <td><a class="cwe-link" href="https://cwe.mitre.org/data/definitions/{v.cwe.replace('CWE-','')}.html" target="_blank">{v.cwe}</a></td>
  <td><code class="fn-name">{_he(v.function_name)}</code></td>
  <td class="addr">{_he(sites_html)}</td>
  <td>
    <span class="cvss-badge" style="--c:{sev_color.get(v.severity,'#888')}">{v.cvss_base}</span>
  </td>
  <td>
    <span class="sev-badge" style="--c:{sev_color.get(v.severity,'#888')}">{v.severity}</span>
  </td>
  <td>
    <div class="prot-row">
      <span class="p {'p-ok' if r.nx else 'p-no'}">NX</span>
      <span class="p {'p-ok' if r.pie else 'p-no'}">PIE</span>
      <span class="p {'p-ok' if r.canary else 'p-no'}">SSP</span>
      <span class="p {'p-ok' if r.relro=='Full' else 'p-partial' if r.relro=='Partial' else 'p-no'}">RELRO</span>
      <span class="p {'p-no' if r.stack_exec else 'p-ok'}">NX-STK</span>
    </div>
  </td>
  <td>
    <button class="ev-btn" onclick="toggleEvidence(this)">▼ Evidence</button>
    <div class="ev-panel" style="display:none">{ev_html}<div class="mitigation"><strong>Fix:</strong> {_he(v.mitigation)}</div></div>
  </td>
</tr>
""")

    # ── binary summary cards ──────────────────────────────────────────────
    cards_html = ""
    for r in reports:
        confirmed_cnt = sum(1 for v in r.vuln_points if v.confidence == "CONFIRMED")
        high_crit_cnt = sum(1 for v in r.vuln_points if v.severity in ("Critical","High"))
        prot_tags = "".join([
            f'<span class="ptag {"ptok" if r.nx else "ptno"}">NX</span>',
            f'<span class="ptag {"ptok" if r.pie else "ptno"}">PIE</span>',
            f'<span class="ptag {"ptok" if r.canary else "ptno"}">Canary</span>',
            f'<span class="ptag {"ptok" if r.relro=="Full" else "ptpart" if r.relro=="Partial" else "ptno"}">{r.relro} RELRO</span>',
            f'<span class="ptag {"ptno" if r.stack_exec else "ptok"}">Exec-Stack</span>',
        ])
        cards_html += f"""
<div class="card" data-score="{r.risk_score}">
  <div class="card-top">
    <span class="card-name">{_he(r.binary_name)}</span>
    <span class="card-score">Score {r.risk_score}</span>
  </div>
  <div class="card-sub">
    {_he(r.arch)} {r.bits}-bit · {_he(r.platform)} · {r.file_size:,} B
    {'· <b class="suid-tag">SUID</b>' if r.is_suid else ''}
    {'· <b class="sgid-tag">SGID</b>' if r.is_sgid else ''}
  </div>
  <div class="card-sub">owner: {_he(r.owner)} · perms: {r.permissions}</div>
  <div class="prot-row" style="margin:6px 0">{prot_tags}</div>
  <div class="card-stats">
    <span>Total: <b>{len(r.vuln_points)}</b></span>
    <span>Confirmed: <b style="color:#30d158">{confirmed_cnt}</b></span>
    <span>High+Critical: <b style="color:#ff2d55">{high_crit_cnt}</b></span>
  </div>
  <div class="card-hash">SHA256: {r.binary_hash_sha256[:32]}…</div>
</div>
"""

    rows_html = "\n".join(report_rows)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BinSmasher CVE Audit Report — {ts}</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
/* ── Reset & base ── */
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0a0a0f;
  --bg2:#111118;
  --bg3:#18181f;
  --border:#2a2a3a;
  --text:#e8e8f0;
  --dim:#888;
  --red:#ff2d55;
  --orange:#ff9f0a;
  --yellow:#ffd60a;
  --green:#30d158;
  --blue:#0a84ff;
  --purple:#bf5af2;
  --font-mono:'JetBrains Mono',monospace;
  --font-ui:'Syne',sans-serif;
}}
body{{background:var(--bg);color:var(--text);font-family:var(--font-ui);font-size:14px;line-height:1.5;min-height:100vh}}

/* ── Header ── */
.header{{
  background:linear-gradient(135deg,#0a0a0f 0%,#13001f 50%,#000d1f 100%);
  border-bottom:1px solid var(--border);
  padding:2rem 2.5rem;
  position:relative;
  overflow:hidden;
}}
.header::before{{
  content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse 60% 80% at 70% 50%,rgba(191,90,242,.12),transparent);
  pointer-events:none;
}}
.header-grid{{display:flex;align-items:center;gap:2rem;flex-wrap:wrap}}
.logo{{
  font-size:2.4rem;font-weight:800;letter-spacing:-.04em;
  background:linear-gradient(135deg,var(--red),var(--purple));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
}}
.header-info h1{{font-size:1.05rem;font-weight:700;color:var(--text);letter-spacing:.05em;text-transform:uppercase}}
.header-info p{{color:var(--dim);font-size:.85rem;font-family:var(--font-mono)}}
.stat-pills{{display:flex;gap:.6rem;flex-wrap:wrap;margin-left:auto}}
.pill{{
  padding:.35rem .9rem;border-radius:999px;font-size:.8rem;font-weight:700;
  font-family:var(--font-mono);letter-spacing:.04em;border:1px solid;
}}
.pill-red{{border-color:var(--red);color:var(--red)}}
.pill-orange{{border-color:var(--orange);color:var(--orange)}}
.pill-green{{border-color:var(--green);color:var(--green)}}
.pill-yellow{{border-color:var(--yellow);color:var(--yellow)}}
.pill-blue{{border-color:var(--blue);color:var(--blue)}}

/* ── Layout ── */
.main{{padding:2rem 2.5rem;max-width:1800px;margin:0 auto}}

/* ── Section title ── */
.section-title{{
  font-size:.7rem;font-weight:700;letter-spacing:.15em;
  text-transform:uppercase;color:var(--dim);
  margin-bottom:1rem;padding-bottom:.4rem;
  border-bottom:1px solid var(--border);
}}

/* ── Cards ── */
.cards-wrap{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2.5rem}}
.card{{
  background:var(--bg2);border:1px solid var(--border);
  border-radius:12px;padding:1.1rem 1.3rem;min-width:260px;max-width:340px;flex:1;
  transition:border-color .2s,transform .2s;
}}
.card:hover{{border-color:var(--purple);transform:translateY(-2px)}}
.card-top{{display:flex;justify-content:space-between;align-items:center;margin-bottom:.3rem}}
.card-name{{font-weight:700;font-size:1rem;color:var(--text)}}
.card-score{{
  font-family:var(--font-mono);font-size:.8rem;
  background:linear-gradient(135deg,var(--red),var(--purple));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  font-weight:700;
}}
.card-sub{{color:var(--dim);font-size:.8rem;margin:.1rem 0}}
.card-stats{{display:flex;gap:1rem;font-size:.82rem;margin-top:.5rem}}
.card-hash{{font-family:var(--font-mono);font-size:.67rem;color:#555;margin-top:.5rem;word-break:break-all}}
.suid-tag,.sgid-tag{{
  font-size:.7rem;font-weight:700;padding:.1rem .4rem;border-radius:4px;
  background:rgba(255,45,85,.2);color:var(--red);
}}

/* ── Controls bar ── */
.controls{{
  background:var(--bg2);border:1px solid var(--border);border-radius:12px;
  padding:1rem 1.3rem;margin-bottom:1.5rem;
  display:flex;gap:.8rem;flex-wrap:wrap;align-items:center;
}}
.search-box{{
  background:var(--bg3);border:1px solid var(--border);border-radius:8px;
  color:var(--text);padding:.5rem .9rem;font-family:var(--font-mono);
  font-size:.85rem;outline:none;flex:1;min-width:200px;
}}
.search-box:focus{{border-color:var(--purple)}}
.filter-sel{{
  background:var(--bg3);border:1px solid var(--border);border-radius:8px;
  color:var(--text);padding:.5rem .9rem;font-size:.85rem;cursor:pointer;
  outline:none;
}}
.filter-sel:focus{{border-color:var(--purple)}}
.btn-reset{{
  background:transparent;border:1px solid var(--border);border-radius:8px;
  color:var(--dim);padding:.5rem 1rem;font-size:.82rem;cursor:pointer;
  transition:border-color .2s,color .2s;
}}
.btn-reset:hover{{border-color:var(--purple);color:var(--text)}}
.count-label{{
  font-family:var(--font-mono);font-size:.8rem;color:var(--dim);margin-left:auto;
}}

/* ── Table ── */
.tbl-wrap{{
  background:var(--bg2);border:1px solid var(--border);
  border-radius:12px;overflow:hidden;
}}
table{{width:100%;border-collapse:collapse;font-size:.82rem}}
thead tr{{background:var(--bg3);border-bottom:2px solid var(--border)}}
th{{
  padding:.75rem 1rem;text-align:left;font-size:.68rem;
  letter-spacing:.1em;text-transform:uppercase;color:var(--dim);
  font-weight:700;cursor:pointer;user-select:none;white-space:nowrap;
}}
th:hover{{color:var(--text)}}
th .sort-arrow{{opacity:.35;margin-left:.3rem}}
tbody tr{{border-bottom:1px solid var(--border);transition:background .15s}}
tbody tr:hover{{background:rgba(191,90,242,.04)}}
tbody tr.hidden-row{{display:none}}
td{{padding:.7rem 1rem;vertical-align:top}}

/* ── Badges ── */
.badge-id{{
  font-family:var(--font-mono);font-size:.72rem;background:var(--bg3);
  border:1px solid var(--border);border-radius:6px;padding:.15rem .4rem;
  color:var(--dim);
}}
.badge-conf{{
  display:inline-block;font-size:.72rem;font-weight:700;padding:.2rem .6rem;
  border-radius:6px;border:1px solid var(--c,#888);color:var(--c,#888);
  font-family:var(--font-mono);
}}
.cat-tag{{
  font-size:.72rem;background:rgba(10,132,255,.12);
  color:var(--blue);padding:.2rem .5rem;border-radius:6px;
  border:1px solid rgba(10,132,255,.25);
}}
.cwe-link{{
  color:var(--purple);text-decoration:none;font-family:var(--font-mono);font-size:.8rem;
}}
.cwe-link:hover{{text-decoration:underline}}
.fn-name{{color:var(--yellow);font-size:.82rem}}
.addr{{color:var(--dim);font-family:var(--font-mono);font-size:.75rem}}
.cvss-badge{{
  display:inline-block;font-weight:700;font-family:var(--font-mono);
  font-size:.85rem;color:var(--c,#888);
}}
.sev-badge{{
  font-size:.72rem;font-weight:700;padding:.2rem .55rem;border-radius:6px;
  background:color-mix(in srgb,var(--c,#888) 15%,transparent);
  color:var(--c,#888);border:1px solid color-mix(in srgb,var(--c,#888) 35%,transparent);
}}
.meta{{color:var(--dim);font-size:.72rem;font-family:var(--font-mono);margin-top:.2rem}}
.prot-row{{display:flex;gap:.3rem;flex-wrap:wrap}}
.p{{
  font-size:.65rem;font-weight:700;padding:.1rem .35rem;
  border-radius:4px;font-family:var(--font-mono);
}}
.p-ok{{background:rgba(48,209,88,.15);color:var(--green);border:1px solid rgba(48,209,88,.3)}}
.p-no{{background:rgba(255,45,85,.15);color:var(--red);border:1px solid rgba(255,45,85,.3)}}
.p-partial{{background:rgba(255,159,10,.15);color:var(--orange);border:1px solid rgba(255,159,10,.3)}}

/* ── Protection tags in cards ── */
.ptag{{font-size:.7rem;font-weight:700;padding:.15rem .4rem;border-radius:5px;font-family:var(--font-mono)}}
.ptok{{background:rgba(48,209,88,.1);color:var(--green);border:1px solid rgba(48,209,88,.25)}}
.ptno{{background:rgba(255,45,85,.1);color:var(--red);border:1px solid rgba(255,45,85,.25)}}
.ptpart{{background:rgba(255,159,10,.1);color:var(--orange);border:1px solid rgba(255,159,10,.25)}}

/* ── Evidence panel ── */
.ev-btn{{
  background:transparent;border:1px solid var(--border);border-radius:6px;
  color:var(--dim);padding:.3rem .6rem;font-size:.75rem;cursor:pointer;
  transition:all .15s;white-space:nowrap;
}}
.ev-btn:hover,.ev-btn.open{{border-color:var(--purple);color:var(--purple)}}
.ev-panel{{
  margin-top:.6rem;background:var(--bg);border:1px solid var(--border);
  border-radius:8px;padding:.7rem .9rem;
}}
.ev-item{{
  font-family:var(--font-mono);font-size:.73rem;color:var(--dim);
  padding:.2rem 0;border-bottom:1px solid var(--bg3);
}}
.ev-item:last-child{{border-bottom:none}}
.mitigation{{
  font-size:.77rem;color:var(--green);margin-top:.5rem;
  padding-top:.4rem;border-top:1px solid var(--border);
}}

/* ── Chart bar ── */
.chart-bar-wrap{{display:flex;gap:1rem;margin-bottom:2.5rem;flex-wrap:wrap}}
.chart-box{{
  background:var(--bg2);border:1px solid var(--border);border-radius:12px;
  padding:1.2rem 1.5rem;flex:1;min-width:220px;
}}
.chart-label{{font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;color:var(--dim);margin-bottom:.8rem}}
.bar-item{{display:flex;align-items:center;gap:.7rem;margin-bottom:.45rem}}
.bar-key{{font-size:.78rem;color:var(--dim);width:90px;text-align:right;flex-shrink:0}}
.bar-track{{flex:1;background:var(--bg3);border-radius:3px;height:8px;overflow:hidden}}
.bar-fill{{height:100%;border-radius:3px;transition:width .4s ease}}
.bar-val{{font-size:.78rem;font-family:var(--font-mono);color:var(--text);width:28px}}

/* ── Footer ── */
.footer{{
  text-align:center;padding:2rem;border-top:1px solid var(--border);
  color:var(--dim);font-size:.78rem;font-family:var(--font-mono);
}}
</style>
</head>
<body>

<header class="header">
  <div class="header-grid">
    <div class="logo">⬡ BS</div>
    <div class="header-info">
      <h1>BinSmasher CVE Audit Report</h1>
      <p>Generated: {ts} · Static binary analysis · Responsible disclosure</p>
    </div>
    <div class="stat-pills">
      <span class="pill pill-blue">Binaries: {len(reports)}</span>
      <span class="pill pill-blue">Findings: {len(all_vps)}</span>
      <span class="pill pill-green">Confirmed: {total_confirmed}</span>
      <span class="pill pill-yellow">Probable: {total_probable}</span>
      <span class="pill pill-red">Critical: {total_critical}</span>
      <span class="pill pill-orange">High: {total_high}</span>
    </div>
  </div>
</header>

<main class="main">

  <!-- ── Charts ── -->
  <div class="section-title">Overview</div>
  <div class="chart-bar-wrap">
    {_bar_chart("Severity Distribution", [
        ("Critical", total_critical, "#ff2d55", len(all_vps)),
        ("High",     total_high,     "#ff9f0a", len(all_vps)),
        ("Medium",   sum(1 for v in all_vps if v.severity=="Medium"), "#ffd60a", len(all_vps)),
        ("Low",      sum(1 for v in all_vps if v.severity=="Low"),    "#30d158", len(all_vps)),
    ])}
    {_bar_chart("Confidence Levels", [
        ("CONFIRMED",   total_confirmed,  "#30d158", len(all_vps)),
        ("PROBABLE",    total_probable,   "#ffd60a", len(all_vps)),
        ("UNCONFIRMED", sum(1 for v in all_vps if v.confidence=="UNCONFIRMED"), "#636366", len(all_vps)),
    ])}
    {_bar_chart("Top Categories", sorted(
        [(cat, sum(1 for v in all_vps if v.category==cat), "#0a84ff", max(1,len(all_vps)))
         for cat in dict.fromkeys(v.category for v in all_vps)],
        key=lambda x: -x[1]
    )[:6])}
  </div>

  <!-- ── Binary cards ── -->
  <div class="section-title">Audited Binaries</div>
  <div class="cards-wrap">{cards_html}</div>

  <!-- ── Controls ── -->
  <div class="section-title">Vulnerability Findings</div>
  <div class="controls">
    <input class="search-box" type="text" id="search" placeholder="🔍  Search binary, function, CWE, category…" oninput="applyFilters()">
    <select class="filter-sel" id="fConf" onchange="applyFilters()">
      <option value="">All Confidence</option>
      <option value="CONFIRMED">CONFIRMED</option>
      <option value="PROBABLE">PROBABLE</option>
      <option value="UNCONFIRMED">UNCONFIRMED</option>
    </select>
    <select class="filter-sel" id="fSev" onchange="applyFilters()">
      <option value="">All Severity</option>
      <option value="Critical">Critical</option>
      <option value="High">High</option>
      <option value="Medium">Medium</option>
      <option value="Low">Low</option>
    </select>
    <select class="filter-sel" id="fCat" onchange="applyFilters()">
      <option value="">All Categories</option>
      {"".join(f'<option value="{c}">{c}</option>' for c in sorted(set(v.category for v in all_vps)))}
    </select>
    <select class="filter-sel" id="fBin" onchange="applyFilters()">
      <option value="">All Binaries</option>
      {"".join(f'<option value="{_he(r.binary_name)}">{_he(r.binary_name)}</option>' for r in reports)}
    </select>
    <button class="btn-reset" onclick="resetFilters()">Reset</button>
    <span class="count-label" id="rowCount">{len(all_vps)} findings</span>
  </div>

  <!-- ── Table ── -->
  <div class="tbl-wrap">
    <table id="mainTable">
      <thead>
        <tr>
          <th onclick="sortTable(0)">ID <span class="sort-arrow">↕</span></th>
          <th onclick="sortTable(1)">Confidence <span class="sort-arrow">↕</span></th>
          <th onclick="sortTable(2)">Binary <span class="sort-arrow">↕</span></th>
          <th onclick="sortTable(3)">Category <span class="sort-arrow">↕</span></th>
          <th onclick="sortTable(4)">CWE <span class="sort-arrow">↕</span></th>
          <th onclick="sortTable(5)">Function <span class="sort-arrow">↕</span></th>
          <th onclick="sortTable(6)">Address(es) <span class="sort-arrow">↕</span></th>
          <th onclick="sortTable(7)">CVSS <span class="sort-arrow">↕</span></th>
          <th onclick="sortTable(8)">Severity <span class="sort-arrow">↕</span></th>
          <th>Protections</th>
          <th>Evidence / Fix</th>
        </tr>
      </thead>
      <tbody id="tableBody">
        {rows_html}
      </tbody>
    </table>
  </div>
</main>

<footer class="footer">
  BinSmasher CVE Auditor v3 · Static analysis only · No exploitation · Responsible disclosure
</footer>

<script>
function applyFilters() {{
  const q    = document.getElementById('search').value.toLowerCase();
  const conf = document.getElementById('fConf').value;
  const sev  = document.getElementById('fSev').value;
  const cat  = document.getElementById('fCat').value;
  const bin  = document.getElementById('fBin').value;
  const rows = document.querySelectorAll('#tableBody tr');
  let visible = 0;
  rows.forEach(row => {{
    const txt  = row.textContent.toLowerCase();
    const show = (
      (!q    || txt.includes(q)) &&
      (!conf || row.dataset.confidence === conf) &&
      (!sev  || row.dataset.severity   === sev) &&
      (!cat  || row.dataset.category   === cat) &&
      (!bin  || row.dataset.binary     === bin)
    );
    row.classList.toggle('hidden-row', !show);
    if (show) visible++;
  }});
  document.getElementById('rowCount').textContent = visible + ' findings';
}}

function resetFilters() {{
  ['search','fConf','fSev','fCat','fBin'].forEach(id => {{
    const el = document.getElementById(id);
    if (el.tagName === 'INPUT') el.value = '';
    else el.value = '';
  }});
  applyFilters();
}}

function toggleEvidence(btn) {{
  const panel = btn.nextElementSibling;
  const open  = panel.style.display === 'none';
  panel.style.display = open ? 'block' : 'none';
  btn.textContent = open ? '▲ Evidence' : '▼ Evidence';
  btn.classList.toggle('open', open);
}}

let sortDir = {{}};
function sortTable(col) {{
  const tbody = document.getElementById('tableBody');
  const rows  = Array.from(tbody.querySelectorAll('tr'));
  sortDir[col] = !sortDir[col];
  rows.sort((a, b) => {{
    const at = a.cells[col]?.textContent.trim() || '';
    const bt = b.cells[col]?.textContent.trim() || '';
    const an = parseFloat(at), bn = parseFloat(bt);
    if (!isNaN(an) && !isNaN(bn)) return sortDir[col] ? an-bn : bn-an;
    return sortDir[col] ? at.localeCompare(bt) : bt.localeCompare(at);
  }});
  rows.forEach(r => tbody.appendChild(r));
}}
</script>
</body>
</html>"""

    return html


def _he(s: str) -> str:
    """HTML escape."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _bar_chart(title: str, items: list) -> str:
    total_max = max((x[1] for x in items), default=1) or 1
    bars = ""
    for label, count, color, _ in items:
        pct = int(count / total_max * 100) if total_max else 0
        bars += f"""
<div class="bar-item">
  <span class="bar-key">{label}</span>
  <div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{color}"></div></div>
  <span class="bar-val">{count}</span>
</div>"""
    return f"""<div class="chart-box">
  <div class="chart-label">{title}</div>
  {bars}
</div>"""


# ── CLI entry point ────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cve_scan.py",
        description="BinSmasher CVE Auditor v3 — Static binary vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cve_scan.py /usr/bin
  python3 cve_scan.py --single /tmp/vuln_test -v
  python3 cve_scan.py /usr/bin /sbin --threshold 100 --confidence CONFIRMED
  python3 cve_scan.py --single ./target --no-taint -o ./out
""",
    )
    parser.add_argument(
        "paths", nargs="*", default=["/usr/bin"],
        help="Directories or files to scan (default: /usr/bin)",
    )
    parser.add_argument(
        "-o", "--output-dir", default="./cve_reports",
        help="Output directory for reports (default: ./cve_reports)",
    )
    parser.add_argument(
        "--threshold", type=int, default=50,
        help="Minimum risk score to include a binary in the report (default: 50)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--single", metavar="BINARY",
        help="Audit a single binary file",
    )
    parser.add_argument(
        "--no-taint", action="store_true",
        help="Disable taint / data-flow analysis",
    )
    parser.add_argument(
        "--confidence",
        choices=["CONFIRMED", "PROBABLE", "UNCONFIRMED"],
        default="PROBABLE",
        help="Minimum confidence level to include in report (default: PROBABLE)",
    )
    parser.add_argument(
        "--no-html", action="store_true",
        help="Skip HTML report generation",
    )

    args = parser.parse_args()

    # Determine scan paths
    if args.single:
        if not os.path.isfile(args.single):
            print(f"[ERROR] File not found: {args.single}", file=sys.stderr)
            sys.exit(1)
        paths = [args.single]
    else:
        paths = args.paths

    # Create auditor
    auditor = CVEAuditor(
        search_paths=paths,
        output_dir=args.output_dir,
        threshold_score=args.threshold,
        verbose=args.verbose,
        taint=not args.no_taint,
        min_confidence=args.confidence,
    )

    rprint("[bold cyan]▶ BinSmasher CVE Auditor v3[/]")
    rprint(f"[dim]Scanning: {paths}[/]")
    rprint(f"[dim]Output:   {args.output_dir}[/]")
    rprint(f"[dim]Taint:    {not args.no_taint}  |  Min confidence: {args.confidence}[/]")
    rprint("")

    reports = auditor.scan()

    if not reports:
        rprint("[yellow]No findings above threshold.[/]")
        sys.exit(0)

    rprint(f"\n[bold green]✔ Audit complete — {len(reports)} binary/ies with findings[/]\n")

    # ── Exports ──────────────────────────────────────────────────────────
    ts = _ts()

    json_all = auditor.export_json_all(reports)
    json_ch  = auditor.export_json_confirmed_high(reports)
    json_ph  = auditor.export_json_probable_high(reports)
    md_mitre = auditor.export_mitre_templates(reports)

    if not args.no_html:
        html_path = auditor.export_html(reports)

    rprint("\n[bold]Output files:[/]")
    rprint(f"  [green]JSON (all)[/]              → {json_all}")
    rprint(f"  [green]JSON (confirmed+high)[/]   → {json_ch}")
    rprint(f"  [green]JSON (probable+high)[/]    → {json_ph}")
    rprint(f"  [green]MITRE CVE templates[/]     → {md_mitre}")
    if not args.no_html:
        rprint(f"  [green]HTML report[/]             → {html_path}")


if __name__ == "__main__":
    main()
