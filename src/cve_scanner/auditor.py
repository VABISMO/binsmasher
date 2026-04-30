#!/usr/bin/env python3
"""
auditor.py — CVEAuditor class: core binary audit engine.

Orchestrates binary scanning, vulnerability detection with false-positive
filtering, taint analysis integration, and report generation.
"""

import logging
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dataclasses import asdict

from .models import VulnPoint, BinaryReport
from .catalog import VULN_CATALOG, MITIGATIONS, DANGEROUS_CAPS
from .scoring import cvss_to_severity, adjust_cvss, compute_risk_score, _cvss_vector
from .analysis import (
    _run, file_hashes, detect_arch, check_protections,
    get_imported_symbols, get_strings_of_interest,
    find_vuln_addresses, get_disasm_context, suid_sgid_check,
    check_fortify_symbols, detect_fortify_level,
    analyze_rodata_format_strings, check_rpath,
    is_kernel_module, extract_modinfo,
    get_system_versions, match_version_cves,
    check_linux_capabilities, check_stack_clash_protection,
    detect_symbol_versions, check_seccomp,
    analyze_plt_got, detect_dead_imports,
    _get_disasm,
)

# Taint analysis (optional)
try:
    from .taint_analyzer import enrich_vuln_points
    HAS_TAINT = True
except ImportError:
    HAS_TAINT = False

# Rich UI (optional)
try:
    from rich.console import Console
    from rich.table import Table
    from rich.logging import RichHandler
    from rich import box
    RICH = True
except ImportError:
    RICH = False

_console = Console(highlight=False) if RICH else None


def rprint(msg: str) -> None:
    """Print with Rich markup if available, plain text otherwise."""
    if RICH:
        _console.print(msg)
    else:
        print(re.sub(r"\[/?[a-zA-Z_ ]+\]", "", msg))


def _ts() -> str:
    """Return a timestamp string for file naming."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _mitigation(fn: str, prot: dict) -> str:
    """Generate mitigation hint for a vulnerability function."""
    base  = MITIGATIONS.get(fn, f"Audit all uses of {fn}() and validate inputs.")
    flags = []
    if not prot.get("nx"):     flags.append("enable NX/DEP (-Wl,-z,noexecstack)")
    if not prot.get("pie"):    flags.append("compile with -fPIE -pie")
    if not prot.get("canary"): flags.append("enable stack canaries (-fstack-protector-strong)")
    if prot.get("relro") == "None": flags.append("enable RELRO (-Wl,-z,relro,-z,now)")
    if flags:
        base += f" Compiler hardening: {', '.join(flags)}."
    return base


class CVEAuditor:
    """Core binary audit engine with false-positive-aware vulnerability detection."""

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
            [RichHandler(console=_console, markup=True, rich_tracebacks=False, show_path=False)]
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
                magic = f.read(4)
                return magic == b"\x7fELF"
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
        # Pre-cache disassembly (used by multiple analysis functions)
        _get_disasm(path)

        arch, bits, platform = detect_arch(path)
        md5h, sha256h        = file_hashes(path)
        st                   = os.stat(path)
        suid, sgid, owner, perms = suid_sgid_check(path)
        prot = check_protections(path, platform)

        # ── Extended analysis ────────────────────────────────────────────
        fortify_safe   = check_fortify_symbols(path)
        fortify_level  = detect_fortify_level(path)
        rodata_safe    = analyze_rodata_format_strings(path)
        rpath_issues   = check_rpath(path)
        is_kmod        = is_kernel_module(path)
        kmod_info      = extract_modinfo(path) if is_kmod else {}
        sys_versions   = get_system_versions()
        aslr_system    = sys_versions.get("aslr_system", "unknown")
        has_caps, caps = check_linux_capabilities(path)
        stack_clash    = check_stack_clash_protection(path)
        seccomp_status = check_seccomp()
        sym_versions   = detect_symbol_versions(path)
        plt_got        = analyze_plt_got(path)

        # Imported symbols
        imported_symbols = get_imported_symbols(path)

        # Dead import detection (for FP reduction)
        dead_imports = detect_dead_imports(path, imported_symbols)

        # Version-based CVE matching
        version_cves = []
        glibc_ver = sys_versions.get("glibc", "")
        kernel_ver = sys_versions.get("kernel", "")
        if glibc_ver:
            version_cves.extend(match_version_cves("glibc", glibc_ver))
        if kernel_ver:
            version_cves.extend(match_version_cves("kernel", kernel_ver))
        # Check for OpenSSL version from symbol versions
        for ver_key in sym_versions:
            if "OPENSSL" in ver_key.upper() or "SSL" in ver_key.upper():
                ver_match = re.search(r'(\d+\.\d+\.\d+)', ver_key)
                if ver_match:
                    version_cves.extend(match_version_cves("openssl", ver_match.group(1)))

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
            is_kernel_module=is_kmod,
            kernel_modinfo=kmod_info,
            rpath_issues=rpath_issues,
            system_versions=sys_versions,
            version_cves=version_cves,
            aslr_system=aslr_system,
            has_linux_caps=has_caps,
            linux_caps=caps,
            fortify_level=fortify_level,
            stack_clash_prot=stack_clash,
            seccomp=seccomp_status,
            symbol_versions=sym_versions,
            imported_libs=imported_symbols,
            strings_of_interest=get_strings_of_interest(path),
            audit_timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # ── Match imported symbols against catalogue (FP-aware) ──────
        seen_canonical: set = set()
        for sym in report.imported_libs:
            canonical = re.split(r"[@\+]", sym)[0].strip("_ \t").lower()
            if canonical not in VULN_CATALOG:
                continue
            if canonical in seen_canonical:
                continue
            seen_canonical.add(canonical)

            entry     = VULN_CATALOG[canonical]
            category  = entry["cat"]
            cwe       = entry["cwe"]
            desc      = entry["desc"]
            base_cvss = entry["cvss"]
            tier      = entry["tier"]
            fortify_fn = entry.get("fortify")

            sites = find_vuln_addresses(path, canonical)

            # ══════════════════════════════════════════════════════════════
            # FALSE POSITIVE FILTERS
            # These are applied IN ORDER. Each filter checks a specific
            # condition where a finding would be a false positive.
            # ══════════════════════════════════════════════════════════════

            # FP-1: Dead import — symbol in PLT but never called from .text
            if canonical in dead_imports and tier != "always":
                self.log.debug(f"  Skipping {canonical}: dead import (PLT-only, no call sites in .text)")
                continue

            # FP-2: FORTIFY protection: _chk variant linked → runtime bounds checking
            is_fortify_protected = (
                fortify_fn is not None and
                fortify_fn not in ("__isoc99_scanf", "__isoc99_sscanf") and
                canonical in fortify_safe
            )

            # FP-3: Context-tier with no actual call sites: imported via PLT
            # but never called from binary code → skip entirely
            if tier == "context" and not sites:
                self.log.debug(f"  Skipping {canonical}: imported but no call sites in binary")
                continue

            # FP-4: Safe variants: only include if SUID/SGID or no protections
            if tier == "safe_variant" and not (
                suid or sgid or not prot["nx"] or not prot["canary"]
            ):
                self.log.debug(f"  Skipping {canonical}: safe variant with good protections")
                continue

            # FP-5: Memory management (malloc/free/realloc/calloc):
            # Universal in C programs — only flag with SUID or missing protections
            if category == "MemoryMgmt" and not (
                suid or sgid or not prot["nx"] or not prot["canary"]
            ):
                continue

            # FP-6: Format string: check rodata for %n (arbitrary write)
            # If rodata shows only constant format strings, reduce significantly
            is_rodata_safe = rodata_safe and category == "FormatString"

            # FP-7: setuid/setgid without SUID bit: usually privilege dropping
            if canonical in ("setuid", "setgid") and not (suid or sgid):
                continue

            # FP-8: dlopen without SUID/SGID and with PIE: low risk
            if canonical == "dlopen" and not (suid or sgid) and prot["pie"]:
                continue

            # FP-9: Network functions (bind/connect/accept): only flag in SUID/SGID/cap binaries
            if category == "NetworkExposed" and not (suid or sgid or has_caps):
                self.log.debug(f"  Skipping {canonical}: network function in non-privileged binary")
                continue

            # FP-10: fork() in non-SUID/non-cap binaries — too common
            if canonical == "fork" and not (suid or sgid or has_caps):
                continue

            # FP-11: mprotect: only flag in SUID/cap binaries
            if canonical == "mprotect" and not (suid or sgid or has_caps):
                continue

            # FP-12: ptrace/prctl: only flag in SUID/cap binaries
            if canonical in ("ptrace", "prctl") and not (suid or sgid or has_caps):
                continue

            # FP-13: Thread-unsafe functions: skip if binary appears single-threaded
            if category == "ThreadUnsafe" and not (
                suid or sgid or has_caps or
                any("pthread" in s.lower() for s in report.imported_libs)
            ):
                self.log.debug(f"  Skipping {canonical}: thread-unsafe in single-threaded binary")
                continue

            # FP-14: FORTIFY level 2 provides stronger protection than level 1
            # For level 2, additional reduction for format strings
            if is_fortify_protected and fortify_level == 2 and category == "FormatString":
                is_fortify_protected = True  # Extra reduction handled in adjust_cvss

            # ── Compute adjusted CVSS ──────────────────────────────────────
            adjusted = adjust_cvss(
                base_cvss, prot["nx"], prot["pie"], prot["canary"], suid,
                fortify_protected=is_fortify_protected,
                tier=tier,
                has_call_sites=bool(sites),
                rodata_safe=is_rodata_safe,
                has_caps=has_caps,
                stack_clash_prot=stack_clash,
            )

            # Extra FORTIFY level 2 reduction for format strings
            if is_fortify_protected and fortify_level == 2 and category == "FormatString":
                adjusted = round(max(adjusted - 0.5, 0.5), 1)

            # Skip if adjusted CVSS drops below actionable threshold
            if adjusted < 2.0 and tier == "safe_variant":
                continue

            # ── Build evidence ────────────────────────────────────────────
            evidence  = [f"Imported symbol: {sym}"]
            if sites:
                evidence.append(f"Call sites: {', '.join(sites)}")
            if is_fortify_protected:
                level_str = f" (level {fortify_level})" if fortify_level else ""
                evidence.append(f"FORTIFY: {fortify_fn} variant linked{level_str} — runtime bounds checking active")
            if is_rodata_safe:
                evidence.append("Rodata analysis: format strings appear constant (no %n found)")
            if tier == "always":
                evidence.append("Risk tier: ALWAYS DANGEROUS — no safe use exists")
            if canonical in dead_imports:
                evidence.append("WARNING: Symbol appears to be dead import (PLT-only)")

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

        # ── RPATH/RUNPATH vulnerabilities ───────────────────────────
        for rp_issue in rpath_issues:
            rpath_vp = VulnPoint(
                vuln_id=self._next_id(),
                category="DynamicLinking",
                cwe="CWE-426",
                function_name="RPATH/RUNPATH",
                location=path,
                description=rp_issue,
                severity="Medium",
                cvss_base=5.5,
                evidence=[rp_issue, f"Binary: {path}"],
                mitigation="Remove RPATH/RUNPATH or use -Wl,-rpath,$ORIGIN only.",
                affected_binary=path,
                binary_hash=sha256h,
                confidence="CONFIRMED",
            )
            report.vuln_points.append(rpath_vp)

        # ── Linux capabilities vulnerabilities ────────────────────────────
        for cap in caps:
            cap_lower = cap.lower()
            cap_info = None
            for known_cap, info in DANGEROUS_CAPS.items():
                if known_cap == cap_lower:
                    cap_info = info
                    break
            if cap_info:
                cap_vp = VulnPoint(
                    vuln_id=self._next_id(),
                    category="LinuxCapability",
                    cwe="CWE-250",
                    function_name=cap_lower,
                    location=path,
                    description=cap_info["desc"],
                    severity=cap_info["severity"],
                    cvss_base=cap_info["cvss"],
                    evidence=[f"Capability: {cap_lower}", cap_info["desc"], f"Binary: {path}"],
                    mitigation=f"Remove capability {cap_lower} unless strictly necessary: setcap -r {path}",
                    affected_binary=path,
                    binary_hash=sha256h,
                    confidence="CONFIRMED",
                )
                report.vuln_points.append(cap_vp)

        # ── Kernel module specific checks ────────────────────────────
        if is_kmod:
            kmod_ver = kmod_info.get("vermagic", "unknown")
            if kernel_ver and kmod_ver and kernel_ver not in kmod_ver:
                kmod_vp = VulnPoint(
                    vuln_id=self._next_id(),
                    category="KernelModule",
                    cwe="CWE-1357",
                    function_name="vermagic_mismatch",
                    location=path,
                    description=f"Kernel module compiled for {kmod_ver} but running kernel is {kernel_ver}",
                    severity="High",
                    cvss_base=7.5,
                    evidence=[f"Module vermagic: {kmod_ver}", f"Running kernel: {kernel_ver}"],
                    mitigation="Recompile module for current kernel version.",
                    affected_binary=path,
                    binary_hash=sha256h,
                    confidence="CONFIRMED",
                )
                report.vuln_points.append(kmod_vp)

            # Check for unsafe module parameters
            parm = kmod_info.get("parm", "")
            if parm and re.search(r'(exec|cmd|shell|system|command)', parm, re.I):
                kmod_exec_vp = VulnPoint(
                    vuln_id=self._next_id(),
                    category="KernelModule",
                    cwe="CWE-78",
                    function_name="module_param",
                    location=path,
                    description=f"Kernel module has dangerous parameter: {parm}",
                    severity="High",
                    cvss_base=7.5,
                    evidence=[f"Module parm: {parm}"],
                    mitigation="Audit module parameter handling — possible command injection.",
                    affected_binary=path,
                    binary_hash=sha256h,
                    confidence="PROBABLE",
                )
                report.vuln_points.append(kmod_exec_vp)

        # ── Version-based CVE findings ───────────────────────────────
        for cve in version_cves:
            cve_vp = VulnPoint(
                vuln_id=self._next_id(),
                category="KnownCVE",
                cwe=cve.get("cwe", "CWE-Other"),
                function_name=cve["id"],
                location="system",
                description=cve["desc"],
                severity=cvss_to_severity(cve["cvss"]),
                cvss_base=cve["cvss"],
                evidence=[f"CVE: {cve['id']}", f"CVSS: {cve['cvss']}", cve["desc"]],
                mitigation=f"Update to latest version. See {cve['id']} advisory.",
                affected_binary=path,
                binary_hash=sha256h,
                confidence="CONFIRMED",
            )
            report.vuln_points.append(cve_vp)

        # ── ASLR system-wide check ──────────────────────────────────
        if aslr_system == "0":
            aslr_vp = VulnPoint(
                vuln_id=self._next_id(),
                category="SystemSecurity",
                cwe="CWE-340",
                function_name="ASLR_disabled",
                location="/proc/sys/kernel/randomize_va_space",
                description="System-wide ASLR is disabled (randomize_va_space=0)",
                severity="High",
                cvss_base=7.5,
                evidence=["ASLR system-wide: DISABLED", "All binaries are easier to exploit"],
                mitigation="Enable ASLR: echo 2 > /proc/sys/kernel/randomize_va_space",
                affected_binary=path,
                binary_hash=sha256h,
                confidence="CONFIRMED",
            )
            report.vuln_points.append(aslr_vp)

        # ── Executable stack check ──────────────────────────────────
        if prot["stack_exec"]:
            exec_stack_vp = VulnPoint(
                vuln_id=self._next_id(),
                category="SystemSecurity",
                cwe="CWE-732",
                function_name="executable_stack",
                location=path,
                description="Binary has executable stack (GNU_STACK RWE) — enables code injection attacks",
                severity="High",
                cvss_base=8.8,
                evidence=["GNU_STACK: RWE (read-write-execute)", "NX bit not enforced"],
                mitigation="Compile with -Wl,-z,noexecstack to disable executable stack.",
                affected_binary=path,
                binary_hash=sha256h,
                confidence="CONFIRMED",
            )
            report.vuln_points.append(exec_stack_vp)

        # ── SUID/SGID privilege escalation (only if dangerous functions present) ────
        dangerous_for_suid = [
            v for v in report.vuln_points
            if v.category in ("BufferOverflow", "CommandInjection", "FormatString",
                              "UseAfterFree", "PrivEsc", "RaceCondition",
                              "TOCTOU", "LinuxCapability", "DynamicLoad")
        ]
        if (suid or sgid) and dangerous_for_suid:
            suid_vp = VulnPoint(
                vuln_id=self._next_id(),
                category="PrivilegeEscalation",
                cwe="CWE-250",
                function_name="setuid/suid_bit",
                location=path,
                description=(
                    f"Binary has SUID{'G' if sgid else ''} bit set AND "
                    f"dangerous functions: "
                    f"{[v.function_name for v in dangerous_for_suid]}"
                ),
                severity="Critical",
                cvss_base=9.3,
                evidence=[
                    f"SUID: {suid}, SGID: {sgid}",
                    f"Owner: {owner}, Permissions: {perms}",
                    f"Dangerous imports: {[v.function_name for v in dangerous_for_suid]}",
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
            report.risk_score = compute_risk_score(report)

        return report

    # ── Scanning ──────────────────────────────────────────────────────────

    def scan(self) -> list:
        """Discover ELF binaries and audit each one."""
        binaries = []
        for sp in self.search_paths:
            if not os.path.exists(sp):
                self.log.warning(f"Path does not exist: {sp}")
                continue
            if os.path.isfile(sp) and self._is_elf(sp):
                binaries.append(sp)
                continue
            for root, dirs, files in os.walk(sp, followlinks=False):
                # Skip irrelevant virtual/ephemeral dirs
                dirs[:] = [d for d in dirs
                           if d not in ("proc", "sys", "dev", "run")]
                for name in files:
                    fp = os.path.join(root, name)
                    if self._is_elf(fp):
                        binaries.append(fp)

        # Deduplicate
        binaries = sorted(set(binaries))
        self.log.info(f"Found {len(binaries)} ELF binaries to audit")

        # System-level checks (run once)
        sys_versions = get_system_versions()
        if sys_versions:
            self.log.info(f"System: kernel={sys_versions.get('kernel','?')} "
                         f"glibc={sys_versions.get('glibc','?')} "
                         f"ASLR={sys_versions.get('aslr_system','?')}")

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
        """Print a summary table of findings for a binary."""
        kmod_tag = " [magenta](kernel module)[/]" if r.is_kernel_module else ""
        suid_tag = " [bold red]SUID[/]" if r.is_suid else ""
        sgid_tag = " [bold red]SGID[/]" if r.is_sgid else ""
        caps_tag = " [bold yellow]CAPS[/]" if r.has_linux_caps else ""

        if not RICH:
            print(f"\n{'='*70}")
            print(f"{r.binary_path}  Score: {r.risk_score}{kmod_tag}{suid_tag}{sgid_tag}{caps_tag}")
            print(f"  NX:{r.nx} PIE:{r.pie} Canary:{r.canary} RELRO:{r.relro} FORTIFY:{r.fortify}")
            if r.fortify_level:
                print(f"  FORTIFY_LEVEL: {r.fortify_level}")
            if r.rpath_issues:
                print(f"  RPATH Issues: {'; '.join(r.rpath_issues)}")
            if r.is_kernel_module:
                print(f"  Kernel Module: {r.kernel_modinfo.get('filename', 'N/A')}")
                print(f"  Vermagic: {r.kernel_modinfo.get('vermagic', 'N/A')}")
            if r.has_linux_caps:
                print(f"  Capabilities: {', '.join(r.linux_caps)}")
            if r.version_cves:
                for cve in r.version_cves:
                    print(f"  CVE: {cve['id']} (CVSS {cve['cvss']}) — {cve['desc']}")
            print(f"{'='*70}")
            for v in r.vuln_points:
                print(f"  [{v.confidence:12}] {v.function_name:12} {v.cwe:10} {v.severity:8} CVSS:{v.cvss_base}")
            return

        t = Table(
            title=f"[bold red]{r.binary_name}[/]  Risk:[yellow]{r.risk_score}[/]"
                  f"  NX:[{'green' if r.nx else 'red'}]{r.nx}[/]"
                  f"  PIE:[{'green' if r.pie else 'red'}]{r.pie}[/]"
                  f"  Canary:[{'green' if r.canary else 'red'}]{r.canary}[/]"
                  f"  RELRO:[{'green' if r.relro=='Full' else 'yellow' if r.relro=='Partial' else 'red'}]{r.relro}[/]"
                  f"  FORTIFY:[{'green' if r.fortify else 'red'}]{r.fortify}[/]"
                  f"{kmod_tag}{suid_tag}{sgid_tag}{caps_tag}",
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
        _console.print(t)

    # ── Export methods (delegate to reporter) ───────────────────────────

    def export_json_all(self, reports: list) -> Path:
        from .reporter import export_json_all
        return export_json_all(reports, self.output_dir, _ts)

    def export_json_confirmed_high(self, reports: list) -> Path:
        from .reporter import export_json_confirmed_high
        return export_json_confirmed_high(reports, self.output_dir, _ts)

    def export_json_probable_high(self, reports: list) -> Path:
        from .reporter import export_json_probable_high
        return export_json_probable_high(reports, self.output_dir, _ts)

    def export_mitre_templates(self, reports: list) -> Path:
        from .reporter import export_mitre_templates
        return export_mitre_templates(reports, self.output_dir, _ts)

    def export_html(self, reports: list) -> Path:
        from .reporter import export_html
        return export_html(reports, self.output_dir, _ts)