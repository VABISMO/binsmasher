#!/usr/bin/env python3
"""
scoring.py — CVSS scoring, severity classification, and risk computation.
"""

from models import VulnPoint, BinaryReport
from catalog import SEVERITY_THRESHOLDS


def cvss_to_severity(score: float) -> str:
    """Convert a CVSS score to a severity label."""
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "Informational"


def adjust_cvss(
    base: float,
    nx: bool,
    pie: bool,
    canary: bool,
    is_suid: bool,
    fortify_protected: bool = False,
    tier: str = "context",
    has_call_sites: bool = True,
    rodata_safe: bool = False,
    has_caps: bool = False,
    stack_clash_prot: bool = False,
) -> float:
    """
    Adjust base CVSS based on binary protections, FORTIFY, call-site presence,
    format string analysis, and other factors.

    Reductions are conservative — we only reduce when evidence strongly suggests
    the vulnerability is mitigated, to minimize false negatives.
    """
    score = base
    # Protection-based reductions
    if nx:      score -= 0.8
    if pie:     score -= 0.6
    if canary:  score -= 0.5
    if not is_suid: score -= 0.3
    if stack_clash_prot: score -= 0.3
    # FORTIFY protection: significant reduction for functions with _chk variants
    if fortify_protected:
        score -= 1.5
    # Tier-based adjustments
    if tier == "safe_variant":
        score -= 2.0
    elif tier == "context" and not has_call_sites:
        # Function imported but never actually called from binary code
        score -= 2.5
    # Format string specific: if rodata analysis shows only constant format strings
    if rodata_safe:
        score -= 2.0
    # Dangerous capabilities bump: if binary has dangerous Linux caps
    if has_caps:
        score += 0.5
    return round(max(score, 0.5), 1)


def compute_risk_score(report: BinaryReport) -> int:
    """
    Compute an integer risk score for a binary based on its findings
    and protections.
    """
    score = sum(int(v.cvss_base * 10) for v in report.vuln_points)
    if report.is_suid:       score += 200
    if report.is_sgid:       score += 150
    if not report.nx:         score += 100
    if not report.pie:        score += 80
    if not report.canary:     score += 60
    if report.relro == "None": score += 40
    if report.rpath_issues:   score += 30
    if report.has_linux_caps: score += 100
    if report.stack_exec:     score += 80
    # Kernel module vermagic mismatch
    if (report.is_kernel_module and
        report.kernel_modinfo.get("vermagic") and
        report.system_versions.get("kernel") and
        report.system_versions["kernel"] not in report.kernel_modinfo.get("vermagic", "")):
        score += 100
    return score


def _cvss_vector(v: VulnPoint) -> str:
    """Generate a CVSS 3.1 vector string for a vulnerability."""
    av = "N" if v.category in ("BufferOverflow", "CommandInjection",
                                "FormatString", "NetworkExposed") else "L"
    pr = "L" if ("SUID" in v.description or v.category == "PrivilegeEscalation") else "N"
    return f"CVSS:3.1/AV:{av}/AC:L/PR:{pr}/UI:N/S:U/C:H/I:H/A:H"