#!/usr/bin/env python3
"""
models.py — Data models for BinSmasher CVE Auditor.

VulnPoint: single vulnerability finding.
BinaryReport: full audit result for one binary.
"""

from dataclasses import dataclass, field


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
    # Extra security metadata
    is_kernel_module: bool  = False
    kernel_modinfo:    dict  = field(default_factory=dict)
    rpath_issues:     list  = field(default_factory=list)
    system_versions:  dict  = field(default_factory=dict)
    version_cves:     list  = field(default_factory=list)
    aslr_system:      str   = "unknown"
    # Enhanced analysis
    has_linux_caps:   bool  = False
    linux_caps:       list  = field(default_factory=list)
    fortify_level:    int   = 0       # 0=none, 1=FORTIFY_SOURCE=1, 2=FORTIFY_SOURCE=2
    stack_clash_prot: bool  = False
    seccomp:          str   = "unknown"
    symbol_versions:  dict  = field(default_factory=dict)
    # Findings
    vuln_points:      list  = field(default_factory=list)
    imported_libs:    list  = field(default_factory=list)
    strings_of_interest: list = field(default_factory=list)
    risk_score:       int   = 0
    audit_timestamp:  str   = ""