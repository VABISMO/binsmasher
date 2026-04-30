#!/usr/bin/env python3
"""
BinSmasher CVE Auditor — Static binary vulnerability scanner for responsible disclosure.

Modules:
  models      — VulnPoint and BinaryReport dataclasses
  catalog     — Vulnerability catalogue, known CVEs, mitigations, fortify mapping
  scoring     — CVSS scoring, severity classification, risk computation
  analysis    — Binary analysis functions (protections, symbols, rodata, etc.)
  auditor     — CVEAuditor class (core scan engine)
  reporter    — HTML, JSON, MITRE CVE export functions
  taint_analyzer — Static taint / data-flow analysis (optional)
"""

from .models import VulnPoint, BinaryReport
from .auditor import CVEAuditor
from .catalog import VULN_CATALOG, KNOWN_CVES, MITIGATIONS, DANGEROUS_CAPS

__all__ = [
    "VulnPoint",
    "BinaryReport",
    "CVEAuditor",
    "VULN_CATALOG",
    "KNOWN_CVES",
    "MITIGATIONS",
    "DANGEROUS_CAPS",
]