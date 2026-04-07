#!/usr/bin/env python3
"""
taint_analyzer.py  v3
Static taint / data-flow analysis using call-graph BFS + argument register heuristics.
Enriches VulnPoint objects with CONFIRMED / PROBABLE / UNCONFIRMED confidence.
"""

import re
import subprocess
import logging
from dataclasses import dataclass, field
from collections import deque
from typing import Optional

log = logging.getLogger("cve_auditor.taint")

# ── Constants ────────────────────────────────────────────────────────────────

TAINT_SOURCES = {
    "recv", "read", "fread", "fgets", "gets", "getenv", "scanf",
    "sscanf", "fgetc", "getc", "getchar", "getdelim", "getline",
    "pread", "recvfrom", "recvmsg",
}
ENTRY_POINTS = {"main", "_start", "start"}
CONFIDENCE_RANK = {"CONFIRMED": 3, "PROBABLE": 2, "UNCONFIRMED": 1}

# Argument registers per ABI
ARG_REGS_64 = {"rdi", "esi", "edx", "ecx", "r8d", "r9d",
               "rsi", "rdx", "rcx", "r8", "r9"}
ARG_REGS_32 = {"eax", "ebx", "ecx", "edx"}


# ── Data model ───────────────────────────────────────────────────────────────

@dataclass
class TaintResult:
    sink_function:  str
    sink_address:   str
    confidence:     str
    taint_path:     list
    source_function: str
    evidence:       list = field(default_factory=list)
    notes:          str  = ""


# ── Helpers ──────────────────────────────────────────────────────────────────

def _run(cmd: list, timeout: int = 25) -> str:
    try:
        return subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, timeout=timeout
        ).decode(errors="ignore")
    except Exception:
        return ""


# ── Call-graph (objdump-based) ───────────────────────────────────────────────

class FastCallGraph:
    """Build a simplified call graph from objdump disassembly."""

    def __init__(self, binary: str) -> None:
        self.binary = binary
        # callee_set per caller
        self.calls:    dict[str, set] = {}
        # address → name
        self.fn_addrs: dict[str, str] = {}
        self._built = False

    def build(self) -> bool:
        out = _run(["objdump", "-d", "--wide", self.binary])
        if not out:
            log.debug("objdump produced no output — skipping call-graph")
            return False

        fn_pat   = re.compile(r"^([0-9a-f]+)\s+<([^>]+)>:\s*$")
        call_pat = re.compile(r"\bcall[q]?\s+[0-9a-f]+\s+<([^>@+]+)(?:@plt|@got)?>")
        current  = "__unknown__"

        for line in out.splitlines():
            fm = fn_pat.match(line)
            if fm:
                addr    = fm.group(1)
                raw     = fm.group(2)
                current = raw.split("@")[0].strip()
                self.calls.setdefault(current, set())
                self.fn_addrs[addr] = current
                continue
            cm = call_pat.search(line)
            if cm:
                callee = cm.group(1).strip()
                self.calls.setdefault(current, set()).add(callee)

        self._built = True
        log.debug(f"Call-graph: {len(self.calls)} nodes, "
                  f"{sum(len(v) for v in self.calls.values())} edges")
        return True

    def callers_of(self, fn: str) -> list[str]:
        return [c for c, cs in self.calls.items() if fn in cs]

    def callees_of(self, fn: str) -> set:
        return self.calls.get(fn, set())

    def known_functions(self) -> set:
        return set(self.calls.keys())

    # BFS: find shortest path from any source → sink (reverse: sink → sources)
    def bfs_to_source(self, sink: str, max_depth: int = 12) -> Optional[list[str]]:
        """Return the call path [source ... sink] if one exists, else None."""
        queue:   deque  = deque([(sink, [sink])])
        visited: set    = {sink}

        while queue:
            curr, path = queue.popleft()
            if len(path) > max_depth:
                continue
            if curr in TAINT_SOURCES or curr in ENTRY_POINTS:
                return path[::-1]
            for caller in self.callers_of(curr):
                if caller not in visited:
                    visited.add(caller)
                    queue.append((caller, path + [caller]))
        return None

    # Forward BFS: check if sink is reachable from sources
    def bfs_from_sources(self, sink: str, max_depth: int = 12) -> Optional[list[str]]:
        """BFS forward from known taint sources toward sink."""
        queue:   deque  = deque()
        visited: set    = set()

        for src in TAINT_SOURCES:
            if src in self.calls:
                queue.append((src, [src]))
                visited.add(src)

        while queue:
            curr, path = queue.popleft()
            if len(path) > max_depth:
                continue
            if curr == sink:
                return path
            for callee in self.callees_of(curr):
                if callee not in visited:
                    visited.add(callee)
                    queue.append((callee, path + [callee]))
        return None


# ── Argument register flow heuristic ─────────────────────────────────────────

class ArgFlow:
    """
    Inspect the bytes just before a call site to see if argument registers
    are loaded from memory (stack/heap — tainted data) rather than immediates.
    """

    def __init__(self, binary: str, bits: int) -> None:
        self.binary = binary
        self.bits   = bits
        self.regs   = ARG_REGS_64 if bits == 64 else ARG_REGS_32

    def check(self, sink_fn: str, sink_addr: str) -> tuple[bool, str]:
        """
        Returns (tainted: bool, reason: str).
        Looks at the 20 instructions preceding the call site.
        """
        out = _run(["objdump", "-d", "--wide", self.binary])
        if not out:
            return True, "objdump unavailable — assuming tainted args"

        # Find the call site address
        call_pat = re.compile(
            r"^\s*([0-9a-f]+):\s+.*<" + re.escape(sink_fn) + r"(?:@plt)?>",
            re.MULTILINE
        )
        matches = list(call_pat.finditer(out))
        if not matches:
            return True, "Call site not found — conservative PROBABLE"

        # Analyse first call site
        m      = matches[0]
        # Grab ~30 lines before this position
        start  = max(0, out.rfind("\n", 0, m.start() - 1))
        chunk  = out[max(0, start - 2000): m.start()]
        lines  = [l.strip() for l in chunk.splitlines() if l.strip()][-25:]

        # Check if any arg register is loaded from memory (tainted)
        mem_load_pat = re.compile(
            r"\b(mov|lea)\b.*?(" + "|".join(self.regs) + r")\s*,\s*"
            r"(?:QWORD PTR|DWORD PTR|PTR)?\s*\[",
            re.IGNORECASE
        )
        imm_load_pat = re.compile(
            r"\b(mov)\b.*?(" + "|".join(self.regs) + r")\s*,\s*0x[0-9a-f]+",
            re.IGNORECASE
        )

        mem_hits = [l for l in lines if mem_load_pat.search(l)]
        imm_hits = [l for l in lines if imm_load_pat.search(l)]

        if mem_hits:
            return True, (
                f"Argument loaded from memory (stack/heap) before call: "
                f"'{mem_hits[-1][:80]}'"
            )
        if imm_hits and not mem_hits:
            return False, (
                f"Argument is immediate constant before call: "
                f"'{imm_hits[-1][:80]}'"
            )

        return True, "Could not determine arg source — conservative PROBABLE"


# ── Main analyzer ─────────────────────────────────────────────────────────────

class TaintAnalyzer:
    def __init__(self, binary: str, arch: str, bits: int) -> None:
        self.binary = binary
        self.cg     = FastCallGraph(binary)
        self.af     = ArgFlow(binary, bits)
        self._built = False

    def _ensure_built(self) -> None:
        if not self._built:
            self.cg.build()
            self._built = True

    def analyze(self, sink_fn: str, sink_addr: str) -> TaintResult:
        self._ensure_built()

        evidence: list[str] = []

        # 1. Reverse BFS: can we trace back to a source?
        rev_path = self.cg.bfs_to_source(sink_fn)

        # 2. Forward BFS as secondary check
        fwd_path = self.cg.bfs_from_sources(sink_fn)

        path = rev_path or fwd_path

        if path:
            tainted, reason = self.af.check(sink_fn, sink_addr)
            evidence.append(f"Call path: {' → '.join(path)}")
            evidence.append(f"Register analysis: {reason}")

            if tainted:
                conf = "CONFIRMED"
                notes = f"Direct taint path found and register args appear user-controlled"
            else:
                conf = "PROBABLE"
                notes = "Call path found but args appear to be immediate constants"

            return TaintResult(
                sink_function=sink_fn,
                sink_address=sink_addr,
                confidence=conf,
                taint_path=path,
                source_function=path[0],
                evidence=evidence,
                notes=notes,
            )

        # 3. No path — check if the function is at least called from somewhere
        callers = self.cg.callers_of(sink_fn)
        if callers:
            evidence.append(f"Called from: {', '.join(callers[:5])}")
            return TaintResult(
                sink_function=sink_fn,
                sink_address=sink_addr,
                confidence="PROBABLE",
                taint_path=[],
                source_function=callers[0] if callers else "unknown",
                evidence=evidence,
                notes="No direct source-to-sink path found, but function is reachable",
            )

        # 4. Function not found in call graph
        return TaintResult(
            sink_function=sink_fn,
            sink_address=sink_addr,
            confidence="UNCONFIRMED",
            taint_path=[],
            source_function="none",
            evidence=["Function not found in call graph — may be dead code or PLT-only"],
            notes="Unreachable / not analysable",
        )


# ── Public API ────────────────────────────────────────────────────────────────

def enrich_vuln_points(
    vuln_points: list,
    binary: str,
    arch: str,
    bits: int,
    min_confidence: str = "PROBABLE",
) -> list:
    """
    Run taint analysis on every VulnPoint and filter by minimum confidence.
    Updates vp.confidence and vp.evidence in-place.
    Returns the filtered list.
    """
    analyzer  = TaintAnalyzer(binary, arch, bits)
    threshold = CONFIDENCE_RANK.get(min_confidence, 2)
    filtered  = []

    for vp in vuln_points:
        # PrivilegeEscalation findings are always kept as-is
        if vp.category == "PrivilegeEscalation":
            filtered.append(vp)
            continue

        result = analyzer.analyze(vp.function_name, vp.location)

        # Update the VulnPoint
        vp.confidence = result.confidence
        for ev in result.evidence:
            vp.evidence.append(f"[Taint] {ev}")
        vp.evidence.append(f"[Taint] {result.notes}")

        if CONFIDENCE_RANK.get(result.confidence, 1) >= threshold:
            filtered.append(vp)

    return filtered
