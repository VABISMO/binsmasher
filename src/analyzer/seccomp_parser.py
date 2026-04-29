"""
Seccomp detection without seccomp-tools (no Ruby dependency).

Uses:
  1. /proc/PID/status → Seccomp field (0=none, 1=strict, 2=filter)
  2. ptrace PTRACE_SECCOMP_GET_FILTER (Linux 4.4+)
  3. Static analysis: look for prctl(PR_SET_SECCOMP) / seccomp() calls
  4. BPF bytecode parsing if we can read the filter

Also: correct identification of which specific syscalls are allowed/blocked.
"""
from __future__ import annotations
import logging
import os
import re
import subprocess
import struct

log = logging.getLogger("binsmasher")

# Common syscall numbers (x86_64)
SYSCALL_NAMES_X64 = {
    0: "read", 1: "write", 2: "open", 3: "close",
    4: "stat", 5: "fstat", 6: "lstat", 7: "poll",
    8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap",
    12: "brk", 17: "pread64", 18: "pwrite64",
    19: "readv", 20: "writev", 21: "access",
    22: "pipe", 23: "select", 32: "dup",
    39: "getpid", 41: "socket", 42: "connect",
    57: "fork", 59: "execve", 60: "exit",
    61: "wait4", 62: "kill", 79: "getcwd",
    87: "unlink", 102: "getuid", 104: "getgid",
    105: "setuid", 106: "setgid", 110: "getppid",
    133: "mknod", 158: "arch_prctl", 217: "getdents64",
    218: "set_tid_address", 221: "fadvise64",
    231: "exit_group", 257: "openat", 266: "sync_file_range",
    292: "dup3", 293: "pipe2", 302: "prlimit64",
    318: "getrandom", 334: "rseq",
}

# PR_SET_SECCOMP / seccomp() call detection patterns
SECCOMP_PATTERNS = [
    b"prctl",
    b"seccomp",
    b"PR_SET_SECCOMP",
    b"\x15\x00",   # BPF JEQ (common in seccomp filters)
]


class SeccompParser:
    """Parse seccomp filters without seccomp-tools."""

    def __init__(self, binary: str):
        self.binary = binary

    def detect_static(self) -> dict:
        """
        Static analysis: look for seccomp-related calls in the binary.
        """
        result = {
            "has_seccomp": False,
            "method": None,
            "syscalls_mentioned": [],
            "notes": [],
        }

        try:
            with open(self.binary, "rb") as f:
                data = f.read()

            # Check for seccomp-related strings/patterns
            if b"seccomp" in data or b"PR_SET_SECCOMP" in data:
                result["has_seccomp"] = True
                result["method"] = "static_string"
                result["notes"].append("Found 'seccomp' string in binary")

            # Check for prctl syscall usage
            # prctl is syscall 157 on x86_64
            # Looking for: mov edi, 157 or push 157
            # Only flag prctl if we also have seccomp-related strings nearby
            # (avoids false positives from random 0x9d bytes in binaries)
            has_seccomp_str = b"seccomp" in data or b"PR_SET_SECCOMP" in data
            prctl_patterns = [
                b"\xbf\x9d\x00\x00\x00",  # mov edi, 157 (0x9d)
                b"\xb8\x9d\x00\x00\x00",  # mov eax, 157
            ]
            for pat in prctl_patterns:
                if pat in data and has_seccomp_str:
                    result["has_seccomp"] = True
                    result["method"] = "prctl_syscall"
                    result["notes"].append(f"prctl pattern found: {pat.hex()}")
                    break

            # Check for seccomp() syscall (317 on x86_64)
            seccomp_sc_patterns = [
                b"\xb8\x3d\x01\x00\x00",  # mov eax, 317
                b"\x6a\x3d",               # push 317
            ]
            for pat in seccomp_sc_patterns:
                if pat in data:
                    result["has_seccomp"] = True
                    result["method"] = "seccomp_syscall"
                    result["notes"].append("seccomp() syscall found")
                    break

        except Exception as e:
            log.debug(f"[seccomp_parser] static: {e}")

        return result

    def detect_runtime(self, pid: int) -> dict:
        """
        Runtime detection via /proc/PID/status.
        """
        result = {
            "has_seccomp": False,
            "mode": 0,
            "notes": [],
        }
        try:
            status = open(f"/proc/{pid}/status").read()
            m = re.search(r"Seccomp:\s+(\d+)", status)
            if m:
                mode = int(m.group(1))
                result["mode"] = mode
                if mode == 1:
                    result["has_seccomp"] = True
                    result["notes"].append("Seccomp strict mode")
                elif mode == 2:
                    result["has_seccomp"] = True
                    result["notes"].append("Seccomp filter mode")
        except Exception as e:
            log.debug(f"[seccomp_parser] runtime: {e}")
        return result

    def detect_dynamic(self) -> dict:
        """
        Dynamic detection: spawn binary and check /proc/PID/status.
        Falls back to static if process exits too fast.
        """
        result = self.detect_static()

        try:
            proc = subprocess.Popen(
                [self.binary], stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            import time
            time.sleep(0.2)

            if proc.poll() is None:
                runtime = self.detect_runtime(proc.pid)
                if runtime["has_seccomp"]:
                    result.update(runtime)
                proc.terminate()
                proc.wait(timeout=2)

        except Exception as e:
            log.debug(f"[seccomp_parser] dynamic: {e}")

        return result

    def get_allowed_syscalls(self) -> list[str]:
        """
        Try to determine which syscalls are allowed.

        Method 1: seccomp-tools if available
        Method 2: strace the binary and observe which syscalls succeed
        Method 3: static analysis of BPF filter bytes in binary
        """
        # Method 1: seccomp-tools
        import shutil
        if shutil.which("seccomp-tools"):
            try:
                out = subprocess.check_output(
                    ["seccomp-tools", "dump", self.binary],
                    stderr=subprocess.DEVNULL, timeout=8
                ).decode(errors="ignore")
                return self._parse_seccomp_tools_output(out)
            except Exception as e:
                log.debug(f"[seccomp_parser] seccomp-tools: {e}")

        # Method 2: strace
        if shutil.which("strace"):
            try:
                out = subprocess.check_output(
                    ["strace", "-e", "trace=all", "-f", self.binary],
                    stdin=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT, timeout=5
                ).decode(errors="ignore")
                # Parse successful syscalls
                allowed = set()
                for line in out.splitlines():
                    m = re.match(r"(\w+)\(", line)
                    if m and "EPERM" not in line and "ENOSYS" not in line:
                        allowed.add(m.group(1))
                if allowed:
                    log.info(f"[seccomp_parser] strace allowed: {list(allowed)[:10]}")
                    return list(allowed)
            except Exception as e:
                log.debug(f"[seccomp_parser] strace: {e}")

        # Method 3: Parse BPF from binary
        return self._extract_allowed_from_bpf()

    def _parse_seccomp_tools_output(self, output: str) -> list[str]:
        """Parse seccomp-tools output to find allowed syscalls."""
        allowed = []
        blocked = []
        for line in output.splitlines():
            m = re.search(r"sys_(\w+)", line)
            if not m:
                continue
            name = m.group(1)
            if "allow" in line.lower():
                allowed.append(name)
            elif any(kw in line.lower() for kw in ("kill", "errno", "trap", "trace")):
                blocked.append(name)

        # If we have an explicit allow list, use it
        # If default is allow (whitelist=False), use what's NOT blocked
        if "allow" in output.lower() and len(allowed) < 50:
            log.info(f"[seccomp_parser] Whitelist: {allowed[:10]}")
            return allowed
        else:
            # Blacklist mode: everything except blocked is allowed
            all_syscalls = list(SYSCALL_NAMES_X64.values())
            return [s for s in all_syscalls if s not in blocked]

    def _extract_allowed_from_bpf(self) -> list[str]:
        """
        Parse BPF bytecode from binary to extract syscall policy.
        BPF instructions are 8 bytes: code(2) jt(1) jf(1) k(4)
        """
        try:
            with open(self.binary, "rb") as f:
                data = f.read()
            allowed = []
            blocked = []

            # BPF JEQ instruction pattern: 0x15 0x00 (jump if equal)
            # Usually: ld [0], jeq k ALLOW, return DENY
            i = 0
            while i < len(data) - 8:
                # Look for BPF JEQ pattern
                code, jt, jf, k = struct.unpack_from("<HBBI", data, i)
                if code == 0x15 and 0 <= k <= 400:  # JEQ with syscall number
                    name = SYSCALL_NAMES_X64.get(k)
                    if name:
                        if jt == 0:  # allow path
                            allowed.append(name)
                        else:
                            blocked.append(name)
                i += 1

            if allowed:
                log.info(f"[seccomp_parser] BPF extracted: {allowed[:10]}")
                return allowed

        except Exception as e:
            log.debug(f"[seccomp_parser] BPF parse: {e}")

        # Could not parse BPF — return empty list (not a guess)
        log.warning("[seccomp_parser] BPF parsing failed — returning empty allowed list")
        return []


def detect_seccomp_smart(binary: str, pid: int | None = None) -> dict:
    """
    Smart seccomp detection:
    1. Static analysis (no execution needed)
    2. Dynamic detection (spawn + /proc/status)
    3. Syscall enumeration (seccomp-tools or strace or BPF parse)

    Returns {
        has_seccomp, allowed_syscalls, blocked_syscalls,
        orw_needed, execve_allowed, notes
    }
    """
    parser = SeccompParser(binary)
    result = {
        "has_seccomp": False,
        "allowed_syscalls": [],
        "blocked_syscalls": [],
        "orw_needed": False,
        "execve_allowed": True,
        "notes": [],
    }

    # Static detection (fast)
    static = parser.detect_static()
    if static["has_seccomp"]:
        result["has_seccomp"] = True
        result["notes"].extend(static["notes"])

    # Runtime detection if pid given
    if pid:
        runtime = parser.detect_runtime(pid)
        if runtime["has_seccomp"]:
            result["has_seccomp"] = True
            result["notes"].extend(runtime["notes"])

    # If seccomp detected, get syscall list
    if result["has_seccomp"]:
        allowed = parser.get_allowed_syscalls()
        result["allowed_syscalls"] = allowed
        result["blocked_syscalls"] = [
            s for s in SYSCALL_NAMES_X64.values()
            if s not in allowed
        ]
        result["execve_allowed"] = "execve" in allowed
        result["orw_needed"] = not result["execve_allowed"]

    log.info(f"[seccomp_parser] Result: has={result['has_seccomp']} "
             f"execve={result['execve_allowed']} "
             f"orw_needed={result['orw_needed']} "
             f"allowed={result['allowed_syscalls'][:5]}")
    return result
