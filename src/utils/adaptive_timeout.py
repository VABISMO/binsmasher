"""
Adaptive timeout based on measured RTT to the target.

Prevents false negatives on high-latency CTF servers (VPN, remote).
All BinSmasher timeouts scale from a single RTT measurement.
"""
from __future__ import annotations

import logging
import socket
import time

log = logging.getLogger("binsmasher")

# Multipliers for different operation types
RTT_MULTIPLIERS = {
    "connect":    3.0,    # connection establishment
    "banner":     2.0,    # reading the welcome banner
    "send_recv":  5.0,    # send payload + receive response
    "recvall":    8.0,    # recvall (may need multiple RTTs)
    "exploit":   15.0,    # full exploit cycle
    "brute":      1.5,    # single brute attempt (keep fast)
}

MIN_TIMEOUTS = {
    "connect": 1.0,
    "banner":  0.5,
    "send_recv": 2.0,
    "recvall":  3.0,
    "exploit": 5.0,
    "brute":   0.5,
}

MAX_TIMEOUTS = {
    "connect": 30.0,
    "banner":  10.0,
    "send_recv": 30.0,
    "recvall":  60.0,
    "exploit": 120.0,
    "brute":   5.0,
}


def measure_rtt(host: str, port: int, samples: int = 3) -> float:
    """
    Measure round-trip time to host:port in seconds.
    Returns median of {samples} TCP connect measurements.
    Uses TCP handshake time as RTT proxy.
    """
    times = []
    for _ in range(samples):
        try:
            t0 = time.perf_counter()
            sock = socket.create_connection((host, port), timeout=5.0)
            t1 = time.perf_counter()
            sock.close()
            times.append(t1 - t0)
        except Exception:
            pass
        time.sleep(0.05)

    if not times:
        log.debug("[rtt] Could not measure RTT — using defaults")
        return 0.05  # 50ms default for localhost

    times.sort()
    rtt = times[len(times) // 2]  # median
    log.info(f"[rtt] RTT to {host}:{port} = {rtt*1000:.1f}ms "
             f"(samples: {[f'{t*1000:.0f}ms' for t in times]})")
    return rtt


class AdaptiveTimeout:
    """
    Holds RTT-scaled timeouts for all operations.

    Usage:
        at = AdaptiveTimeout(host, port)
        # Measurements happen lazily or explicitly
        at.measure()

        conn.settimeout(at.connect)
        conn.recvline(timeout=at.banner)
        conn.sendline(payload)
        data = conn.recvall(timeout=at.recvall)
    """

    def __init__(self, host: str, port: int,
                 rtt: float | None = None):
        self.host = host
        self.port = port
        self._rtt = rtt
        self._measured = rtt is not None

    def measure(self, samples: int = 3) -> float:
        """Explicitly measure RTT. Cached after first call."""
        if not self._measured:
            self._rtt = measure_rtt(self.host, self.port, samples)
            self._measured = True
        return self._rtt

    @property
    def rtt(self) -> float:
        if not self._measured:
            self.measure()
        return self._rtt

    def _timeout(self, op: str) -> float:
        rtt = self.rtt
        mult = RTT_MULTIPLIERS.get(op, 5.0)
        min_t = MIN_TIMEOUTS.get(op, 1.0)
        max_t = MAX_TIMEOUTS.get(op, 60.0)
        return max(min_t, min(max_t, rtt * mult + rtt))

    @property
    def connect(self) -> float:
        return self._timeout("connect")

    @property
    def banner(self) -> float:
        return self._timeout("banner")

    @property
    def send_recv(self) -> float:
        return self._timeout("send_recv")

    @property
    def recvall(self) -> float:
        return self._timeout("recvall")

    @property
    def exploit(self) -> float:
        return self._timeout("exploit")

    @property
    def brute(self) -> float:
        return self._timeout("brute")

    def __repr__(self) -> str:
        rtt = self._rtt if self._measured else "?"
        return (f"AdaptiveTimeout(rtt={rtt}, "
                f"connect={self.connect:.1f}s, "
                f"send_recv={self.send_recv:.1f}s, "
                f"exploit={self.exploit:.1f}s)")


# ── Integration helper ────────────────────────────────────────────────────────

_GLOBAL_AT: AdaptiveTimeout | None = None


def get_adaptive_timeout(host: str, port: int,
                          force_remeasure: bool = False) -> AdaptiveTimeout:
    """Get or create a global AdaptiveTimeout for the current target."""
    global _GLOBAL_AT
    if (_GLOBAL_AT is None
            or _GLOBAL_AT.host != host
            or _GLOBAL_AT.port != port
            or force_remeasure):
        _GLOBAL_AT = AdaptiveTimeout(host, port)
    return _GLOBAL_AT


def patch_connect_with_adaptive_timeout(exploiter_instance) -> None:
    """
    Monkey-patch an ExploitGenerator instance so _connect() uses
    adaptive timeouts instead of the hardcoded 3.0s.

    Call after creating the ExploitGenerator but before find_offset().
    """
    at = get_adaptive_timeout(exploiter_instance.host,
                               exploiter_instance.port)

    original_connect = exploiter_instance._connect.__func__

    def adaptive_connect(self, retries=1, timeout=None):
        effective_timeout = timeout if timeout is not None else at.connect
        return original_connect(self, retries=retries, timeout=effective_timeout)

    import types
    exploiter_instance._connect = types.MethodType(adaptive_connect, exploiter_instance)
    log.info(f"[adaptive] Patched _connect: timeout={at.connect:.1f}s "
             f"(RTT={at.rtt*1000:.0f}ms)")
