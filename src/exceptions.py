"""BinSmasher exception hierarchy.

Provides structured error handling instead of bare except/return None.
Each exception class carries meaningful context about what went wrong.
"""
from __future__ import annotations


class BinSmasherError(Exception):
    """Base exception for all BinSmasher errors."""
    pass


class OffsetNotFound(BinSmasherError):
    """Could not determine the overflow offset.

    Attributes:
        method: Which detection method was tried (corefile, gdb, remote, udp)
        pattern_size: Cyclic pattern size that was used
        binary: Path to the binary being analyzed
    """
    def __init__(self, method: str = "", pattern_size: int = 0,
                 binary: str = "", details: str = ""):
        self.method = method
        self.pattern_size = pattern_size
        self.binary = binary
        msg = f"Offset not found via {method}"
        if details:
            msg += f": {details}"
        super().__init__(msg)


class ExploitFailed(BinSmasherError):
    """Exploit was attempted but RCE was not confirmed.

    Attributes:
        technique: Which exploit technique was used (ret2win, ret2libc, etc.)
        offset: Overflow offset that was used
        payload_size: Size of the exploit payload in bytes
        output: Raw output from the target (if any)
    """
    def __init__(self, technique: str = "", offset: int = 0,
                 payload_size: int = 0, output: bytes = b""):
        self.technique = technique
        self.offset = offset
        self.payload_size = payload_size
        self.output = output
        super().__init__(
            f"Exploit '{technique}' failed at offset {offset} "
            f"(payload={payload_size}B, output={len(output)}B)")


class ConnectionFailed(BinSmasherError):
    """Could not connect to the target service.

    Attributes:
        host: Target host
        port: Target port
        retries: Number of connection attempts
        tls: Whether TLS was used
    """
    def __init__(self, host: str = "", port: int = 0,
                 retries: int = 0, tls: bool = False):
        self.host = host
        self.port = port
        self.retries = retries
        self.tls = tls
        proto = "TLS" if tls else "TCP"
        super().__init__(
            f"Connection to {proto}://{host}:{port} failed after {retries} retries")


class CanaryLeakFailed(BinSmasherError):
    """Could not leak the stack canary.

    Attributes:
        methods_tried: List of methods that were attempted
        is_fork: Whether the binary was detected as a fork server
    """
    def __init__(self, methods_tried: list | None = None,
                 is_fork: bool = False):
        self.methods_tried = methods_tried or []
        self.is_fork = is_fork
        fork_str = " (fork-server)" if is_fork else ""
        super().__init__(
            f"Canary leak failed{fork_str}: tried {', '.join(self.methods_tried)}")


class LibcNotFound(BinSmasherError):
    """Could not identify or locate the libc library.

    Attributes:
        symbol: Symbol that was used for the leak attempt
        leaked_addr: Address that was leaked (if any)
        tried_local: Whether local libc lookup was attempted
        tried_api: Whether libc.rip API was attempted
    """
    def __init__(self, symbol: str = "", leaked_addr: int = 0,
                 tried_local: bool = False, tried_api: bool = False):
        self.symbol = symbol
        self.leaked_addr = leaked_addr
        self.tried_local = tried_local
        self.tried_api = tried_api
        addr_str = f" @ {hex(leaked_addr)}" if leaked_addr else ""
        super().__init__(f"Libc not found for {symbol}{addr_str}")


class NoGadgetsFound(BinSmasherError):
    """Required ROP gadgets were not found in the binary.

    Attributes:
        gadget_names: List of gadget names that were not found
        binary: Path to the binary
    """
    def __init__(self, gadget_names: list | None = None, binary: str = ""):
        self.gadget_names = gadget_names or []
        self.binary = binary
        super().__init__(
            f"Required gadgets not found: {', '.join(self.gadget_names)}")


class SeccompDetected(BinSmasherError):
    """Seccomp sandbox detected that blocks the current exploit strategy.

    Attributes:
        blocked_syscalls: Syscalls that are blocked
        orw_needed: Whether open/read/write is still allowed
    """
    def __init__(self, blocked_syscalls: list | None = None,
                 orw_needed: bool = False):
        self.blocked_syscalls = blocked_syscalls or []
        self.orw_needed = orw_needed
        super().__init__(
            f"Seccomp blocks: {', '.join(self.blocked_syscalls[:5])}"
            f"{'... ORW recommended' if orw_needed else ''}")


class PayloadTooLarge(BinSmasherError):
    """Exploit payload exceeds the available buffer size.

    Attributes:
        payload_size: Size of the generated payload
        max_size: Maximum size that fits in the buffer
        technique: Exploit technique that generated the payload
    """
    def __init__(self, payload_size: int = 0, max_size: int = 0,
                 technique: str = ""):
        self.payload_size = payload_size
        self.max_size = max_size
        self.technique = technique
        super().__init__(
            f"Payload ({payload_size}B) exceeds buffer ({max_size}B) "
            f"for {technique}")


class ShellcodeGenerationFailed(BinSmasherError):
    """Could not generate shellcode for the target architecture.

    Attributes:
        arch: Target architecture
        cmd: Command that was requested
        bad_bytes: Bad bytes that must be avoided
    """
    def __init__(self, arch: str = "", cmd: str = "",
                 bad_bytes: bytes = b""):
        self.arch = arch
        self.cmd = cmd
        self.bad_bytes = bad_bytes
        super().__init__(
            f"Shellcode generation failed for {arch} (cmd={cmd!r}, "
            f"bad_bytes={len(bad_bytes)})")


class BinaryAnalysisFailed(BinSmasherError):
    """Static or dynamic binary analysis failed.

    Attributes:
        binary: Path to the binary
        reason: Reason for failure
    """
    def __init__(self, binary: str = "", reason: str = ""):
        self.binary = binary
        self.reason = reason
        super().__init__(f"Analysis failed for {binary}: {reason}")