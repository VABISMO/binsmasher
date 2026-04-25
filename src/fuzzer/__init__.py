from __future__ import annotations
"""BinSmasher – fuzzer package.

Importable exactly as the original fuzzer.py:
    from fuzzer import Fuzzer
"""

from .afl import AFLMixin
from .boofuzz_fuzz import BoofuzzMixin
from .mutation import MutationMixin
from .offset_roto import OffsetRotoMixin
from .udp import UDPMixin
from .core_analysis import CoreAnalysisMixin
from .gdb_scripts import GDBScriptsMixin
from .solana import SolanaMixin


class Fuzzer(
    AFLMixin,           # afl_fuzz
    BoofuzzMixin,       # fuzz_target
    MutationMixin,      # mutation_fuzz
    OffsetRotoMixin,    # find_offset_roto, sigfault_analysis
    UDPMixin,           # find_offset_udp_payload, deliver_exploit_udp, send_raw_payload, …
    CoreAnalysisMixin,  # _find_offset_from_core_stack, _extract_rip_from_coredumpctl, …
    GDBScriptsMixin,    # generate_gdb_script
    SolanaMixin,        # fuzz_bpf, exploit_deser, dos_quic, exploit_snapshot_assert
):
    """Network and binary fuzzer.

    Composed from thematic mixin classes; the public API is identical
    to the original single-file Fuzzer.
    """

    def __init__(self, binary, host, port, log_file, platform):
        self.binary = binary
        self.host = host
        self.port = port
        self.log_file = log_file
        self.platform = platform
        # Set by find_offset_udp after stack scan; read by main for constraint check
        self._last_stack_scan_offset: int | None = None


__all__ = ["Fuzzer"]
