"""BinSmasher – analyzer package.

Importable exactly as the original analyzer.py:
    from analyzer import BinaryAnalyzer
"""

from .static import StaticAnalysisMixin
from .protections import ProtectionsMixin
from .dynamic import DynamicAnalysisMixin
from .library import LibraryMixin
from .seccomp import SeccompMixin
from .recovery import RecoveryMixin


class BinaryAnalyzer(
    DynamicAnalysisMixin,   # setup_context, frida_analyze
    StaticAnalysisMixin,    # static_analysis, _list_functions, _r2, VULNERABLE_FUNCTIONS, …
    ProtectionsMixin,       # check_protections, _checksec_*
    LibraryMixin,           # load_library_offsets, query_libc_rip, …
    SeccompMixin,           # detect_seccomp, patch_binary_for_local
    RecoveryMixin,          # recover_functions_stripped, mte_info, grep_unsafe_source
):
    """Static & dynamic binary analysis.

    Composed from thematic mixin classes; the public API is identical
    to the original single-file BinaryAnalyzer.
    """

    def __init__(self, binary: str, log_file: str) -> None:
        self.binary = binary
        self.log_file = log_file
        self.platform = "linux"
        self.arch = "amd64"


__all__ = ["BinaryAnalyzer"]

from .cache import load_cache, save_cache, clear_cache
from .angr_analysis import angr_find_win, angr_find_vulnerabilities

from .vuln_detect import VulnDetector, VulnInfo
from .libc_db import (resolve_from_leak, lookup_by_symbol,
                       detect_libc_version, get_one_gadgets, LIBC_DB)
