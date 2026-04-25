"""BinSmasher – utils package.

Importable exactly as the original utils.py:
    from utils import ExploitConfig, RichHelpFormatter, setup_logging, print_summary, console
"""

from ._console import console
from .logging_setup import setup_logging
from .config import ExploitConfig
from .display import RichHelpFormatter, print_summary

__all__ = [
    "console",
    "setup_logging",
    "ExploitConfig",
    "RichHelpFormatter",
    "print_summary",
]

from ._process import (
    no_core_preexec,
    core_preexec,
    set_core_pattern,
    cleanup_cores,
    get_workdir,
    default_log_path,
    CORE_DIR,
    WORK_DIR as BS_WORK_DIR,
    LOG_DIR,
)

from .adaptive_timeout import AdaptiveTimeout, get_adaptive_timeout, measure_rtt
from .json_output import build_result, write_json, print_json, write_summary_markdown
