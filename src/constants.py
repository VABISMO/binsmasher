"""Shared constants for BinSmasher.

Single source of truth for version strings, win-function patterns,
RCE confirmation markers, and other values used across modules.
"""
from __future__ import annotations

# ── Version ──────────────────────────────────────────────────────────────────
VERSION = "4.4.0"

# ── Win-function detection patterns ──────────────────────────────────────────
# Used by: win_detector.py, orchestrator.py, arm64.py, session.py,
#          core_analysis.py, angr_analysis.py
# NOTE: The canonical source of truth for this list is
#       exploiter/win_detector.py (where the win detector lives).
# constants.py cannot `from exploiter.win_detector import DEFAULT_WIN_PATTERNS`
# because exploiter/__init__.py imports modules that import constants at top
# level (e.g. exploiter/orchestrator.py, exploiter/gadgets.py), which creates a
# circular import. Keep this list BYTE-FOR-BYTE identical to the one in
# exploiter/win_detector.py. Do NOT add "system" — it is a libc function, not a
# win function (jumping to system@plt without rdi setup doesn't work); see the
# comment in exploiter/win_detector.py.
DEFAULT_WIN_PATTERNS = [
    # Common CTF patterns
    "win", "flag", "shell", "backdoor", "secret", "easy",
    # Variations
    "print_flag", "cat_flag", "get_flag", "read_flag", "show_flag",
    "get_shell", "give_shell", "spawn_shell", "drop_shell",
    "spawn", "pwned", "success", "solve", "victory", "solved",
    # Challenge-specific patterns
    "exec_shell", "do_shell", "run_shell",
    # Common naming conventions
    "win_func", "flag_func", "shell_func", "getFlag", "getShell",
    # Hidden/backdoor patterns
    "hidden", "debug", "admin", "root", "priv",
    # Numeric patterns (sometimes used)
    "func_win", "pwn",
]

# ── RCE confirmation markers ────────────────────────────────────────────────
# Checked in exploit output to confirm shell/RCE
# Union of all previously-used marker lists across the codebase
WIN_MARKERS = [
    b"uid=", b"uid=0", b"uid=1",
    b"PWNED", b"pwned", b"PWNED{",
    b"flag{", b"FLAG{",
    b"root:", b"sh-",
    b"$ ", b"# ",
    b"/bin/sh", b"/bin/bash",
    b"CFI_BYPASS", b"HEAP_PWNED", b"REVSHELL_OK", b"SHELLPWNED",
    b"Congratulations", b"congratulations",
    b"You won", b"you won", b"correct",
    b"level passed", b"passwd", b"success",
]

# ── Default bad bytes ───────────────────────────────────────────────────────
DEFAULT_BAD_BYTES = b"\x00\x0a\x0d"

# ── Default libc path (Linux x86_64) ────────────────────────────────────────
DEFAULT_LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6"

# ── Default ports and hosts ─────────────────────────────────────────────────
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 4444
DEFAULT_CMD = "id"