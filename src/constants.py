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
DEFAULT_WIN_PATTERNS = [
    "win", "flag", "shell", "backdoor", "secret", "easy",
    "print_flag", "cat_flag", "get_flag", "read_flag", "show_flag",
    "get_shell", "give_shell", "spawn_shell", "drop_shell",
    "spawn", "pwned", "success", "solve", "victory", "solved",
    "system", "exec_shell", "do_shell", "run_shell",
    "win_func", "flag_func", "shell_func",
    "getFlag", "getShell", "hidden", "debug", "admin", "root",
    "priv", "func1", "func_win", "pwn", "ret",
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