"""Process helpers: core-dump suppression and shared temp-dir management."""
import os
import glob
import shutil
import tempfile
import threading

# ── Dedicated temp root ───────────────────────────────────────────────────────
# All BinSmasher runtime junk (cores, GDB scripts, work dirs, logs) goes here.
# Created once at import time so every module shares the same path.

_tmproot = tempfile.mkdtemp(prefix="binsmasher_")
CORE_DIR = os.path.join(_tmproot, "cores")
WORK_DIR = os.path.join(_tmproot, "work")
LOG_DIR  = os.path.join(_tmproot, "logs")

for _d in (CORE_DIR, WORK_DIR, LOG_DIR):
    os.makedirs(_d, exist_ok=True)

_cleanup_registered = False
_cleanup_lock = threading.Lock()


def _register_cleanup() -> None:
    """Register atexit cleanup once — removes the entire tmproot."""
    global _cleanup_registered
    with _cleanup_lock:
        if _cleanup_registered:
            return
        import atexit
        atexit.register(_do_cleanup)
        _cleanup_registered = True


def _do_cleanup() -> None:
    try:
        shutil.rmtree(_tmproot, ignore_errors=True)
    except Exception:
        pass


_register_cleanup()


# ── preexec helpers ───────────────────────────────────────────────────────────

def no_core_preexec() -> None:
    """preexec_fn: disable core dumps for this child process."""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass
    try:
        os.setsid()
    except Exception:
        pass


def core_preexec() -> None:
    """preexec_fn: enable cores, redirect to CORE_DIR."""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE,
                           (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    except Exception:
        pass
    try:
        os.chdir(CORE_DIR)
    except Exception:
        pass
    try:
        os.setsid()
    except Exception:
        pass


# ── core pattern helper ───────────────────────────────────────────────────────

def set_core_pattern(pattern: str | None = None) -> None:
    """Write /proc/sys/kernel/core_pattern. Silently ignores permission errors."""
    target = pattern or os.path.join(CORE_DIR, "core.%e.%p")
    try:
        with open("/proc/sys/kernel/core_pattern", "w") as f:
            f.write(target)
    except Exception:
        pass


def cleanup_cores() -> None:
    """Delete all core files in CORE_DIR."""
    for f in glob.glob(os.path.join(CORE_DIR, "core*")):
        try:
            os.unlink(f)
        except Exception:
            pass


# ── workdir helper ────────────────────────────────────────────────────────────

def get_workdir(binary_path: str) -> str:
    """
    Return a per-binary work directory inside the shared tmp root.
    Never creates directories adjacent to the binary.
    """
    bname = os.path.basename(binary_path) if binary_path else "unknown"
    wd = os.path.join(WORK_DIR, bname)
    os.makedirs(wd, exist_ok=True)
    return wd


def default_log_path(name: str = "binsmasher.log") -> str:
    """Return a log path inside LOG_DIR (never in project root)."""
    return os.path.join(LOG_DIR, name)
