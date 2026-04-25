"""
Binary analysis cache — saves r2/checksec results keyed by file hash.
Avoids re-running expensive analysis on the same binary.
"""
from __future__ import annotations
import hashlib
import json
import logging
import os
import time

log = logging.getLogger("binsmasher")

CACHE_DIR = os.path.join(os.path.expanduser("~"), ".binsmasher_cache")
CACHE_VERSION = 2
MAX_AGE_SECONDS = 86400 * 7   # 1 week


def _binary_hash(binary_path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(binary_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()[:16]


def _cache_path(binary_path: str) -> str:
    os.makedirs(CACHE_DIR, exist_ok=True)
    bname = os.path.basename(binary_path)
    bhash = _binary_hash(binary_path)
    if not bhash:
        return ""
    return os.path.join(CACHE_DIR, f"{bname}_{bhash}_v{CACHE_VERSION}.json")


def load_cache(binary_path: str, key: str) -> dict | None:
    """Load a cached result. Returns None on miss or stale."""
    path = _cache_path(binary_path)
    if not path or not os.path.isfile(path):
        return None
    try:
        data = json.loads(open(path).read())
        if time.time() - data.get("_ts", 0) > MAX_AGE_SECONDS:
            log.debug(f"[cache] stale: {path}")
            return None
        result = data.get(key)
        if result is not None:
            log.debug(f"[cache] hit: {binary_path} / {key}")
        return result
    except Exception as e:
        log.debug(f"[cache] load error: {e}")
        return None


def save_cache(binary_path: str, key: str, value) -> None:
    """Save a result to cache."""
    path = _cache_path(binary_path)
    if not path:
        return
    try:
        data = {}
        if os.path.isfile(path):
            try:
                data = json.loads(open(path).read())
            except Exception:
                data = {}
        data["_ts"] = time.time()
        data[key] = value
        with open(path, "w") as f:
            json.dump(data, f)
        log.debug(f"[cache] saved: {binary_path} / {key}")
    except Exception as e:
        log.debug(f"[cache] save error: {e}")


def clear_cache(binary_path: str | None = None) -> None:
    """Clear cache for a binary, or entire cache if binary_path is None."""
    if binary_path:
        path = _cache_path(binary_path)
        if path and os.path.isfile(path):
            os.unlink(path)
            log.info(f"[cache] cleared: {binary_path}")
    else:
        import shutil
        shutil.rmtree(CACHE_DIR, ignore_errors=True)
        log.info("[cache] cleared all")
