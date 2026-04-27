"""
Dynamic libc offset extraction — NO HARDCODED OFFSETS.
Extracts all symbols dynamically from the actual libc binary using nm/objdump/strings.
Maintains a minimal fallback DB only for offline scenarios.
"""
from __future__ import annotations
import subprocess
import re
import os
import logging
import urllib.request
import json as _json

log = logging.getLogger("binsmasher")

# ── Minimal fallback DB (only for offline/no-binary scenarios) ───────────────
# These are LAST RESORT - dynamic extraction is always preferred
FALLBACK_DB: dict[str, dict[str, int]] = {
    "glibc-2.31-amd64": {
        "system": 0x055410, "puts": 0x080ED0, "binsh": 0x1B75AA,
    },
    "glibc-2.35-amd64": {
        "system": 0x050D70, "puts": 0x080E50, "binsh": 0x1B45BD,
    },
}

LIBC_DB = FALLBACK_DB

# ── Core Dynamic Extraction Functions ─────────────────────────────────────────

def _run_cmd(cmd: list[str], timeout: int = 10) -> str | None:
    """Run a command and return stdout, or None on failure."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            stderr=subprocess.DEVNULL, text=True
        )
        return result.stdout if result.returncode == 0 else None
    except Exception:
        return None


def extract_symbols_from_libc(libc_path: str) -> dict[str, int]:
    """
    Extract ALL symbol offsets dynamically from a libc binary.
    This is the PRIMARY method - no hardcoding.
    """
    if not libc_path or not os.path.isfile(libc_path):
        return {}
    
    offsets = {}
    
    # 1. Extract symbols using nm -D
    nm_out = _run_cmd(["nm", "-D", "--defined-only", libc_path])
    if nm_out:
        for line in nm_out.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                try:
                    addr = int(parts[0], 16)
                    sym_type = parts[1]
                    name = parts[2]
                    # We want function symbols (T, W) and some data (D, B)
                    if sym_type in ("T", "W", "D", "B", "R"):
                        offsets[name] = addr
                except ValueError:
                    pass
    
    # 2. Also try readelf -s for more complete coverage
    readelf_out = _run_cmd(["readelf", "-s", libc_path])
    if readelf_out:
        for line in readelf_out.splitlines():
            # Format:    Num:    Value  Size Type    Bind   Vis      Ndx Name
            # Example:   123: 0000000000055410   45 FUNC    WEAK   DEFAULT   13 system
            parts = line.split()
            if len(parts) >= 8:
                try:
                    addr = int(parts[1], 16)
                    name = parts[7]
                    if "FUNC" in line or "OBJECT" in line:
                        if name not in offsets:
                            offsets[name] = addr
                except ValueError:
                    pass
    
    # 3. Extract /bin/sh string location using strings
    strings_out = _run_cmd(["strings", "-t", "x", libc_path])
    if strings_out:
        for line in strings_out.splitlines():
            if line.strip().endswith("/bin/sh"):
                parts = line.strip().split()
                if parts:
                    try:
                        offsets["binsh"] = int(parts[0], 16)
                        break
                    except ValueError:
                        pass
    
    # 4. Extract common aliases for easier lookup
    if "__libc_system" in offsets and "system" not in offsets:
        offsets["system"] = offsets["__libc_system"]
    if "__GI___libc_start_main" in offsets and "__libc_start_main" not in offsets:
        offsets["__libc_start_main"] = offsets["__GI___libc_start_main"]
    
    log.info(f"[libc_db] Dynamically extracted {len(offsets)} symbols from {libc_path}")
    return offsets


def extract_io_symbols(libc_path: str, offsets: dict[str, int] | None = None) -> dict[str, int]:
    """
    Extract _IO_* symbols needed for FSOP/House of Apple.
    """
    if offsets is None:
        offsets = extract_symbols_from_libc(libc_path)
    
    io_syms = {}
    for name, addr in offsets.items():
        if name.startswith("_IO_"):
            io_syms[name] = addr
    
    # Common aliases
    if "_IO_2_1_stdin_" in offsets:
        io_syms["stdin"] = offsets["_IO_2_1_stdin_"]
    if "_IO_2_1_stdout_" in offsets:
        io_syms["stdout"] = offsets["_IO_2_1_stdout_"]
    if "_IO_2_1_stderr_" in offsets:
        io_syms["stderr"] = offsets["_IO_2_1_stderr_"]
    
    return io_syms


def find_libc_path(binary: str) -> str | None:
    """Find the libc library path used by a binary."""
    # 1. Use ldd
    ldd_out = _run_cmd(["ldd", binary])
    if ldd_out:
        for line in ldd_out.splitlines():
            # Match: libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x...)
            # or: libc.so.6 => /lib/x86_64-linux-gnu/libc-2.31.so (0x...)
            m = re.search(r"libc[^\s]*\s*=>\s*(/\S+libc[^\s]*)", line)
            if m:
                path = m.group(1)
                if os.path.isfile(path):
                    return path
    
    # 2. Try common locations
    common_paths = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/x86_64-linux-gnu/libc-2.31.so",
        "/lib/x86_64-linux-gnu/libc-2.35.so",
        "/lib/aarch64-linux-gnu/libc.so.6",
        "/lib/i386-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/lib/libc.so.6",
    ]
    for path in common_paths:
        if os.path.isfile(path):
            return path
    
    # 3. Try to resolve symlink
    try:
        path = "/lib/x86_64-linux-gnu/libc.so.6"
        if os.path.islink(path):
            real = os.path.realpath(path)
            if os.path.isfile(real):
                return real
    except Exception:
        pass
    
    return None


def detect_glibc_version(libc_path: str | None = None) -> str | None:
    """Detect glibc version from libc binary or system."""
    if libc_path and os.path.isfile(libc_path):
        # Try strings output for version string
        strings_out = _run_cmd(["strings", libc_path])
        if strings_out:
            m = re.search(r"GNU C Library.*?release version (\d+\.\d+)", strings_out)
            if m:
                return m.group(1)
            # Alternative: look for version in path
            m = re.search(r"libc-(\d+\.\d+)\.so", libc_path)
            if m:
                return m.group(1)
    
    # Try ldd --version
    ldd_out = _run_cmd(["ldd", "--version"])
    if ldd_out:
        m = re.search(r"(\d+\.\d+)", ldd_out)
        if m:
            return m.group(1)
    
    return None


def calculate_tcache_offset(libc_path: str, libc_base: int = 0) -> int | None:
    """
    Calculate tcache_perthread_struct offset dynamically.
    This structure varies by glibc version, so we find it dynamically.
    """
    offsets = extract_symbols_from_libc(libc_path)
    
    # Try direct symbol
    if "tcache_perthread_struct" in offsets:
        return offsets["tcache_perthread_struct"]
    
    # Try __libc_tcache as alternative
    if "__libc_tcache" in offsets:
        return offsets["__libc_tcache"]
    
    # Estimate from thread pointer if we have the symbols
    # tcache is usually at thread_area + 0x10 or similar
    # This is architecture and version dependent
    return None


def find_one_gadgets(libc_path: str) -> list[int]:
    """
    Find one_gadget offsets by running one_gadget tool.
    Returns list of candidate offsets.
    """
    try:
        out = subprocess.check_output(
            ["one_gadget", libc_path],
            stderr=subprocess.DEVNULL,
            text=True
        )
        gadgets = []
        for line in out.splitlines():
            m = re.match(r"(0x[0-9a-fA-F]+)", line)
            if m:
                gadgets.append(int(m.group(1), 16))
        if gadgets:
            log.info(f"[libc_db] Found {len(gadgets)} one_gadgets")
        return gadgets
    except FileNotFoundError:
        log.debug("[libc_db] one_gadget tool not installed")
        return []
    except Exception as e:
        log.debug(f"[libc_db] one_gadget error: {e}")
        return []


# ── Page-offset index for libc fingerprinting ────────────────────────────────

_PAGE_INDEX: dict[tuple[str, str], list[str]] = {}


def _build_fallback_index() -> None:
    """Build index for fallback DB lookups."""
    global _PAGE_INDEX
    _PAGE_INDEX = {}
    for libc_key, symbols in FALLBACK_DB.items():
        for sym, off in symbols.items():
            page_off = hex(off & 0xfff)
            key = (sym, page_off)
            if key not in _PAGE_INDEX:
                _PAGE_INDEX[key] = []
            _PAGE_INDEX[key].append(libc_key)


_build_fallback_index()


# ── Public API ────────────────────────────────────────────────────────────────

def lookup_by_symbol(symbol: str, leaked_addr: int) -> list[dict]:
    """
    Given a leaked address for a known symbol, find matching libc entries.
    Returns list of { libc_key, libc_base, offsets }.
    """
    page_off = hex(leaked_addr & 0xfff)
    key = (symbol, page_off)
    matches = _PAGE_INDEX.get(key, [])
    
    results = []
    for libc_key in matches:
        sym_off = FALLBACK_DB[libc_key].get(symbol)
        if sym_off is None:
            continue
        libc_base = leaked_addr - sym_off
        if libc_base & 0xfff != 0:
            continue
        results.append({
            "libc_key": libc_key,
            "libc_base": libc_base,
            "offsets": FALLBACK_DB[libc_key],
            "sym_offset": sym_off,
        })
        log.info(f"[libc_db] Fallback match: {libc_key}  base={hex(libc_base)}")
    
    return results


def get_offsets(libc_key: str) -> dict:
    """Get offsets for a libc key (fallback only)."""
    return FALLBACK_DB.get(libc_key, {})


def get_one_gadgets(libc_key: str) -> list[int]:
    """Return one_gadget offsets for a libc key (fallback only)."""
    d = FALLBACK_DB.get(libc_key, {})
    gadgets = []
    for i in range(10):
        off = d.get(f"one_gadget_{i}")
        if off:
            gadgets.append(off)
    return gadgets


def resolve_from_leak(symbol: str, leaked_addr: int,
                      libc_path: str | None = None) -> dict | None:
    """
    Resolve libc base and all offsets from a leaked symbol address.
    
    Priority:
    1. Extract dynamically from libc_path on disk (nm/objdump/strings)
    2. Query libc.rip API (internet)
    3. Use fallback DB (offline last resort)
    """
    # 1. Dynamic extraction from libc on disk
    if libc_path and os.path.isfile(libc_path):
        offsets = extract_symbols_from_libc(libc_path)
        if symbol in offsets:
            sym_off = offsets[symbol]
            libc_base = leaked_addr - sym_off
            if libc_base & 0xfff == 0:  # Page-aligned
                absolute = {k: libc_base + v for k, v in offsets.items()}
                absolute["__libc_base__"] = libc_base
                absolute["_libc_key"] = f"dynamic:{libc_path}"
                log.info(f"[libc_db] Resolved dynamically from {libc_path}: base={hex(libc_base)}")
                return absolute
    
    # 2. libc.rip API
    try:
        page_off = hex(leaked_addr & 0xfff)
        url = f"https://libc.rip/api/v1/find?symbols={symbol}={page_off}"
        req = urllib.request.Request(url, headers={"User-Agent": "BinSmasher/4"})
        with urllib.request.urlopen(req, timeout=8) as r:
            results = _json.loads(r.read())
        if results:
            best = results[0]
            sym_off = int(best["symbols"][symbol], 16)
            base = leaked_addr - sym_off
            absolute = {k: base + int(v, 16) for k, v in best["symbols"].items()}
            absolute["__libc_base__"] = base
            absolute["_libc_key"] = best.get("id", "libc.rip")
            log.info(f"[libc_db] Resolved via libc.rip: {best.get('id')}")
            return absolute
    except Exception as e:
        log.debug(f"[libc_db] libc.rip: {e}")
    
    # 3. Fallback DB
    matches = lookup_by_symbol(symbol, leaked_addr)
    if matches:
        best = matches[0]
        base = best["libc_base"]
        offs = best["offsets"]
        absolute = {k: base + v for k, v in offs.items()}
        absolute["__libc_base__"] = base
        absolute["_libc_key"] = best["libc_key"]
        log.info(f"[libc_db] Resolved via fallback DB: {best['libc_key']}")
        return absolute
    
    log.warning(f"[libc_db] Could not resolve {symbol}={hex(leaked_addr)}")
    return None


def detect_libc_version(binary: str) -> tuple[str | None, dict]:
    """
    Detect libc version and extract ALL offsets dynamically.
    This is the main entry point for libc analysis.
    """
    libc_path = find_libc_path(binary)
    libc_version = detect_glibc_version(libc_path)
    
    if libc_version:
        log.info(f"[libc_db] Detected glibc version: {libc_version}")
    
    # Always try dynamic extraction first
    if libc_path and os.path.isfile(libc_path):
        offsets = extract_symbols_from_libc(libc_path)
        if offsets:
            log.info(f"[libc_db] Extracted {len(offsets)} symbols from {libc_path}")
            return libc_version, offsets
    
    # Fallback to version-based lookup
    if libc_version:
        for key in FALLBACK_DB:
            if libc_version in key:
                log.info(f"[libc_db] Using fallback offsets for {key}")
                return libc_version, FALLBACK_DB[key]
    
    return libc_version, {}


# ── Additional utility functions ──────────────────────────────────────────────

def get_all_function_offsets(libc_path: str) -> dict[str, int]:
    """Get all function offsets from libc for ROP/FSOP."""
    offsets = extract_symbols_from_libc(libc_path)
    functions = {}
    wanted = {
        "system", "execve", "execv", "execvp", "popen",
        "puts", "printf", "sprintf", "fprintf", "dprintf",
        "read", "write", "open", "openat", "close",
        "mmap", "mprotect", "munmap",
        "malloc", "free", "calloc", "realloc",
        "memcpy", "memmove", "memset",
        "strcpy", "strncpy", "strcat", "strncat",
        "__libc_start_main", "main",
        "__malloc_hook", "__free_hook", "__realloc_hook",
        "_IO_list_all", "_IO_wfile_jumps", "_IO_2_1_stdin_",
        "environ", "__environ",
    }
    for name in wanted:
        if name in offsets:
            functions[name] = offsets[name]
    return functions


def get_got_plt_offsets(binary_path: str) -> tuple[dict[str, int], dict[str, int]]:
    """Extract GOT and PLT offsets from a binary."""
    got = {}
    plt = {}
    
    # Use readelf for GOT
    readelf_out = _run_cmd(["readelf", "-r", binary_path])
    if readelf_out:
        for line in readelf_out.splitlines():
            # Format: 000000404018  00000200000007 R_X86_64_JUMP_SLOT  puts
            parts = line.split()
            if len(parts) >= 5 and "JUMP_SLOT" in line:
                try:
                    addr = int(parts[0], 16)
                    name = parts[4]
                    got[name] = addr
                except ValueError:
                    pass
    
    # Use objdump for PLT
    objdump_out = _run_cmd(["objdump", "-d", "-j", ".plt", binary_path])
    if objdump_out:
        for line in objdump_out.splitlines():
            # Format: 401020 <puts@plt>:
            m = re.match(r"\s*([0-9a-f]+)\s*<(\w+)@plt>:", line)
            if m:
                try:
                    addr = int(m.group(1), 16)
                    name = m.group(2)
                    plt[name] = addr
                except ValueError:
                    pass
    
    return got, plt