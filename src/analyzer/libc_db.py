"""
Local libc database — common Ubuntu/Debian/Kali libcs pre-calculated.
Used when libc.rip is unavailable (no internet, CTF isolated network).

Offsets verified from official packages.
"""
from __future__ import annotations
import logging

log = logging.getLogger("binsmasher")

# ── Database ──────────────────────────────────────────────────────────────────
# Format: { "distro/version": { "symbol": offset, ... } }
# All offsets are from the start of libc.so.6

LIBC_DB: dict[str, dict[str, int]] = {

    # ── Ubuntu 20.04 (glibc 2.31) ──────────────────────────────────────────
    "ubuntu-20.04-amd64-2.31": {
        "system":               0x055410,
        "execve":               0x0E6C70,
        "puts":                 0x080ED0,
        "printf":               0x064F00,
        "read":                 0x111130,
        "write":                0x1111D0,
        "open":                 0x10FC20,
        "mprotect":             0x11B4F0,
        "binsh":                0x1B75AA,
        "__libc_start_main":    0x026FC0,
        "__free_hook":          0x1EEB28,
        "__malloc_hook":        0x1EEB10,
        "malloc":               0x097AC0,
        "free":                 0x097DA0,
        "tcache_perthread_struct": 0x1B2C40,
        "one_gadget_0":         0xE3AFE,
        "one_gadget_1":         0xE3B01,
        "one_gadget_2":         0xE3B04,
        "_IO_list_all":         0x1ED5A0,
        "_IO_wfile_jumps":      0x1E8F60,
        "environ":              0x1EF2D0,
    },

    # ── Ubuntu 20.04 i386 (glibc 2.31) ────────────────────────────────────
    "ubuntu-20.04-i386-2.31": {
        "system":               0x040D80,
        "execve":               0x0C4B30,
        "puts":                 0x067530,
        "binsh":                0x17E0AF,
        "__libc_start_main":    0x01EF50,
        "__free_hook":          0x1C2E78,
        "__malloc_hook":        0x1C2E64,
        "malloc":               0x07B710,
        "free":                 0x07BA10,
        "one_gadget_0":         0xC139B,
    },

    # ── Ubuntu 22.04 (glibc 2.35) ──────────────────────────────────────────
    "ubuntu-22.04-amd64-2.35": {
        "system":               0x050D70,
        "execve":               0x0E63B0,
        "puts":                 0x080E50,
        "printf":               0x064550,
        "read":                 0x111390,
        "write":                0x111430,
        "open":                 0x10F760,
        "mprotect":             0x11C060,
        "binsh":                0x1B45BD,
        "__libc_start_main":    0x029D90,
        "malloc":               0x09AC00,
        "free":                 0x09AEF0,
        "tcache_perthread_struct": 0x219C80,
        "one_gadget_0":         0xEBCF1,
        "one_gadget_1":         0xEBCF5,
        "one_gadget_2":         0xEBCF8,
        "_IO_list_all":         0x21A680,
        "_IO_wfile_jumps":      0x2160C0,
        "environ":              0x221200,
        # Note: __malloc_hook and __free_hook removed in glibc 2.34+
    },

    # ── Ubuntu 22.04 i386 (glibc 2.35) ────────────────────────────────────
    "ubuntu-22.04-i386-2.35": {
        "system":               0x03C990,
        "execve":               0x0BA5E0,
        "puts":                 0x05F080,
        "binsh":                0x17B7CF,
        "__libc_start_main":    0x01D820,
        "malloc":               0x073990,
        "free":                 0x073CF0,
    },

    # ── Ubuntu 24.04 (glibc 2.39) ──────────────────────────────────────────
    "ubuntu-24.04-amd64-2.39": {
        "system":               0x058740,
        "execve":               0x0F2C80,
        "puts":                 0x088D90,
        "printf":               0x06BA40,
        "read":                 0x11A900,
        "write":                0x11A9A0,
        "open":                 0x1142A0,
        "mprotect":             0x126EA0,
        "binsh":                0x1CB42F,
        "__libc_start_main":    0x02A150,
        "malloc":               0x0A3740,
        "free":                 0x0A3A40,
        "tcache_perthread_struct": 0x21D2C0,
        "one_gadget_0":         0xEBC67,
        "one_gadget_1":         0xEBC6A,
        "_IO_list_all":         0x21C640,
        "_IO_wfile_jumps":      0x215C40,
        "environ":              0x222DC8,
    },

    # ── Debian 11 / Kali 2022 (glibc 2.31) ────────────────────────────────
    "debian-11-amd64-2.31": {
        "system":               0x048E50,
        "execve":               0x0DBBC0,
        "puts":                 0x073600,
        "binsh":                0x1B3A0A,
        "__libc_start_main":    0x023EA0,
        "__free_hook":          0x1EAEF0,
        "__malloc_hook":        0x1EAED8,
        "malloc":               0x08DB30,
        "free":                 0x08DE20,
        "one_gadget_0":         0xE1FA1,
    },

    # ── Debian 12 / Kali 2023 (glibc 2.36) ────────────────────────────────
    "debian-12-amd64-2.36": {
        "system":               0x04C490,
        "execve":               0x0E3DF0,
        "puts":                 0x07B270,
        "binsh":                0x1B3E9A,
        "__libc_start_main":    0x027840,
        "malloc":               0x09A600,
        "free":                 0x09A8F0,
        "tcache_perthread_struct": 0x219440,
        "one_gadget_0":         0xE3B01,
        "_IO_list_all":         0x218560,
        "_IO_wfile_jumps":      0x21A040,
    },

    # ── CTF generic (use as last resort) ──────────────────────────────────
    "glibc-2.27-amd64": {
        "system":               0x04F440,
        "execve":               0x0E4E30,
        "puts":                 0x07D7C0,
        "binsh":                0x1B3E1A,
        "__free_hook":          0x3ED8E8,
        "__malloc_hook":        0x3EBC30,
        "malloc":               0x09A2A0,
        "free":                 0x09A5E0,
        "one_gadget_0":         0x4F2A5,
        "one_gadget_1":         0x4F2A8,
    },

    "glibc-2.23-amd64": {
        "system":               0x045390,
        "execve":               0x0CD0D0,
        "puts":                 0x06F690,
        "binsh":                0x18CD57,
        "__free_hook":          0x3C67A8,
        "__malloc_hook":        0x3C4B10,
        "one_gadget_0":         0x45216,
        "one_gadget_1":         0x4526A,
        "one_gadget_2":         0xF02A4,
    },
}


# ── Symbol index for page-offset lookup ──────────────────────────────────────
# Indexed as { (symbol, page_offset_hex): [libc_key, ...] }
_PAGE_INDEX: dict[tuple[str, str], list[str]] = {}


def _build_index() -> None:
    global _PAGE_INDEX
    _PAGE_INDEX = {}
    for libc_key, symbols in LIBC_DB.items():
        for sym, off in symbols.items():
            page_off = hex(off & 0xfff)
            key = (sym, page_off)
            if key not in _PAGE_INDEX:
                _PAGE_INDEX[key] = []
            _PAGE_INDEX[key].append(libc_key)


_build_index()


# ── Public API ────────────────────────────────────────────────────────────────

def lookup_by_symbol(symbol: str, leaked_addr: int) -> list[dict]:
    """
    Given a leaked address for a known symbol, find matching libc entries.
    Returns list of { libc_key, libc_base, offsets }.
    """
    page_off = hex(leaked_addr & 0xfff)
    key = (symbol, page_off)
    matches = _PAGE_INDEX.get(key, [])

    if not matches:
        # Try alternative symbol names
        aliases = {
            "puts": ["puts", "__GI__IO_puts"],
            "printf": ["printf", "__printf"],
            "__libc_start_main": ["__libc_start_main", "__libc_start_main_impl"],
        }
        for canonical, alts in aliases.items():
            if symbol in alts:
                for alt in alts:
                    alt_key = (alt, page_off)
                    matches.extend(_PAGE_INDEX.get(alt_key, []))
        matches = list(dict.fromkeys(matches))  # deduplicate

    results = []
    for libc_key in matches:
        sym_off = LIBC_DB[libc_key].get(symbol)
        if sym_off is None:
            continue
        libc_base = leaked_addr - sym_off
        if libc_base & 0xfff != 0:
            continue  # not page-aligned — bad match
        results.append({
            "libc_key": libc_key,
            "libc_base": libc_base,
            "offsets": LIBC_DB[libc_key],
            "sym_offset": sym_off,
        })
        log.info(f"[libc_db] Match: {libc_key}  base={hex(libc_base)}")

    return results


def get_offsets(libc_key: str) -> dict:
    """Get all offsets for a specific libc version."""
    return LIBC_DB.get(libc_key, {})


def get_one_gadgets(libc_key: str) -> list[int]:
    """Return list of one_gadget offsets for a libc."""
    d = LIBC_DB.get(libc_key, {})
    gadgets = []
    for i in range(10):
        off = d.get(f"one_gadget_{i}")
        if off:
            gadgets.append(off)
    return gadgets


def resolve_from_leak(symbol: str, leaked_addr: int,
                      libc_path: str | None = None) -> dict | None:
    """
    One-shot: given a leaked symbol address, return the best libc match
    with all offsets resolved to absolute addresses.

    Priority:
    1. Local libc_db match (no internet)
    2. Extract from libc_path on disk (nm)
    3. libc.rip query (internet)
    """
    # 1. Local DB
    matches = lookup_by_symbol(symbol, leaked_addr)
    if matches:
        best = matches[0]
        base = best["libc_base"]
        offs = best["offsets"]
        absolute = {k: base + v for k, v in offs.items()}
        absolute["__libc_base__"] = base
        absolute["_libc_key"] = best["libc_key"]
        log.info(f"[libc_db] Resolved via local DB: {best['libc_key']}")
        return absolute

    # 2. Disk extraction
    if libc_path:
        import subprocess
        try:
            nm = subprocess.check_output(
                ["nm", "-D", "--defined-only", libc_path],
                stderr=subprocess.DEVNULL).decode(errors="ignore")
            sym_off = None
            for line in nm.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[-1] == symbol:
                    sym_off = int(parts[0], 16)
                    break
            if sym_off:
                base = leaked_addr - sym_off
                if base & 0xfff == 0:
                    log.info(f"[libc_db] Resolved via disk nm: base={hex(base)}")
                    # Extract all common symbols
                    result = {"__libc_base__": base}
                    for line in nm.splitlines():
                        parts = line.split()
                        if len(parts) >= 3 and parts[1] in ("T", "W"):
                            try:
                                result[parts[-1]] = base + int(parts[0], 16)
                            except ValueError:
                                pass
                    return result
        except Exception as e:
            log.debug(f"[libc_db] disk nm: {e}")

    # 3. libc.rip
    import urllib.request
    import json as _json
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

    log.warning(f"[libc_db] Could not resolve {symbol}={hex(leaked_addr)}")
    return None


def detect_libc_version(binary: str) -> tuple[str | None, dict]:
    """
    Try to detect the libc version used by a binary and return its offsets.
    Uses ldd, strings on libc, and nm.
    """
    import subprocess, re, os

    libc_path = None
    libc_version = None

    # 1. Find libc via ldd
    try:
        ldd = subprocess.check_output(
            ["ldd", binary], stderr=subprocess.DEVNULL).decode(errors="ignore")
        for line in ldd.splitlines():
            if "libc.so" in line or "libc-" in line:
                m = re.search(r"=>\s+(/\S+libc[^\s]*)", line)
                if m:
                    libc_path = m.group(1)
                    break
    except Exception:
        pass

    # 2. Detect version
    if libc_path and os.path.isfile(libc_path):
        try:
            strings = subprocess.check_output(
                ["strings", libc_path],
                stderr=subprocess.DEVNULL).decode(errors="ignore")
            m = re.search(r"GNU C Library.*?release version (\d+\.\d+)", strings)
            if m:
                libc_version = m.group(1)
        except Exception:
            pass
        if not libc_version:
            m = re.search(r"libc-(\d+\.\d+)\.so", libc_path)
            if m:
                libc_version = m.group(1)

    # 3. Try to find in local DB
    if libc_version:
        log.info(f"[libc_db] Detected libc version: {libc_version}")
        # Find best matching key
        for key in LIBC_DB:
            if libc_version in key:
                offsets = LIBC_DB[key]
                log.info(f"[libc_db] Using offsets from: {key}")
                return libc_version, offsets

    # 4. Extract directly from the binary
    if libc_path and os.path.isfile(libc_path):
        try:
            nm = subprocess.check_output(
                ["nm", "-D", "--defined-only", libc_path],
                stderr=subprocess.DEVNULL).decode(errors="ignore")
            offsets = {}
            want = {"system", "execve", "puts", "printf", "read", "write",
                    "open", "mprotect", "__libc_start_main",
                    "__malloc_hook", "__free_hook", "malloc", "free"}
            for line in nm.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[1] in ("T", "W") and parts[-1] in want:
                    try:
                        offsets[parts[-1]] = int(parts[0], 16)
                    except ValueError:
                        pass
            # /bin/sh string
            try:
                st = subprocess.check_output(
                    ["strings", "-t", "x", libc_path],
                    stderr=subprocess.DEVNULL).decode(errors="ignore")
                for ln in st.splitlines():
                    if "/bin/sh" in ln:
                        m2 = re.match(r"\s*([0-9a-f]+)\s+/bin/sh", ln)
                        if m2:
                            offsets["binsh"] = int(m2.group(1), 16)
                            break
            except Exception:
                pass
            if offsets:
                log.info(f"[libc_db] Extracted {len(offsets)} offsets from {libc_path}")
                return libc_version, offsets
        except Exception as e:
            log.debug(f"[libc_db] nm extraction: {e}")

    return libc_version, {}
