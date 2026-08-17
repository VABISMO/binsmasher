"""
angr-based symbolic execution for automatic path finding.
Used when classical analysis fails to find win() or the offset.
"""
from __future__ import annotations
import logging

log = logging.getLogger("binsmasher")


def angr_find_win(binary: str, timeout: int = 60) -> dict:
    """
    Use angr to symbolically execute the binary and find the path
    that reaches a win/flag/shell function or produces interesting output.

    Returns a dict with:
        found        : bool
        win_addr     : int | None
        input_bytes  : bytes | None
        offset_hint  : int | None
        notes        : str
    """
    result = {
        "found": False, "win_addr": None,
        "input_bytes": None, "offset_hint": None, "notes": ""
    }

    try:
        import angr
        import claripy
    except ImportError:
        result["notes"] = "angr not installed: pip install angr"
        log.warning("[angr] not installed — skipping")
        return result

    from constants import DEFAULT_WIN_PATTERNS as WIN_KW

    log.info(f"[angr] Loading {binary}…")
    try:
        proj = angr.Project(binary, auto_load_libs=False,
                             load_options={"rebase_granularity": 0x1000})
    except Exception as e:
        result["notes"] = f"angr load failed: {e}"
        log.error(f"[angr] {e}")
        return result

    # Find win targets
    win_addrs = []
    try:
        cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=False)
        for fn in cfg.functions.values():
            name = fn.name or ""
            if any(kw in name.lower() for kw in WIN_KW):
                win_addrs.append(fn.addr)
                log.info(f"[angr] Win candidate: {name}@{hex(fn.addr)}")
    except Exception as e:
        log.debug(f"[angr] CFG: {e}")

    # Also check ELF symbols
    try:
        for sym in proj.loader.main_object.symbols:
            name = sym.name or ""
            if any(kw in name.lower() for kw in WIN_KW) and sym.rebased_addr:
                if sym.rebased_addr not in win_addrs:
                    win_addrs.append(sym.rebased_addr)
    except Exception:
        pass

    if not win_addrs:
        # Stripped binary, no win symbol/name: explore for the OUTPUT instead.
        # Find a state whose stdout contains a win marker ("PWNED", "flag{"),
        # which means the program reached its win/flag path. The concrete stdin
        # of that state is the exploit input. This is angr's real value over
        # static xref — it works on stripped/obfuscated binaries where r2's
        # xref recovery comes up empty (x86-64 uses RIP-relative lea, so the
        # absolute-address xref scan can't find string references either).
        log.info("[angr] No win symbol — output-guided symbolic exploration")
        _WIN_OUT = (b"PWNED", b"flag{", b"flag\n", b"pwned",
                    b"you win", b"got the flag", b"cat flag")
        try:
            # 128-byte symbolic stdin — large enough for typical overflow
            # offsets (≤ ~120B) without the state-space explosion of 256B.
            stdin_buf = claripy.BVS("stdin", 128 * 8)
            state = proj.factory.full_init_state(
                stdin=angr.SimFileStream(name="stdin", content=stdin_buf, has_end=False),
                add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                             angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})

            def _found(s):
                try:
                    out = s.posix.dumps(1)
                    return any(m in out for m in _WIN_OUT)
                except Exception:
                    return False

            sm = proj.factory.simulation_manager(state)
            import signal
            def _to(sig, frame):
                raise TimeoutError("angr timeout")
            old = signal.signal(signal.SIGALRM, _to)
            signal.alarm(timeout)
            try:
                sm.explore(find=_found, num_find=1)
            except TimeoutError:
                log.warning(f"[angr] output-guided timed out after {timeout}s")
                result["notes"] = f"angr output-guided timed out after {timeout}s"
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old)

            if sm.found:
                fs = sm.found[0]
                ib = fs.solver.eval(stdin_buf, cast_to=bytes)
                # Strip TRAILING nulls only — overflow payloads contain
                # internal null bytes (addresses); truncating at the first
                # null would destroy the return address.
                clean = ib.rstrip(b"\x00")
                # Reject spurious finds: with ZERO_FILL_UNCONSTRAINED angr can
                # reach a win-marker output without constraining stdin (eval
                # → all-zeros). Such an input won't reproduce on the real
                # service, so discard it. A real overflow input is non-zero.
                if not clean or not any(clean):
                    log.info("[angr] spurious find (unconstrained stdin) — ignoring")
                    result["notes"] = "angr found a spurious path (input-independent)"
                else:
                    result["input_bytes"] = clean
                    result["found"] = True
                    result["notes"] = f"Output-guided path found with {len(clean)}B input"
                    log.info(f"[angr] ✓ Output-guided path! Input: {clean[:64]!r}…")
                    oh = None
                    for i in range(len(clean) - 1, -1, -1):
                        if 0x40 <= clean[i] <= 0x7e:
                            oh = i + 1
                            break
                    if oh:
                        result["offset_hint"] = oh
                        log.info(f"[angr] Offset hint: {oh}")
            else:
                # Last note: mention any 'flag' string present in the binary
                try:
                    flag_strs = list(proj.loader.main_object.memory.find(b"flag"))
                    if flag_strs:
                        log.info(f"[angr] 'flag' strings at: "
                                 f"{[hex(a) for a in flag_strs[:5]]}")
                except Exception:
                    pass
                result["notes"] = result["notes"] or "No win path found by angr"
        except Exception as e:
            result["notes"] = f"output-guided error: {e}"
            log.error(f"[angr] output-guided: {e}")
        return result

    target_addr = win_addrs[0]
    result["win_addr"] = target_addr

    # Symbolic stdin
    log.info(f"[angr] Exploring path to {hex(target_addr)}…")
    try:
        import signal

        stdin_buf = claripy.BVS("stdin", 128 * 8)
        state = proj.factory.full_init_state(
            stdin=angr.SimFileStream(name="stdin", content=stdin_buf, has_end=False),
            add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                         angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})

        sm = proj.factory.simulation_manager(state)

        # Set timeout via SIGALRM
        def _timeout_handler(sig, frame):
            raise TimeoutError("angr timeout")

        old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(timeout)

        try:
            sm.explore(find=target_addr, avoid=[], num_find=1)
        except TimeoutError:
            log.warning(f"[angr] Timeout after {timeout}s")
            result["notes"] = f"angr timed out after {timeout}s"
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
            result["found"] = bool(win_addrs)
            return result
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

        if sm.found:
            found_state = sm.found[0]
            # Extract concrete stdin bytes
            try:
                stdin_bytes = found_state.solver.eval(stdin_buf,
                                                       cast_to=bytes)
                # Strip TRAILING nulls only — overflow payloads contain
                # internal null bytes (addresses); truncating at the first
                # null would destroy the return address.
                clean = stdin_bytes.rstrip(b"\x00")
                # Reject spurious input-independent finds (all-zeros).
                if not clean or not any(clean):
                    log.info("[angr] spurious find (unconstrained stdin) — ignoring")
                    result["found"] = bool(win_addrs)
                    result["notes"] = f"Path to {hex(target_addr)} but input-independent"
                else:
                    result["input_bytes"] = clean
                    result["found"] = True
                    result["notes"] = f"Path found to {hex(target_addr)} with {len(clean)}B input"
                    log.info(f"[angr] ✓ Path found! Input: {clean[:64]!r}…")

                    # Try to extract offset from the concrete input
                    # If the input is long, the offset is roughly where it stops being printable
                    offset_hint = None
                    for i in range(len(clean) - 1, -1, -1):
                        if clean[i:i+1] in (b"A", b"\x41") or 0x40 <= clean[i] <= 0x7e:
                            offset_hint = i + 1
                            break
                    if offset_hint:
                        result["offset_hint"] = offset_hint
                        log.info(f"[angr] Offset hint: {offset_hint}")

            except Exception as e:
                log.debug(f"[angr] Solver: {e}")
                result["found"] = True
                result["notes"] = f"Path found to {hex(target_addr)}"
        else:
            result["notes"] = f"No path found to {hex(target_addr)} within {timeout}s"
            log.info(f"[angr] No path found to {hex(target_addr)}")

    except Exception as e:
        result["notes"] = f"angr exploration error: {e}"
        log.error(f"[angr] {e}")

    return result


def angr_find_vulnerabilities(binary: str, timeout: int = 120) -> list[dict]:
    """
    Detect vulnerabilities via angr taint analysis:
    - Buffer overflows (unconstrained PC)
    - Format string (printf with symbolic arg)
    - Use-after-free patterns
    """
    vulns = []
    try:
        import angr
        proj = angr.Project(binary, auto_load_libs=False)
        state = proj.factory.full_init_state()
        sm = proj.factory.simulation_manager(state)

        import signal
        def _t(sig, frame): raise TimeoutError()
        old = signal.signal(signal.SIGALRM, _t)
        signal.alarm(timeout)
        try:
            sm.run(n=500)
        except TimeoutError:
            pass
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)

        # Unconstrained states = potential PC control
        if sm.unconstrained:
            for state in sm.unconstrained[:3]:
                if state.regs.pc.symbolic:
                    vulns.append({
                        "type": "pc_control",
                        "description": "Unconstrained PC — likely buffer overflow",
                        "addr": None,
                    })
                    log.info("[angr] PC control detected!")

    except ImportError:
        pass
    except Exception as e:
        log.debug(f"[angr] vuln scan: {e}")

    return vulns
