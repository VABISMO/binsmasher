"""ROTO offset heuristic and SIGFAULT analysis methods for Fuzzer."""
import socket
import logging

log = logging.getLogger("binsmasher")


class OffsetRotoMixin:
    """Methods: find_offset_roto, sigfault_analysis."""

    def find_offset_roto(self, pattern_size: int = 300, attempts: int = 6):
        from pwn import cyclic, context
        import socket as _socket
        log.info("ROTO heuristic offset search…")

        prev_resp_len = None
        for mult in range(1, attempts + 1):
            sz = pattern_size * mult
            pat = cyclic(sz)
            try:
                s = _socket.create_connection((self.host, self.port), timeout=2.0)
                try:
                    s.recv(256)
                except Exception:
                    pass
                s.sendall(pat + b'\n')
                s.settimeout(2.0)
                resp = b""
                try:
                    while True:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
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
                    log.info(f"ROTO: truncated response ({resp_len}B < {sz // 4}B) → estimated offset ~{est}")
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

    def sigfault_analysis(self, binary: str, pattern_size: int = 300) -> dict:
        from pwn import cyclic, cyclic_find, process, context, ELF
        import resource

        log.info("SIGFAULT analysis: spawning local process with cyclic…")
        result = {"offset": None, "crash_addr": None, "signal": None, "method": None}

        for mult in range(1, 4):
            sz = pattern_size * mult
            pat = cyclic(sz)
            try:
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                p = process([binary], stderr=open("/dev/null", "wb"))
                p.sendline(pat)
                try:
                    p.recvall(timeout=2)
                except Exception:
                    pass
                try:
                    p.wait(timeout=3)
                except Exception:
                    p.kill()
                    p.wait(timeout=1)

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
                                result["offset"] = off
                                result["crash_addr"] = pc
                                result["method"] = "corefile"
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
