"""Mutation fuzzing methods for Fuzzer."""
import os
import random
import socket
import time
import logging
from pathlib import Path

log = logging.getLogger("binsmasher")


class MutationMixin:
    """Methods: mutation_fuzz."""

    def mutation_fuzz(self, num_cases=500, timeout=1.0):
        log.info(f"Mutation fuzzing {self.host}:{self.port} ({num_cases} cases)…")
        crashes = 0
        seeds = [b"A" * 128, b"\x00" * 128, b"\xff" * 128,
                 b"%s" * 32, b"%n" * 32, b"A" * 4096, b"\x7f" * 64, b"\x80" * 64]

        def mutate(data):
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
                ints = [b"\xff\xff\xff\xff", b"\x00\x00\x00\x00", b"\x80\x00\x00\x00", b"\x7f\xff\xff\xff"]
                pos = random.randint(0, len(data))
                chunk = random.choice(ints)
                data[pos:pos + len(chunk)] = chunk[:len(data) - pos]
            else:
                data = data * random.randint(2, 8)
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
