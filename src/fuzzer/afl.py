"""AFL++ coverage-guided fuzzing methods for Fuzzer."""
import os
import time
import subprocess
import logging
from pathlib import Path

log = logging.getLogger("binsmasher")


class AFLMixin:
    """Methods: afl_fuzz."""

    def afl_fuzz(self, binary_args, timeout_sec=30):
        log.info("Starting AFL++ coverage-guided fuzzing…")
        afl_in = Path("afl_in")
        afl_out = Path("afl_out")
        afl_in.mkdir(exist_ok=True)
        afl_out.mkdir(exist_ok=True)
        seeds = [b"A" * 64, b"\x00" * 64, b"\xff" * 64,
                 b"GET / HTTP/1.1\r\n\r\n", os.urandom(64), b"%p" * 16, b"\x41" * 256]
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
