"""Function recovery, MTE detection and source analysis methods for BinaryAnalyzer."""
import subprocess
import re
import os
import json
import logging

log = logging.getLogger("binsmasher")


class RecoveryMixin:
    """Methods: recover_functions_stripped, mte_info, grep_unsafe_source."""

    def recover_functions_stripped(self):
        log.info("Recovering functions from stripped binary…")
        recovered = []
        try:
            out = subprocess.check_output(["r2", "-A", "-q", "-c", "aaa; aac; aan; aflj", self.binary],
                                           stderr=subprocess.DEVNULL, timeout=60).decode(errors="ignore")
            try:
                for fn in json.loads(out):
                    recovered.append((fn.get("offset", 0), fn.get("name", "unknown")))
            except Exception:
                for line in out.splitlines():
                    m = re.match(r"(0x[0-9a-fA-F]+)", line)
                    if m:
                        recovered.append((int(m.group(1), 16), f"fcn_{m.group(1)}"))
        except Exception as e:
            log.warning(f"  r2 stripped: {e}")
        try:
            arch_prologues = {
                "amd64":   [b"\x55\x48\x89\xE5", b"\x55\x48\x8B\xEC"],
                "i386":    [b"\x55\x89\xE5",       b"\x55\x89\xEC"],
                "arm":     [b"\x00\x48\x2D\xE9",  b"\xF0\x4F\x2D\xE9"],
                "aarch64": [b"\xFF\x03\x01\xD1",  b"\xFD\x7B\xBF\xA9"],
            }
            prologues = arch_prologues.get(self.arch, arch_prologues["amd64"])
            data = open(self.binary, "rb").read()
            for prologue in prologues:
                idx = 0
                while True:
                    idx = data.find(prologue, idx)
                    if idx == -1:
                        break
                    if not any(a == idx for a, _ in recovered):
                        recovered.append((idx, f"prologue_{hex(idx)}"))
                    idx += len(prologue)
        except Exception as e:
            log.warning(f"  prologue scan: {e}")
        try:
            import angr
            proj = angr.Project(self.binary, auto_load_libs=False)
            cfg = proj.analyses.CFGFast()
            for addr, fn in list(cfg.functions.items())[:50]:
                if not any(a == addr for a, _ in recovered):
                    recovered.append((addr, fn.name or f"angr_{hex(addr)}"))
        except ImportError:
            pass
        except Exception as e:
            log.warning(f"  angr: {e}")
        log.info(f"Stripped: {len(recovered)} candidates")
        return recovered

    def mte_info(self):
        from pwn import context
        info = {"mte_detected": False, "arch": context.arch, "bypass_hint": "N/A"}
        if context.arch not in ("aarch64",):
            info["bypass_hint"] = "MTE is ARM64-only"
            return info
        try:
            re_out = subprocess.check_output(["readelf", "-d", self.binary],
                                              stderr=subprocess.DEVNULL).decode(errors="ignore")
            nm_out = subprocess.check_output(["nm", self.binary],
                                              stderr=subprocess.DEVNULL).decode(errors="ignore")
            if "memtag" in re_out.lower() or "__hwasan" in nm_out.lower():
                info["mte_detected"] = True
                info["bypass_hint"] = "MTE: (1) brute 16 tags, (2) %p leak tag nibble, (3) mmap no PROT_MTE"
        except Exception as e:
            log.warning(f"MTE: {e}")
        return info

    def grep_unsafe_source(self, source_path):
        log.info(f"Grepping Rust source in {source_path} for 'unsafe'…")
        unsafe_files = []
        unsafe_total = 0
        try:
            for root, _, files in os.walk(source_path):
                for fname in files:
                    if not fname.endswith(".rs"):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        content = open(fpath, encoding="utf-8", errors="ignore").read()
                        n = content.count("unsafe")
                        if n:
                            unsafe_total += n
                            unsafe_files.append(fpath)
                            log.debug(f"  {fpath}: {n}")
                    except OSError:
                        pass
            log.info(f"unsafe: {unsafe_total} in {len(unsafe_files)} files")
            return unsafe_files
        except Exception as e:
            log.error(f"Source grep: {e}")
            return []
