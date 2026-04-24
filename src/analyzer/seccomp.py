"""Seccomp detection and binary patching methods for BinaryAnalyzer."""
import subprocess
import re
import os
import logging

log = logging.getLogger("binsmasher")


class SeccompMixin:
    """Methods: detect_seccomp, patch_binary_for_local."""

    def detect_seccomp(self):
        log.info("Detecting seccomp filters…")
        result = {"enabled": False, "rules": [], "orw_needed": False, "allowed": [], "blocked": []}
        import shutil
        if not shutil.which("seccomp-tools"):
            log.warning("seccomp-tools not installed: gem install seccomp-tools")
            return result
        try:
            out = subprocess.check_output(["seccomp-tools", "dump", self.binary],
                                           stderr=subprocess.DEVNULL, timeout=12).decode(errors="ignore")
            if not out.strip():
                return result
            result["enabled"] = True
            result["rules"] = out.strip().splitlines()
            for line in result["rules"]:
                low = line.lower()
                m = re.search(r"sys_(\w+)", line)
                name = m.group(1) if m else None
                if "allow" in low and name:
                    result["allowed"].append(name)
                elif ("kill" in low or "errno" in low or "trap" in low) and name:
                    result["blocked"].append(name)
            result["orw_needed"] = ("execve" in result["blocked"] or
                (bool(result["allowed"]) and "execve" not in result["allowed"]))
            log.info(f"seccomp: enabled={result['enabled']} orw_needed={result['orw_needed']}")
        except subprocess.TimeoutExpired:
            log.warning("seccomp-tools timed out")
        except Exception as e:
            log.warning(f"seccomp detection failed: {e}")
        return result

    def patch_binary_for_local(self, libc_path, ld_path=""):
        import shutil as _sh
        if _sh.which("pwninit"):
            cmd = ["pwninit", "--bin", self.binary, "--libc", libc_path, "--no-template"]
            if ld_path:
                cmd += ["--ld", ld_path]
            try:
                subprocess.run(cmd, check=True, timeout=30,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                candidate = self.binary + "_patched"
                if os.path.isfile(candidate):
                    log.info(f"pwninit: {candidate}")
                    return candidate
            except Exception as e:
                log.warning(f"pwninit failed: {e}")
        if _sh.which("patchelf"):
            patched = self.binary + "_patched"
            try:
                _sh.copy2(self.binary, patched)
                if not ld_path:
                    arch_interp = {
                        "amd64":   "/lib64/ld-linux-x86-64.so.2",
                        "i386":    "/lib/ld-linux.so.2",
                        "arm":     "/lib/ld-linux-armhf.so.3",
                        "aarch64": "/lib/ld-linux-aarch64.so.1",
                    }
                    ld_path = arch_interp.get(self.arch, "/lib64/ld-linux-x86-64.so.2")
                rpath = os.path.dirname(os.path.abspath(libc_path))
                subprocess.run(["patchelf", "--set-interpreter", ld_path, "--set-rpath", rpath, patched],
                               check=True, timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                log.info(f"patchelf: {patched}")
                return patched
            except Exception as e:
                log.error(f"patchelf failed: {e}")
        else:
            log.warning("Neither pwninit nor patchelf found")
        return self.binary
