"""
Correct binary metadata detection.

Fixes known issues with the existing protections.py:
  - PIE detection: check ELF type ET_DYN (0x03) vs ET_EXEC (0x02)
  - NX detection: parse GNU_STACK program header permissions
  - RELRO: check both GNU_RELRO segment and BIND_NOW dynamic flag
  - Canary: nm -D for __stack_chk_fail
  - ASLR: read /proc/sys/kernel/randomize_va_space
"""
from __future__ import annotations
import logging
import os
import struct
import subprocess

log = logging.getLogger("binsmasher")

# ELF magic and constants
ELF_MAGIC = b"\x7fELF"
ET_EXEC   = 2    # static executable (NO PIE)
ET_DYN    = 3    # shared object / PIE executable


def get_elf_type(binary: str) -> int | None:
    """Read ELF type from header. Returns ET_EXEC(2) or ET_DYN(3)."""
    try:
        with open(binary, "rb") as f:
            magic = f.read(4)
            if magic != ELF_MAGIC:
                return None
            f.seek(16)  # e_type offset
            e_type = struct.unpack("<H", f.read(2))[0]
            return e_type
    except Exception as e:
        log.debug(f"[binary_info] get_elf_type: {e}")
        return None


def is_pie(binary: str) -> bool:
    """
    Correct PIE detection: ET_DYN = PIE, ET_EXEC = no PIE.
    The old method (checking 'PIE enabled' in checksec output) is unreliable
    when checksec is not installed.
    """
    etype = get_elf_type(binary)
    if etype is None:
        return False
    result = (etype == ET_DYN)
    log.debug(f"[binary_info] PIE={result} (ET={etype})")
    return result


def is_nx(binary: str) -> bool:
    """
    NX detection via GNU_STACK program header.
    If GNU_STACK has execute permission (flags & PF_X), NX is OFF.
    """
    try:
        out = subprocess.check_output(
            ["readelf", "-W", "-l", binary],
            stderr=subprocess.DEVNULL).decode(errors="ignore")
        for line in out.splitlines():
            if "GNU_STACK" in line:
                # Last column is the flags: RW, RWE, etc.
                parts = line.split()
                if parts:
                    flags = parts[-2] if len(parts) >= 2 else parts[-1]
                    if "E" in flags:
                        return False   # Executable stack → NX off
                return True            # No execute bit → NX on
    except Exception as e:
        log.debug(f"[binary_info] NX check: {e}")
    return True  # Assume NX on if unknown


def get_relro(binary: str) -> str:
    """
    Correct RELRO detection:
      Full RELRO  = GNU_RELRO segment + BIND_NOW in .dynamic
      Partial RELRO = GNU_RELRO segment only
      No RELRO    = neither
    """
    has_relro_seg = False
    has_bind_now = False

    try:
        # Check for GNU_RELRO program header
        ph_out = subprocess.check_output(
            ["readelf", "-W", "-l", binary],
            stderr=subprocess.DEVNULL).decode(errors="ignore")
        has_relro_seg = "GNU_RELRO" in ph_out

        # Check for BIND_NOW in dynamic section
        dyn_out = subprocess.check_output(
            ["readelf", "-W", "-d", binary],
            stderr=subprocess.DEVNULL).decode(errors="ignore")
        has_bind_now = ("BIND_NOW" in dyn_out
                        or ("FLAGS" in dyn_out and "BIND_NOW" in dyn_out))
        # Also check FLAGS_1 NODELETE
        if "FLAGS_1" in dyn_out:
            for line in dyn_out.splitlines():
                if "FLAGS_1" in line and "NOW" in line:
                    has_bind_now = True
    except Exception as e:
        log.debug(f"[binary_info] RELRO check: {e}")

    if has_relro_seg and has_bind_now:
        return "Full RELRO"
    elif has_relro_seg:
        return "Partial RELRO"
    else:
        return "No RELRO"


def has_canary(binary: str) -> bool:
    """Detect stack canary via __stack_chk_fail in symbols (dynamic or static)."""
    # Try dynamic symbols first
    try:
        out = subprocess.check_output(
            ["nm", "-D", binary], stderr=subprocess.DEVNULL
        ).decode(errors="ignore")
        if "__stack_chk_fail" in out:
            return True
    except Exception:
        pass
    # Try all symbols (including static binaries)
    try:
        out = subprocess.check_output(
            ["nm", binary], stderr=subprocess.DEVNULL
        ).decode(errors="ignore")
        if "__stack_chk_fail" in out or "stack_chk" in out:
            return True
    except Exception:
        pass
    # Fallback: readelf -s covers both dynamic and static symbol tables
    try:
        out = subprocess.check_output(
            ["readelf", "-s", binary], stderr=subprocess.DEVNULL
        ).decode(errors="ignore")
        return "__stack_chk_fail" in out or "stack_chk" in out
    except Exception:
        pass
    return False


def get_aslr() -> int:
    """Read system ASLR setting: 0=off, 1=partial, 2=full."""
    try:
        with open("/proc/sys/kernel/randomize_va_space") as f:
            val = f.read().strip()
        return int(val)
    except Exception:
        return 2  # assume ASLR on


def get_arch(binary: str) -> tuple[str, str]:
    """
    Detect platform and architecture from ELF header.
    Returns (platform, arch) e.g. ("linux", "amd64").
    """
    try:
        with open(binary, "rb") as f:
            f.read(4)   # magic
            ei_class = struct.unpack("B", f.read(1))[0]  # 1=32bit 2=64bit
            ei_data  = struct.unpack("B", f.read(1))[0]  # 1=LE 2=BE
            f.seek(18)
            e_machine = struct.unpack("<H", f.read(2))[0]

        arch_map = {
            0x03: "i386",
            0x3e: "amd64",
            0x28: "arm",
            0xb7: "aarch64",
            0x08: "mips",
            0xf3: "riscv",
        }
        arch = arch_map.get(e_machine, "unknown")
        platform = "linux"

        # Check for Android (look for /system/bin/linker in interpreter)
        try:
            out = subprocess.check_output(
                ["readelf", "-l", binary], stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            if "/system/bin/linker" in out:
                platform = "android"
        except Exception:
            pass

        log.debug(f"[binary_info] arch={arch} platform={platform} "
                  f"e_machine={hex(e_machine)}")
        return platform, arch

    except Exception as e:
        log.debug(f"[binary_info] get_arch: {e}")
        return "linux", "amd64"


def full_binary_info(binary: str) -> dict:
    """
    Complete binary metadata with correct detection methods.
    Supersedes unreliable checksec-dependent detection.
    """
    platform, arch = get_arch(binary)
    return {
        "platform": platform,
        "arch":     arch,
        "pie":      is_pie(binary),
        "nx":       is_nx(binary),
        "relro":    get_relro(binary),
        "canary":   has_canary(binary),
        "aslr":     get_aslr() >= 1,
        "aslr_level": get_aslr(),
    }
