"""Dynamic analysis and context setup methods for BinaryAnalyzer."""
import subprocess
import time
import logging

log = logging.getLogger("binsmasher")


class DynamicAnalysisMixin:
    """Methods: setup_context, frida_analyze."""

    def setup_context(self):
        try:
            result = subprocess.check_output(["file", self.binary],
                                              stderr=subprocess.DEVNULL).decode().lower()
        except FileNotFoundError:
            log.error("`file` command not found.")
            raise SystemExit(1)
        platform, arch = "linux", "amd64"
        if "elf" in result:
            try:
                interp_out = subprocess.check_output(
                    ["readelf", "-l", self.binary], stderr=subprocess.DEVNULL
                ).decode(errors="ignore")
                is_android = ("/system/bin/linker" in interp_out
                              or "/system/bin/linker64" in interp_out)
            except Exception:
                is_android = False
            platform = "android" if is_android else "linux"
            if "32-bit" in result:
                arch = "arm" if "arm" in result else "i386"
            elif "64-bit" in result:
                arch = "aarch64" if "aarch64" in result else "amd64"
        elif "pe32+" in result:
            platform, arch = "windows", "amd64"
        elif "pe32" in result:
            platform, arch = "windows", "i386"
        elif "mach-o" in result:
            platform = "macos"
            arch = "arm64" if "arm64" in result else "amd64"
        else:
            log.warning("Unknown binary format — assuming Linux x86_64")
        try:
            from pwn import context as pctx
            pctx(arch=arch, os=platform if platform != "macos" else "linux")
        except Exception as e:
            log.warning(f"pwntools context: {e}")
        log.info(f"Platform: {platform.upper()}  Arch: {arch}")
        self.platform = platform
        self.arch = arch
        return platform, arch

    def frida_analyze(self, binary_args):
        log.info("Starting Frida dynamic analysis…")
        try:
            import frida
        except ImportError:
            log.error("frida not installed: pip install frida-tools")
            return False
        script_code = """
'use strict';
const targets=["gets","strcpy","sprintf","scanf","recv","read","malloc","free","printf","system"];
targets.forEach(function(fn){
    var addr=Module.findExportByName(null,fn); if(!addr)return;
    Interceptor.attach(addr,{onEnter:function(args){send({fn:fn,arg0:args[0].toString(),tid:this.threadId});}});
});
"""
        cmd = [self.binary] + binary_args if binary_args else [self.binary]
        try:
            import subprocess as sp
            proc = sp.Popen(cmd, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
            time.sleep(0.5)
            session = frida.attach(proc.pid)
            script = session.create_script(script_code)
            msgs = []
            script.on("message", lambda m, d: msgs.append(m))
            script.load()
            time.sleep(3)
            script.unload()
            session.detach()
            proc.terminate()
            proc.wait(timeout=5)
            log.info(f"Frida captured {len(msgs)} events")
            for m in msgs[:20]:
                log.debug(f"  Frida → {m.get('payload', m)}")
            return True
        except Exception as e:
            log.warning(f"Frida attach failed: {e}")
            return False
