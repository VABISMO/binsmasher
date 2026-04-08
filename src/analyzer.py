#!/usr/bin/env python3
"""
BinSmasher – analyzer.py  v4
Static & dynamic analysis.
New: query_libc_rip, detect_seccomp, patch_binary_for_local.
"""

import subprocess, os, re, time, json, logging, urllib.request, urllib.error
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("binsmasher")


class BinaryAnalyzer:

    VULNERABLE_FUNCTIONS = [
        "gets","strcpy","strcat","sprintf","vsprintf","scanf","sscanf",
        "read","fread","recv","memcpy","memmove","strncpy","strncat",
        "mpg123_decode","malloc","free","realloc","calloc",
    ]
    FORMAT_STRING_FUNCTIONS = [
        "printf","fprintf","sprintf","snprintf","vprintf","vfprintf",
        "vsprintf","vsnprintf","dprintf","syslog",
    ]
    RUST_SPECIFIC = [
        "panic","assert","unwrap","deserial","borsh","bincode",
        "execute_transaction","process_transaction","solana_program","anchor_lang",
    ]

    def __init__(self, binary, log_file):
        self.binary   = binary
        self.log_file = log_file
        self.platform = "linux"
        self.arch     = "amd64"

    def setup_context(self):
        try:
            result = subprocess.check_output(["file",self.binary],
                                              stderr=subprocess.DEVNULL).decode().lower()
        except FileNotFoundError:
            log.error("`file` command not found."); raise SystemExit(1)
        platform, arch = "linux", "amd64"
        if "elf" in result:
            # Detect Android by ELF interpreter path, not just architecture
            try:
                interp_out = subprocess.check_output(
                    ["readelf", "-l", self.binary], stderr=subprocess.DEVNULL
                ).decode(errors="ignore")
                is_android = ("/system/bin/linker" in interp_out
                              or "/system/bin/linker64" in interp_out)
            except Exception:
                is_android = False
            platform = "android" if is_android else "linux"
            if "32-bit" in result:   arch = "arm" if "arm" in result else "i386"
            elif "64-bit" in result: arch = "aarch64" if "aarch64" in result else "amd64"
        elif "pe32+" in result: platform, arch = "windows","amd64"
        elif "pe32" in result:  platform, arch = "windows","i386"
        elif "mach-o" in result:
            platform="macos"; arch="arm64" if "arm64" in result else "amd64"
        else: log.warning("Unknown binary format — assuming Linux x86_64")
        try:
            from pwn import context as pctx
            pctx(arch=arch, os=platform if platform!="macos" else "linux")
        except Exception as e: log.warning(f"pwntools context: {e}")
        log.info(f"Platform: {platform.upper()}  Arch: {arch}")
        self.platform = platform; self.arch = arch
        return platform, arch

    def static_analysis(self):
        log.info("Running static analysis (radare2)…")
        network_funcs = {
            "linux":   ["socket","bind","connect","listen","accept","recv","send","recvfrom","sendto"],
            "android": ["socket","bind","connect","listen","accept","recv","send","recvfrom","sendto"],
            "windows": ["WSAStartup","socket","bind","connect","listen","accept","recv","send"],
            "macos":   ["socket","bind","connect","listen","accept","recv","send"],
        }.get(self.platform, ["socket","recv","send"])
        findings = {"vulnerable_functions":[],"format_string_functions":[],
                    "network_functions":[],"heap_functions":[],"rust_functions":[],"all_functions":[]}
        all_searched = (self.VULNERABLE_FUNCTIONS+self.FORMAT_STRING_FUNCTIONS
                        +network_funcs+self.RUST_SPECIFIC)
        r2_out = ""
        for r2_cmd in (f"aaa; iz~{'|'.join(all_searched)}", f"is~{'|'.join(all_searched)}",
                       f"ii~{'|'.join(all_searched)}"):
            try: r2_out += self._r2(r2_cmd) + "\n"
            except Exception as e: log.debug(f"r2 cmd failed: {e}")
        nm_out = ""
        for cmd in (["nm","-D",self.binary],["readelf","-s",self.binary]):
            try: nm_out += subprocess.check_output(cmd,stderr=subprocess.DEVNULL).decode(errors="ignore")
            except: pass
        combined = r2_out + nm_out
        for fn in self.VULNERABLE_FUNCTIONS:
            if fn in combined:
                findings["vulnerable_functions"].append(fn)
                if fn in ("malloc","free","realloc","calloc"):
                    findings["heap_functions"].append(fn)
        for fn in self.FORMAT_STRING_FUNCTIONS:
            if fn in combined: findings["format_string_functions"].append(fn)
        for fn in network_funcs:
            if fn in combined: findings["network_functions"].append(fn)
        for fn in self.RUST_SPECIFIC:
            if fn in combined: findings["rust_functions"].append(fn)
        for k in findings:
            if k != "all_functions": findings[k] = list(dict.fromkeys(findings[k]))
        functions = self._list_functions()
        findings["all_functions"] = functions
        if not functions:
            log.warning("No functions detected — binary may be stripped.")
            return findings, None, []
        priority_keywords = ["main","handle","client","process","input","recv","read",
                             "transaction","execute","svm","borsh"]
        target_function = None
        for kw in priority_keywords:
            for name,_ in functions:
                if kw in name.lower(): target_function=name; break
            if target_function: break
        if not target_function: target_function = functions[0][0]
        table = Table(title="Static Analysis",show_header=True,header_style="bold cyan")
        table.add_column("Category",style="cyan"); table.add_column("Detected",style="white")
        for k,v in findings.items():
            if k!="all_functions": table.add_row(k.replace("_"," ").title(),", ".join(v) or "—")
        table.add_row("Target Function",target_function)
        table.add_row("Fn sample (first 8)",
                      ", ".join(n for n,_ in functions[:8])+("…" if len(functions)>8 else ""))
        console.print(table)
        log.debug(f"All functions ({len(functions)}): {[n for n,_ in functions]}")
        return findings, target_function, functions

    def _list_functions(self):
        for cmd in ("afl","afll"):
            try:
                raw=self._r2(cmd); fns=self._parse_function_list(raw)
                if fns: return fns
            except: pass
        try:
            raw=self._r2("is"); fns=[]
            for line in raw.splitlines():
                parts=line.split()
                if len(parts)>=4 and parts[0].startswith("0x") and "FUNC" in line:
                    try:
                        addr=int(parts[0],16); name=parts[-1]
                        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$",name): fns.append((name,addr))
                    except: pass
            if fns: return fns
        except: pass
        try:
            out=subprocess.check_output(["nm",self.binary],stderr=subprocess.DEVNULL).decode(errors="ignore")
            fns=[]
            for line in out.splitlines():
                parts=line.split()
                if len(parts)>=3 and parts[1] in ("T","t"):
                    name=parts[2]
                    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$",name):
                        fns.append((name, int(parts[0],16) if parts[0]!="0"*len(parts[0]) else 0))
            if fns: return fns
        except: pass
        return [("main",0x0)]

    def _parse_function_list(self,raw):
        fns=[]
        for line in raw.splitlines():
            parts=line.split()
            if not parts or not parts[0].startswith("0x"): continue
            try:
                addr=int(parts[0],16); name=parts[-1]
                if (name and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$",name)
                        and not name.startswith(("sym.imp.","loc.","sub."))):
                    fns.append((name,addr))
            except: pass
        return fns

    def _r2(self,cmd):
        full=f"r2 -A -q -c '{cmd}' {self.binary}"
        return subprocess.check_output(full,shell=True,
                                        stderr=subprocess.DEVNULL,timeout=30).decode(errors="ignore")

    def check_protections(self):
        log.info("Checking binary protections…")
        stack_exec=True; nx=aslr=canary=pie=False
        relro="No RELRO"; safeseh=cfg=fortify=shadow_stack="N/A"
        try:
            if self.platform in ("linux","android"):
                stack_exec,nx,aslr,canary,relro,pie,fortify,shadow_stack=self._checksec_linux()
            elif self.platform=="windows":
                nx,aslr,canary,safeseh,cfg,pie=self._checksec_windows(); stack_exec=not nx
            elif self.platform=="macos":
                stack_exec,nx,aslr,canary,pie=self._checksec_macos()
        except Exception as e: log.warning(f"Protection check error: {e}")
        table=Table(title="Binary Protections",show_header=True,header_style="bold cyan")
        table.add_column("Protection",style="cyan"); table.add_column("Value",style="white")
        def yn(v): return "[green]Yes[/]" if v else "[red]No[/]"
        table.add_row("NX / DEP",yn(nx)); table.add_row("Stack Canary",yn(canary))
        table.add_row("ASLR / PIE",f"{yn(aslr)} / {yn(pie)}"); table.add_row("RELRO",relro)
        table.add_row("Stack Executable",yn(stack_exec)); table.add_row("FORTIFY_SOURCE",str(fortify))
        table.add_row("Shadow Stack (CET)",str(shadow_stack))
        if self.platform=="windows":
            table.add_row("SafeSEH",str(safeseh)); table.add_row("CFG",str(cfg))
        console.print(table)
        return stack_exec,nx,aslr,canary,relro,safeseh,cfg,fortify,pie,shadow_stack

    def _checksec_linux(self):
        stack_exec=nx=aslr=canary=pie=False; relro="No RELRO"
        fortify="Disabled"; shadow_stack="Disabled"
        try:
            re_out=subprocess.check_output(["readelf","-W","-l",self.binary],
                                            stderr=subprocess.DEVNULL).decode(errors="ignore")
            for line in re_out.splitlines():
                if "GNU_STACK" in line: stack_exec="RWE" in line; break
            nx=not stack_exec
            if "GNU_PROPERTY" in re_out:
                props=subprocess.check_output(["readelf","-n",self.binary],
                                               stderr=subprocess.DEVNULL).decode(errors="ignore")
                if "IBT" in props or "SHSTK" in props: shadow_stack="Enabled (CET)"
        except: pass
        try:
            cs=subprocess.check_output(["checksec","--file",self.binary],
                                        stderr=subprocess.STDOUT).decode(errors="ignore")
            nx=nx or ("NX enabled" in cs); aslr="PIE enabled" in cs; canary="Canary found" in cs
            pie=aslr; fortify="Fortified" if "FORTIFY" in cs else "Disabled"
            if "Full RELRO" in cs: relro="Full RELRO"
            elif "Partial RELRO" in cs: relro="Partial RELRO"
        except FileNotFoundError:
            log.warning("checksec not installed — using readelf/nm fallback")
            try:
                nm=subprocess.check_output(["nm","-D",self.binary],
                                            stderr=subprocess.DEVNULL).decode(errors="ignore")
                canary="__stack_chk_fail" in nm
            except: pass
            try:
                re_dyn=subprocess.check_output(["readelf","-d",self.binary],
                                                stderr=subprocess.DEVNULL).decode(errors="ignore")
                if "BIND_NOW" in re_dyn: relro="Full RELRO"
                elif "GNU_RELRO" in re_dyn: relro="Partial RELRO"
            except: pass
        return stack_exec,nx,aslr,canary,relro,pie,fortify,shadow_stack

    def _checksec_windows(self):
        import pefile
        nx=aslr=canary=False; safeseh=cfg="Disabled"
        pe=pefile.PE(self.binary); dc=pe.OPTIONAL_HEADER.DllCharacteristics
        nx=bool(dc&0x0100); aslr=bool(dc&0x0040); canary=bool(dc&0x10000)
        safeseh="Enabled" if dc&0x0400 else "Disabled"; cfg="Enabled" if dc&0x4000 else "Disabled"
        return nx,aslr,canary,safeseh,cfg,aslr

    def _checksec_macos(self):
        stack_exec=nx=aslr=canary=pie=False
        try:
            out=subprocess.check_output(["otool","-l",self.binary],
                                         stderr=subprocess.DEVNULL).decode(errors="ignore")
            nx="stack_exec" not in out; aslr=pie="PIE" in out
            nm=subprocess.check_output(["nm",self.binary],
                                        stderr=subprocess.DEVNULL).decode(errors="ignore")
            canary="___stack_chk_guard" in nm
        except Exception as e: log.warning(f"macOS checksec: {e}")
        return stack_exec,nx,aslr,canary,pie

    def frida_analyze(self,binary_args):
        log.info("Starting Frida dynamic analysis…")
        try: import frida
        except ImportError: log.error("frida not installed: pip install frida-tools"); return False
        script_code="""
'use strict';
const targets=["gets","strcpy","sprintf","scanf","recv","read","malloc","free","printf","system"];
targets.forEach(function(fn){
    var addr=Module.findExportByName(null,fn); if(!addr)return;
    Interceptor.attach(addr,{onEnter:function(args){send({fn:fn,arg0:args[0].toString(),tid:this.threadId});}});
});
"""
        cmd=[self.binary]+binary_args if binary_args else [self.binary]
        try:
            import subprocess as sp
            proc=sp.Popen(cmd,stdout=sp.DEVNULL,stderr=sp.DEVNULL)
            time.sleep(0.5); session=frida.attach(proc.pid)
            script=session.create_script(script_code); msgs=[]
            script.on("message",lambda m,d: msgs.append(m)); script.load()
            time.sleep(3); script.unload(); session.detach(); proc.terminate()
            log.info(f"Frida captured {len(msgs)} events")
            for m in msgs[:20]: log.debug(f"  Frida → {m.get('payload',m)}")
            return True
        except Exception as e: log.warning(f"Frida attach failed: {e}"); return False

    def load_library_offsets(self):
        log.info("Loading library offsets…")
        base_addr=None
        LIBC_OFFSETS={"libc.so.6":{
            "2.27":{"system":0x04F440,"binsh":0x1B3E1A,"execve":0x0E4E30,"puts":0x07D7C0,"tcache":0x3C4B20},
            "2.31":{"system":0x055410,"binsh":0x1B75AA,"execve":0x0E6C70,"tcache":0x1B2C40,"puts":0x080ED0},
            "2.35":{"system":0x050D70,"binsh":0x1B45BD,"execve":0x0E63B0,"tcache":0x219C80,"puts":0x080E50},
            "2.38":{"system":0x054EF0,"binsh":0x1BC351,"execve":0x0EAEA0,"tcache":0x21B2C0,"puts":0x0849C0},
            "2.39":{"system":0x058740,"binsh":0x1CB42F,"execve":0x0F2C80,"tcache":0x21D2C0,"puts":0x088D90},
        }}
        try:
            if self.platform in ("linux","android"):
                ldd_cmd=(["adb","shell",f"ldd {self.binary}"] if self.platform=="android"
                         else ["ldd",self.binary])
                try: ldd_out=subprocess.check_output(ldd_cmd,stderr=subprocess.DEVNULL).decode()
                except: ldd_out=""
                try:
                    if self.platform == "android":
                        maps_out = subprocess.check_output(
                            ["adb","shell","cat /proc/1/maps"], stderr=subprocess.DEVNULL
                        ).decode()
                        for line in maps_out.splitlines():
                            if "libc" in line and "r-xp" in line:
                                base_addr = int(line.split("-")[0], 16)
                                log.info(f"libc base (adb): {hex(base_addr)}"); break
                    else:
                        ldd_map = subprocess.check_output(
                            ["ldd", self.binary], stderr=subprocess.DEVNULL
                        ).decode()
                        for line in ldd_map.splitlines():
                            if "libc" in line:
                                m = re.search(r"=>\s+\S+\s+\((0x[0-9a-fA-F]+)\)", line)
                                if m:
                                    base_addr = int(m.group(1), 16)
                                    log.info(f"libc base (ldd): {hex(base_addr)}"); break
                except Exception: pass
            elif self.platform=="windows":
                import pefile; pe=pefile.PE(self.binary)
                dlls=[d.Name.decode() for d in pe.DIRECTORY_ENTRY_IMPORT]
                log.info(f"Imported DLLs: {dlls}")
                return dlls[0] if dlls else None,"unknown",{},None
            version, libc_path = self._detect_libc_version()
            offsets = LIBC_OFFSETS.get("libc.so.6", {}).get(version, {}) if version else {}
            if offsets:
                log.info(f"Loaded libc offsets for v{version}: {list(offsets.keys())}")
                return "libc.so.6", version, offsets, base_addr
            # Not in built-in table: extract from real libc binary on disk
            if libc_path and os.path.isfile(libc_path):
                extracted = self._extract_offsets_from_libc(libc_path)
                if extracted:
                    log.info(f"Extracted {len(extracted)} offsets from {libc_path}")
                    return "libc.so.6", version or "unknown", extracted, base_addr
            version_str = version or "unknown"
            log.warning(f"No built-in offsets for libc {version_str} — will query libc.rip after leak")
            return "libc.so.6", version_str, {}, base_addr
        except Exception as e:
            log.warning(f"Library offset loading failed: {e}"); return None,None,{},None

    def _detect_libc_version(self):
        """Returns (version_str, libc_path) or (None, None) if detection fails."""
        # Strategy 1: read version from the libc linked to the target binary
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
                            except Exception: pass
                        if vm:
                            log.info(f"libc version from target: {vm.group(1)} ({libc_path})")
                            return vm.group(1), libc_path
                        return None, libc_path  # path found but version unknown
        except Exception: pass
        # Strategy 2: host ldd --version
        try:
            out = subprocess.check_output(["ldd","--version"],stderr=subprocess.STDOUT).decode()
            m = re.search(r"(\d+\.\d+)", out)
            if m:
                log.info(f"libc version from host ldd: {m.group(1)}")
                return m.group(1), None
        except Exception: pass
        log.warning("Could not detect libc version — offsets will be fetched from libc.rip after leak")
        return None, None

    def _extract_offsets_from_libc(self, libc_path):
        """Extract symbol offsets from a real libc binary using nm."""
        offsets = {}
        symbols_wanted = {"system","execve","puts","printf","open","read","write","__libc_system"}
        try:
            nm_out = subprocess.check_output(
                ["nm","-D","--defined-only", libc_path], stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            for line in nm_out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[1] in ("T","W"):
                    name = parts[2]
                    if name in symbols_wanted:
                        try: offsets[name] = int(parts[0], 16)
                        except ValueError: pass
        except Exception as e: log.debug(f"nm libc extraction: {e}")
        try:
            st = subprocess.check_output(
                ["strings","-t","x", libc_path], stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            for line in st.splitlines():
                if line.strip().endswith("/bin/sh"):
                    m = re.match(r"\s*([0-9a-fA-F]+)\s+/bin/sh", line)
                    if m: offsets["binsh"] = int(m.group(1), 16); break
        except Exception as e: log.debug(f"strings /bin/sh: {e}")
        if "system" not in offsets and "__libc_system" in offsets:
            offsets["system"] = offsets["__libc_system"]
        return offsets

    def query_libc_rip(self,leaked_addr,symbol="puts"):
        log.info(f"Querying libc.rip: {symbol} leaked @ {hex(leaked_addr)}…")
        page_offset=hex(leaked_addr&0xfff)
        url=f"https://libc.rip/api/v1/find?symbols={symbol}={page_offset}"
        try:
            req=urllib.request.Request(url,headers={"User-Agent":"BinSmasher/4"})
            with urllib.request.urlopen(req,timeout=10) as resp:
                results=json.loads(resp.read())
        except urllib.error.URLError as e:
            log.warning(f"libc.rip unreachable: {e}"); return {}
        except Exception as e:
            log.error(f"libc.rip error: {e}"); return {}
        if not results:
            log.warning(f"libc.rip: no match for {symbol}+{page_offset}"); return {}
        best=results[0]
        log.info(f"libc.rip match: {best.get('id','unknown')} ({len(results)} candidates)")
        sym_offset=int(best["symbols"][symbol],16); libc_base=leaked_addr-sym_offset
        absolute={"__libc_base__":libc_base,"id":best.get("id","unknown")}
        for name,off_str in best["symbols"].items():
            try: absolute[name]=libc_base+int(off_str,16)
            except: pass
        log.info(f"libc base: {hex(libc_base)}  system: {hex(absolute.get('system',0))}")
        return absolute

    def detect_seccomp(self):
        log.info("Detecting seccomp filters…")
        result={"enabled":False,"rules":[],"orw_needed":False,"allowed":[],"blocked":[]}
        import shutil
        if not shutil.which("seccomp-tools"):
            log.warning("seccomp-tools not installed: gem install seccomp-tools"); return result
        try:
            out=subprocess.check_output(["seccomp-tools","dump",self.binary],
                                         stderr=subprocess.DEVNULL,timeout=12).decode(errors="ignore")
            if not out.strip(): return result
            result["enabled"]=True; result["rules"]=out.strip().splitlines()
            for line in result["rules"]:
                low=line.lower(); m=re.search(r"sys_(\w+)",line); name=m.group(1) if m else None
                if "allow" in low and name: result["allowed"].append(name)
                elif ("kill" in low or "errno" in low or "trap" in low) and name:
                    result["blocked"].append(name)
            result["orw_needed"]=("execve" in result["blocked"] or
                (bool(result["allowed"]) and "execve" not in result["allowed"]))
            log.info(f"seccomp: enabled={result['enabled']} orw_needed={result['orw_needed']}")
        except subprocess.TimeoutExpired: log.warning("seccomp-tools timed out")
        except Exception as e: log.warning(f"seccomp detection failed: {e}")
        return result

    def patch_binary_for_local(self,libc_path,ld_path=""):
        import shutil as _sh
        if _sh.which("pwninit"):
            cmd=["pwninit","--bin",self.binary,"--libc",libc_path,"--no-template"]
            if ld_path: cmd+=["--ld",ld_path]
            try:
                subprocess.run(cmd,check=True,timeout=30,
                               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                candidate=self.binary+"_patched"
                if os.path.isfile(candidate): log.info(f"pwninit: {candidate}"); return candidate
            except Exception as e: log.warning(f"pwninit failed: {e}")
        if _sh.which("patchelf"):
            patched=self.binary+"_patched"
            try:
                _sh.copy2(self.binary,patched)
                if not ld_path:
                    arch_interp = {
                        "amd64":   "/lib64/ld-linux-x86-64.so.2",
                        "i386":    "/lib/ld-linux.so.2",
                        "arm":     "/lib/ld-linux-armhf.so.3",
                        "aarch64": "/lib/ld-linux-aarch64.so.1",
                    }
                    ld_path = arch_interp.get(self.arch, "/lib64/ld-linux-x86-64.so.2")
                rpath=os.path.dirname(os.path.abspath(libc_path))
                subprocess.run(["patchelf","--set-interpreter",ld_path,"--set-rpath",rpath,patched],
                               check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                log.info(f"patchelf: {patched}"); return patched
            except Exception as e: log.error(f"patchelf failed: {e}")
        else: log.warning("Neither pwninit nor patchelf found")
        return self.binary

    def recover_functions_stripped(self):
        log.info("Recovering functions from stripped binary…")
        recovered=[]
        try:
            out=subprocess.check_output(["r2","-A","-q","-c","aaa; aac; aan; aflj",self.binary],
                                         stderr=subprocess.DEVNULL,timeout=60).decode(errors="ignore")
            try:
                for fn in json.loads(out): recovered.append((fn.get("offset",0),fn.get("name","unknown")))
            except:
                for line in out.splitlines():
                    m=re.match(r"(0x[0-9a-fA-F]+)",line)
                    if m: recovered.append((int(m.group(1),16),f"fcn_{m.group(1)}"))
        except Exception as e: log.warning(f"  r2 stripped: {e}")
        try:
            arch_prologues = {
                "amd64":   [b"\x55\x48\x89\xE5", b"\x55\x48\x8B\xEC"],
                "i386":    [b"\x55\x89\xE5",       b"\x55\x89\xEC"],
                "arm":     [b"\x00\x48\x2D\xE9",  b"\xF0\x4F\x2D\xE9"],
                "aarch64": [b"\xFF\x03\x01\xD1",  b"\xFD\x7B\xBF\xA9"],
            }
            prologues = arch_prologues.get(self.arch, arch_prologues["amd64"])
            data = open(self.binary,"rb").read()
            for prologue in prologues:
                idx = 0
                while True:
                    idx = data.find(prologue, idx)
                    if idx == -1: break
                    if not any(a==idx for a,_ in recovered):
                        recovered.append((idx, f"prologue_{hex(idx)}"))
                    idx += len(prologue)
        except Exception as e: log.warning(f"  prologue scan: {e}")
        try:
            import angr
            proj=angr.Project(self.binary,auto_load_libs=False); cfg=proj.analyses.CFGFast()
            for addr,fn in list(cfg.functions.items())[:50]:
                if not any(a==addr for a,_ in recovered):
                    recovered.append((addr,fn.name or f"angr_{hex(addr)}"))
        except ImportError: pass
        except Exception as e: log.warning(f"  angr: {e}")
        log.info(f"Stripped: {len(recovered)} candidates"); return recovered

    def mte_info(self):
        from pwn import context
        info={"mte_detected":False,"arch":context.arch,"bypass_hint":"N/A"}
        if context.arch not in ("aarch64",):
            info["bypass_hint"]="MTE is ARM64-only"; return info
        try:
            re_out=subprocess.check_output(["readelf","-d",self.binary],stderr=subprocess.DEVNULL).decode(errors="ignore")
            nm_out=subprocess.check_output(["nm",self.binary],stderr=subprocess.DEVNULL).decode(errors="ignore")
            if "memtag" in re_out.lower() or "__hwasan" in nm_out.lower():
                info["mte_detected"]=True
                info["bypass_hint"]="MTE: (1) brute 16 tags, (2) %p leak tag nibble, (3) mmap no PROT_MTE"
        except Exception as e: log.warning(f"MTE: {e}")
        return info

    def grep_unsafe_source(self,source_path):
        log.info(f"Grepping Rust source in {source_path} for 'unsafe'…")
        unsafe_files=[]; unsafe_total=0
        try:
            for root,_,files in os.walk(source_path):
                for fname in files:
                    if not fname.endswith(".rs"): continue
                    fpath=os.path.join(root,fname)
                    try:
                        content=open(fpath,encoding="utf-8",errors="ignore").read()
                        n=content.count("unsafe")
                        if n: unsafe_total+=n; unsafe_files.append(fpath); log.debug(f"  {fpath}: {n}")
                    except OSError: pass
            log.info(f"unsafe: {unsafe_total} in {len(unsafe_files)} files"); return unsafe_files
        except Exception as e: log.error(f"Source grep: {e}"); return []
