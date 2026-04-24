"""GDB script generation methods for Fuzzer."""
import os
import shlex
import logging

log = logging.getLogger("binsmasher")


class GDBScriptsMixin:
    """Methods: generate_gdb_script."""

    def generate_gdb_script(self, binary: str, offset: int, exploit_type: str = "ret2win",
                             win_addr: int = 0, libc_base: int = 0, mode: str = "pwndbg") -> str:
        from pwn import context, ELF
        workdir = os.path.join(os.path.dirname(os.path.abspath(binary)), "_bs_work")
        os.makedirs(workdir, exist_ok=True)
        bname = os.path.basename(binary)
        outfile = os.path.join(workdir, bname + "_" + mode + ".gdb")
        arch = "amd64" if context.arch == "amd64" else "i386"
        q = shlex.quote(binary)
        sz = offset + 64

        lines = [
            "set pagination off",
            "set confirm off",
            "file " + q,
        ]

        if mode == "peda":
            lines.append("source /usr/share/peda/peda.py")

        lines += [
            "",
            "# ── find offset ─────────────────────────────────────────────",
            "define bs_find_offset",
            "  set $pat_size = " + str(sz),
            "  run <<< $(python3 -c 'from pwn import cyclic; import sys; sys.stdout.buffer.write(cyclic(" + str(sz) + "))')",
            "  info registers rip",
            "  python",
            "from pwn import cyclic_find",
            "v = gdb.parse_and_eval('$rip')",
            "off = cyclic_find(int(v) & 0xffffffff)",
            "print('cyclic_find offset:', off)",
            "  end",
            "end",
            "",
        ]

        if win_addr:
            lines += [
                "# ── win function ─────────────────────────────────────────────",
                "break *" + hex(win_addr),
                "",
            ]

        try:
            elf = ELF(binary, checksec=False)
            funcs = [n for n, a in elf.symbols.items() if a and not n.startswith("_")][:6]
            lines.append("# breakpoints on interesting functions (uncomment to enable):")
            for fn in funcs:
                lines.append("# break " + fn)
            lines.append("")
        except Exception:
            pass

        lines += [
            "# ── stack helpers ────────────────────────────────────────────",
            "define bs_stack",
            "  x/32gx $rsp",
            "end",
            "define bs_regs",
            "  info registers",
            "end",
            "",
            "define bs_exploit",
            "  python",
            "from pwn import *",
            "context.arch = '" + arch + "'",
            "e   = ELF('" + binary.replace("'", "\\'") + "', checksec=False)",
            "rop = ROP(e)",
            "win = e.symbols.get('win', " + (hex(win_addr) if win_addr else "0") + ")",
            "g   = rop.find_gadget(['ret'])",
            "ret_g = g[0] if g else 0",
            "payload = b'A'*" + str(offset) + " + p64(ret_g) + p64(win) if win else b'A'*" + str(offset + 8),
            "print('Payload (' + str(len(payload)) + 'B):', payload.hex())",
            "  end",
            "end",
            "",
        ]

        if mode == "pwndbg":
            lines += [
                "# pwndbg tips:",
                "# telescope $rsp 20   — annotated stack view",
                "# checksec            — binary protections",
                "# rop                 — ROP gadget search",
                "# heap                — heap chunk view",
                "# got                 — GOT table",
            ]
        elif mode == "peda":
            lines += [
                "# PEDA tips:",
                "# pattern create 200  — create De Bruijn pattern",
                "# pattern offset EIP  — find offset from pattern",
                "# checksec            — binary protections",
                "# ropgadget           — ROP gadgets",
                "# searchmem /bin/sh   — search memory for string",
            ]
        else:
            lines += [
                "# vanilla GDB tips:",
                "# x/32gx $rsp        — dump stack",
                "# info functions     — list functions",
                "# disas main         — disassemble main",
            ]

        script = '\n'.join(lines) + '\n'
        with open(outfile, "w") as f:
            f.write(script)
        log.info("GDB " + mode + " script → " + outfile)
        log.info("  Run: gdb -x " + outfile)
        return outfile
