import pwn
import random
import time

if pwn.args.REMOTE:
    io = pwn.remote("localhost", 1024)
else:
    io = pwn.process("python3 main.py", shell=True)

random.seed(int(time.time()))

io.recvuntil(b"n = ")
n = int(io.recvline())
io.recvuntil(b"y = ")
y = int(io.recvline())

x = random.randrange(1, n)

b0_counter = 1
b1_counter = 2

for i in range(128):
    b = random.randrange(2)
    if b == 0:
        s = pow(y, b0_counter, n)
        z = pow(y, (b0_counter + 1) // 2, n)
        b0_counter += 2
    else:
        z = b1_counter
        s = pow(b1_counter, 2, n)
        b1_counter += 1

    io.sendlineafter(b"Provide s: ", str(s).encode())
    io.sendlineafter(b"Provide z: ", str(z).encode())

io.interactive()
