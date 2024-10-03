## About

Author: Corgo

`pwn` `medium`

Given libc leak & buffer overflow, BUT the remote system has no binaries other than the vulnerable program

## Solve

- perform the following ROP chain:
- use mprotect() to mark all of libc as RWX
- use gets() to write shellcode to a place of your choice
- jump to that shellcode, with that shellcode opening and reading flag.txt



```bash
python solve.py
```