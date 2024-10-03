## About

Author: `corgo`

`pwn` `medium`




> The king of flags has sent you on a journey across the world with nothing but a pie. Will you prevail?

## Description

- PIE disabled program gives user infinite-use arbitrary read
- User must leak the base of EVERYTHING loaded into memory using this vulnerability

## Solve

- We know the program's base address as PIE is disabled
- We can parse ld's `link_map` to get the base address of libc, ld, and vdso
- libc has tons of symbols containing heap addresses, `main_arena` is an easy pick
- libc also has the symbol `__environ` which leaks a stack address. the stack is a little inconsistent but you can guess the base using that about ~30% of the time.
- some googling shows that `vsyscall` isn't affected by ASLR and can be hardcoded
that's everything you need, so just submit all that and you're done
