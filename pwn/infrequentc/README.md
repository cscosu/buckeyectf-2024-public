## About

Author: `corgo`

`pwn` `hard`


Small frequency analysis program with very sneaky vulnerability

## Solve

 - `char`s are signed!
 - sending a character with its MSB set causes the character-counting loop to increment a negative index of `counts`
 - increment `largest` enough to have the 'most frequent' message leak a libc address
 - increment `filename` enough to make it start at the return address
 - supply a onegadget as your filename, get a shell
