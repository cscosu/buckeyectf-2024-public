## About

Author: `corgo`

`rev` `medium`

Autohotkey keylogger compiled to exe

## Solve

- this 'compilation' is really just shoving autohotkey and your script into the same .exe, same idea as those python-to-exe packagers
- therefore, `strings` can recover the macro or you can open the .exe as a ZIP and look in .rsrc/RCDATA/
- read macro code, it's just a keylogger that checks if you've typed the flag at any point. flag itself is obfsucated with a simple XOR cipher
