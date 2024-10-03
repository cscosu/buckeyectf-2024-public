## About

Author: `corgo`

`misc` `hard`

Get RCE with Python's format string vulnerability-- previously thought impossible

## Solve

*very* hard to fit in a TLDR, full writeup [here](https://corgi.rip/posts/buckeye-writeups/#gentleman)

- user model in `models.py` has a format string vulnerability in its `__repr__`
- this function is used, but its output is never directly shown to the user
- this means you cannot leak flask's `SECRET_KEY` or anything similar; RCE is required
- while .format() can only access attributes and index objects, those still perform function calls
- search python standard library to find that the `ctypes.cdll` object lets you load arbitrary libraries into the interpreter by indexing it
- use score saving endpoint to write a malicious library to disk, load with `ctypes.cdll[/file/to/load]`


