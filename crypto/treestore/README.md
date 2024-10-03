# treestore

> I learned about IPFS the other day and tried rolling my own implementation!

## Challenge

- The server adds a `flag.bmp` file into the treestore at startup.
- Users can send files (base64 encoded) to store in the treestore.
- The server tells them how many new chunks were added.
- Files are split in 16 byte chunks, and the structure of the file is stored in a Merkle Tree
  (technically a Merkle DAG).
- Normally the server should allow you to query a file given a hash, but `get_file` is not implemented.
- The goal is to get the contents of `flag.bmp` from the server

## Solution

> TLDR: The number of new chunks can be used as a compression oracle to deduce
> the contents of flag.bmp. This is easier said than done due to the tree
> structure.

Let's say a certain 16 byte chunk with contents `A` already exists on the server.
- Then adding a new file with contents `A` will cause the server to print `0 chunks added`.
- On the other hand, adding a new file with contents `B` will cause the server to print `1 chunks
  added`.

Basically, the server de-duplicates chunks, and we can use this to deduce what chunks are in
`flag.bmp`.

Since `make_flag.py` is provided, we know exactly how the flag is rendered in a BMP image.
- BMP files basically consist of some headers (info about height, width, pixel format),
  followed by bytes that specify the full grid of pixels.
- Since the flag is rendered in black in white with a bitmap font, there are likely not that many
  unique 16 byte chunks. We can bruteforce this. Use `make_flag.py` to render all possible
  characters in the flag, and get all unique 16 byte chunks (see `collect_leaf_nodes()`). There are
  only 20 unique chunks, and `flag.bmp` contains 19 of these.
- However, we don't know the length of the flag (i.e. the image width). But we can also bruteforce
  this, because the BMP header format is predictable (see `guess_image_width()`)

Now that we have all 16 byte chunks in the flag (i.e. the leaf nodes), we need to figure out how
these chunks are paired together (i.e. understand the layer above the leaf nodes).
- Since there are only 19 leaf nodes, simply bruteforce all possible pairs (there are approximately
  `19 ** 2 == 361` pairs).
- Note that a parent node can have identical child nodes.
- Also note that a parent node can have an empty right node. This is tricky to deal with, but see
  the solve script for details.
- Once we have the second layer nodes, we can find the third layer nodes the same way. Repeat this
  until you there is only one node left. It must be the root node, which means you have the complete
  `flag.bmp` file now!
- Note: The largest layer of `flag.bmp` only contains 166 nodes, which requires guessing `166 ** 2 ==
  27556` pairs.

See `solve.py` for a complete solve script.
See `solve_fast.py` for a faster solve script, which sends files in bulk to the server.
