import hashlib
import struct


"""
Copied implementation of TreeStore, but with some more helpful functions.
"""


chunk_size = 16
hash_size = 32
leaf_node_identifier = b"L"
empty_node_identifier = b"E"
internal_node_identifier = b"I"


def get_chunks(xs, n: int = chunk_size):
    for i in range(0, len(xs), n):
        yield xs[i : i + n]


def pairwise(xs):
    # # pairwise("ABCDEFG") → AB CD EF G
    iterator = iter(xs)
    while True:
        a = next(iterator, None)
        b = next(iterator, None)
        if a != None:
            yield a, b
        else:
            break


def get_hash(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()


class TreeStoreHelpful:
    def __init__(self):
        self.table = dict()

    def add_file(self, file: bytes):
        added_chunks = 0
        layer_added_chunks = 0

        hashes = []
        for chunk in get_chunks(file):
            data = leaf_node_identifier + chunk
            hash = get_hash(data)
            if hash not in self.table:
                self.table[hash] = data
                layer_added_chunks += 1
            hashes.append(hash)

        # print(f"Added {layer_added_chunks} leaf nodes")
        added_chunks += layer_added_chunks

        while len(hashes) > 1:
            layer_added_chunks = 0
            new_hashes = []
            for left, right in pairwise(hashes):
                if right == None:
                    right = empty_node_identifier

                data = internal_node_identifier + left + right
                hash = get_hash(data)
                if hash not in self.table:
                    self.table[hash] = data
                    layer_added_chunks += 1
                new_hashes.append(hash)

            # print(f"Added {layer_added_chunks} nodes at layer")
            added_chunks += layer_added_chunks
            hashes = new_hashes

        # print(f"{added_chunks} total chunks were added")
        # print(f"Root hash: {hashes[0].hex()}")

    def get_file(self, hash: bytes):
        if hash == empty_node_identifier:
            return b""
        if hash not in self.table:
            raise ValueError(f"Hash {hash.hex()} not found")

        data = self.table[hash]
        if data[0] == leaf_node_identifier[0]:
            result = data[1:]
            return result
        elif data[0] == internal_node_identifier[0]:
            hash_left = data[1 : 1 + hash_size]
            hash_right = data[1 + hash_size : 1 + hash_size * 2]
            # print(f"Internal node: {hash.hex()} {hash_left.hex()} {hash_right.hex()}")
            data_left = self.get_file(hash_left)
            data_right = self.get_file(hash_right)
            return data_left + data_right
        else:
            raise ValueError(f"Invalid data {data} for hash {hash.hex()}")
