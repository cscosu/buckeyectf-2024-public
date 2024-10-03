from tree_store_helpful import *
from PIL import Image, ImageFont, ImageDraw
import string
import struct
from collections import OrderedDict
import pwn
from base64 import b64encode
from tqdm import tqdm


"""
Version of solve.py that sends payloads in bulk to the server to solve faster on a slow connection.

With my connection to the challenge server, it took 1 hour and 37 minutes for solve.py to complete.
It took 3 minutes and 51 seconds for solve_fast.py to complete.

For some reason, this script hangs for me in io.sendline() ONLY when "pwn.args.REMOTE" is false
(i.e. it only works through a network connection, not through a process connection)
"""


class RemoteTreeStore:
    def __init__(self):
        self.connect()

    def connect(self):
        if pwn.args.REMOTE:
            # self.io = pwn.remote("localhost", 1024)
            self.io = pwn.remote("challs.pwnoh.io", 13420)
        else:
            self.io = pwn.process("python3 ../main.py", shell=True)
        self.n_bytes_sent = 0

    def reconnect(self):
        self.io.close()
        self.connect()

    def add_file(self, file: bytes) -> int:
        try:
            self.io.sendlineafter(b">>> ", b64encode(file))
            s = self.io.recvline()

            if b"Max storage exceeded" in s:
                self.reconnect()
                return self.add_file(file)

            self.n_bytes_sent += len(file)
            n = int(s.split(b"chunks were added\n")[0].decode())
            return n

        except EOFError:
            self.reconnect()
            return self.add_file(file)

    def add_files_bulk(self, files: list[bytes]) -> list[int]:
        n_bytes = sum(len(file) for file in files)
        assert n_bytes <= 2 * 1024 * 1024
        if self.n_bytes_sent + n_bytes > 2 * 1024 * 1024:
            print("[*] Going to exceed max storage; reconnecting")
            self.reconnect()

        payload = b"\n".join(b64encode(file) for file in files)
        self.io.sendlineafter(b">>> ", payload)

        results = [0] * len(files)
        for i in range(len(files)):
            while True:
                s = self.io.recvline()
                if b"chunks were added" in s:
                    break

            n = int(s.split(b"chunks were added\n")[0].removeprefix(b">>> ").decode())
            results[i] = n

        self.n_bytes_sent += n_bytes
        return results


# Connection to the remote tree store
remote_ts = RemoteTreeStore()

# Local tree store with some helpful functions
local_ts = TreeStoreHelpful()


def render(msg: str):
    char_size = (16, 32)  # (width, height)
    width = char_size[0] * len(msg)
    image = Image.new("RGBA", (width, char_size[1]), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    font = ImageFont.load("./ter-x32b.pil")  # Terminus 32px
    draw.text((0, 0), msg, font=font)
    image.save("all.bmp", format="BMP")


def guess_image_width() -> int:
    # We need to figure out how many characters are in the flag (i.e. how wide the image is).
    # The second chunk contains image width, so keep guessing until the chunk matches.
    min_chars = len("bctf{xxx}")
    max_chars = 32
    for n_chars in range(min_chars, max_chars):
        image_width = 16 * n_chars
        second_chunk = get_second_chunk(image_width)
        n = remote_ts.add_file(second_chunk)
        if n == 0:
            print(f"[+] Found image width: {image_width}")
            return image_width

    raise ValueError("Couldn't find image width")


def get_file_size(image_width: int):
    return image_width * 128 + 54


def get_first_chunk(image_width: int):
    len_file = get_file_size(image_width)
    return bytes.fromhex(
        "424d{}00000000360000002800".format(struct.pack("<I", len_file).hex())
    )


def get_second_chunk(image_width: int):
    return bytes.fromhex(
        "0000{}20000000010020000000".format(struct.pack("<I", image_width).hex())
    )


def get_third_chunk(image_width: int):
    len_image = image_width * 128
    return bytes.fromhex(
        "0000{}c40e0000c40e00000000".format(struct.pack("<I", len_image).hex())
    )


def collect_leaf_nodes(image_width: int) -> list[bytes]:
    # Get the first three chunks. We only need the image_width to deduce these.
    first_chunk = get_first_chunk(image_width)
    second_chunk = get_second_chunk(image_width)
    third_chunk = get_third_chunk(image_width)
    assert remote_ts.add_file(first_chunk) == 0
    assert remote_ts.add_file(second_chunk) == 0
    assert remote_ts.add_file(third_chunk) == 0

    leaf_nodes = [first_chunk, second_chunk, third_chunk]

    # Create an image with all possible characters to get all possible leaf nodes.
    render(
        "bctf{ + "
        + string.ascii_lowercase
        + string.ascii_uppercase
        + string.digits
        + "_}"
    )
    with open("all.bmp", "rb") as f:
        image_bytes = f.read()

    chunks = list(get_chunks(image_bytes))
    chunks = chunks[
        3:
    ]  # ignore first 3 chunks because they just contain BMP header stuff
    possible_chunks = sorted(list(set(chunks)))
    print(f"[*] Found {len(possible_chunks)} possible unique chunks")

    # Now filter down to the chunks that are actually in the flag file.
    for chunk in possible_chunks:
        if remote_ts.add_file(chunk) == 0:
            leaf_nodes.append(chunk)

    print(f"[+] Found {len(leaf_nodes)} leaf nodes")
    return leaf_nodes


def collect_second_layer_nodes(leaf_nodes: list[bytes]):
    nodes = []

    for chunk_a in tqdm(leaf_nodes):
        # Because the last chunk is not a full chunk size, it's possible to send the same file with
        # different `data_left` and `data_right` values.
        # Case A: 00000000000000000000000000000000 + 000000000000
        # Case B: 000000000000 + 00000000000000000000000000000000
        # However, case B should never occur, because the small chunk should always be at the end.
        # So if `data_left` is the small chunk, skip those cases.
        if len(chunk_a) % chunk_size != 0:
            continue

        files = []
        chunk_bs = leaf_nodes
        for chunk_b in chunk_bs:
            files.append(chunk_a + chunk_b)

        ns = remote_ts.add_files_bulk(files)

        for i, n in enumerate(ns):
            if n == 0:
                chunk_b = chunk_bs[i]
                local_ts.add_file(chunk_a + chunk_b)
                hash_a = get_hash(leaf_node_identifier + chunk_a)
                hash_b = get_hash(leaf_node_identifier + chunk_b)
                hash_ab = get_hash(internal_node_identifier + hash_a + hash_b)
                nodes.append(hash_ab)

    # Note: If we wanted to be thorough, we should also check for this possibility
    #    [x]
    #   /   \
    # [a]  [empty]
    #
    # Fortunately this case doesn't occur for the flag, so it's fine.

    print(f"[+] Found {len(nodes)} second layer nodes")
    return nodes


third_layer_nodes = dict()
parent_hashes = dict()


def bruteforce_parent_nodes(nodes: list[bytes]) -> list[bytes]:
    parent_nodes = []
    for hash_a in tqdm(nodes):
        data_left = local_ts.get_file(hash_a)

        # Because the last chunk is not a full chunk size, it's possible to send the same file with
        # different `data_left` and `data_right` values.
        # Case A: 00000000000000000000000000000000000000000000ffffffffffffffffffff + 00000000000000000000000000000000000000000000
        # Case B: 00000000000000000000000000000000000000000000 + ffffffffffffffffffff00000000000000000000000000000000000000000000
        # However, case B should never occur, because the small chunk should always be at the end.
        # So if `data_left` contains a small chunk, skip those cases.
        if len(data_left) % chunk_size != 0:
            continue

        files = []
        hash_bs = nodes
        data_rights = [local_ts.get_file(hash_b) for hash_b in hash_bs]
        for data_right in data_rights:
            file = data_left + data_right
            files.append(file)

        ns = remote_ts.add_files_bulk(files)

        for i, n in enumerate(ns):
            hash_b = hash_bs[i]
            file = files[i]
            if n == 0:
                hash_ab = get_hash(internal_node_identifier + hash_a + hash_b)
                parent_nodes.append(hash_ab)
                local_ts.add_file(file)
                parent_hashes[hash_ab] = (hash_a, hash_b)

    if len(parent_nodes) == 1:
        return parent_nodes

    # Now we have to consider the case where a parent has an empty right child

    # Take any of the known parents we just found.
    # Make sure to avoid picking the one that contains the small chunk.
    known_parent = None
    for parent in parent_nodes:
        if len(local_ts.get_file(parent)) % chunk_size == 0:
            known_parent = parent
            break
    assert known_parent != None

    # Let kp = known_parent.
    # We want to know if x already exists in the tree or not.
    # To do this, we call `add_file` with
    # file = data(kp) + data(x)
    # file = data(kp) + data(child)
    #
    # There are three possible outcomes:
    # - Two new nodes are created: x and y. Then clearly x does not already exist in the tree.
    # - One new node is created: x. Then x already exists in the tree! So we should add it to our
    #   list.
    # - No new nodes are created. Then x and y both already exist in the tree! We should add x to
    #   our list. On the next iteration, we can find y with the same method.
    #
    #             [y]
    #          /       \
    #     [kp]           [x]
    #    /    \        /    \
    # [...] [...]  [child]  [empty]

    files = []
    data_left = local_ts.get_file(known_parent)
    childs = nodes
    data_rights = [local_ts.get_file(child) for child in childs]
    for data_right in data_rights:
        file = data_left + data_right
        files.append(file)

    ns = remote_ts.add_files_bulk(files)

    for i, n in enumerate(ns):
        child = childs[i]
        if n <= 1:
            data = internal_node_identifier + child + empty_node_identifier
            parent = get_hash(data)
            parent_nodes.append(parent)
            local_ts.table[parent] = data

    return parent_nodes


def collect_third_layer_and_above_nodes(second_layer_nodes: list[bytes], len_file: int):
    nodes = second_layer_nodes
    while len(nodes) > 1:
        parent_nodes = bruteforce_parent_nodes(nodes)
        print(f"[+] Found {len(parent_nodes)} parent nodes")
        nodes = parent_nodes
        remote_ts.reconnect()

    print(f"[+] Root node: {nodes[0].hex()}")
    da_flag = local_ts.get_file(nodes[0])
    with open("da_flag.bmp", "wb") as f:
        f.write(da_flag)
    print(f"[+] Flag written to da_flag.bmp")


def solve():
    image_width = guess_image_width()
    remote_ts.reconnect()
    leaf_nodes = collect_leaf_nodes(image_width)
    second_layer_nodes = collect_second_layer_nodes(leaf_nodes)
    remote_ts.reconnect()
    collect_third_layer_and_above_nodes(second_layer_nodes, get_file_size(image_width))


if __name__ == "__main__":
    solve()
