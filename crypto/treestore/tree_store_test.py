from tree_store import *


def test_add_file_one_chunk():
    ts = TreeStore()
    file = b"a" * chunk_size
    ts.add_file(file)
    data_a = leaf_node_identifier + b"a" * chunk_size
    hash_a = get_hash(data_a)
    assert len(ts.table) == 1
    assert ts.table[hash_a] == data_a


def test_add_file_two_chunks():
    ts = TreeStore()
    file = b"a" * chunk_size
    file += b"b" * chunk_size
    ts.add_file(file)

    data_a = leaf_node_identifier + b"a" * chunk_size
    data_b = leaf_node_identifier + b"b" * chunk_size
    hash_a = get_hash(data_a)
    hash_b = get_hash(data_b)
    data_ab = internal_node_identifier + hash_a + hash_b
    hash_ab = get_hash(data_ab)

    assert len(ts.table) == 3
    assert ts.table[hash_a] == data_a
    assert ts.table[hash_b] == data_b
    assert ts.table[hash_ab] == data_ab


def test_add_file_three_chunks():
    ts = TreeStore()
    file = b"a" * chunk_size
    file += b"b" * chunk_size
    file += b"c" * chunk_size
    ts.add_file(file)

    data_a = leaf_node_identifier + b"a" * chunk_size
    data_b = leaf_node_identifier + b"b" * chunk_size
    data_c = leaf_node_identifier + b"c" * chunk_size
    hash_a = get_hash(data_a)
    hash_b = get_hash(data_b)
    hash_c = get_hash(data_c)
    data_ab = internal_node_identifier + hash_a + hash_b
    hash_ab = get_hash(data_ab)
    data_c_parent = internal_node_identifier + hash_c + empty_node_identifier
    hash_c_parent = get_hash(data_c_parent)
    data_root = internal_node_identifier + hash_ab + hash_c_parent
    hash_root = get_hash(data_root)

    assert len(ts.table) == 6
    assert ts.table[hash_a] == data_a
    assert ts.table[hash_b] == data_b
    assert ts.table[hash_c] == data_c
    assert ts.table[hash_ab] == data_ab
    assert ts.table[hash_c_parent] == data_c_parent
    assert ts.table[hash_root] == data_root


def test_add_file_dedup_two_chunks():
    ts = TreeStore()
    file = b"a" * chunk_size
    file += b"a" * chunk_size
    ts.add_file(file)

    data_a = leaf_node_identifier + b"a" * chunk_size
    hash_a = get_hash(data_a)
    data_aa = internal_node_identifier + hash_a + hash_a
    hash_aa = get_hash(data_aa)

    assert len(ts.table) == 2
    assert ts.table[hash_a] == data_a
    assert ts.table[hash_aa] == data_aa


def test_add_file_dedup_three_chunks():
    ts = TreeStore()
    file = b"a" * chunk_size
    file += b"a" * chunk_size
    file += b"b" * chunk_size
    ts.add_file(file)

    data_a = leaf_node_identifier + b"a" * chunk_size
    data_b = leaf_node_identifier + b"b" * chunk_size
    hash_a = get_hash(data_a)
    hash_b = get_hash(data_b)
    data_aa = internal_node_identifier + hash_a + hash_a
    hash_aa = get_hash(data_aa)
    data_b_parent = internal_node_identifier + hash_b + empty_node_identifier
    hash_b_parent = get_hash(data_b_parent)
    data_root = internal_node_identifier + hash_aa + hash_b_parent
    hash_root = get_hash(data_root)

    assert len(ts.table) == 5
    assert ts.table[hash_a] == data_a
    assert ts.table[hash_b] == data_b
    assert ts.table[hash_aa] == data_aa
    assert ts.table[hash_b_parent] == data_b_parent
    assert ts.table[hash_root] == data_root


def test_add_add_file():
    ts = TreeStore()
    with open("flag.bmp", "rb") as f:
        flag_bytes = f.read()
    print(f"Flag has {len(flag_bytes)} bytes")
    ts.add_file(flag_bytes)


def test_add_file_dedup_four_chunks():
    ts = TreeStore()
    file = bytes.fromhex("424d36c800000000000036000000280000009001000020000000010020000000000000c80000c40e0000c40e0000000000000000000000000000000000000000")
    ts.add_file(file)

    data_a = leaf_node_identifier + file[:16]
    data_b = leaf_node_identifier + file[16:32]
    hash_a = get_hash(data_a)
    hash_b = get_hash(data_b)
    data_ab = internal_node_identifier + hash_a + hash_b
    hash_ab = get_hash(data_ab)

    data_c = leaf_node_identifier + file[32:48]
    data_d = leaf_node_identifier + file[48:64]
    hash_c = get_hash(data_c)
    hash_d = get_hash(data_d)
    data_cd = internal_node_identifier + hash_c + hash_d
    hash_cd = get_hash(data_cd)

    data_root = internal_node_identifier + hash_ab + hash_cd
    hash_root = get_hash(data_root)

    assert len(ts.table) == 6
    assert ts.table[hash_a] == data_a
    assert ts.table[hash_b] == data_b
    assert ts.table[hash_ab] == data_ab
    assert ts.table[hash_c] == data_c
    assert ts.table[hash_d] == data_d
    assert ts.table[hash_cd] == data_cd
    assert ts.table[hash_root] == data_root

    assert ts.add_file(file[32:48] + file[48:64]) == 0


if __name__ == "__main__":
    test_add_file_one_chunk()
    test_add_file_two_chunks()
    test_add_file_three_chunks()

    test_add_file_dedup_two_chunks()
    test_add_file_dedup_three_chunks()

    test_add_add_file()
