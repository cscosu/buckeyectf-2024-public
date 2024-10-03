from tree_store_helpful import *


def test_add_file_one_chunk():
    ts = TreeStoreHelpful()
    file = b"a" * chunk_size
    ts.add_file(file)
    data_a = leaf_node_identifier + b"a" * chunk_size
    hash_a = get_hash(data_a)
    assert len(ts.table) == 1
    assert ts.table[hash_a] == data_a

    fetched_file = ts.get_file(hash_a)
    assert fetched_file == file


def test_add_file_two_chunks():
    ts = TreeStoreHelpful()
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

    fetched_file = ts.get_file(hash_ab)
    assert fetched_file == file


if __name__ == "__main__":
    test_add_file_one_chunk()
    test_add_file_two_chunks()
