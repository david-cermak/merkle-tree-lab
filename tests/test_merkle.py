"""Unit tests for RFC 6962 Merkle hashing and inclusion proofs."""

import hashlib
import unittest

from lab import merkle


class TestHashing(unittest.TestCase):
    def test_leaf_hash_uses_0x00_prefix(self):
        data = b"hello"
        self.assertEqual(merkle.hash_leaf(data), hashlib.sha256(b"\x00hello").digest())

    def test_node_hash_uses_0x01_prefix(self):
        left, right = b"L" * 32, b"R" * 32
        self.assertEqual(merkle.hash_children(left, right), hashlib.sha256(b"\x01" + left + right).digest())

    def test_empty_root(self):
        self.assertEqual(merkle.empty_root(), hashlib.sha256(b"").digest())

    def test_single_leaf_root_is_the_leaf_hash(self):
        leaves = [merkle.hash_leaf(b"only")]
        self.assertEqual(merkle.root_from_hashes(leaves), leaves[0])

    def test_largest_power_of_two(self):
        self.assertEqual(merkle.largest_power_of_two_less_than(2), 1)
        self.assertEqual(merkle.largest_power_of_two_less_than(3), 2)
        self.assertEqual(merkle.largest_power_of_two_less_than(4), 2)
        self.assertEqual(merkle.largest_power_of_two_less_than(5), 4)
        self.assertEqual(merkle.largest_power_of_two_less_than(9), 8)


class TestInclusionProofs(unittest.TestCase):
    def test_round_trip_for_many_sizes(self):
        for size in range(1, 40):
            leaves = [merkle.hash_leaf(f"leaf-{i}".encode()) for i in range(size)]
            root = merkle.root_from_hashes(leaves)
            for index in range(size):
                proof = merkle.inclusion_proof(leaves, index)
                self.assertTrue(
                    merkle.verify_inclusion(leaves[index], index, size, proof, root),
                    f"failed for size={size} index={index}",
                )

    def test_wrong_root_is_rejected(self):
        leaves = [merkle.hash_leaf(f"leaf-{i}".encode()) for i in range(5)]
        root = merkle.root_from_hashes(leaves)
        proof = merkle.inclusion_proof(leaves, 2)
        bad_root = bytes([root[0] ^ 0xFF]) + root[1:]
        self.assertFalse(merkle.verify_inclusion(leaves[2], 2, 5, proof, bad_root))

    def test_index_out_of_range(self):
        leaves = [merkle.hash_leaf(b"a")]
        with self.assertRaises(IndexError):
            merkle.inclusion_proof(leaves, 1)


if __name__ == "__main__":
    unittest.main()
