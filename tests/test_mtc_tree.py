"""Conformance tests for the MTC subtree primitives (draft Section 4).

The draft ships "accumulated" test vectors in Appendix C: a single SHA-256 over
every valid input of an algorithm, for trees up to size 130. Matching all three
of them means this implementation agrees with the specification on subtree
validity, subtree hashes, subtree inclusion proofs, and subtree consistency
proofs, without pinning down thousands of individual vectors.
"""

import hashlib
import unittest

from lab.mtc import tree

MAX_SIZE = 130


def _test_tree(size: int) -> list[bytes]:
    """The draft's tree ``D_n``: ``d[i] = 0x00 + i``, hashed as leaves."""
    return [tree.merkle.hash_leaf(bytes([i])) for i in range(size)]


def _consistent(
    proof, start: int, end: int, tree_size: int, hashes: list[bytes], expected=None
) -> bool:
    """Run the Section 4.4.3 verifier, deriving the hashes the caller omits."""
    if expected is None:
        expected = tree.subtree_hash(hashes, start, end)
    return tree.verify_subtree_consistency_proof(
        proof, start, end, tree_size, expected, tree.merkle.root_from_hashes(hashes)
    )


class TestSubtreeValidity(unittest.TestCase):
    def test_documented_examples(self):
        # [0, x) and [x, x) are always valid; [7, 9) is not, because
        # BIT_CEIL(2) == 2 and 7 is not a multiple of 2.
        self.assertTrue(tree.is_valid_subtree(0, 9))
        self.assertTrue(tree.is_valid_subtree(7, 7))
        self.assertFalse(tree.is_valid_subtree(7, 9))
        self.assertTrue(tree.is_valid_subtree(4, 8))
        self.assertTrue(tree.is_valid_subtree(8, 13))
        self.assertFalse(tree.is_valid_subtree(5, 13))

    def test_every_prefix_is_a_subtree(self):
        # The draft says so outright: "For all x, [0, x) is a valid subtree (0
        # is a multiple of everything)." Worth pinning because it is the
        # opposite of what the recursive definition in Section 4.1 suggests,
        # and a stricter check here would reject valid short prefixes.
        for end in range(0, 40):
            self.assertTrue(tree.is_valid_subtree(0, end), f"[0, {end})")

    def test_misaligned_starts_are_rejected(self):
        for start, end in [(5, 8), (17, 20), (2, 5), (3, 7), (7, 9)]:
            self.assertFalse(tree.is_valid_subtree(start, end), f"[{start}, {end})")

    def test_bit_ceil(self):
        self.assertEqual(tree.bit_ceil(0), 1)
        self.assertEqual(tree.bit_ceil(1), 1)
        self.assertEqual(tree.bit_ceil(2), 2)
        self.assertEqual(tree.bit_ceil(3), 4)
        self.assertEqual(tree.bit_ceil(8), 8)
        self.assertEqual(tree.bit_ceil(9), 16)

    def test_rejects_nonsense(self):
        self.assertFalse(tree.is_valid_subtree(-1, 4))
        self.assertFalse(tree.is_valid_subtree(5, 4))


class TestAccumulatedVectors(unittest.TestCase):
    """Draft Appendix C.1: rolling hashes over all valid inputs."""

    def test_c1_1_subtree_hashes(self):
        digest = hashlib.sha256()
        for end in range(0, MAX_SIZE + 1):
            hashes = _test_tree(end)
            for start in range(end + 1):
                if not tree.is_valid_subtree(start, end):
                    continue
                digest.update(
                    f"[{start}, {end}) "
                    f"{tree.subtree_hash(hashes, start, end).hex()}\n".encode()
                )
        self.assertEqual(
            digest.hexdigest(), "b82806ad4265bb151c1119c0f4db437bb4d1a1f887b3a7fba1cd4ebf552e3e81"
        )

    def test_c1_2_subtree_inclusion_proofs(self):
        digest = hashlib.sha256()
        for end in range(0, MAX_SIZE + 1):
            hashes = _test_tree(end)
            for start in range(end + 1):
                if not tree.is_valid_subtree(start, end):
                    continue
                for index in range(start, end):
                    proof = tree.subtree_inclusion_proof(hashes, start, end, index)
                    line = f"{index} [{start}, {end})"
                    for node in proof:
                        line += f" {node.hex()}"
                    digest.update(f"{line}\n".encode())
        self.assertEqual(
            digest.hexdigest(), "ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f"
        )

    def test_c1_3_subtree_consistency_proofs(self):
        digest = hashlib.sha256()
        for n in range(MAX_SIZE + 1):
            hashes = _test_tree(n)
            for end in range(0, n + 1):
                for start in range(end + 1):
                    if not tree.is_valid_subtree(start, end):
                        continue
                    proof = tree.subtree_consistency_proof(hashes, start, end)
                    line = f"[{start}, {end}) {n}"
                    for node in proof:
                        line += f" {node.hex()}"
                    digest.update(f"{line}\n".encode())
        self.assertEqual(
            digest.hexdigest(), "10fa99b37bf9bf9ffa26b412fbd98bd75363256d0b75d61bc4538b9c9c5a0a74"
        )


class TestInclusionProofEvaluation(unittest.TestCase):
    """The verifier-side cases the appendix describes after C.1.2."""

    def setUp(self):
        self.hashes = _test_tree(16)

    def test_evaluates_to_subtree_hash(self):
        for start, end in ((0, 8), (0, 16), (8, 16), (0, 12)):
            expected = tree.subtree_hash(self.hashes, start, end)
            for index in range(start, end):
                proof = tree.subtree_inclusion_proof(self.hashes, start, end, index)
                got = tree.evaluate_subtree_inclusion_proof(
                    proof, start, end, index, self.hashes[index]
                )
                self.assertEqual(got, expected, f"index {index} of [{start}, {end})")

    def test_rejects_truncated_and_extended(self):
        # Structural tampering: the proof no longer has the length the subtree's
        # shape demands, so evaluation fails outright (Section 4.3.2 step 1).
        proof = tree.subtree_inclusion_proof(self.hashes, 0, 16, 3)
        expected = tree.subtree_hash(self.hashes, 0, 16)
        for broken in (proof[:-1], proof + [b"\x00"], proof + [b"\x00" * 32]):
            self.assertIsNone(
                tree.evaluate_subtree_inclusion_proof(broken, 0, 16, 3, self.hashes[3]),
                f"{len(broken)} hashes accepted",
            )
        self.assertEqual(
            tree.evaluate_subtree_inclusion_proof(proof, 0, 16, 3, self.hashes[3]), expected
        )

    def test_rejects_wrong_leaf_and_malformed_hashes(self):
        # Content tampering: still structurally sound, so the caller gets a
        # different subtree hash back and the comparison in the draft's
        # verify_subtree_inclusion_proof is what rejects it.
        proof = tree.subtree_inclusion_proof(self.hashes, 0, 16, 3)
        expected = tree.subtree_hash(self.hashes, 0, 16)
        wrong_leaf = tree.evaluate_subtree_inclusion_proof(proof, 0, 16, 3, b"\x00" * 32)
        self.assertIsNotNone(wrong_leaf)
        self.assertNotEqual(wrong_leaf, expected)
        for position in range(len(proof)):
            for bad_hash in (b"\x00" * 32, proof[position][:-1], proof[position] + b"\x00"):
                corrupt = list(proof)
                corrupt[position] = bad_hash
                self.assertNotEqual(
                    tree.evaluate_subtree_inclusion_proof(corrupt, 0, 16, 3, self.hashes[3]),
                    expected,
                    f"hash {position} accepted",
                )

    def test_rejects_index_outside_subtree(self):
        proof = tree.subtree_inclusion_proof(self.hashes, 0, 8, 3)
        self.assertIsNone(tree.evaluate_subtree_inclusion_proof(proof, 0, 8, 9, self.hashes[9]))
        self.assertIsNone(tree.evaluate_subtree_inclusion_proof(proof, 1, 8, 3, self.hashes[3]))


class TestConsistencyProofVerification(unittest.TestCase):
    def setUp(self):
        self.hashes = _test_tree(16)

    def test_verifies_every_valid_subtree(self):
        for end in range(0, len(self.hashes) + 1):
            for start in range(end + 1):
                if not tree.is_valid_subtree(start, end):
                    continue
                proof = tree.subtree_consistency_proof(self.hashes, start, end)
                self.assertTrue(
                    _consistent(proof, start, end, 16, self.hashes), f"[{start}, {end})"
                )

    def test_verifies_every_valid_subtree_in_bigger_trees(self):
        # The verifier has to survive ragged trees, where a subtree can straddle
        # the top-level split and has to be decomposed rather than walked.
        for size in (6, 13, 14, 20, 32, 33, 64):
            hashes = _test_tree(size)
            for end in range(0, size + 1):
                for start in range(end + 1):
                    if not tree.is_valid_subtree(start, end):
                        continue
                    proof = tree.subtree_consistency_proof(hashes, start, end)
                    self.assertTrue(
                        _consistent(proof, start, end, size, hashes),
                        f"[{start}, {end}) in tree of {size}",
                    )

    def test_draft_section_4_4_2_examples(self):
        # The two worked examples, spelled out as interval identities so the
        # generator cannot drift from the figures in the draft.
        hashes = _test_tree(14)
        mth = lambda a, b: tree.merkle.root_from_hashes(hashes[a:b])  # noqa: E731

        # [4, 8) is a node of the tree, so the verifier is assumed to know its
        # hash; the proof carries the two siblings on the way to the root.
        self.assertEqual(
            tree.subtree_consistency_proof(hashes, 4, 8), [mth(0, 4), mth(8, 14)]
        )
        self.assertTrue(_consistent([mth(0, 4), mth(8, 14)], 4, 8, 14, hashes))
        # [8, 13) is not a node, so its own pieces come first and the subtree
        # hash is rebuilt from them before continuing to the root.
        proof = [mth(12, 13), mth(13, 14), mth(8, 12), mth(0, 8)]
        self.assertEqual(tree.subtree_consistency_proof(hashes, 8, 13), proof)
        self.assertTrue(_consistent(proof, 8, 13, 14, hashes))

    def test_workshop_landmarks(self):
        # The landmark in the center exercise: a 20-entry log with subtrees
        # [0, 16) and [16, 20), plus the two checkpoints.
        hashes = _test_tree(20)
        for start, end in ((0, 16), (16, 20), (0, 20), (0, 12)):
            proof = tree.subtree_consistency_proof(hashes, start, end)
            self.assertTrue(
                _consistent(proof, start, end, 20, hashes), f"landmark [{start}, {end})"
            )
            # The entry the exercise asks about, index 3.
            if start <= 3 < end:
                inclusion = tree.subtree_inclusion_proof(hashes, start, end, 3)
                self.assertEqual(
                    tree.evaluate_subtree_inclusion_proof(inclusion, start, end, 3, hashes[3]),
                    tree.subtree_hash(hashes, start, end),
                )

    def test_batch_covering_subtrees_verify_against_the_log_root(self):
        # The property a CA leans on: whatever interval a cert covers, the two
        # subtrees covering it each prove into the log's root hash.
        hashes = _test_tree(20)
        for end in range(1, 21):
            for start in range(end):
                for sub_start, sub_end in tree.find_subtrees(start, end):
                    if sub_start == sub_end:
                        continue  # the empty subtree, covered by its own rule
                    proof = tree.subtree_consistency_proof(hashes, sub_start, sub_end)
                    self.assertTrue(
                        _consistent(proof, sub_start, sub_end, 20, hashes),
                        f"[{sub_start}, {sub_end}) covering [{start}, {end})",
                    )

    def test_rejects_corrupt_and_replaced_hashes(self):
        for start, end in ((0, 8), (4, 8), (8, 13), (0, 16)):
            proof = tree.subtree_consistency_proof(self.hashes, start, end)
            for position in range(len(proof)):
                corrupt = list(proof)
                corrupt[position] = b"\x00" * 32
                self.assertFalse(
                    _consistent(corrupt, start, end, 16, self.hashes),
                    f"corrupt hash {position} of [{start}, {end}) accepted",
                )
            # A proof for one subtree must not verify for another.
            for other_start, other_end in ((0, 4), (8, 16), (0, 16)):
                if (other_start, other_end) == (start, end):
                    continue
                if not tree.is_valid_subtree(other_start, other_end):
                    continue
                self.assertFalse(
                    _consistent(proof, other_start, other_end, 16, self.hashes),
                    f"proof for [{start}, {end}) accepted for [{other_start}, {other_end})",
                )

    def test_rejects_wrong_subtree_hash(self):
        proof = tree.subtree_consistency_proof(self.hashes, 0, 8)
        self.assertFalse(
            _consistent(proof, 0, 8, 16, self.hashes, expected=b"\x00" * 32)
        )

    def test_rejects_wrong_root_hash(self):
        proof = tree.subtree_consistency_proof(self.hashes, 0, 8)
        self.assertFalse(
            tree.verify_subtree_consistency_proof(
                proof, 0, 8, 16, tree.subtree_hash(self.hashes, 0, 8), b"\x00" * 32
            )
        )

    def test_rejects_truncated_proof(self):
        proof = tree.subtree_consistency_proof(self.hashes, 0, 8)
        self.assertFalse(_consistent(proof[:-1], 0, 8, 16, self.hashes))

    def test_rejects_subtree_beyond_tree(self):
        proof = tree.subtree_consistency_proof(self.hashes, 0, 8)
        self.assertFalse(_consistent(proof, 0, 8, 4, self.hashes))

    def test_empty_subtree(self):
        self.assertEqual(tree.subtree_consistency_proof(self.hashes, 4, 4), [])
        self.assertTrue(
            tree.verify_subtree_consistency_proof(
                [], 4, 4, 16, tree.merkle.empty_root(), tree.merkle.root_from_hashes(self.hashes)
            )
        )
        self.assertFalse(
            tree.verify_subtree_consistency_proof(
                [], 4, 4, 16, b"\x00" * 32, tree.merkle.root_from_hashes(self.hashes)
            )
        )


class TestFindSubtrees(unittest.TestCase):
    def test_draft_example(self):
        # Figure 10: [5, 13) is covered by [4, 8) and [8, 13).
        self.assertEqual(tree.find_subtrees(5, 13), ((4, 8), (8, 13)))

    def test_degenerate_intervals(self):
        self.assertEqual(tree.find_subtrees(7, 8), ((7, 8), (8, 8)))
        self.assertEqual(tree.find_subtrees(7, 7), ((7, 7), (7, 7)))

    def test_result_is_always_two_valid_subtrees(self):
        for end in range(0, 40):
            for start in range(end + 1):
                left, right = tree.find_subtrees(start, end)
                self.assertTrue(tree.is_valid_subtree(*left), f"{left} for [{start}, {end})")
                self.assertTrue(tree.is_valid_subtree(*right), f"{right} for [{start}, {end})")
                self.assertLessEqual(left[1], right[0], f"{left} {right} for [{start}, {end})")
                self.assertLessEqual(start, left[1], f"{left} for [{start}, {end})")
                self.assertEqual(right[1], end, f"{right} for [{start}, {end})")
                self.assertLessEqual(end - start, tree.bit_ceil(end - start) or 1)

    def test_covering_subtree_contains_index(self):
        hashes = _test_tree(20)
        for end in range(1, 21):
            for start in range(end):
                for index in range(start, end):
                    subtree = tree.covering_subtree(hashes, start, end, index)
                    self.assertTrue(subtree[0] <= index < subtree[1])
                    self.assertTrue(tree.is_valid_subtree(*subtree))


if __name__ == "__main__":
    unittest.main()
