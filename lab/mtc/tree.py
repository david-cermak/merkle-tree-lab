"""Subtrees, subtree inclusion proofs, and subtree consistency proofs.

This is the Merkle primitive of ``draft-ietf-plants-merkle-tree-certs-06``
Section 4, implemented against the draft's own pseudocode and validated by the
accumulated test vectors in Appendix C (``tests/test_mtc_tree.py``).

The hash domains are RFC 6962's, so the leaf and node hashing reuse
:mod:`lab.merkle`::

    leaf  = SHA256(0x00 || entry)
    node  = SHA256(0x01 || left || right)

What Section 4 adds on top of RFC 6962 is the notion of a **subtree**: a
Merkle tree over a slice ``D[start:end]`` that is aligned well enough with the
whole tree to be proven consistent with it. A slice is a valid subtree when
``start`` is a multiple of ``BIT_CEIL(end - start)`` (Section 4.1). Not every
interval qualifies -- the smallest valid subtree containing ``[7, 9)`` in a
9-element tree is the whole tree -- but any interval can be covered by **two**
valid subtrees (Section 4.5), which is what lets a CA sign an arbitrary batch.

Two proof types do the work:

* a **subtree inclusion proof** walks an entry up to the subtree that contains
  it, yielding the subtree hash (Section 4.3);
* a **subtree consistency proof** walks a subtree up to the whole-tree hash,
  showing the subtree really sits at those positions in the bigger tree
  (Section 4.4). It omits the subtree's own root hash, because the verifier
  already knows that value -- that value is precisely what is being
  authenticated.
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

from .. import merkle

Subtree = Tuple[int, int]

#: A proof is an ordered list of hashes, leaf level first.
Proof = List[bytes]


def bit_ceil(n: int) -> int:
    """Return ``BIT_CEIL(n)``: the smallest power of two >= ``n``.

    ``BIT_CEIL(0)`` is 1, matching the draft's note that ``[x, x)`` is a valid
    subtree because "BIT_CEIL(0) is 1".
    """
    if n <= 1:
        return 1
    return 1 << (n - 1).bit_length()


def is_valid_subtree(start: int, end: int) -> bool:
    """Return ``True`` if ``[start, end)`` is a valid subtree (Section 4.1).

    A subtree is valid when ``0 <= start <= end`` and ``start`` is a multiple
    of ``BIT_CEIL(end - start)``.
    """
    if start < 0 or end < start:
        return False
    return start % bit_ceil(end - start) == 0


def subtree_hash(leaf_hashes: Sequence[bytes], start: int, end: int) -> bytes:
    """Return ``MTH(D[start:end])`` -- the hash of the subtree ``[start, end)``."""
    return merkle.root_from_hashes(leaf_hashes[start:end])


def subtree_inclusion_proof(
    leaf_hashes: Sequence[bytes], start: int, end: int, index: int
) -> Proof:
    """Return a subtree inclusion proof for ``index`` in ``[start, end)``.

    This is the RFC 6962 inclusion proof for the independent tree over
    ``D[start:end]``, so it contains at most ``BIT_WIDTH(end - start - 1)``
    hashes (Section 4.3).
    """
    if not is_valid_subtree(start, end):
        raise ValueError(f"[{start}, {end}) is not a valid subtree")
    if end > len(leaf_hashes):
        raise ValueError(f"subtree [{start}, {end}) exceeds tree size {len(leaf_hashes)}")
    if not start <= index < end:
        raise ValueError(f"index {index} outside subtree [{start}, {end})")
    return merkle.inclusion_proof(leaf_hashes[start:end], index - start)


def evaluate_subtree_inclusion_proof(
    proof: Sequence[bytes], start: int, end: int, index: int, entry_hash: bytes
) -> bytes | None:
    """Evaluate an untrusted inclusion proof, returning the subtree hash.

    Implements Section 4.3.2, whose two shift variables are *relative to the
    subtree*: ``fn = index - start`` and ``sn = end - start - 1``. Returns
    ``None`` on any structural failure -- an invalid subtree interval, an index
    outside it, or a proof whose length does not match the shape of the subtree
    -- so an untrusted proof can be fed in directly. A proof that is
    structurally sound but says the wrong thing yields a *different* hash
    rather than ``None``; the draft's ``verify_subtree_inclusion_proof`` is then
    a single comparison against the expected hash.
    """
    if not is_valid_subtree(start, end) or not start <= index < end:
        return None
    try:
        return merkle.root_from_inclusion_proof(
            index - start, end - start, entry_hash, list(proof)
        )
    except (IndexError, ValueError):
        return None


def subtree_consistency_proof(
    leaf_hashes: Sequence[bytes], start: int, end: int
) -> Proof:
    """Return the subtree consistency proof for ``[start, end)``.

    ``SUBTREE_PROOF(start, end, D_n)`` from Section 4.4.1, written as the
    draft writes it: a recursion over the tree split at the largest power of
    two below ``n``, appending the sibling root at each step. The first hash
    is omitted when it equals the subtree hash the verifier already knows.
    """
    if not is_valid_subtree(start, end):
        raise ValueError(f"[{start}, {end}) is not a valid subtree")
    if end > len(leaf_hashes):
        raise ValueError(f"subtree [{start}, {end}) exceeds tree size {len(leaf_hashes)}")
    if start == end:
        return []
    return _subtree_subproof(leaf_hashes, start, end, omit_first=True)


def _subtree_subproof(
    hashes: Sequence[bytes], start: int, end: int, omit_first: bool
) -> Proof:
    n = len(hashes)
    if start == 0 and end == n:
        return [] if omit_first else [merkle.root_from_hashes(hashes)]

    k = merkle.largest_power_of_two_less_than(n)
    if end <= k:
        # The subtree is left of the split: prove against the left child and
        # carry the right child.
        return _subtree_subproof(hashes[:k], start, end, omit_first) + [
            merkle.root_from_hashes(hashes[k:])
        ]
    if k <= start:
        # The subtree is right of the split: prove against the right child and
        # carry the left child.
        return _subtree_subproof(hashes[k:], start - k, end - k, omit_first) + [
            merkle.root_from_hashes(hashes[:k])
        ]
    # start < k < end, which forces start == 0: the subtree straddles the
    # split, so it has to be split too.
    return _subtree_subproof(hashes[k:], 0, end - k, omit_first=False) + [
        merkle.root_from_hashes(hashes[:k])
    ]


def verify_subtree_consistency_proof(
    proof: Sequence[bytes],
    start: int,
    end: int,
    tree_size: int,
    subtree_hash_value: bytes,
    root_hash: bytes,
) -> bool:
    """Verify a subtree consistency proof (Section 4.4.3).

    Returns ``True`` only if the proof reconstructs both ``subtree_hash_value``
    and ``root_hash`` from the same sequence of hashes, with no tree positions
    left over. ``proof`` is not modified.

    One detail of the draft's pseudocode is worth spelling out, because
    "Until X, do Y" reads ambiguously: step 5 is a ``while`` over the negation
    of its stop condition, so the shift loop runs while ``fn != sn`` *and* the
    low bit of ``sn`` is **set**. That is the reading under which every proof
    in Appendix C.1.3 -- 42,892 of them -- verifies, and it is what the two
    worked examples in Section 4.4.2 need.
    """
    if not is_valid_subtree(start, end) or end > tree_size:
        return False

    remaining = list(proof)

    if start == end:
        return not remaining and subtree_hash_value == merkle.empty_root()

    fn, sn, tn = start, end - 1, tree_size - 1

    if sn == tn:
        while fn != sn:
            fn >>= 1
            sn >>= 1
            tn >>= 1
    else:
        while fn != sn and sn & 1:
            fn >>= 1
            sn >>= 1
            tn >>= 1

    if fn == sn:
        fr = sr = subtree_hash_value
    elif remaining:
        fr = sr = remaining.pop(0)
    else:
        return False

    for c in remaining:
        if tn == 0:
            return False
        if sn & 1 or sn == tn:
            if fn < sn:
                fr = merkle.hash_children(c, fr)
            sr = merkle.hash_children(c, sr)
            while not sn & 1:
                fn >>= 1
                sn >>= 1
                tn >>= 1
        else:
            sr = merkle.hash_children(sr, c)
        fn >>= 1
        sn >>= 1
        tn >>= 1

    return tn == 0 and fr == subtree_hash_value and sr == root_hash


def find_subtrees(start: int, end: int) -> Tuple[Subtree, Subtree]:
    """Return two subtrees that efficiently cover ``[start, end)``.

    Section 4.5.1, with the draft's own reference implementation. The returned
    pair is ``(left, right)`` where ``left.end == right.start``,
    ``right.end == end`` (so the right subtree carries no extra elements), and
    each is a valid subtree no larger than ``BIT_CEIL(end - start)``.

    Note that ``left`` may start *before* ``start``: covering an interval
    without wasting proof space is only possible by reaching left.
    """
    if start > end:
        raise ValueError("start must be <= end")
    if end - start <= 1:
        return (start, end), (end, end)
    last = end - 1
    # Where start's and last's tree paths diverge.
    split = (start ^ last).bit_length() - 1
    mask = (1 << split) - 1
    mid = last & ~mask
    # Maximize the left endpoint: just before start's path leaves the right
    # edge of its new subtree.
    left_split = (~start & mask).bit_length()
    left_start = start & ~((1 << left_split) - 1)
    return (left_start, mid), (mid, end)


def covering_subtree(leaf_hashes: Sequence[bytes], start: int, end: int, index: int) -> Subtree:
    """Return whichever of the two covering subtrees contains ``index``.

    Section 4.5.1: the pair covers the interval, so exactly one of the two
    contains any given index in it.
    """
    left, right = find_subtrees(start, end)
    for subtree in (left, right):
        if subtree[0] <= index < subtree[1]:
            return subtree
    raise ValueError(f"index {index} is not covered by {[left, right]}")
