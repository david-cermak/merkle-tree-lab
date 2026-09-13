"""RFC 6962 Merkle tree hashing and inclusion proofs.

Certificate Transparency uses the hashing rules from RFC 6962:

* An empty tree hashes to ``SHA256("")``.
* A leaf (an entry) hashes to ``SHA256(0x00 || leaf_data)``.
* An internal node hashes to ``SHA256(0x01 || left_hash || right_hash)``.

The leading domain-separation bytes (0x00 for leaves, 0x01 for nodes) stop a
leaf value from being mistaken for an internal node, which is what makes the
tree safe against second-preimage attacks.

A Merkle tree over ``n`` leaves is built by splitting at ``k``, the largest
power of two strictly smaller than ``n``::

    root(leaves) = H(root(leaves[:k]) || root(leaves[k:]))

That is the exact split used by RFC 6962, and it matters: it determines both
the root and the shape of inclusion proofs.
"""

from __future__ import annotations

import hashlib
from typing import List, Sequence

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def hash_leaf(data: bytes) -> bytes:
    """Return the RFC 6962 leaf hash ``SHA256(0x00 || data)``."""
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def hash_children(left: bytes, right: bytes) -> bytes:
    """Return the RFC 6962 internal-node hash ``SHA256(0x01 || left || right)``."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def empty_root() -> bytes:
    """Return the RFC 6962 hash of an empty tree, ``SHA256("")``."""
    return hashlib.sha256(b"").digest()


def largest_power_of_two_less_than(n: int) -> int:
    """Return the largest power of two strictly smaller than ``n`` (n >= 2)."""
    if n < 2:
        raise ValueError("n must be >= 2")
    return 1 << ((n - 1).bit_length() - 1)


def root_from_hashes(hashes: Sequence[bytes]) -> bytes:
    """Compute the Merkle root from a sequence of leaf hashes."""
    n = len(hashes)
    if n == 0:
        return empty_root()
    if n == 1:
        return hashes[0]
    k = largest_power_of_two_less_than(n)
    return hash_children(root_from_hashes(hashes[:k]), root_from_hashes(hashes[k:]))


def inclusion_proof(hashes: Sequence[bytes], index: int) -> List[bytes]:
    """Return the inclusion (audit) proof for ``index``.

    The returned list is ordered from the leaf level up to the root: the first
    element is the sibling of the leaf, the last is the sibling just below the
    root.
    """
    n = len(hashes)
    if not 0 <= index < n:
        raise IndexError(f"index {index} out of range for tree of size {n}")
    if n == 1:
        return []
    k = largest_power_of_two_less_than(n)
    if index < k:
        return inclusion_proof(hashes[:k], index) + [root_from_hashes(hashes[k:])]
    return inclusion_proof(hashes[k:], index - k) + [root_from_hashes(hashes[:k])]


def inner_proof_size(index: int, size: int) -> int:
    """Height at which the paths to leaves ``index`` and ``size-1`` diverge."""
    return (index ^ (size - 1)).bit_length()


def decomp_incl_proof(index: int, size: int) -> tuple[int, int]:
    """Split an inclusion proof into (inner, border) lengths.

    Inner hashes can be left or right siblings; border hashes are left siblings
    only, one per level above the fork point.
    """
    inner = inner_proof_size(index, size)
    border = bin(index >> inner).count("1")
    return inner, border


def _chain_inner(seed: bytes, proof: Sequence[bytes], index: int) -> bytes:
    for level, sibling in enumerate(proof):
        if (index >> level) & 1 == 0:
            seed = hash_children(seed, sibling)
        else:
            seed = hash_children(sibling, seed)
    return seed


def _chain_border_right(seed: bytes, proof: Sequence[bytes]) -> bytes:
    for sibling in proof:
        seed = hash_children(sibling, seed)
    return seed


def root_from_inclusion_proof(
    index: int, tree_size: int, leaf_hash: bytes, proof: Sequence[bytes]
) -> bytes:
    """Recompute the Merkle root from an inclusion proof.

    This follows the RFC 6962 algorithm: a proof splits into an *inner* part
    (siblings on both sides, below the fork with the rightmost leaf) and a
    *border* part (left siblings only, above the fork). Folding by leaf-index
    parity alone is not enough for unbalanced trees.
    """
    if not 0 <= index < tree_size:
        raise IndexError(f"index {index} out of range for tree of size {tree_size}")
    inner, border = decomp_incl_proof(index, tree_size)
    if len(proof) != inner + border:
        raise ValueError(f"wrong proof size {len(proof)}, want {inner + border}")
    result = _chain_inner(leaf_hash, proof[:inner], index)
    return _chain_border_right(result, proof[inner:])


def verify_inclusion(
    leaf_hash: bytes,
    index: int,
    tree_size: int,
    proof: Sequence[bytes],
    root: bytes,
) -> bool:
    """Verify an inclusion proof against a trusted Merkle root."""
    if index >= tree_size:
        return False
    try:
        return root_from_inclusion_proof(index, tree_size, leaf_hash, proof) == root
    except (IndexError, ValueError):
        return False


def explain_inclusion(
    leaf_hash: bytes,
    index: int,
    tree_size: int,
    proof: Sequence[bytes],
) -> tuple[bytes, list[dict]]:
    """Recompute the root while describing each hashing step.

    Returns ``(computed_root, steps)`` where each step records the sibling, its
    side, the hash before and after, and whether the step is part of the inner
    proof or the right border. This is what the ``walk`` command prints.
    """
    inner, _border = decomp_incl_proof(index, tree_size)
    steps: list[dict] = []
    current = leaf_hash
    for level, sibling in enumerate(proof):
        if level < inner:
            if (index >> level) & 1 == 0:
                side = "right"
                nxt = hash_children(current, sibling)
            else:
                side = "left"
                nxt = hash_children(sibling, current)
            kind = "inner"
        else:
            side = "left"
            nxt = hash_children(sibling, current)
            kind = "border"
        steps.append(
            {
                "level": level,
                "kind": kind,
                "side": side,
                "sibling": sibling,
                "before": current,
                "after": nxt,
            }
        )
        current = nxt
    return current, steps
