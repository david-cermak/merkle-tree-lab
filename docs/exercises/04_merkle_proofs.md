# Exercise 4 — Merkle proofs, step by step

**Goal:** see that an inclusion proof does not contain the whole log — it is a
short list of sibling hashes that, combined with one leaf hash, reconstructs the
log's root.

**Prerequisites:** a running log with at least a few entries:

```bash
make lab-up
make fill N=8
```

`make fill` issues eight *distinct* leaf certificates from the same
intermediate and submits each one. It has to: `make demo` re-submits the single
leaf in `out/pki`, and a CT log deduplicates entries by certificate, so running
`make demo` twice integrates one entry and leaves a tree of size 1. With a
single leaf there are no siblings, and this exercise has nothing to show.

## Background

RFC 6962 hashes a Merkle tree like this:

```
leaf  = SHA256(0x00 || leaf_data)
node  = SHA256(0x01 || left || right)
```

The `0x00`/`0x01` prefixes are domain separation: they stop a leaf value from
being mistaken for an internal node.

The tree over `n` leaves splits at `k`, the largest power of two **strictly
smaller** than `n`:

```
root = node(root(leaves[:k]), root(leaves[k:]))
```

This is why CT trees are not perfect binary trees, and why the audit path has an
*inner* part (siblings that may be left or right) and a *border* part (left
siblings only).

## Step 1 — pick a leaf

```bash
python3 -m lab.cli proof --storage-dir log --index 2
```

You get `leaf_hash`, `leaf_index`, `tree_size`, and `audit_path`.

Questions:

1. How many hashes are in the audit path?
2. If the log had 1 000 000 entries, roughly how many hashes would the path
   have? (Hint: log₂.)
3. How does that compare with downloading the whole log?

## Step 2 — walk the path by hand

```bash
python3 -m lab.cli walk --storage-dir log --index 2
```

For each step, note:

* the sibling hash,
* whether the sibling is on the **left** or the **right**,
* the hash produced.

At the end, compare the computed root with the checkpoint root. They must match.

Now do it again for the **last** leaf, and compare the two walks:

```bash
python3 -m lab.cli walk --storage-dir log --index 7
```

Leaf 2's path mixes `sibling right` and `sibling left` and is labelled
`[inner, ...]`. Leaf 7's is all `sibling left` and is labelled `[border, ...]`.
That is the inner/border split from the Background section, and leaf 7 is the
one that produces it. Which index would give the longest all-left path, and why
is it the *last* leaf rather than the first?

## Step 3 — break it

Change one byte of the leaf hash in a saved proof and verify again:

```bash
python3 -m lab.cli proof --storage-dir log --index 2 --output out/proof.json
# edit out/proof.json: flip a character in "leaf_hash"
python3 -m lab.cli verify --storage-dir log --index 2 --proof out/proof.json
```

It should report `INVALID`. Explain why a single-bit change anywhere in the path
changes the root.

## Step 4 — SCT vs inclusion proof

An **SCT** is the log saying *"I promise to include this certificate."* An
**inclusion proof** is *"here is cryptographic evidence that it is included."*

1. When you submit a certificate, which one do you get back immediately?
2. What must be published before an inclusion proof can be checked?
3. Why is a promise alone not enough?

## Step 5 — a subtree, not the tree

Merkle Tree Certificates replace the whole tree with a *subtree*: they prove an
entry is in some interval `[start, end)` rather than in the entire log. That is
what lets a cosigner sign a batch of new entries once instead of signing the
whole tree each time.

You will need `is_valid_subtree` in [exercise 5](05_mtc_four_shapes.md), so try
the rule now. Section 4.1 says an interval is a subtree when its **start** is a
multiple of `BIT_CEIL(end - start)` — the next power of two at least as large as
the interval's length:

```python
from lab.mtc.tree import is_valid_subtree, find_subtrees
for start, end in [(0, 3), (0, 4), (0, 5), (0, 6), (0, 8),
                   (1, 4), (2, 4), (2, 6), (4, 12), (6, 8)]:
    print(f"[{start}, {end}) -> {is_valid_subtree(start, end)}")
print(find_subtrees(0, 20))
```

1. Why is `[0, 6)` a valid subtree but `[2, 6)` is not, even though they have
   the same length?
2. Why is `[12, 20)` **not** a subtree? (A landmark's subtrees are near it, and
   it is worth seeing why the interval a landmark covers is not itself one of
   its subtrees.)
3. `find_subtrees(0, 20)` returns the two subtrees covering `[0, 20)`. Work out
   the rule, then say what a landmark at tree size 24 with a previous landmark
   at 16 would return — and how that differs from a landmark at 24 that follows
   a landmark at 0.

## Answer key

1. **Step 1:** the number of hashes is `⌈log₂ n⌉`; for 1 000 000 entries, 20
   hashes, about 640 bytes. The whole log would be 32 MB.
2. **Step 2:** the walk ends with `MATCH`. Every step is a SHA-256 over the
   previous hash, the sibling, and the `0x01` node domain, so changing any
   sibling changes the root — and the root is what the checkpoint signs. In a
   tree of 8 the path is 3 hashes. Leaf 2's is `inner` (right, left, right) and
   leaf 7's is all `border` (left, left, left): the border part is the run of
   left siblings at the end of the path, and it exists because the tree of 8 is
   a perfect subtree, so the last leaf is reached entirely by going left. The
   first leaf would give the mirror image — all right siblings — and the longest
   all-left path belongs to whichever leaf sits in the rightmost subtree, which
   in a perfect tree is the last one.
3. **Step 3:** a single-bit change anywhere in the path changes the root,
   because hashing is not linear. The changed root no longer equals the
   signed root, so the proof is `INVALID`.
4. **Step 4:** you get the SCT immediately; an inclusion proof requires the log
   to have published a checkpoint that covers the entry's index. A promise is
   not evidence, and one SCT per certificate cannot show selective disclosure.
5. **Step 5:** the rule is alignment, and it comes from consistency proofs.
   `[0, 6)` has length 6, so it needs `start` to be a multiple of
   `BIT_CEIL(6) = 8` — and 0 is. `[2, 6)` has the same length but 2 is not a
   multiple of 8, so the interval is not aligned with the surrounding tree and
   could not be separated from it in a consistency proof. `[12, 20)` has
   length 8 and needs `start` to be a multiple of 8; 12 is not, which is
   exactly why a landmark at 20 is split into `[0, 16)` and `[16, 20)` rather
   than into `[0, 12)` and `[12, 20)`. The covering rule (§4.5) splits an
   interval into the largest subtree starting at or after `start` and the
   remainder: `find_subtrees(0, 20)` is `((0, 16), (16, 20))`,
   `find_subtrees(16, 24)` is `((16, 20), (20, 24))`, and
   `find_subtrees(0, 24)` is `((0, 16), (16, 24))`. A landmark's subtrees
   depend on the **previous** landmark's tree size, because they cover
   `[prev, tree_size)` — the entries added since the last landmark. That is why
   a landmark is not a snapshot of the tree but a record of what changed.

## Takeaway

The proof size grows with `log₂(subtree size)`, not with the tree size. That is
the property Certificate Transparency relies on, and the property Merkle Tree
Certificates reuse for a *subtree*, which is usually much smaller than the tree.
