# Exercise 5 — Merkle proofs, step by step

**Goal:** see that an inclusion proof does not contain the whole log — it is a
short list of sibling hashes that, combined with one leaf hash, reconstructs the
log's root.

**Prerequisites:** a running log with at least a few entries
(`make lab-up`, then submit several certificates with `make demo` or
`python3 -m lab.cli submit ...`).

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

## Takeaway

The proof size grows with `log₂(tree size)`, not with the tree size. That is the
property Certificate Transparency relies on, and the property Merkle Tree
Certificates reuse.
