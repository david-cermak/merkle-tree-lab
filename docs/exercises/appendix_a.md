# Appendix A — Tree structure and proof hashes (default index 3)

This appendix sketches the Merkle tree for the default scenario (20 log entries,
with a null entry at index 7) and shows, schematically, which hashes each
proof-carrying certificate shape actually includes for **index 3**.

It covers the three shapes that carry an inclusion proof:

| shape | proves membership in | proof hashes |
|---|---|---|
| standalone (tree-relative) | `[0, 20)` — whole tree | 5 |
| landmark-relative | `[0, 16)` — the landmark's subtree | 4 |
| checkpoint-relative | `[0, 8)` — a checkpoint-signed subtree | 3 |

The directly signed shape carries no inclusion proof, so it is not shown.

## A.1 The tree

Hashing follows RFC 6962: a leaf is `H(0x00 || entry)` and an internal node is
`H(0x01 || left || right)`. A tree over `n` leaves splits at the largest power
of two strictly smaller than `n`. For 20 leaves that means the root splits
`[0, 20)` into `[0, 16)` and `[16, 20)`, and the recursion continues from there.

Node labels name the interval they cover; `L7*` is the null entry at index 7.

```
R    = MTH([0,20))
├── T0  = MTH([0,16))
│   ├── O0 = MTH([0,8))
│   │   ├── Q0 = MTH([0,4))
│   │   │   ├── P0 = H(L0, L1)          # [0,2)
│   │   │   └── P2 = H(L2, L3)          # [2,4)
│   │   └── Q4 = MTH([4,8))
│   │       ├── P4 = H(L4, L5)          # [4,6)
│   │       └── P6 = H(L6, L7*)         # [6,8)   L7 is the null entry
│   └── O8 = MTH([8,16))
│       ├── Q8  = MTH([8,12))
│       │   ├── P8  = H(L8, L9)         # [8,10)
│       │   └── P10 = H(L10, L11)       # [10,12)
│       └── Q12 = MTH([12,16))
│           ├── P12 = H(L12, L13)       # [12,14)
│           └── P14 = H(L14, L15)       # [14,16)
└── T16 = MTH([16,20))
    ├── P16 = H(L16, L17)               # [16,18)
    └── P18 = H(L18, L19)               # [18,20)

L0  L1  L2  L3  L4  L5  L6  L7*  L8  L9  L10  L11  L12  L13  L14  L15  L16  L17  L18  L19
 0   1   2   3   4   5   6   7    8   9   10   11   12   13   14   15   16   17   18   19
```

`MTH([a,b))` is the root of the subtree over those indices; `Li` is the leaf
hash of entry `i`, and `L7*` is the null entry (it occupies index 7 but carries
no certificate).

## A.2 The proof path for leaf 3

Leaf 3 sits at `L3`. Walking from `L3` up to the whole-tree root `R` visits

```
L3 -> P2 -> Q0 -> O0 -> T0 -> R
```

At each step the verifier needs the **sibling** of the node it just computed, so
that it can hash the pair. The number of siblings is the number of levels on the
path: 5 to reach `R`, and fewer if the proof stops at an inner subtree root.

The annotated tree below marks the five siblings needed for the
**standalone (tree-relative)** proof; `[n]` is that hash's position in the proof
list (leaf level first).

```
R    = MTH([0,20))              <-- compare here (standalone)
├── T0  = MTH([0,16))           <-- recomputed; also the landmark target (A.4)
│   ├── O0 = MTH([0,8))         <-- recomputed; also the checkpoint target (A.5)
│   │   ├── Q0 = MTH([0,4))     ... on the path ...
│   │   │   ├── P0 = H(L0, L1)  [2]  sibling of P2
│   │   │   └── P2 = H(L2, L3)  ... on the path ...
│   │   └── Q4 = MTH([4,8))     [3]  sibling of Q0
│   └── O8 = MTH([8,16))        [4]  sibling of O0
└── T16 = MTH([16,20))          [5]  sibling of T0

L2 = leaf(entry 2)              [1]  sibling of L3
L3 = leaf(entry 3)              <-- the entry being proven
```

So the standalone proof is the ordered list

```
[1] L2   [2] P0   [3] Q4   [4] O8   [5] T16
```

## A.3 Standalone (tree-relative) — `[0, 20)`, 5 hashes

Recompute upward from `L3`, folding in one sibling per level; the final hash is
the whole-tree root, compared against the published root.

```
 1.  P2  = H(L2, L3)       # L2 is proof hash 1
 2.  Q0  = H(P0, P2)       # P0 is proof hash 2
 3.  O0  = H(Q0, Q4)       # Q4 is proof hash 3
 4.  T0  = H(O0, O8)       # O8 is proof hash 4
 5.  R   = H(T0, T16)      # T16 is proof hash 5  -> compare to root([0,20))
```

## A.4 Landmark-relative — `[0, 16)`, 4 hashes

The first landmark's subtrees are `[0, 16)` and `[16, 20)`, so index 3 is proven
in `[0, 16)`. The same first four steps are performed, and the result is
compared against the landmark's `[0, 16)` subtree hash instead of the root.

```
 1.  P2  = H(L2, L3)       # L2 is proof hash 1
 2.  Q0  = H(P0, P2)       # P0 is proof hash 2
 3.  O0  = H(Q0, Q4)       # Q4 is proof hash 3
 4.  T0  = H(O0, O8)       # O8 is proof hash 4  -> compare to landmark hash([0,16))
```

The landmark carries no cosignature in this shape: the client must already hold
`MTH([0,16))`, so the certificate contains only the proof.

## A.5 Checkpoint-relative — `[0, 8)`, 3 hashes

Checkpoint `[0, 8)` is the covering subtree that contains index 3. The walk stops
one level lower; the result is compared against the checkpoint's cosigned
`[0, 8)` subtree hash.

```
 1.  P2  = H(L2, L3)       # L2 is proof hash 1
 2.  Q0  = H(P0, P2)       # P0 is proof hash 2
 3.  O0  = H(Q0, Q4)       # Q4 is proof hash 3  -> compare to checkpoint hash([0,8))
```

## A.6 Notes

* **Why 5, 4, and 3?** Each count is the height of the tree being proven:
  `[0, 20)` needs 5 levels to reach the root, `[0, 16)` needs 4, and `[0, 8)`
  needs 3. The three proofs are prefixes of the same path, so the landmark and
  checkpoint proofs reuse the first four and first three hashes respectively.
* **Null entry.** `L7*` participates in the tree like any other leaf (as part of
  `P6` / `Q4`), but it attests no certificate — certifying index 7 is refused.
  It does not appear on index 3's proof path.
* **Binding.** The certificate serial is `(log_number << 48) | index`, which ties
  the proof to index 3. Replaying a proof for index 4 as if it were for index 3
  fails the serial/index consistency check before any hashing.
* **Tamper detection.** Changing any field of entry 3 changes `L3`, and therefore
  every recomputed node above it — `P2`, `Q0`, `O0`, `T0`, and `R`. The proof
  then no longer matches whichever interval root the shape is checked against.
