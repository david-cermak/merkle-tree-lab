# Exercise 5 — One log, four certificates

**Goal:** watch all four Merkle Tree Certificate shapes come out of a single
issuance log, measure them, and then ask what a relying party can actually
check with what it already knows.

**Time:** 30 minutes. This is the centrepiece; if you are short on time, do
Steps 1, 2, and 4 and leave Step 5 for discussion.

**Prerequisites:** the repository's `.venv` (ML-DSA needs `cryptography>=46`;
the system Python is often older). Everything here is offline — no log server,
no network.

---

## Step 1 — build the CA

```bash
make mtc-lab
```

That is one command, and it is the whole setup. It creates a CA
(`1.3.6.1.4.1.32473.100`), an issuance log of **20 entries** (log number 8, with
a null entry at index 7), **two checkpoints** (at tree sizes 12 and 20), and
**one landmark** at tree size 20. It saves everything to `out/mtc/scenario.json`
and prints the root hashes.

Two things to notice in the output:

1. The **null entry** at index 7. It occupies an index in the log but carries no
   certificate — a real CA uses those for a revoked or mis-issued entry, so that
   the rest of the log's indices never move. Try certifying it:
   `make mtc-shapes INDEX=7` — the command refuses, and says why.
2. The **serial number** of entry 3: `2251799813685251`. Decode it. The draft
   packs the log number and the index into one integer, `(log << 48) | index`.
   Which bits hold the log number?

Then look at the landmark's two subtrees, `[0, 16)` and `[16, 20)`. §6.4.1 says
a landmark's subtrees are **the two subtrees that cover
`[prev_tree_size, tree_size)`** — the entries added since the *previous*
landmark. This is the first real landmark, so `prev` is 0 and the interval is
`[0, 20)`; §4.5 splits it as `[0, 16)` and `[16, 20)`. Confirm the rule:

```python
from lab.mtc.tree import find_subtrees
find_subtrees(0, 20)    # ((0, 16), (16, 20))
find_subtrees(16, 24)   # ((16, 20), (20, 24))
find_subtrees(0, 24)    # ((0, 16), (16, 24))
```

1. A landmark is therefore *not* a snapshot of the tree — it is a record of
   what was **added** since the last one. What does that mean for a client that
   has been offline for a long time and has missed several landmarks?
2. Why is the interval a landmark covers — `[0, 20)` here — not itself one of
   its subtrees? (You checked the rules in
   [exercise 4, step 5](04_merkle_proofs.md).)

## Step 2 — cut the four shapes

```bash
make mtc-shapes
```

One entry, four certificates:

| shape | subtree | signatures | signature bytes | proof hashes | landmark-dependent | total bytes |
|---|---|---|---|---|---|---|
| directly signed | - | 1 | 3309 | 0 | no | 5439 |
| standalone (tree-relative) | [0, 20) | 2 | 4840 | 5 | no | 7165 |
| checkpoint-relative | [0, 8) | 2 | 4840 | 3 | no | 7101 |
| landmark-relative | [0, 16) | 0 | 0 | 4 | yes | 2269 |

Read the last column honestly. **The MTC shapes are not smaller than a
traditionally signed certificate.** The two cosigned shapes are *larger*, because
they carry two ML-DSA-44 cosignatures (2 420 B each) instead of one ML-DSA-65
signature (3 309 B). What they buy is not size — it is transparency, and the
ability to amortise one cosignature pair across a whole batch of entries.

The one shape that is genuinely smaller is the **landmark-relative** one: no
signature bytes at all, because the client is expected to already hold the
subtree hash. That is the trade: the CA signs nothing here, and the client must
know something in advance.

The command also prints the arithmetic — signature bytes, proof bytes, and
"fields" (the rest: subject, issuer, validity, public key, extensions). Check
the proof bytes yourself: 5 hashes × 32 bytes = 160, 4 × 32 = 128, 3 × 32 = 96.

**Why do the three proof sizes differ (5, 4, and 3)?** They are the heights of
the three different trees the proofs live in. Work out each one from the
interval in the table.

## Step 3 — look at a certificate

```bash
cat out/mtc/certificate-landmark.json
```

Every shape is stored as JSON next to the scenario. The human-readable summary
of each is in the `text` field; the size is the number of bytes the lab's
encoding produces.

Note that the **subject public key is in the certificate** but **not in the log
entry**. The entry has only its 32-byte hash. That is the single idea that makes
a 1 974-byte ML-DSA-65 key affordable in a log: the log stores a digest, and
the client pays for the key once, in the certificate.

## Step 4 — what can a client actually check?

This is the part that matters. Run the verification walk at three levels of
knowledge:

```bash
python3 -m lab.cli mtc verify --knows cosigners
python3 -m lab.cli mtc verify --knows landmark
python3 -m lab.cli mtc verify --knows all
```

| client knows | direct | standalone | checkpoint | landmark |
|---|---|---|---|---|
| nothing | refused | refused | refused | refused |
| cosigner keys | refused | verified | verified | **not yet checkable** |
| + landmark hashes | refused | verified | verified | verified |
| + the CA's key | verified | verified | verified | verified |

Read the refusals; they are the point of the exercise.

* A client that knows only the **cosigner keys** can check the two cosigned
  shapes, because the cosignatures are signatures it can verify. It **cannot**
  check the landmark-relative one — not because the certificate is bad, but
  because the client has nothing to compare the proof against yet. The message
  says *"it becomes checkable when the landmark arrives"*. Not-yet-checkable is
  not the same as invalid, and a client that conflates them will drop perfectly
  good certificates.
* A client that **holds the landmark** needs no cosigners at all for that
  shape, and never contacts the CA during the handshake. It is holding two
  32-byte hashes per landmark.
* The **directly signed** shape is the odd one out: it verifies with nothing but
  the CA's ordinary key, which the client already had before any of this
  existed. That is its only advantage, and it is why the directly signed shape
  is in the comparison at all.

## Step 5 — break it

The lab will tamper with a certificate for you and check that every shape
notices:

```bash
python3 -m lab.cli mtc verify --knows all --tamper
```

It changes the subjectAltName and shows all four shapes refusing. Ask *how* each
one notices, because the four answers are different:

* the **direct** shape fails the signature check — the SAN is inside the signed
  body;
* the **cosigned** shapes fail because the entry hash changes, so the
  cosignature no longer covers the subtree;
* the **landmark-relative** shape fails because the entry hash no longer matches
  the landmark subtree hash the client already holds.

Then make a more interesting break by hand. Certify a *different* entry and
claim a different one:

```bash
python3 -m lab.cli mtc shapes --index 4
python3 -m lab.cli mtc verify --index 4 --knows landmark
```

The serial number check (Step 1) is what stops a proof for index 4 being
replayed as a proof for index 3: the serial packs the index in its low 48 bits,
and a mismatch is caught before anything is hashed. Find that check in the
output by making a certificate whose serial and proof disagree.

## Step 6 — discussion: which shape would you deploy?

There is no negotiation in this lab (see the plan's D5), so argue it out.

| | needs cosigners | needs a landmark | verifiable without the log |
|---|---|---|---|
| directly signed | no | no | yes |
| standalone | yes | no | yes |
| checkpoint-relative | yes | no | yes |
| landmark-relative | no | yes | yes |

1. The draft's §8 describes a CA and client *negotiating* which shape to use.
   What would you negotiate on? Bandwidth, latency, or what the client can
   verify cheaply?
2. A landmark expires (§6.4). §6.4.1 says a CA **SHOULD** set a landmark's
   expiry to *the current time plus the CA's maximum certificate lifetime*. Work
   out what that guarantees: can a landmark ever expire while a certificate it
   covers is still valid? And what does it let a client do with the hash
   afterwards — throw it away, or keep it forever?
3. The draft notes that "mistakes in landmark sequence allocation only impact
   availability, not integrity". Give an example of a landmark-sequence mistake
   that would hurt availability but not let a bad certificate through.
4. The checkpoint-relative shape exists because the CA signs the subtrees
   covering *new* entries each time it checkpoints (§6.1). So one cosignature
   pair covers many certificates. Estimate: for a log adding 1 000 entries per
   checkpoint, how many cosignature bytes per entry, amortised? (Two covering
   subtrees, two cosigners each, 2 420 B per signature.)
5. The directly signed shape is *not* an MTC. If you deployed it, what
   transparency property would you have given up?

## Takeaway

Merkle Tree Certificates are not a way to make certificates smaller. They are a
way to make a certificate's *log membership* checkable by someone who never
downloaded the log, using a set of public keys and a handful of 32-byte hashes
that the client obtained out of band.

Three things to carry into the rest of the workshop:

1. The **entry hash is the binding constraint**. Every field of the log entry —
   subject, key hash, validity, SANs — feeds one SHA-256, and that hash is what
   the cosigners signed or the landmark published. Change any field and all four
   shapes fail, for four different reasons.
2. The **cosignatures are amortised**, not eliminated. Two ML-DSA-44 signatures
   are amortised over a batch of entries, which is why a checkpoint-relative
   certificate can be larger than a signed one and still be the right choice.
3. **What the client already knows decides the shape.** That is why the draft
   negotiates.

## Where this lab deviates from the draft

It is a teaching simulator, and it says so in every module. Deliberately
simplified, per the plan's D7:

* Field order, the 12-byte `"subtree/v1\n\0"` cosignature label, the
  `(log << 48) | index` serial layout, and the `0x00`/`0x01` hash domains are
  faithful to the draft.
* The draft actually uses two encodings. `CosignedMessage` (§5.3.1) and
  `MTCProof` (§6.1) are TLS presentation language, and the lab implements the
  primitives they are built from faithfully — so a cosignature here is a real
  signature over a real, draft-shaped message. The log entry and the certificate
  around it are ASN.1/DER in the draft; those are a compact documented TLV here,
  which is why nothing here interoperates with a real MTC implementation.
* `TBSCertificateLogEntry` is that TLV structure rather than DER. The leaf
  hashes are real SHA-256 over the real bytes, so the tree arithmetic is exact
  — only the byte layout is ours.
* Certificates are dataclasses that print, not X.509. There is no ACME, no TLS
  handshake, and no wire negotiation.
* The validity encoding is compressed rather than ASN.1 `Time`, so the printed
  timestamps fit on a slide.

## Further reading

* `docs/mtc-draft.txt` §§5–7 — the normative text this lab follows.
* `docs/mtc-cheat-sheet.md` — one page of field layouts and OID arcs.
* `lab/mtc/` — the implementation, in the order the exercise uses it:
  `log.py` → `cosigners.py` → `landmarks.py` → `certs.py` → `client.py`.
* `PLAN-update.md` — why the lab is scoped this way.
