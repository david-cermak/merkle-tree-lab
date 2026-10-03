# Appendix B — Frequently asked questions

These are the questions that come up most often after Exercise 5. They are
deliberately high level: they are about *who holds what state, and why*, not
about the lab's byte layout. Where an answer leans on the draft, the section is
named so you can read the normative text yourself (`docs/mtc-draft.txt`).

---

## A. Logs and growth

### Q1. A CA issues certificates forever. Doesn't the inclusion proof grow forever too?

It depends on the shape. A proof is one sibling hash per level of the **subtree**
it is checked against, so its size is logarithmic in *that subtree's* size — not
in the log's age. Which subtree you pick decides whether it grows:

* **standalone** proves into the whole current tree `[0, N)`. `N` grows forever,
  so **yes — the standalone proof grows forever**, but only logarithmically.
  Details and a script below.
* **checkpoint-relative** proves into a recent checkpoint's covering subtree;
  bounded by how often the CA checkpoints.
* **landmark-relative** proves into a landmark subtree, which spans only the
  entries added since the previous landmark (§6.4.1). Allocate a landmark every
  hour and the subtree stops growing, so the proof size is effectively constant
  no matter how old the log is. The draft's hourly-landmark estimate is 23
  hashes, or 736 bytes, with no signatures at all.

**How bad is "forever" for standalone?** The draft's own figures (§6.5) let you
work it out: under 7-day certificates renewed at 75% of life (reissued every 126
hours), one large CA issues about 5.4 million entries per hour. Here is a quick
script — save it as `standalone_growth.py` and pass the horizon in years:

```python
#!/usr/bin/env python3
"""Standalone proof size after N years of 7-day certificate issuance."""
import sys

def tree_size_after(years, active_certs=682_000_000, reissue_hours=126.0):
    hours_per_year = 365.25 * 24
    issuances_per_hour = active_certs / reissue_hours
    entries = issuances_per_hour * hours_per_year * years
    proof_hashes = max(0, int(entries - 1).bit_length())  # ceil(log2(entries))
    return issuances_per_hour, entries, proof_hashes

def main():
    years = float(sys.argv[1]) if len(sys.argv) > 1 else 10.0
    rate, entries, hashes = tree_size_after(years)
    print(f"{years:g} years at {rate:,.0f} entries/hour")
    print(f"  tree size (whole log) : {entries:,.0f} entries")
    print(f"  standalone proof      : {hashes} hashes = {hashes * 32} bytes")

if __name__ == "__main__":
    main()
```

Running it at the two ends of the range:

```text
$ python3 standalone_growth.py 10
10 years at 5,412,698 entries/hour
  tree size (whole log) : 474,477,142,857 entries
  standalone proof      : 39 hashes = 1248 bytes

$ python3 standalone_growth.py 20
20 years at 5,412,698 entries/hour
  tree size (whole log) : 948,954,285,714 entries
  standalone proof      : 40 hashes = 1280 bytes
```

So the whole log approaches a trillion entries while the standalone proof moves
from 39 to 40 hashes: roughly **one extra hash each time the log doubles**. Early
on the log doubles about yearly, so the proof gains a hash per year; later the
doublings space out and growth slows further. The draft's "32 hashes covers 2³²
entries" (§6.5) is true but worth reading carefully — at 5.4M/hour, 2³² entries
is only about **33 days** of one large CA's issuance; the point is that even
enormous logs stay in the tens of hashes, not that the proof is frozen. The
`active_certs` and `reissue_hours` defaults are the draft's per-CA assumptions;
change them to model a different operator (1,000,000 active certificates gives
about 30 hashes after 10 years).

### Q2. How can a log be served forever if it only ever grows?

The log's *contents* never shrink, but the draft makes sure its **costs scale
with the retention window, not with the log's lifetime**:

* Entries are small and fixed-size: a hash of the public key, not the key, and
  no signature (§12.3).
* Only the latest checkpoint is signed. Each new checkpoint subsumes the old
  one, so old signatures and old signed subtrees can be discarded (§10.1.1).
* Long-expired entries can be revoked in bulk and then pruned or simply not
  served (§7.5, §5.2.2). A serving protocol is allowed to serve only a portion
  of the log.
* Mirrors and cosigners can absorb read traffic instead of the CA (§10.1.2).

So "serve forever" really means "serve the recent window, keep the append-only
commitment". Old data still exists in mirrors if someone wants to audit it; the
CA is not required to serve every byte forever.

### Q3. What does append-only actually buy us, if entries are just bytes?

It is what makes the log **tamper-evident**. Each leaf hash feeds the nodes
above it, so changing any entry changes every ancestor hash and therefore the
checkpoint root. A CA cannot quietly edit or remove an entry after the fact
without breaking every proof and checkpoint that covers it, which monitors and
cosigners would notice.

Append-only is also why indices are stable. Stable indices let a relying party
say "revoke everything after index k" for all time (§7.5).

### Q4. What stops a CA from running two logs and showing different people different things?

Equivocation is the classic transparency failure, and MTC relies on the same
defences as CT: third parties. A CA cosigner follows one append-only view and
signs subtrees consistent with it (§5.3). If the CA signs two conflicting
subtrees or checkpoints, the inconsistency is detectable by anyone holding both.
Standalone certificates are only accepted when the client's cosigner policy is
met; landmark-relative certificates depend on subtree hashes that relying
parties obtained and validated out of band (§7.4). Cosigners can mirror the log
so a hidden entry eventually surfaces.

### Q5. What is the difference between a checkpoint and a landmark?

Both are anchors, but they answer different questions.

* A **checkpoint** is the signed tree head at some size: "here is the whole tree
  so far". A proof into a checkpoint's subtree authenticates a recent batch.
* A **landmark** is a *sequence of tree sizes* chosen infrequently (§6.4.1). Its
  subtrees cover the interval `[prev_tree_size, tree_size)` — what was **added
  since the previous landmark**. A landmark is therefore not a snapshot; it is a
  record of what changed.

Clients predistribute active landmark subtrees (two hashes per landmark in this
lab) and can then verify landmark-relative certificates with no signature in the
handshake.

---

## B. Revocation, null entries, and mistakes

### Q6. The log is append-only, so how do you revoke a certificate?

You never touch the log. Revocation is a separate, out-of-band statement: a
relying party maintains a list of **revoked ranges of serial numbers** (§7.5).
Because a serial is `(log_number << 48) | index`, a range can revoke a span of
indices inside one log, or whole logs.

This is deliberately coarse and cheap. It lets an operator revoke everything
after index k in one statement, skip serving long-expired entries, and bound
monitoring to a limited range of log numbers (§12.2.2). It is complementary to
ordinary certificate-level revocation: CRLs and OCSP still work unchanged,
because a log entry is uniquely identified by its issuer and serial.

### Q7. Can we rewrite a valid entry to a null entry, like index 7, to undo a mis-issue?

No. Rewriting a leaf is exactly the tampering the Merkle tree detects: the leaf
hash changes, so every node above it changes, so every proof and checkpoint that
covers that index becomes inconsistent. There is no "edit" operation on an
append-only log, by construction.

To neutralize a certificate you **revoke** it (Q6). The entry stays in the log
as evidence of what the CA did, which is the point.

### Q8. Then what is a null entry for, and why reserve a slot instead of deleting?

A `null_entry` is a log entry that carries no information; certifying one is a
no-op (§5.2). It occupies an index like any other leaf, and any index may be
null.

The reason to reserve a slot is **index stability**. If a CA knows at issuance
time that an index should not hold a real certificate — a placeholder, a
mis-issue it refuses to certify, or a revoked issuance — it commits a null entry
there and moves on. The indices of every other entry never shift, so landmark
subtrees and range revocations keep pointing at the same things.

The key distinction: a null entry is chosen **when the slot is created**. You
cannot turn an existing valid entry into one later.

### Q9. Why does revocation care so much about stable indices?

Because range revocation is only meaningful if "index k" always means the same
entry. If indices could be reused or renumbered, "revoke everything after k"
would eventually revoke the wrong certificates. The append-only property plus
null entries guarantee that an index, once allocated, is permanent.

---

## C. Proofs, clients, and state

### Q10. If landmark-relative is smaller, why would anyone ever carry the two cosignatures of a standalone certificate?

Because the client may not hold anything in advance yet. The shapes are a
progression from "client knows nothing" to "client already has trusted state":

* **directly signed** — no proof; the client needs only the CA's key (baseline,
  but not transparent).
* **standalone** — the certificate carries the proof *and* the cosignatures, so
  it verifies against cosigner keys the client already trusts.
* **checkpoint-relative** — same idea, anchored to a recent checkpoint subtree.
* **landmark-relative** — no signatures, but the client must already hold the
  landmark subtree hash out of band.

The two cosignatures are not per-certificate waste: they cover the whole subtree
that the batch of certificates proves into, so the cost is **amortised**. For a
log adding 1 000 entries per checkpoint, two covering subtrees signed by two
cosigners is four signatures of 2 420 bytes — roughly ten bytes per entry
(Exercise 5, Step 6).

### Q11. How much state does a client have to hold for landmark-relative verification?

Very little, and it is bounded. Per landmark, the client holds the subtree hash
(or two, for the two covering subtrees). The lab's client holds two 32-byte
hashes per landmark. The draft lets a relying party cap the number of active
landmarks it accepts per CA and discard the newest ones if a CA over-allocates
(§7.4), so the out-of-band state has a ceiling rather than growing with the log.

### Q12. A client has been offline and missed several landmarks. Is it stuck?

Not permanently, but it may need more than a single landmark. A landmark records
what was added since the previous one, so a client that skipped several may need
several landmark updates, or one newer landmark plus a consistency proof
showing the subtrees fit together. This is the trade-off in §6.4.1: frequent
landmarks reduce certificate delay but increase the client's predistributed
state, and infrequent landmarks do the reverse.

The important failure mode is a client that treats "I cannot check this yet" as
"I must reject this". It is the single most useful line in the lab: **not yet
checkable is not the same as invalid**.

### Q13. Can a client verify a certificate without contacting the CA or the log during the handshake?

Yes, for every MTC shape:

* **standalone / checkpoint-relative** — the client holds the cosigner public
  keys and checks the cosignatures in the certificate.
* **landmark-relative** — the client holds the landmark subtree hashes and there
  are no signatures to check at all.

In all cases the client must have obtained a small amount of state out of band
(keys, or subtree hashes). It does not download the log, and it does not call
the CA.

### Q14. How can a certificate be valid before its landmark exists? Isn't that a hole?

No. When the CA issues an entry, what is available depends on how far the log
has progressed:

* A **standalone** certificate can be issued immediately; it carries its own
  signatures.
* A **landmark-relative** certificate for that entry can only be constructed
  once a landmark covers it, and a relying party can only accept it once it has
  that landmark's trusted subtree (§10.4).

So a client might get the standalone form first and the smaller landmark form
"after a processing delay" (§1). A certificate that is simply early is not
invalid — it becomes checkable when the landmark arrives. Rejecting it because
verification is not possible *yet* would drop good certificates.

### Q15. Landmarks have an expiry. What if one expires while a certificate it covers is still valid?

It cannot, if the CA follows the draft. A landmark's expiration **MUST** be
greater than or equal to the `notAfter` of every entry below its tree size, and
a CA **SHOULD** set it to the current time plus its maximum certificate lifetime
(§6.4.1).

That guarantee is what lets a client bound its state: once every certificate a
landmark covers has expired, the client can throw that landmark hash away
instead of keeping it forever. Only *unexpired* landmarks are "active", and a
client keeps a bounded number of those.

---

## D. Trust and deployment

### Q16. We already have X.509 and Certificate Transparency. Why would we switch?

The pressure is post-quantum, short-lived certificates. A CT log stores the
whole certificate — public key and signature — so with ML-DSA entries get large
and, because certificates are reissued every ~126 hours, they are added
constantly. An MTC log stores a 32-byte hash of the key and no signature, so
entries stay small (§12.3), and one cosignature pair is amortised over a whole
batch instead of per certificate.

What MTC buys is not a smaller certificate: the lab's two cosigned shapes are
*larger* than a traditional one. It buys a membership proof that a relying party
can check **without ever downloading the log**, and log storage that scales with
issuance rate rather than with certificate size.

### Q17. When is MTC the wrong tool?

When the size and transparency problems are not yours. Exercise 2 is the honest
counterexample: an internal PKI where you control both ends, every client is
configured with the root directly, and nobody external is watching for
mis-issuance. There, ordinary post-quantum X.509 over TLS already works, and MTC
would add cosigners, landmark distribution, and protocol machinery in exchange
for a guarantee that no one is positioned to use.

### Q18. Who are the cosigners, and why should a relying party trust them?

A cosigner follows an append-only view of the log and signs subtrees consistent
with it (§5.3). Each has a public key and a **cosigner ID** that identifies the
key, the algorithm, and the role. The draft defines several roles: a CA cosigner
that certifies entries, a witness that only checks append-only, and a mirror
that copies the log.

A relying party trusts them because it chose them, exactly as it chooses trust
anchors today. The policy question — how many cosigners, of which roles, with
what availability — is what the relying party's configuration decides (§7.3).

### Q19. If the log only stores a *hash* of the public key, can't a CA hide a bad key?

It changes what monitors can see, and the draft says so (§12.3). A monitor sees
an unrecognized hash rather than an unrecognized key; any unrecognized hash —
even with an unknown preimage — indicates an unauthorized certificate. What is
harder is *studies of weak keys* (for example, shared-prime analyses), which now
require fetching the public key separately from the TLS server or from the CA.
That is a deliberate trade for smaller entries, not something the design hides.

### Q20. If the certificate carries the public key, why does the log entry only hash it?

Because the log is the part that scales with volume, and the certificate is what
the client pays for once. A 1 974-byte ML-DSA-65 key is expensive to store for
every single issuance, but the client only ever needs the key for the
certificate it is verifying. So the log stores the 32-byte digest, and the
certificate carries the key (Exercise 5, Step 3). Hashes keep the log small;
certificates stay self-contained.

### Q21. Can I deploy the output of this lab?

No. The lab is a teaching simulator and says so. It is faithful in the places
that matter for the arithmetic — the hash domains, the cosignature label, the
`(log << 48) | index` serial — but its proof structure adds fields the draft does
not have, records a landmark number the draft has no field for, defines four
shapes instead of three, and has no wire format or TLS handshake. It will not
interoperate with a real MTC implementation.

---

## E. Real deployment and the actual numbers

### Q22. How many certificates are we actually talking about?

Big. The draft quotes a snapshot from 18 September 2026 (§6.5):

* roughly **one billion TLS servers** in the Web PKI (Cloudflare);
* **~682 million active certificates** from Let's Encrypt alone — a single CA;
* **~2.9 billion unexpired certificates** in CT logs across all CAs;
* a current issuance rate of **~591,000 certificates per hour** across all CAs.

Any logging design at this scale has to work in the billions of live
certificates and hundreds of thousands of new issuances per hour. That is the
regime MTC is designed for, and it is why "store the whole certificate" does not
scale once keys and signatures get big.

### Q23. What changes when certificates are shortened to 7 days?

This is the pressure multiplier. The draft assumes a **7-day certificate
lifetime**, renewed when the certificate is 75% through its life, so each
certificate is reissued every **126 hours** (§6.5). Re-running the issuance
numbers with that cadence gives:

* **~5,400,000 certificates per hour** for one large CA;
* **~23,000,000 certificates per hour** across all CAs (the all-CA figure).

So the log's *append rate* rises by roughly an order of magnitude even before
post-quantum algorithms make each entry bigger. Shorter-lived certificates mean
more entries, not just larger ones — which is exactly why amortising a
cosignature over a whole batch (Q10) and scaling with a retention window (Q2)
matter.

### Q24. How big are the proofs at real scale?

Small and bounded by cadence, not by the log's age (§6.5):

* If the CA mints a **checkpoint every 2 seconds**, a standalone subtree spans
  around **3,000 certificates** → **12 hashes** → **384 bytes**.
* If it allocates a **new landmark every hour**, a landmark-relative subtree
  spans around **5,400,000 certificates** → **23 hashes** → **736 bytes**, with
  **no signatures at all**.

And the ceiling is friendly: **32 hashes (1,024 bytes)** is enough for any
subtree up to 2³² ≈ **4,294,967,296 certificates**. Landmark allocation cadence
is the tuning knob: allocate more often and proofs get smaller but clients
receive more updates; allocate less often and the reverse.

### Q25. How much bigger do post-quantum certificates make CT logs?

About **40×** (Cloudflare). The draft's numbers (§1) are:

| algorithm | public key | signature |
|---|---|---|
| ML-DSA-44 | 1,312 B | 2,420 B |
| ML-DSA-65 | 1,952 B | 3,309 B |

Two SCTs plus the leaf certificate signature add **7,260 bytes** of
authentication overhead with ML-DSA-44 and **9,927 bytes** with ML-DSA-65. A CT
log entry contains the public key *and* a CA signature, so it balloons along
with both. MTC's answer is to store a 32-byte **hash** of the key and no
per-entry signature at all (Q20). Exercise 3 measures the same effect in the
lab: the CT log stores an ~5,600-byte ML-DSA-65 leaf, while the MTC issuance log
stores **131 bytes** for the same certificate — roughly **43× smaller**.

### Q26. Has any of this been run at Internet scale, or is it all theory?

It has been run. Cloudflare and Chrome ran an experiment that served **billions
of MTCs** to **50% of Chrome Beta 146**. In the common landmark-relative case,
the TLS handshake needed only **one public key, one signature, and an inclusion
proof under 1 kB**. At the median it was **9% faster than a classical signature
chain** (most of that from eliding an intermediate), and the expectation is a
much larger gain once post-quantum signatures are actually in play.

Cloudflare is now building a real CA with MTC issuance, targeting **early 2027**
for inclusion in Chrome's Quantum-resistant Root Store. So the numbers in this
appendix are not hypothetical.

### Q27. What do real root programs require for cosigning?

At least two cosignatures. Chrome's Quantum-resistant Root Program draft policy
mandates:

* one cosignature from a **Chrome-recognized Mirroring Cosigner operated by a
  distinct organization**, and
* one from the **issuing MTC CA itself**.

That is why the lab's standalone and checkpoint-relative shapes carry exactly
**two ML-DSA-44 cosignatures**, and why the client-knowledge table in Exercise 5
has a "knows cosigners" row. Cloudflare will operate mirrors for other pilot CAs
and require at least one independent cosignature on its own issued certificates.

### Q28. Cloudflare said the landmark handshake needed "one signature". I thought landmark-relative certificates have no signatures — what's going on?

This is a fair reading, and the honest answer is that the **draft does not
describe that experiment** — it is Cloudflare's description of their Chrome
trial, not normative text. But the apparent contradiction resolves if you are
careful about *which* signature is meant.

A landmark-relative MTC contains no cosignatures; the certificate's "signature"
field is just the inclusion proof (§6.2, §6.4, and Cloudflare's own description
of the form: "the signature value consists of the lightweight inclusion proof
with no heavyweight post-quantum signatures at all"). What Cloudflare counts as
the **one signature** is best read as the TLS handshake's `CertificateVerify`
signature — the server proving possession of the private key for the public key
that the MTC attests. A certificate-authenticated TLS 1.3 handshake has one, no
matter what kind of certificate is used. So the handshake is:

* **one public key** — the subject key, carried in the certificate;
* **one signature** — the server's proof-of-possession in the handshake, not a
  certificate or cosigner signature;
* **one inclusion proof** — under 1 kB, connecting the certificate to a trusted
  landmark subtree.

That is consistent with the draft. What the blog does *not* spell out is that
distinction, which is exactly why the sentence is easy to misread. If instead
they meant a signature inside the certificate, that would not be a
landmark-relative certificate as the draft defines it. The draft is silent on
the experiment, so treat "one signature" as the handshake signature and not as a
change to the landmark-relative construction.

### Q29. If landmark-relative is so much smaller, why keep a standalone fallback at scale?

Because not every client can use a landmark. Clients can be newly installed,
offline, or missing the relevant landmark update (Q12). Servers therefore retain
a **standalone certificate as a fallback**, and the deployed system is
"landmark-relative when the client can negotiate it, something else otherwise".
In the Cloudflare/Chrome experiment, when a landmark-relative certificate could
not be negotiated the server fell back to the traditional certificate chain
rather than even a standalone MTC. Landmarks are the optimisation; they are not
the only path.

## F. Embedded and stateless clients

The flip side of "what the client already knows" is a client that **cannot** hold
or update state: a constrained device, a device with no update channel, or an
operator who simply does not want to run an out-of-band landmark distribution
channel. The draft supports this, and it is the case for standalone certificates.

### Q30. I'm an embedded client with no update channel. Can I use MTC at all?

Yes — use the **standalone** shape. It is self-contained: the certificate carries
an inclusion proof and a set of cosignatures, and the relying party verifies
them against cosigner public keys it already has. The draft's configuration list
(§7.1) is static except for revocation:

* the CA ID,
* the log hash algorithm (e.g. SHA-256),
* the supported cosigner IDs and public keys,
* a policy on which cosigner combinations to accept (§7.3),
* an optional list of trusted subtrees, and
* revoked serial-number ranges.

Only the last two are the "state" parts, and both are optional in the sense that
a client can still verify a standalone certificate without them: verification
falls through to checking the cosignatures (§7.2, steps 11–12). So a device can
be built with the cosigner keys pinned at manufacture and never updated, and it
will verify standalone certificates. It will, however, be larger on the wire than
a landmark-relative certificate, and it will not track new revocations.

### Q31. What exactly must a standalone-only client store, and what can it ignore?

Store: the CA ID, the hash algorithm, and the cosigner ID/key pairs plus a
cosigner policy (§7.1). All of that can be frozen at build time. A policy that
requires only the **CA cosigner** is explicitly allowed by the draft for
applications that do not enforce transparency:

> "In applications that do not enforce transparency requirements, a relying
> party MAY implement a policy that only checks for a signature from the CA
> cosigner." (§7.3)

Ignore: trusted subtree hashes and landmark updates — those are only needed for
the landmark-relative optimization (§7.4). Unrecognized cosignatures are ignored,
so a certificate carrying extra cosigners still verifies (§7.2 step 12, §7.3).

The honest gap: **revocation state**. A client with no update channel cannot
learn about new revoked ranges. The draft lets a relying party revoke everything
before some `minSerial` up front, but subsequent revocations require updates
(§7.5). This is the same limitation an embedded client already has with CRLs, and
the draft does not solve it.

### Q32. My client can't even afford to verify Merkle proofs or check cosignatures cheaply. Then what?

Fall back to a **directly-signed certificate** — the draft's non-MTC form
(defined in §2.1), signed by the CA's ordinary key. It carries no proof and needs
no log state at all; the client pins the CA key and checks one signature. The
cost is exactly what MTC is trying to add: the client gives up log-membership
transparency. If you want to stay in the MTC family but minimize work, the
draft's CA-cosigner-only policy (Q31) is the middle ground: one cosignature
check over the subtree, no landmark state.

### Q33. Can an embedded client use landmark-relative certificates without any update channel?

Not practically. Landmark-relative verification requires the current **trusted
subtree hash**, which the draft says is obtained from an out-of-band update
channel (§7.4). A device with no update path cannot acquire new landmarks. It
could ship with landmark hashes baked in, but landmarks expire (§6.4.1, and Q15)
and new certificates are issued into new landmark subtrees, so a frozen set goes
stale. For a non-updating device, standalone (or direct) is the honest answer.

### Q34. Does standalone still give me transparency, or only authenticity?

Be precise about the two properties, because the draft separates them (§7.3):

* **Authenticity** — the entry was certified by the CA — needs a signature from
  the **CA cosigner key**.
* **Transparency** — the entry is publicly visible so monitors can catch
  mis-issuance — needs a **quorum of additional cosigners** that enforce a
  consistent view (a witness role), and ideally serve a copy (a mirror role).

A standalone client that only checks the CA cosigner, as an embedded device
might, gets authenticity but **not** transparency enforcement. The certificate is
still in the log, so third-party monitors can catch problems; the client itself
is just not the one watching. This is the trade an embedded design makes: fewer
moving parts per device, relying on the wider ecosystem for monitoring.

## G. How trees grow: checkpoints, landmarks, and consistency

This section is the one deliberate exception to the "no low-level detail" rule:
how the Merkle tree grows, how a landmark's subtrees relate to the whole tree,
and how a consistency proof shows that an old subtree still sits inside a newer
tree. Notation follows the draft: `[start, end)` is the half-open interval
`start <= i < end` (the same thing as `(start, end]` if you prefer). All node
labels are intervals; `MTH([a,b))` is the hash of that subtree.

Every example below is worked with the same 40 consecutive leaf hashes, so the
numbers are exact and reproducible.

### G.1 What grows, and what stays put

A **checkpoint** at tree size `N` is the root `MTH([0, N))` of the whole tree. As
`N` increases, the root changes, but the draft's key fact is that **subtrees are
stable** (§4.1): if `end <= N1 <= N2`, then `[start, end)` has the same hash in
both trees. Growth only ever *adds* nodes; it never recomputes the nodes the old
tree already had.

A **landmark** at tree size `N` is not the whole tree. Its subtrees cover the
interval `[prev_tree_size, N)` — what was added since the previous landmark
(§6.4.1). So landmarks tile the growth history, while checkpoints describe the
whole tree at a moment.

### G.2 Worked example: landmarks at 20 and 40

Start with a first landmark at size 20, then a second at size 40.

```
tree size 20                                 tree size 40
R20 = H([0,16), [16,20))                     R40 = H([0,32), [32,40))
         /          \                                 /          \
     [0,16)      [16,20)                         [0,32)       [32,40)
     /    \       /    \                         /    \        /    \
 [0,8) [8,16) [16,18) [18,20)                [0,16) [16,32) [32,36) [36,40)
     ^                                            ^
     |                                            |
     +---- the same node in both trees ----------+
          (a "binary part": the leftmost 2^k entries)
```

The covering rule (§4.5) gives the landmark subtrees:

```
find_subtrees(0, 20)  = ([0, 16), [16, 20))   # landmark 1
find_subtrees(20, 40) = ([16, 32), [32, 40))  # landmark 2
find_subtrees(0, 40)  = ([0, 32), [32, 40))   # whole tree at 40
find_subtrees(0, 32)  = ([0, 16), [16, 32))
```

Laid out along the entry indices:

```
index: 0 ........... 16 ........... 20 ................... 32 .......... 40
       |<-- L1 subtree 1 [0,16) -->|
                     |<-- L1 subtree 2 [16,20) -->|
                     |<--------- L2 subtree 1 [16,32) ---------->|
                                              |<-- L2 subtree 2 [32,40) -->|
```

Three things to notice:

1. **`[0,16)` is shared.** It is the leftmost node of the tree at 20 *and* at 40,
   and it is also the left child of `[0,32)`. This is the "binary part": the
   leftmost `2^k` entries. `[0,32)` is the binary part of the size-40 checkpoint,
   just as `[0,16)` is the binary part of the size-20 tree.
2. **`[20,40)` is not a valid subtree** — `start = 20` is not a multiple of
   `BIT_CEIL(20) = 32` — so the second landmark cannot use `[20,40)` directly.
   That is *why* the covering rule reaches back to `[16,32)` and `[32,40)`.
   Landmark 2's first subtree therefore **overlaps** landmark 1's region; that
   overlap is normal and is what keeps the interval aligned.
3. **The new checkpoint is rebuilt from the old node plus new nodes.** With
   `[0,16)` unchanged, the size-40 root is

   ```
   MTH([0,32))  = H( MTH([0,16)) , MTH([16,32)) )
   R40          = H( MTH([0,32)) , MTH([32,40)) )
   ```
   and `[16,32)` is itself new: `MTH([16,32)) = H( MTH([16,24)) , MTH([24,32)) )`,
   with `MTH([16,24)) = H( MTH([16,20)) , MTH([20,24)) )`. So the old landmark's
   `[16,20)` node survives inside the new tree, one level deeper.

### G.3 Consistency proofs, concretely

Consistency answers: "I hold this old subtree hash; can you show me it really is
a subtree of your newer tree, with the same contents?" The proof is a short list
of sibling hashes that reconstructs both the old hash and the new root.

**A client holds `MTH([0,16))` from landmark 1, and a checkpoint at size 40
arrives.** The consistency proof for `[0,16)` against the size-40 tree is
**two hashes**:

```
MTH([16,32)) , MTH([32,40))
```

and it folds cleanly:

```
MTH([0,32)) = H( MTH([0,16)) , MTH([16,32)) )     # recompute the left half
R40         = H( MTH([0,32)) , MTH([32,40)) )     # recompute the root
```

If the recomputed `R40` equals the checkpoint's signed root, then the client's
`[0,16)` hash is consistent with that checkpoint. Nothing else is needed.

**A client holds `MTH([16,32))`, landmark 2's first subtree.** The proof against
the size-40 tree is again **two hashes**, just in the other order:

```
MTH([0,16)) , MTH([32,40))
```

```
MTH([0,32)) = H( MTH([0,16)) , MTH([16,32)) )     # note: [16,32) is the known hash
R40         = H( MTH([0,32)) , MTH([32,40)) )
```

Same equation, because `[0,16)` and `[16,32)` are the two children of `[0,32)`.
For contrast, `MTH([0,32))` itself needs only **one** proof hash (`MTH([32,40))`),
because `[0,32)` is the root's left child: `R40 = H(MTH([0,32)), MTH([32,40)))`.

**A client holds the old checkpoint root `R20 = MTH([0,20))` and wants the new
`R40`.** Now the proof is **five hashes**:

```
MTH([16,20)) , MTH([20,24)) , MTH([24,32)) , MTH([0,16)) , MTH([32,40))
```

and the fold is the story of peeling the old root apart and rebuilding upward.
The verifier knows `R20 = H(MTH([0,16)), MTH([16,20)))`, so it can check the two
returned children against it, then:

```
MTH([16,24)) = H( MTH([16,20)) , MTH([20,24)) )
MTH([16,32)) = H( MTH([16,24)) , MTH([24,32)) )
MTH([0,32))  = H( MTH([0,16))  , MTH([16,32)) )
R40          = H( MTH([0,32))  , MTH([32,40)) )
```

The old root is not simply a prefix of the new root — the nodes were hashed
together, so you need the siblings to take it apart. That is why checkpoint
consistency costs a handful of hashes and not zero, and why the size stays
logarithmic: five hashes for 20→40 entries, and one more roughly each time the
tree doubles.

Finally, the small case: a landmark at size 20 and `MTH([0,16))` — the proof is
**one hash**, `MTH([16,20))`, since `R20 = H(MTH([0,16)), MTH([16,20)))`.

### G.4 What this means for client state

This is the engine behind the client-state story (Q11–Q15):

* A relying party stores a landmark's **subtree hashes**, not the tree.
* When a newer reference checkpoint arrives, it uses **subtree consistency
  proofs** like the ones above to confirm each trusted subtree is consistent with
  that checkpoint (§7.4).
* Because subtrees are stable (§4.1), old hashes never go stale in the sense of
  changing — they only need re-proving against newer checkpoints, and can be
  dropped once the certificates they cover have expired.

## The one-sentence answer to most of these

Every design decision in MTC is about **who holds what state, and how much**.
Proofs grow with the subtree, not the log; revocation is out of band; null
entries keep indices stable; and the shape a client can check depends on what it
already knows. When you are unsure, ask which of those is changing.
