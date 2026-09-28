Workshop agenda — 90–135 min

Full run is about 135 minutes. To hit 90–120, drop section 3 (the
algorithm landscape is a talk, not a lab), shorten section 1, and cut
exercise 05's steps 3 and 5. Section 7 is the one to protect: it is
the centrepiece, and it is the only section that needs no log server.

Each hands-on section names its worksheet in docs/exercises/.

0. From X.509 to Merkle Tree Certificates — 15 min

Goal: Build the mental model before touching the tools.

Start with the familiar:

identity
   ↓
public key
   ↓
X.509 certificate
   ↓
CA signature

Then introduce the certificate chain:

Root CA
   ↓
Intermediate CA
   ↓
Server certificate

Then ask the next question:

What if a trusted CA issues a certificate it shouldn't?

Introduce Certificate Transparency:

Certificate
     ↓
   CT log
     ↓
Merkle tree
     ↓
signed tree head

Explain:

what a CT log is
what an SCT is
what an inclusion proof is
why Merkle trees are useful
that CT is already used by today's public Web PKI
that CT is not a PQC technology

Then introduce the problem:

Classical signature → relatively small

PQC signature → potentially several KB

And finally:

Could we use the Merkle tree not just to log certificates, but as part of how certificates are authenticated?

That is the motivation for MTC.

1. Baseline: How expensive are PQC certificates? — 20 min

Worksheet: docs/exercises/01_pqc_sizes.md

This should be the first hands-on section.

1.1 Classical baseline

Generate a small traditional PKI:

Root CA
   ↓
Intermediate CA
   ↓
server certificate

Use a classical algorithm such as RSA or ECDSA.

Measure:

public-key size
signature size
certificate DER size
chain size

The important thing is to establish a reference point.

1.2 ML-DSA

Generate the equivalent hierarchy using ML-DSA.

Measure exactly the same things.

Students should now be able to see:

ECDSA certificate:     ~X bytes
ML-DSA certificate:    ~Y bytes

rather than merely hearing that "PQC is bigger."

1.3 SLH-DSA

Repeat with SLH-DSA.

This is useful because it demonstrates that "PQC signature size" isn't one number.

Different PQ signature schemes make different engineering trade-offs.

1.4 Look inside the certificate

Use OpenSSL to inspect:

SubjectPublicKeyInfo
signature algorithm
public key
signature

Then ask:

Where did the extra bytes actually come from?

This is a very useful exercise before introducing MTC.

2. PQC certificates without MTC — 15 min

Worksheet: docs/exercises/02_private_pki_tls.md

I'd make this a first-class workshop section, because it's an important practical conclusion.

The message is:

You can use ordinary PQC X.509 certificates today without using Merkle Tree Certificates.

For example, imagine an internal infrastructure:

                   Your Root CA
                       |
             +---------+---------+
             |                   |
        Service CA          Firmware CA
             |                   |
       +-----+-----+        +----+----+
       |           |        |         |
    device A    device B   FW v1    FW v2

Nobody needs Google, Mozilla, Apple, public CT logs, or browser root programs.

You control both ends.

You can simply create your own CA and distribute its root certificate to:

embedded devices
servers
containers
service meshes
CI infrastructure
developer machines
firmware verification tools

And then use ordinary X.509 certificates with PQ signatures.

Practical exercise

Build a small private PQC PKI:

self-signed PQ root
       ↓
PQ intermediate
       ↓
PQ leaf certificate

Then use it for something tangible.

For example:

curl
  ↓
TLS server
  ↓
ML-DSA certificate

or:

Firmware
   ↓
ML-DSA signature
   ↓
device verification

This section answers an important practical question:

If I have my own infrastructure, why should I care about MTC?

The answer should be:

You might not need it.

If you have a small private PKI, the simplest solution may simply be conventional PQC X.509.

MTC becomes interesting when the scale and repeated-signature overhead justify the additional machinery.

3. PQC algorithm landscape — 10 min

I'd put a short "what else is out there?" section here rather than letting the workshop imply that ML-DSA and SLH-DSA are the entire PQ signature world.

Explain three categories:

Standardized NIST signatures

ML-DSA

General-purpose lattice-based signature.

Good candidate for the main certificate experiments.

SLH-DSA

Hash-based signatures.

Interesting as a contrast because signatures are much larger, but security assumptions are different.

Other algorithms

Introduce Falcon / FN-DSA as an interesting example.

One nuance I'd correct in the workshop material: rather than saying simply that Falcon "is not standardized," I'd explain the current status carefully.

Falcon was selected by NIST for standardization as FN-DSA, but the final FIPS standard is not the same thing as saying that the algorithm is already an established X.509/Web-PKI standard. wolfSSL currently provides native Falcon-512 and Falcon-1024 support, explicitly describing it as anticipating FN-DSA standardization.

This makes Falcon a very good experimental comparison, but not the algorithm I'd build the main workshop around.

You could show:

                    PQ signatures

              ┌─────────┴─────────┐
              │                   │
        standardized          emerging/
        NIST FIPS             evolving
              │                   │
       ┌──────┴──────┐           Falcon
       │             │
    ML-DSA       SLH-DSA

Then mention implementation ecosystems:

OpenSSL
wolfSSL/wolfCrypt
liboqs
other TLS/crypto libraries

The lesson:

Algorithm standardization, X.509 standardization, TLS support, and library support are four different things.

That's a very useful takeaway for engineers.

4. Run your own Certificate Transparency log — 15 min

Worksheet: docs/exercises/03_ct_log.md

Now return to CT.

Students already understand the theory and have seen the size problem.

Now:

docker compose up

Bring up your TesseraCT-based log.

Explain the architecture:

        CA / issuer
             |
             | submit certificate
             v
          CT log
             |
             v
        Merkle tree
             |
       +-----+------+
       |            |
   checkpoint    inclusion
                   proof

Students submit their own certificates.

Then inspect what the log actually stores.

This is particularly valuable for PQC:

What happens to CT log storage when every entry contains a large PQ certificate?

That ties directly back to the motivation for MTC.

The current MTC draft explicitly points out that CT log overhead grows with certificate/public-key/signature size and with increasing numbers of shorter-lived certificates.

5. Merkle proofs — 10 min

Worksheet: docs/exercises/04_merkle_proofs.md

Now get concrete.

Take one certificate from the log.

Generate an inclusion proof.

Walk through it manually:

certificate
     ↓
   hash
     ↓
+sibling
     ↓
   hash
     ↓
+sibling
     ↓
   hash
     ↓
 Merkle root

Compare that root with the authenticated tree state.

The key lesson:

The proof doesn't contain the entire log.

Then reinforce the distinction:

SCT
   =
"I promise to include this."

Inclusion proof
   =
"Here is cryptographic proof that
 it is included."
6. Cosigners and the subtree — 10 min

The log publishes an authenticated checkpoint/tree head, and it signs it
with two cosigners:

                 Log
                  |
        signed checkpoint
        (subtree [0, N) of
         the whole log)
                  |
            +-----+-----+
            |           |
        CA cosigner  external cosigner
            |           |
        cosignature  cosignature
            +-----+-----+
                  |
              verifier

The unit a cosigner signs is a *subtree*, not the tree. Whenever the CA
checkpoints, it also signs the subtrees covering the entries added since
the last checkpoint, and every certificate in that batch reuses those
signatures. That is where the amortisation comes from.

Discuss:

what a cosignature asserts ("this subtree has this hash")
why a subtree rather than the whole tree
why a timestamped signature for a checkpoint, and
  nothing else (§5.3.2)
why the CA's own cosigner ID equals its CA ID (§5.4)
that the draft's separate *witness* architecture is not
  built in this workshop -- cosigners are

7. One log, four certificates — 30 min

This is the centrepiece, and it is hands-on.

    make mtc-lab

One command builds the CA: an issuance log of 20 entries (with a null
entry at index 7), two checkpoints, one landmark, and real ML-DSA keys
for two cosigners plus the CA. It prints the log entry size, which is
the storage argument in one number:

    the log entry      131 bytes, hashed to 32 bytes
    a CT-style entry   would instead carry the whole 1974-byte
                       public key and a signature

Then cut all four shapes from the same entry:

    make mtc-shapes

        shape                subtree    sigs  sig bytes  total
        ---------------------------------------------------
        directly signed      --            1       3309   5439
        standalone           [0, 20)      2       4840   7165
        checkpoint-relative  [0, 8)       2       4840   7101
        landmark-relative    [0, 16)      0          0   2269

Say the surprising part out loud: the MTC shapes are *bigger*. Two
ML-DSA-44 cosignatures cost more than one ML-DSA-65 signature. MTC is
not a compression scheme. What it buys is transparency, and the
ability to sign a batch instead of a certificate.

The one genuinely small row is the landmark-relative one, and it is
small only because the client is expected to already hold the hash.

Then show what a client can actually check:

    python3 -m lab.cli mtc verify --knows cosigners
    python3 -m lab.cli mtc verify --knows landmark

        client knows     direct  standalone  checkpoint  landmark
        --------------------------------------------------------
        cosigner keys    refused  verified    verified    not yet
                                                        checkable
        + landmark       refused  verified    verified    verified
        + the CA's key   verified  verified    verified    verified

"Not yet checkable" is the line to stop on. A landmark-relative
certificate is not wrong, it is unverifiable until the client has the
landmark. A client that treats those the same will drop good
certificates.

Finish the section by changing one field and watching all four shapes
refuse it, each for a different reason:

    python3 -m lab.cli mtc verify --knows all --tamper

Worksheet: docs/exercises/05_mtc_four_shapes.md

8. Discussion: where would I actually use this? — 10 min

I'd finish with a practical decision matrix. The worksheet for this
section is docs/exercises/06_where_to_use.md.

Public Web PKI

Today:

Traditional X.509
+
CT

MTC:

Interesting future direction, but not something today's mainstream browsers/TLS stacks generally support.

The current MTC document is still an Internet-Draft.

Internal PKI
Your CA
+
your trust store
+
PQC X.509

This may already be enough.

No need to introduce MTC unless you have a reason.

Firmware

This is particularly interesting.

You might have:

Firmware
   |
   | ML-DSA signature
   v
Bootloader
   |
   v
device

For firmware, a straightforward PQ signature may actually be preferable because you often want a simple, offline-verifiable artifact.

A Merkle-tree construction could become interesting when you're signing huge numbers of artifacts or want a transparency/audit mechanism.

Artifact / software supply chain

Another good use case:

CI
 |
 +-- artifact A
 +-- artifact B
 +-- artifact C
 ...
 |
 v
transparency log

Here the tree-based approach becomes much more interesting because you naturally have large numbers of signed objects.

9. Final discussion: three possible strategies

I'd end the workshop with this slide. It is the same table as
docs/exercises/06_where_to_use.md, so the room can follow along:

Strategy A -- Traditional PQC X.509

CA
 ↓
PQC certificate
 ↓
PQC signature

Simple. Available now.

Excellent for:

internal PKI
service mesh
private infrastructure
embedded devices
firmware/artifacts
Strategy B — PQC + traditional CT
PQC certificate
      |
      +---- CA PQ signature
      |
      +---- CT
             |
             +---- SCT
             +---- Merkle tree

This is conceptually closest to today's Web PKI.

But the large PQ certificate/signature still exists.

Strategy C — Merkle Tree Certificate
                issuance log
                     |
                 Merkle tree
                     |
                 tree root
                     |
              PQ signature(s)
                     |
          +----------+----------+
          |                     |
     inclusion proof       cosignatures
          |                     |
          +----------+----------+
                     |
                  MTC

More complicated.

Potentially much more efficient at scale.

But it requires new protocol and implementation support.
opencode -s ses_f65479062ffeIXVYDQD0Bx6zYG