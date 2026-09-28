# Facilitator notes — Merkle Tree Certificates workshop

Target length: **90–120 minutes**. The agenda is in
[`mtc_workshop.md`](mtc_workshop.md); the implementation is documented in
[`../IMPL.md`](../IMPL.md); the worksheets are in [`exercises/`](exercises/).

## One-time setup (before the session)

```bash
git clone <repo> && cd merkle-tree-lab
make submodules
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
export PATH="$HOME/ossl-3.5/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/ossl-3.5/lib64:$HOME/ossl-3.5/lib:$LD_LIBRARY_PATH"
make measure      # warms the PKI cache and prints the size table
make mtc-lab      # builds the MTC scenario; no network needed
```

**Use the `.venv`.** The MTC lab generates real ML-DSA keys, which needs
`cryptography>=46`. A system Python older than that will fail at
`import cryptography` with a confusing error about `mldsa`. The `Makefile`
picks up `.venv/bin/python` automatically if it exists.

Confirm `openssl version` shows 3.5+ and `go version` can fetch 1.27
(`GOTOOLCHAIN=go1.27.0 go version`). Pre-building avoids surprises on stage:

```bash
make build-tesseract
```

The MTC half of the workshop (everything from the "one log, four certificates"
section on) needs **no log server, no Go, no OpenSSL**. If TesseraCT fails to
build, you can still run the centrepiece.

## Timing

| Min | Section | Lab command | Expected output |
|---:|---|---|---|
| 0–15 | From X.509 to MTC (theory) | — | discussion |
| 15–35 | Baseline PQC cost | `make measure` | size table (below) |
| 35–50 | PQC X.509 without MTC | `make pki ALG=mldsa65 && make tls-demo` | `Verification: OK`, `Peer signature type: mldsa65` |
| 50–60 | CT log and what it stores | `make lab-up`, `make demo` | `Inclusion: VALID`, `Checkpoint sig: VALID` |
| 60–75 | Merkle proofs, step by step | `make fill N=8`, then `make walk INDEX=2` and `INDEX=7` | hash-by-hash, `MATCH: True`, one `inner` and one `border` path |
| 75–105 | **One log, four certificates** | `make mtc-shapes`, `python3 -m lab.cli mtc verify` | the four-shape table (below) |
| 105–120 | Which shape would you deploy? | — | discussion |

The 30-minute block is exercise 05, the centrepiece. If the room is going
slowly, cut its Step 3 and Step 5 and keep Steps 1, 2, and 4 — the shape table
and the client-knowledge table are the two things the rest of the session
refers back to.

## Expected MTC output

`make mtc-lab` prints the log ID, the two checkpoint roots, the landmark's two
subtree hashes, and the entry size. The two numbers to have on screen:

```
  the log entry      131 bytes, hashed to 32 bytes
  a CT-style entry   would instead carry the whole 1974-byte public key and a signature
```

`make mtc-shapes` prints the table the whole workshop builds toward:

| shape | subtree | signatures | signature bytes | proof hashes | landmark-dependent | total bytes |
|---|---|---|---|---|---|---|
| directly signed | - | 1 | 3309 | 0 | no | 5439 |
| standalone (tree-relative) | [0, 20) | 2 | 4840 | 5 | no | 7165 |
| checkpoint-relative | [0, 8) | 2 | 4840 | 3 | no | 7101 |
| landmark-relative | [0, 16) | 0 | 0 | 4 | yes | 2269 |

**Say out loud that the MTC shapes are bigger.** Two ML-DSA-44 cosignatures
(2 420 B each) cost more than one ML-DSA-65 signature (3 309 B). People expect
the MTC rows to be smaller and the numbers will surprise them. The honest
framing: the point is transparency and amortisation, not size. The one row that
is genuinely small is the landmark-relative one, and it is small only because
the client already holds the hash.

`python3 -m lab.cli mtc verify --knows cosigners` then
`--knows landmark` is the other output worth having ready:

| client knows | direct | standalone | checkpoint | landmark |
|---|---|---|---|---|
| cosigner keys | refused | verified | verified | **not yet checkable** |
| + landmark hashes | refused | verified | verified | verified |
| + the CA's key | verified | verified | verified | verified |

The "not yet checkable" line is the single most useful thing in the lab. Pause
on it: a client that treats not-yet-checkable as invalid will drop valid
certificates, and that distinction is the reason landmarks have expiry.

`--tamper` changes one SAN and shows all four shapes refusing, each for a
different reason.

## Talking points

* **Sizes:** ML-DSA ≈ 4–5.6 KB, SLH-DSA ≈ 8 KB per certificate. The CA signature
  is the dominant cost for SLH-DSA; ML-DSA splits it between key and signature.
* **The storage argument:** an ML-DSA-65 CT log entry is ~7 600 B; the MTC entry
  is 131 B, because it stores a *hash* of the key and no signature. ~58×.
* **Private PKI:** if you control both ends, ordinary PQC X.509 over TLS works
  today. You may not need MTC at all.
* **CT is not PQC:** CT is a transparency mechanism; it can log PQC certificates
  but does not make signatures quantum-safe.
* **Proof vs promise:** the SCT is a promise; the inclusion proof is evidence.
* **Amortization:** one cosignature pair covers a whole batch of entries added
  between checkpoints. This is what makes a *larger* certificate the right
  choice at scale.
* **What the client knows decides the shape.** That is why the draft has
  negotiation — which is discussed in exercise 05 step 6, not simulated.

## Expected size table

| Algorithm | Family | Cert (DER) | Public key | Signature | Chain |
|---|---|---:|---:|---:|---:|
| ECDSA P-256 | classical | 478 | 91 | 71 | 901 |
| RSA-2048 | classical | 868 | 294 | 256 | 1681 |
| ML-DSA-44 | PQC | 4070 | 1334 | 2420 | 8085 |
| ML-DSA-65 | PQC | 5599 | 1974 | 3309 | 11143 |
| SLH-DSA-SHA2-128s | PQC | 8238 | 50 | 7856 | 16421 |

(Regenerate with `make measure`; exact bytes may vary slightly by OpenSSL build.)

## Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `cannot import name 'MLDSA65PrivateKey'` | `cryptography` older than 46 | use `.venv/bin/python`, reinstall from `requirements.txt` |
| `algorithm unimplemented` on submit | TesseraCT built with Go < 1.27 | `make build-tesseract` (uses `GOTOOLCHAIN=go1.27.0`) |
| `invalid CA certificate` | missing `basicConstraints=CA:TRUE` | use `scripts/openssl/ca_ext.cnf` (already wired) |
| `certificate signed by unknown authority` | leaf does not chain to the log's `--roots_pem_file` | log the matching algorithm (default `mldsa65`) |
| `checkpoint was not published in time` | log not running / wrong storage dir | `make lab-down && make lab-up` |
| `no scenario at out/mtc/scenario.json` | `mtc shapes` or `mtc verify` before `mtc lab` | run `make mtc-lab` first; the commands share state on disk |
| `entry 7 is a null entry and cannot be certified` | expected — index 7 is the null entry | pick another index |
| port already in use | stale process | `make lab-down` |

## What is intentionally out of scope

* The **witness architecture**. The draft's witness design is a separate
  proposal; this workshop does not build it. See `PLAN-update.md` D1.
* The **MTC bundle** and any wire format. Certificates here are dataclasses in
  a documented TLV, not X.509 and not interoperable.
* **Negotiation.** Discussed in exercise 05 step 6, not simulated.
* SLH-DSA and Falcon are **not logged** (Go cannot validate them); they are for
  size comparison only.
* No scale/throughput test; the amortisation argument is made by hand in
  exercise 05 step 6.

## Facilitation tips

* Keep `make measure` output on screen for the first half.
* Run `make fill N=8` *before* exercise 04, not `make demo` twice. `make demo`
  resubmits the same leaf, the log deduplicates it, and the tree stays at size 1
  with no siblings to pause at. Fill first, then walk `--index 2` and `--index 7`
  slowly: one path is `inner`, the other is all `border`, and the contrast is the
  thing the room remembers.
* For the MTC half, run `make mtc-lab` *before* the session starts so the
  scenario is on disk. It takes about a second.
* When the shape table appears, ask the room to predict which row is smallest
  before you say anything. Most people guess the MTC rows.
* End on the client-knowledge table, not the size table. The design question in
  exercise 06 is the discussion people remember.
