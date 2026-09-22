# Facilitator notes — Merkle Tree Certificates workshop

Target length: **90–120 minutes**. The agenda is in
[`mtc_workshop.md`](mtc_workshop.md); the implementation is documented in
[`../IMPL.md`](../IMPL.md).

## One-time setup (before the session)

```bash
git clone <repo> && cd merkle-tree-lab
make submodules
python3 -m pip install -r requirements.txt
export PATH="$HOME/ossl-3.5/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/ossl-3.5/lib64:$HOME/ossl-3.5/lib:$LD_LIBRARY_PATH"
make measure      # warms the PKI cache and prints the size table
```

Confirm `openssl version` shows 3.5+ and `go version` can fetch 1.27
(`GOTOOLCHAIN=go1.27.0 go version`). Pre-building avoids surprises on stage:

```bash
make build-tesseract
make build-witness
```

## Timing

| Min | Section | Lab command | Expected output |
|---:|---|---|---|
| 0–15 | From X.509 to MTC (theory) | — | discussion |
| 15–35 | Baseline PQC cost | `make measure` | size table (below) |
| 35–50 | PQC X.509 without MTC | `make pki ALG=mldsa65 && make tls-demo` | `Verification: OK`, `Peer signature type: mldsa65` |
| 50–60 | Algorithm landscape | `make measure` + table | ML-DSA vs SLH-DSA contrast |
| 60–75 | Run your own CT log | `make lab-up`, `make demo` | `Inclusion: VALID`, `Checkpoint sig: VALID` |
| 75–85 | Merkle proofs | `make walk INDEX=0` | hash-by-hash, `MATCH: True` |
| 85–95 | Checkpoints & witnesses | `make witness-demo` | `witness cosig: VALID` |
| 95–105 | MTC-shaped bundle | `make bundle` | size comparison |
| 105–120 | Discussion | — | decision matrix |

## Talking points

* **Sizes:** ML-DSA ≈ 4–5.6 KB, SLH-DSA ≈ 8 KB per certificate. The CA signature
  is the dominant cost for SLH-DSA; ML-DSA splits it between key and signature.
* **Private PKI:** if you control both ends, ordinary PQC X.509 over TLS works
  today. You may not need MTC at all.
* **CT is not PQC:** CT is a transparency mechanism; it can log PQC certificates
  but does not make signatures quantum-safe.
* **Proof vs promise:** the SCT is a promise; the inclusion proof is evidence.
* **Amortization:** one checkpoint signature covers the whole tree; each
  certificate only carries an audit path of `log₂(N)` hashes.
* **Witnessing:** the log alone can equivocate; a witness cosignature over the
  checkpoint constrains what the log can publish.

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
| `algorithm unimplemented` on submit | TesseraCT built with Go < 1.27 | `make build-tesseract` (uses `GOTOOLCHAIN=go1.27.0`) |
| `invalid CA certificate` | missing `basicConstraints=CA:TRUE` | use `scripts/openssl/ca_ext.cnf` (already wired) |
| `certificate signed by unknown authority` | leaf does not chain to the log's `--roots_pem_file` | log the matching algorithm (default `mldsa65`) |
| `checkpoint was not published in time` | log not running / wrong storage dir | `make lab-down && make lab-up` |
| witness cosignature missing | log started without `--additional_signer`/`--witness_policy_file` | `make witness-demo` |
| port already in use | stale process | `make lab-down`, `scripts/run_witness.sh stop` |

## What is intentionally out of scope

* SLH-DSA and Falcon are **not logged** (Go cannot validate them); they are for
  size comparison only.
* The MTC bundle is a teaching artifact, not the MTC wire format.
* No scale/throughput test in v1; the amortization argument is made analytically.

## Facilitation tips

* Keep `make measure` output on screen for the whole session.
* After `make demo`, run `make walk` slowly; pause at each sibling.
* For the witness demo, show the checkpoint **before** (2 signatures) and
  **after** (3 signatures) enabling witnessing.
* If short on time, skip `make tls-demo` and the bundle, keep measure + CT log +
  proofs + witnesses.
