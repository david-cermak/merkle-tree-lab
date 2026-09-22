# IMPL.md — How the Merkle Tree Lab is built

This document explains, workstream by workstream, how the lab is implemented and **why** each
piece works the way it does. It is written for workshop participants: read it alongside the code
under `lab/` and the shell scripts under `scripts/`.

The lab has these implemented workstreams:

| Workstream | Theme | Main artifacts |
|---|---|---|
| **WS1** | Repo hygiene & reproducibility | submodule, `Makefile`, `README.md`, packaging |
| **WS2** | Python static-ct client | `lab/merkle.py`, `lab/certs.py`, `lab/note.py`, `lab/staticct.py`, `lab/cli/` |
| **WS3** | PQC PKI & size measurement | `lab/pki.py`, `lab/measure.py`, `scripts/openssl/*`, `scripts/tls_demo.sh` |
| **WS4** | CT log lab | `scripts/run_tesseract.sh`, `lab.cli demo`, `scripts/workshop.sh` |
| **WS5** | Merkle proof walkthrough | `lab/merkle.py` `explain_inclusion`, `lab.cli walk`, `docs/exercises/05_*` |
| **WS6** | Checkpoints & witnesses | `lab/note.py` `verify_cosignature`, `tools/witness/`, `scripts/witness_demo.sh` |
| **WS7** | MTC-shaped bundle | `lab/bundle.py`, `lab.cli bundle` |
| **WS9** | Workshop materials | `docs/facilitator_notes.md`, `docs/exercises/`, `abstract.md` |
| **WS10** | Verification & CI | `tests/`, `.github/workflows/ci.yml`, `scripts/workshop.sh` |

WS8 (optional Falcon via oqs-provider) is intentionally **not** implemented yet; SLH-DSA and
Falcon are measurement-only.

---

## 0. The big picture

We run a **local Certificate Transparency log** and drive it from Python.

```
        Python client (lab/)
   add-chain │  HTTP JSON          ┌───────────────────────────────┐
             └────────────────────►│  TesseraCT POSIX (Go 1.27)    │
                                 │  storage: ./log               │
   checkpoint + entry bundles    │  roots:   ./out/pki/.../root  │
             ◄────────────────────┤  key:     ./out/log-key.pem   │
                                 └───────────────┬───────────────┘
                                                 │
                                                 ▼
                    log/checkpoint  +  log/tile/data/*  +  log/tile/*
```

There are three concepts to keep straight:

1. **Submission** is a normal HTTP POST (`/ct/v1/add-chain`). It returns a *Signed Certificate
   Timestamp* (SCT): the log's promise to include the certificate.
2. **Monitoring** is not an API. The log writes a signed **checkpoint** and Merkle **tiles** to
   disk (or a static file server). Clients read those files.
3. **Proofs** are not requested from the log. The client reads the logged entries, rebuilds the
   Merkle tree, and derives inclusion proofs locally.

TesseraCT implements [static-ct-api](https://c2sp.org/static-ct-api) and
[tlog-tiles](https://c2sp.org/tlog-tiles). The client is deliberately small: standard-library
HTTP + JSON, plus `cryptography` for one ECDSA verification.

---

## WS1 — Repo hygiene and reproducibility

### What changed

The repository originally held a Trillian + Go experiment. We removed all of it and made the
repository self-describing:

* Deleted `impl/trillian/`, the Go client tools under `cmd/`, the root `go.mod`/`go.sum`, the
  prebuilt binaries, `demo.sh`, `docker-compose.yml`, and the old scripts.
* Pinned TesseraCT as a **git submodule** at commit `3f03bb6` (`impl/tesseract`, TesseraCT
  `v0.1.3-rc2-15-g30fd1469`).
* Added `Makefile`, `pyproject.toml`, `requirements.txt`, and rewrote `README.md`.

### Why a submodule?

A CT log is a *server*. We depend on an exact, reviewed version of that server, but we do not
want to copy its source into our history. A submodule records a single commit hash, so
`git submodule update --init` gives everyone the same code:

```bash
make submodules          # git submodule update --init --recursive
```

### Why Go 1.27?

TesseraCT validates submitted certificate chains with Go's `crypto/x509`. Go only learned to
verify **ML-DSA** signatures in **1.27**:

```
Go 1.25 / 1.26 : x509: cannot verify signature: algorithm unimplemented
Go 1.27        : OK (parsed sigalg=ML-DSA-65)
```

The `Makefile` therefore builds with `GOTOOLCHAIN=go1.27.0`. If your machine has an older Go,
`GOTOOLCHAIN=auto` will download 1.27 for you. SLH-DSA and Falcon are still unsupported by Go's
`x509`; that is why they are measurement-only in this lab.

### The Makefile as documentation

`make help` lists every task. The important ones:

```bash
make submodules        # fetch TesseraCT
make build-tesseract   # build the POSIX log server (Go 1.27)
make pki ALG=mldsa65   # generate one certificate chain
make measure           # generate all chains and measure sizes
make lab-up            # start the log
make demo              # submit + verify
make lab-down          # stop the log
make workshop          # the whole happy path
make test              # unit tests
```

**Check yourself:** `git submodule status` should show `30fd1469... impl/tesseract`.

---

## WS2 — The Python static-ct client

This is the heart of the lab. It lives in `lab/` and has four modules plus a CLI.

### 2.1 Merkle hashing and proofs — `lab/merkle.py`

RFC 6962 defines three hashes:

```
empty tree  = SHA256("")
leaf        = SHA256(0x00 || leaf_data)
node        = SHA256(0x01 || left_hash || right_hash)
```

The `0x00`/`0x01` prefixes are **domain separation**: without them, an attacker could present a
leaf whose bytes look like an internal node and forge proofs.

A tree over `n` leaves is split at `k`, the largest power of two strictly smaller than `n`:

```
root(leaves) = node(root(leaves[:k]), root(leaves[k:]))
```

This split is what makes a CT tree *not* a perfect binary tree, and it is the reason inclusion
proof verification is subtler than "fold by index parity".

An inclusion proof is the list of sibling hashes from the leaf up to the root. We generate it
recursively in `inclusion_proof()`, and verify it in `verify_inclusion()`. Verification must
follow the RFC 6962 algorithm, which splits the proof into:

* an **inner** part — siblings below the point where the path to `index` diverges from the path
  to the last leaf (`size-1`); these can be left *or* right siblings;
* a **border** part — left siblings only, one per level above the fork.

```python
inner, border = decomp_incl_proof(index, size)     # counts
result = chain_inner(leaf_hash, proof[:inner], index)
result = chain_border_right(result, proof[inner:])
```

A naive implementation that only looks at `index` parity passes for power-of-two sizes and
**fails for size 3** — a classic workshop "aha". The unit tests sweep every index for sizes
1..39 to make sure both paths are correct.

### 2.2 Certificates without a parser — `lab/certs.py`

`cryptography` did not understand ML-DSA at the time of writing, so we cannot rely on it to read
post-quantum certificates. Instead `certs.py`:

* extracts DER from PEM with a regex + base64;
* walks the DER with a ~30-line ASN.1 TLV reader.

An X.509 certificate is:

```
Certificate ::= SEQUENCE {
    tbsCertificate       TBSCertificate,      -- contains the public key
    signatureAlgorithm   AlgorithmIdentifier, -- e.g. ML-DSA-65
    signatureValue       BIT STRING           -- the CA's signature
}
```

Inside the TBS, `SubjectPublicKeyInfo` is the 6th field (7th when the optional explicit
`version` is present). That gives us the four numbers we care about:

| Field | Meaning |
|---|---|
| `der_size` | the whole certificate on the wire |
| `spki_size` | the encoded public key |
| `signature_size` | the CA signature (the PQC blow-up) |
| `tbs_size` | the signed body |

**Check yourself:** run `make measure` and look at `out/measurements.md`.

### 2.3 Signed checkpoints — `lab/note.py`

TesseraCT publishes its current tree state as a **note**:

```
example.com/workshop
1
50f62eba6b968e3eb308b258ca606c30e052382494d6ca3592c7b4d1df5ef052

— example.com/workshop <base64 signature>
```

The first three lines are the signed message (`origin\nsize\nroot\n`). The signature line decodes
to:

```
key hash (4) || timestamp (8) || hash_alg (1)=0x04 || sig_alg (1)=0x03 || sig_len (2) || ECDSA sig
```

The ECDSA signature is over SHA-256 of an RFC 6962 `TreeHeadSignature`:

```
0x00 || 0x01 || timestamp(8) || tree_size(8) || root_hash(32)
```

`lab/note.py` parses the checkpoint, recomputes that structure, and verifies the signature with
`cryptography` (using `Prehashed(SHA256())`). It also recomputes the note key hash:

```
key_hash = first 4 bytes of SHA256(origin || "\n" || 0x05 || SHA256(SPKI))
```

so a signature from the wrong key is rejected before we even try to verify it.

**Check yourself:** `python3 -m lab.cli checkpoint --storage-dir log --pubkey out/log-key.pem`
prints `signature : VALID`.

### 2.4 Entry bundles and the Merkle leaf — `lab/staticct.py`

Submission uses HTTP:

```python
client.add_chain([leaf_der, intermediate_der])   # POST /ct/v1/add-chain
```

Monitoring reads files. Each `tile/data/...` **entry bundle** holds up to 256 entries. The
bytes for one x509 entry are:

```
timestamp(8) || entry_type=0(2) || uint24(cert) || uint16(extensions) || uint16(fingerprints)
```

The `extensions` field embeds the global leaf index (extension type 0, length 5, 5-byte index).

Crucially, the hash that goes into the Merkle tree is **not** these bytes. It is the RFC 6962
`MerkleTreeLeaf`:

```
version(1)=0 || leaf_type(1)=0 || timestamp(8) || entry_type(2) || uint24(cert) || uint16(extensions)
```

The fingerprints are dropped, and two leading zero bytes are added. `Entry.merkle_tree_leaf()`
builds exactly this, and `Entry.leaf_hash()` wraps it with `SHA256(0x00 || ...)`.

The client then:

1. reads all entry bundles (`read_entry_bundles`);
2. hashes every entry (`leaf_hashes`);
3. rebuilds the tree and derives proofs (`merkle.*`).

Because the log is small, this is cheap — and it makes the whole Merkle construction visible
instead of hidden behind an RPC.

**Check yourself:** after `make lab-up` and `make demo`, run
`python3 -m lab.cli proof --storage-dir log --index 0`.

### 2.5 CLI — `lab/cli/__main__.py`

```bash
python3 -m lab.cli submit    --chain leaf.crt int.crt
python3 -m lab.cli checkpoint --storage-dir log --pubkey out/log-key.pem
python3 -m lab.cli proof     --storage-dir log --index 0
python3 -m lab.cli verify    --storage-dir log --index 0 --pubkey out/log-key.pem
python3 -m lab.cli pki       --algorithm mldsa65
python3 -m lab.cli measure   --generate
python3 -m lab.cli demo      --storage-dir log --log-key out/log-key.pem
```

### 2.6 Tests

```bash
make test        # python3 -m unittest discover -s tests -v
```

The suite covers hashing vectors, proof round-trips for sizes 1..39, note parse/verify/tamper,
entry-bundle parsing, MerkleTreeLeaf layout, and DER size parsing. It runs in well under a
second and needs no running log.

---

## WS3 — PQC PKI and size measurement

### 3.1 Building a chain — `lab/pki.py`

Every algorithm produces the same hierarchy:

```
root CA (self-signed)  ->  intermediate CA  ->  leaf (server) certificate
```

The OpenSSL steps are the same for classical and post-quantum keys; only the key type changes:

```bash
# root
openssl req -x509 -newkey ML-DSA-65 -keyout root.key -out root.crt -days 3650 -nodes \
  -subj "/CN=ML-DSA-65 Root" -addext "basicConstraints=critical,CA:TRUE"

# intermediate CSR + cert
openssl req -new -newkey ML-DSA-65 -keyout int.key -out int.csr -nodes -subj "/CN=... Intermediate"
openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -CAcreateserial -out int.crt \
  -days 1825 -extfile scripts/openssl/ca_ext.cnf -extensions v3_ca

# leaf CSR + cert, then verify
openssl x509 -req -in leaf.csr -CA int.crt -CAkey int.key -CAcreateserial -out leaf.crt \
  -days 365 -extfile scripts/openssl/leaf_ext.cnf -extensions v3_leaf
openssl verify -CAfile root.crt -untrusted int.crt leaf.crt
```

**The classic trap:** `openssl x509 -req` does not mark the intermediate as a CA by default, so
`openssl verify` fails with `error 79 at 1 depth lookup: invalid CA certificate`. The extension
configs in `scripts/openssl/` set `basicConstraints=critical,CA:TRUE` and fix it.

Generate one chain or the whole set:

```bash
make pki ALG=mldsa65
make pki-all
```

### 3.2 Measuring the cost — `lab/measure.py`

`make measure` generates the default set and writes `out/measurements.md` and
`out/measurements.json`. Representative results (leaf certificate):

| Algorithm | Family | Cert (DER) | Public key (SPKI) | Signature | Chain |
|---|---|---:|---:|---:|---:|
| ECDSA P-256 | classical | 478 | 91 | 71 | 901 |
| RSA-2048 | classical | 868 | 294 | 256 | 1681 |
| ML-DSA-44 | PQC | 4070 | 1334 | 2420 | 8085 |
| ML-DSA-65 | PQC | 5599 | 1974 | 3309 | 11143 |
| SLH-DSA-SHA2-128s | PQC | 8238 | 50 | 7856 | 16421 |

Two lessons fall out of the table:

* "PQC is bigger" is not one number: ML-DSA and SLH-DSA differ by ~3x.
* The **signature** dominates for SLH-DSA, while ML-DSA splits the cost between public key and
  signature. That is exactly the pressure that motivates Merkle Tree Certificates.

### 3.3 Using the private PQC PKI — `scripts/tls_demo.sh`

The private-PKI point: if you control both ends, ordinary PQC X.509 over TLS works **today**,
with no CT log and no browsers involved.

```bash
make pki ALG=mldsa65
make tls-demo
```

The script starts one `openssl s_server` with the ML-DSA leaf (and sends the intermediate via
`-cert_chain`), connects one `openssl s_client`, and prints:

```
subject=CN=leaf.example (ML-DSA-65)
Peer signature type: mldsa65
Verification: OK
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Verify return code: 0 (ok)
```

The client validates the chain against the private root and the handshake is signed with the
post-quantum key.

---

## WS4 — Running the CT log lab

### 4.1 Starting the log — `scripts/run_tesseract.sh`

TesseraCT's POSIX backend is a single binary with no database:

```bash
make build-tesseract     # bin/tesseract-posix, built with Go 1.27
make lab-up              # scripts/run_tesseract.sh start
```

The script:

1. builds the binary if needed;
2. generates an **ECDSA** checkpoint key (`out/log-key.pem`) if missing — the log's own
   checkpoint signature is ECDSA;
3. generates the `mldsa65` PKI if the roots file is missing;
4. starts the server with:
   `--storage_dir`, `--origin`, `--private_key`, `--roots_pem_file`,
   `--checkpoint_interval=1s`, `--enable_publication_awaiter=false`;
5. waits for the first `checkpoint` file and records the PID under `log/tesseract.pid`.

`make lab-down` stops it. `GOMEMLIMIT=2GiB` is set because BadgerDB (the antispam store) can
spike memory during compaction.

Only certificates that chain to `--roots_pem_file` are accepted, and only ML-DSA/classical
chains can be validated by Go (see WS1). SLH-DSA and Falcon are **not** submitted.

### 4.2 Submit and verify — `python3 -m lab.cli demo`

`make demo` runs the full client-side flow:

1. load (or generate) the ML-DSA leaf + intermediate;
2. `POST /ct/v1/add-chain` and read the leaf index out of the returned SCT extensions;
3. poll the entry bundles and checkpoint until the entry is present and covered;
4. locate the matching entry by comparing the stored certificate bytes;
5. rebuild the Merkle tree and produce the inclusion proof;
6. verify the proof against the checkpoint root;
7. verify the checkpoint's ECDSA signature with the log key.

Expected output:

```
Submitted mldsa65 leaf certificate
  SCT timestamp : 1789325684891
  leaf index    : 0
Checkpoint    : size=1 root=50f62eba...
Inclusion     : VALID (0 audit hash(es))
Checkpoint sig: VALID
```

Submitting the same chain again is deduplicated by TesseraCT and returns the same leaf index —
a good demonstration that the log is a set, not a stream.

### 4.3 The whole path — `make workshop`

`scripts/workshop.sh` chains the smoke test: measure, `lab-up`, `demo`, `walk`, `checkpoint`
verification, `bundle`, then `lab-down` (via a trap). If this completes, the environment is
healthy.

---

## WS5 — Merkle proof walkthrough

WS2 already builds and verifies proofs. WS5 makes the process *visible*.

`lab/merkle.py` exposes `explain_inclusion(leaf_hash, index, size, proof)`, which folds the
audit path back to the root exactly like `root_from_inclusion_proof`, but records each step:
the sibling hash, whether it was used on the **left** or the **right**, and the resulting hash.
The split into the *inner* part (parity-driven, siblings on either side) and the *border* part
(left siblings only) is printed so students can see why a CT tree is not a perfect binary tree.

```bash
make walk INDEX=2
# or: python3 -m lab.cli walk --storage-dir log --index 2
```

The command prints the leaf hash, every hashing step, and finally compares the computed root
with the checkpoint root (`MATCH: True`). The companion worksheet is
`docs/exercises/05_merkle_proofs.md`.

---

## WS6 — Checkpoints, witnesses, and cosignatures

### 6.1 The problem

A log can publish two different checkpoints of the same size (a *split view*). An inclusion
proof only shows a certificate is in *some* tree; it does not pin *which* tree. A **witness**
fixes this by independently checking append-only behaviour and cosigning the checkpoint.

### 6.2 The local witness — `tools/witness/`

TesseraCT has native witnessing support (`--witness_policy_file`, `--additional_signer`), but it
needs a witness endpoint. The public witness network requires registering your log key, so for an
offline workshop we ship a minimal witness server:

```
tools/witness keygen --name NAME --out FILE   # Ed25519 note key + cosignature verifier
tools/witness serve  --listen ADDR --signer-key FILE --log-vkey FILE
```

The server wraps `github.com/transparency-dev/witness` with an in-memory store, trusts the log's
additional signer key via `VerifierForLog`, and exposes the tlog-witness
`POST /add-checkpoint` endpoint.

### 6.3 Wiring it up

`scripts/setup_witness.sh` generates, under `out/witness/`:

* `log-signer.key` — an Ed25519 note signer used by TesseraCT's `--additional_signer`;
* `log-vkey.txt` — its verifier key, trusted by the witness;
* `witness.key` / `witness-vkey.txt` — the witness key and its **CosignatureV1** verifier key;
* `policy.txt` — a Sigsum-format witness policy.

`scripts/run_tesseract.sh` passes `--additional_signer` and `--witness_policy_file` when
`ADDITIONAL_SIGNER` and `WITNESS_POLICY` are set. `scripts/witness_demo.sh` (and
`make witness-demo`) runs the whole flow.

After enabling witnessing, the checkpoint gains a third signature line:

```
— example.com/workshop ...   (primary ECDSA, RFC6962)
— example.com/workshop ...   (additional Ed25519 log signer)
— witness.local ...          (witness cosignature)
```

### 6.4 Verifying cosignatures in Python

`lab/note.py` implements C2SP tlog-cosignature. The signed message is:

```
cosignature/v1
time <unix seconds>
<checkpoint note text>
```

and the signature line's base64 decodes to `keyhash(4) || timestamp(8) || ed25519 sig(64)`.
The key hash is `SHA256(name || "\n" || 0x04 || ed25519_pubkey)` truncated to 4 bytes. The
`checkpoint` CLI command verifies it:

```bash
python3 -m lab.cli checkpoint --storage-dir log \
  --pubkey out/log-key.pem --witness-vkey out/witness/witness-vkey.txt
# log signature  : VALID
# witness cosig  : VALID (witness.local)
```

Worksheet: `docs/exercises/06_witnesses.md`.

---

## WS7 — The MTC-shaped bundle

`lab/bundle.py` assembles the pieces the lab already produces into one JSON object:

```
certificate + inclusion proof + signed checkpoint + signatures
```

`lab.cli bundle` builds it for a leaf, writes `out/mtc_bundle.json`, and reports its size against
both a single conventional leaf certificate and a full chain:

```bash
make bundle INDEX=0
```

Representative single-certificate result (ML-DSA-65):

```
conventional leaf certificate          : 5599 bytes
conventional chain (leaf+intermediate) : 11143 bytes
MTC-shaped bundle (JSON, base64 cert)  : 8298 bytes
```

The bundle is **not** the MTC wire format — it is a teaching artifact. It is JSON with a base64
certificate (~33% overhead), and for one certificate it may be larger or smaller than the chain.
The point is the *shape* of the trade: a conventional certificate repeats a large PQ signature,
whereas the bundle replaces it with a short audit path plus a shared, witnessed checkpoint
signature. The exercise asks students to reason about the crossover scale.

Worksheet: `docs/exercises/07_mtc_bundle.md`.

---

## WS9 — Workshop materials and end-to-end flow

* `README.md` — prerequisites, quickstart, repository layout, materials index.
* `abstract.md` — updated to the TesseraCT + Python + PQC + witness story.
* `docs/facilitator_notes.md` — timing table, talking points, expected outputs, common failures,
  and what is intentionally out of scope.
* `docs/exercises/` — six worksheets (`01`, `02`, `04`, `05`, `06`, `07`) plus an index.
* `scripts/workshop.sh` — the single end-to-end command (`make workshop`), also used as the
  smoke test.

## WS10 — Verification and CI

* `tests/` — 26 unit tests covering hashing, proofs (sizes 1..39), note signatures, witness
  cosignatures, entry bundles, DER sizes, PKI measurement, and bundles.
* `make test` runs them with the standard-library `unittest` runner (no extra dependency).
* `make lint` runs `ruff check lab tests` (config in `pyproject.toml`).
* `.github/workflows/ci.yml` runs lint + unit tests on Python 3.12, and builds the witness tool
  with Go 1.25.
* `make workshop` is the manual smoke test (needs Go 1.27 and OpenSSL 3.5, so it is not run in
  CI).

---

## 5. End-to-end walkthrough

```bash
# one-time
make submodules
python3 -m pip install -r requirements.txt

# section 1: how big is PQC?
make measure
cat out/measurements.md

# section 2: a private PQC PKI over TLS
make pki ALG=mldsa65
make tls-demo

# sections 4-7: a CT log, submission, proof, witness, and bundle
make lab-up
make demo
make walk INDEX=0
python3 -m lab.cli verify --storage-dir log --index 0 --pubkey out/log-key.pem
make bundle INDEX=0
make lab-down

# native witnessing (starts a local witness + a witnessed log)
make witness-demo

# or everything at once
make workshop
```

---

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `x509: cannot verify signature: algorithm unimplemented` on submit | TesseraCT built with Go < 1.27 | `make build-tesseract` with `GOTOOLCHAIN=go1.27.0` |
| `error 79 ... invalid CA certificate` from `openssl verify` | intermediate missing `CA:TRUE` | use `scripts/openssl/ca_ext.cnf` |
| `checkpoint was not published in time` | server not running or wrong `--storage-dir` | check `log/tesseract.log`, `make lab-up` |
| `failed to verify add-chain contents` | leaf does not chain to `--roots_pem_file` | generate the PKI that matches the configured root |
| checkpoint has only 2 signatures | log started without witness flags | `make witness-demo` (sets `ADDITIONAL_SIGNER`/`WITNESS_POLICY`) |
| witness cosignature invalid | wrong `--witness-vkey`, or witness restarted with a new key | re-run `scripts/setup_witness.sh`; keys are persisted under `out/witness/` |
| `Permission denied` running a script | missing exec bit | `chmod +x scripts/*.sh` |
| stale PID / port in use | previous run not stopped | `make lab-down`; `scripts/run_witness.sh stop` |

---

## 7. Mapping to the workshop agenda

| Agenda section | Lab support |
|---|---|
| 1. Baseline PQC cost | `make measure`, `lab/certs.py`, `lab/pki.py` |
| 2. PQC X.509 without MTC | `make tls-demo` |
| 3. Algorithm landscape | measurement table; Falcon optional via oqs-provider (WS8, skipped) |
| 4. Run your own CT log | `make lab-up`, `make demo`, `lab/staticct.py` |
| 5. Merkle proofs | `lab/merkle.py`, `make walk`, `lab.cli proof`/`verify` |
| 6. Checkpoints & witnesses | `lab/note.py`, `tools/witness/`, `make witness-demo` |
| 7. MTC-shaped certificate | `lab/bundle.py`, `make bundle` |
| 8–9. Discussion | `docs/facilitator_notes.md` |

---

## 8. Commit map

Each workstream landed as its own commit (WS5+WS7 share a commit because their CLI wiring is
intertwined):

| Commit | Workstream |
|---|---|
| `chore(ws1): migrate repo from Trillian/Go to TesseraCT/Python scaffolding` | WS1 |
| `feat(ws2): Python static-ct client and RFC6962 Merkle proofs` | WS2 |
| `feat(ws3): multi-algorithm PKI, size measurement, and TLS demo` | WS3 |
| `feat(ws4): TesseraCT runner and end-to-end submit/verify demo` | WS4 |
| `feat(ws5+ws7): Merkle walkthrough and MTC-shaped bundle` | WS5, WS7 |
| `feat(ws6): native Tessera witness and cosignature verification` | WS6 |
| `docs(ws9+ws10): facilitator notes, exercises, CI` | WS9, WS10 |
