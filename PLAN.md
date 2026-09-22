# PLAN — Merkle Tree Certificates Workshop (TesseraCT edition)

Status: **finalized** (decisions locked — see §11)
Owner: David
Content source of truth: `docs/mtc_workshop.md` (the agenda). `README.md` and `abstract.md`
still describe the old Go/Trillian experiment and must be rewritten.

**Major change from the previous revision: the CT log backend moves from Trillian to
[TesseraCT](https://github.com/transparency-dev/tesseract) (`impl/tesseract`).** Trillian is
dropped. This document plans the workshop around TesseraCT, a Python client, and a PQC-first
PKI lab.

Locked decisions (details in §11):

- CT log: **TesseraCT POSIX**, container-free, TesseraCT pinned as a git submodule.
- PQC algorithm in the log: **ML-DSA only** (requires Go ≥ 1.27). SLH-DSA is measurement-only.
- Client/tooling: **Python**, static-ct-api HTTP + tlog-tiles.
- Checkpoints/witnesses: **native TesseraCT** signed checkpoint + native Tessera witness.
- Private-PQC-PKI lab: **TLS demo only** (one server, one client).
- MTC section: **single-certificate bundle and size only**; no scale test in v1.
- Falcon: **optional last step**, via **oqs-provider** (not wolfSSL).

---

## 1. Scope and goals

Build a hands-on lab that lets attendees, on their own laptop:

1. Generate a classical PKI (ECDSA/RSA) and a PQC PKI (ML-DSA, plus SLH-DSA for size contrast) and
   measure the real size cost of PQC signatures.
2. Build a private PQC X.509 PKI and use it over **TLS** (one server, one client) **without** MTC.
3. Run a local CT log with TesseraCT, submit ML-DSA certificates, fetch the signed checkpoint.
4. Verify Merkle inclusion proofs from scratch in Python.
5. See native signed checkpoints and native Tessera witnesses/cosignatures.
6. Assemble and size an "MTC-shaped" bundle vs. a conventional PQC certificate.

Non-goals (this iteration):

- Re-introducing Trillian or Trillian-based CTFE.
- Implementing the full MTC Internet-Draft / wire format.
- Public Web PKI / browser integration.
- Cloud (GCP/AWS) deployments; the workshop uses the POSIX backend.
- Logging SLH-DSA or Falcon certificates (measurement-only).
- Scale/throughput testing (single-certificate size analysis only; scaling may come later).

---

## 2. Verified findings (all checked on this machine)

### 2.1 TesseraCT builds and runs locally with no database

- TesseraCT has a **POSIX backend**: a single Go binary, storage on a local POSIX filesystem,
  no MySQL/Spanner, no leader election, no extra services. Ideal for a laptop workshop.
- Built `cmd/tesseract/posix` successfully (33 MB binary). Ran it with:
  `--http_endpoint`, `--storage_dir`, `--origin`, `--private_key`, `--roots_pem_file`.
- Startup creates: `checkpoint`, `tile/data/...`, `tile/<level>/...`, `issuer/`, `roots/`,
  `.state/` (BadgerDB antispam). GOMEMLIMIT is recommended (BadgerDB compaction spikes).
- Submission API works over HTTP: `POST /ct/v1/add-chain` with
  `{"chain": ["<base64 DER>", ...]}` returns an SCT. `GET /ct/v1/get-roots` also exists.
- **Monitoring is not an HTTP API**: the signed `checkpoint` and tiles are read directly from
  the storage directory (or served statically as the monitoring URL). This is the
  [static-ct-api](https://c2sp.org/static-ct-api) + [tlog-tiles](https://c2sp.org/tlog-tiles) model.

### 2.2 Client is HTTP + tlog-tiles, not gRPC → Python is a clean fit (validated)

- The old Trillian gRPC/protobuf/Python-stub plan is obsolete. The client is plain HTTP + JSON
  plus file/tile reads. No protobuf, no gRPC.
- **Validated end-to-end in pure Python**: parsed the entry bundle
  `tile/data/000.p/1`, reconstructed the RFC6962 `MerkleTreeLeaf`, computed
  `SHA256(0x00 || MerkleTreeLeaf)`, and it **exactly matched the signed checkpoint root**.
  Leaf layout (per `tessera/ctonly/ct.go`):
  `version(1)=0 || leaf_type(1)=0 || timestamp(8) || entry_type(2) || uint24(cert) || uint16(ext) || ext`,
  where `ext` carries the 5-byte leaf index; the entry bundle also stores fingerprints that are
  **not** committed by the leaf hash.
- Checkpoint is a signed [note](https://pkg.go.dev/golang.org/x/mod/sumdb/note) in the format:
  ```
  <origin>
  <tree_size>
  <base64 root hash>
  <blank line>
  — <origin> <base64 signature>
  ```
- Because workshop logs are small, the Python client can rebuild the whole Merkle tree in
  memory to produce inclusion proofs, then verify against the checkpoint root. This is simpler
  and more teachable than tile-walking; tiles remain available for the "real" static-ct flow.

### 2.3 Signed checkpoints are native; witnesses exist but are experimental

- TesseraCT publishes a **signed checkpoint** every interval — this closes the previous plan's
  biggest gap (Trillian had removed root signatures entirely).
- The primary checkpoint signer is **ECDSA only** (`x509.ParseECPrivateKey` on `--private_key`).
- Witnessing is supported but **experimental and fail-open** (checkpoints publish even without
  enough cosignatures). Policy uses the Sigsum trust-policy format; `--additional_signer` adds
  note signers.
- `github.com/transparency-dev/formats/note` already implements **ML-DSA-44 cosignature v1**
  (`algMLDSA44`, `NewMLDSASigner`/`NewMLDSAVerifier`). So a **PQC cosigner/witness demo is
  feasible**, while the log's own checkpoint signature stays ECDSA.

### 2.4 PQC certificate support in the CT log — the critical matrix

TesseraCT validates submitted chains with `internal/lax509` (a `crypto/x509` fork) and Go's
stdlib signature verification. Results:

| Algorithm | OpenSSL 3.5 cert gen | TesseraCT accepts into log | Notes |
|---|---|---|---|
| ECDSA P-256 | yes | **yes** | control; verified add-chain 200 + checkpoint |
| RSA | yes | yes (expected) | control |
| ML-DSA-44/65/87 | yes | **yes, only with Go ≥ 1.27** | Go 1.25/1.26: `x509: cannot verify signature: algorithm unimplemented`; Go 1.27 parses `ML-DSA-65` and `CheckSignatureFrom` OK |
| SLH-DSA | yes | **no** | Go 1.27 stdlib still reports `algorithm unimplemented`; chain rejected `signed by unknown authority` |
| Falcon/FN-DSA | no (needs provider) | no (Go stdlib) | optional showcase only |

Concretely reproduced:

- TesseraCT built with Go 1.25.0 → ML-DSA `add-chain` returned **HTTP 400**
  (`certificate signed by unknown authority`).
- TesseraCT rebuilt with **Go 1.27.0** → ML-DSA `add-chain` returned **HTTP 200**, checkpoint
  tree size advanced to 1.
- SLH-DSA rejected under both Go 1.25 and Go 1.27.

Implications and options are detailed in §6.

### 2.5 Podman works; POSIX needs no container at all

- `podman 4.9.3`, rootless, can pull/build OCI images (verified pulling `golang:1.27-alpine`).
- `podman build` / `podman run` are drop-in for the TesseraCT Dockerfiles
  (`cmd/tesseract/posix/ci/Dockerfile`). **The Dockerfile pins `golang:1.25.8`; it must be
  bumped to `golang:1.27` for ML-DSA support.**
- `podman compose` currently **fails**: no compose provider installed
  (`docker-compose`/`podman-compose` missing). Not a problem for POSIX (no compose needed).
  If we want the S3+MySQL variant, we must install `podman-compose` or convert
  `cmd/tesseract/posix/ci/docker-compose.yml` to a podman kube/quadlet.
- Recommended workshop default: **run the TesseraCT binary directly** (no container); offer the
  podman image as an optional packaging step.

### 2.6 Falcon via OpenSSL provider (not wolfSSL)

- OpenSSL 3.5.0 has no Falcon. The user wants the **OpenSSL provider** route.
- Route: build `liboqs` + **`oqs-provider`** for OpenSSL 3.x, then use the standard `openssl`
  CLI (`-provider oqsprovider`) for Falcon-512/1024 keys, certs, and signatures — consistent
  with the ML-DSA/SLH-DSA workflow.
- `liboqs-python` 0.16.0 is installable from PyPI (programmatic fallback).
- Caveats: `oqs-provider` version must match the OpenSSL 3.5 provider ABI; and, like SLH-DSA,
  Go/TesseraCT cannot validate Falcon chains, so Falcon stays out of the CT log for now.

### 2.7 Environment / prerequisites

- Go: system is 1.22.2 but `GOTOOLCHAIN=auto` fetches newer toolchains; Go 1.27.0 downloaded and
  used successfully. Pin **Go 1.27.x** for the TesseraCT build.
- Python 3.12, `cryptography` 41.0.7 available; PyPI reachable.
- `impl/tesseract` is now a **git submodule pinned to commit `3f03bb6` (TesseraCT
  `v0.1.3-rc2-15-g30fd1469`)**. Reproducibility is solved; `git submodule update --init` is part
  of setup.
- `impl/trillian` should be removed once migration is done.

---

## 3. Target architecture

```
Browser/CLI (Python)
   │  add-chain (HTTP JSON)      ┌─────────────────────────────┐
   └────────────────────────────►│  TesseraCT POSIX (Go 1.27)   │
                                 │  --storage_dir ./log         │
   read checkpoint + tiles       │  --roots_pem_file ...        │
   ◄─────────────────────────────┤  --private_key (ECDSA)       │
                                 └──────────────┬──────────────┘
                                                │ storage_dir
                                                ▼
                          checkpoint (signed note) + tile/data/* + tile/* + issuer/*
```

Python responsibilities: submit chains, read the signed checkpoint, read/parse entry bundles,
rebuild the Merkle tree, produce/verify inclusion (and consistency) proofs, and assemble an
MTC-shaped bundle. PQC signing of the bundle/checkpoint is done with OpenSSL (ML-DSA), and
optionally cosigned via ML-DSA note cosignature v1.

---

## 4. Proposed repository layout

```
merkle-tree-lab/
├── PLAN.md
├── README.md                     # rewritten: prereqs, quickstart, agenda map
├── Makefile                      # setup, build-tesseract, lab-up, lab-down, workshop, test, measure
├── requirements.txt / pyproject.toml
├── docs/
│   ├── mtc_workshop.md           # agenda (mostly accurate; §4 already says TesseraCT)
│   ├── facilitator_notes.md      # timing, talking points, expected outputs
│   └── exercises/
├── lab/                          # Python package (client + tooling)
│   ├── staticct.py               # add-chain, read checkpoint, entry bundles, tiles
│   ├── merkle.py                 # RFC6962 leaf/node hashing, tree build, inclusion/consistency proofs
│   ├── note.py                   # parse + verify signed checkpoints (ECDSA; ML-DSA optional)
│   ├── certs.py                  # PEM/DER parse, size measurement
│   ├── pki.py                    # OpenSSL chain generation per algorithm
│   ├── bundle.py                 # MTC-shaped bundle + size comparison
│   └── cli/                      # submit, checkpoint, proof, verify, measure, pki, bundle
├── scripts/
│   ├── gen_pki.sh                # root → intermediate → leaf per algorithm
│   ├── run_tesseract.sh          # build (Go 1.27) + run POSIX log
│   ├── submit_chain.py           # thin wrapper for demos
│   └── openssl/                  # ca_ext.cnf, leaf_ext.cnf (fixes invalid-CA trap)
├── tools/falcon/                 # optional (last step): liboqs + oqs-provider build + helper
├── tests/
└── impl/tesseract/               # TesseraCT git submodule @ 3f03bb6
```

Remove: `impl/trillian/`, `cmd/` (Go client tools), root `go.mod`/`go.sum`, committed binaries
(`create_tree`, `submit_cert`, `get_sth`, `get_proof`, `verify_proof`), `demo.sh`.
Keep `impl/tesseract` only (to build the server).

---

## 5. Workstreams

### WS1 — Repo hygiene & reproducibility

- [x] Add `impl/tesseract` as a pinned git submodule at commit `3f03bb6`.
- [ ] Delete `impl/trillian/` and all Go client tooling (`cmd/`, root `go.mod`/`go.sum`, binaries).
- [ ] Pin **Go 1.27.x** in docs/tooling; `GOTOOLCHAIN` handling in `Makefile`.
- [ ] `.gitignore`: `log/`, `certs/`, `out/`, `*.der`, venv, generated artifacts.
- [ ] `Makefile` targets: `build-tesseract`, `lab-up`, `lab-down`, `pki`, `workshop`, `test`, `measure`.

### WS2 — Python static-ct client (core, validated)

- [ ] `staticct.py`: `add_chain(chain_der)` (HTTP POST), `get_roots()`, read `checkpoint`,
      enumerate/parse `tile/data/*` entry bundles, read hash tiles.
- [ ] `merkle.py`: RFC6962 `H(0x00||leaf)` / `H(0x01||l||r)`; build tree from leaf hashes;
      generate + verify inclusion proofs; consistency proofs.
- [ ] `note.py`: parse checkpoint note; verify ECDSA signature (via `cryptography`);
      optional ML-DSA cosignature verification (liboqs-python or oqs-provider).
- [ ] `cli/`: `submit`, `checkpoint`, `proof`, `verify` with JSON outputs for the slides.
- [ ] Unit tests: golden leaf-hash vector from the verified bundle above; proof round-trips.

### WS3 — Multi-algorithm PKI + size measurement (sections 1–3)

- [ ] `scripts/openssl/` CA + leaf extension configs (fixes the `invalid CA certificate` trap).
- [ ] `gen_pki.sh` / `pki.py`: root → intermediate → leaf for ECDSA P-256, RSA-2048,
      ML-DSA-44/65/87, and SLH-DSA variants (**measurement only**, never logged).
      Falcon added later if WS8 lands.
- [ ] `measure.py`: public-key size, signature size, cert DER/PEM size, chain size; markdown + JSON.
- [ ] "Look inside the certificate" exercise (SPKI, sig alg, signature).
- [ ] Private-PQC-PKI lab: **TLS demo only** — start one `openssl s_server` with an ML-DSA leaf and
      connect with one `openssl s_client`. No firmware/artifact-signing demo in v1.

### WS4 — CT log lab with TesseraCT (section 4)

- [ ] `run_tesseract.sh`: build with Go 1.27 and start POSIX log with ECDSA log key + configured
      roots; expose storage dir. Container-free (binary run directly).
- [ ] Generate chains and submit them; inspect stored entries (`tile/data`) and the signed
      `checkpoint`.
- [ ] PQC angle: submit **ML-DSA** chains and measure entry/storage size vs. classical. SLH-DSA is
      not submitted.
- [ ] Optional: serve `storage_dir` over HTTP as the monitoring URL; document static-ct-api paths.

### WS5 — Merkle proofs (section 5)

- [ ] Inclusion proof generation + verification in pure Python (validated hashing already).
- [ ] Facilitator walkthrough hashing leaf → siblings → root.
- [ ] Exercise: SCT (promise) vs. inclusion proof (evidence).

### WS6 — Checkpoints, witnesses, cosignatures (section 6)

- [ ] Use the native signed checkpoint as the authenticated tree head.
- [ ] Verify the checkpoint signature in Python (ECDSA note).
- [ ] Use **native Tessera witnessing**: configure a witness policy and `--additional_signer`,
      show cosignatures appearing on the checkpoint. Keep it simple; no custom cosigner.
      Practical note: native witnessing needs a witness endpoint — prefer a local witness
      (transparency-dev witness) for an offline lab; the public dev witness requires registering
      the log key. If neither is practical, show the cosignature flow with the witness policy and
      document the limitation.
- [ ] Demonstrate split-view/freshness concepts; note TesseraCT witnessing is experimental.

### WS7 — MTC-shaped bundle + size comparison (section 7)

- [ ] `bundle.py`: leaf/cert + inclusion proof + signed checkpoint + cosignatures.
- [ ] **Single-certificate** size comparison vs. a conventional PQC certificate; explain the
      amortization idea conceptually without running a scale test.
- [ ] Replace `demo.sh` with `make workshop`.

### WS8 — Optional Falcon / FN-DSA showcase (section 3 stretch — last step)

- [ ] Build `liboqs` + **`oqs-provider`** for OpenSSL 3.5; document exact versions/build steps.
- [ ] Falcon-512/1024 key + cert + signature size measurements via the same `openssl` CLI.
- [ ] Note the CT-log caveat (Go cannot validate Falcon chains); keep it measurement-only.
- [ ] Time-box; fall back to a recorded demo if the provider build is fragile.

### WS9 — Workshop materials & end-to-end flow

- [ ] Rewrite `README.md` (TesseraCT + Python + PQC) and `abstract.md`; remove Trillian references.
- [ ] `docs/facilitator_notes.md` (timing 90–120 min, expected outputs, common failures).
- [ ] Per-section worksheets in `docs/exercises/`.
- [ ] `make workshop` happy path; each section runnable independently.

### WS10 — Verification & CI

- [ ] `pytest` suite (unit + integration with a throwaway POSIX log).
- [ ] `ruff` + format check.
- [ ] Smoke script: build TesseraCT, start log, gen PKI, submit, checkpoint, proof, verify, bundle.
- [ ] Pin Go, Python, and OpenSSL versions.

---

## 6. PQC CT-log support plan (decided)

**Decision: log ML-DSA certificates only.** TesseraCT can log ML-DSA if built with Go ≥ 1.27;
this is verified working (`add-chain` → 200, checkpoint advances).

- **ML-DSA (in scope):** build TesseraCT with Go 1.27.x. This covers the main PQC demonstration
  (4–5.5 KB certs). Update the Dockerfile/docs accordingly (Dockerfile bump is only relevant if
  the optional podman path is ever used).
- **SLH-DSA (out of scope for the log):** never submitted to TesseraCT. It remains a
  measurement-only algorithm in section 1.3 to show that "PQC signature size" is not one number.
- **Falcon (out of scope for the log):** measurement-only via oqs-provider (WS8, optional last
  step). Go/TesseraCT cannot validate Falcon chains.

No `lax509` patch, no validation bypass, no Go-version gymnastics beyond pinning 1.27.x.

---

## 7. Container strategy: container-free (decided)

- **No containers in the workshop.** `make lab-up` builds (Go 1.27) and runs the TesseraCT POSIX
  binary directly, with a local `storage_dir`. This is the simplest, most reliable path and
  avoids the `podman compose` provider gap entirely.
- Podman is available (4.9.3, rootless) and can build/run the TesseraCT Dockerfiles if needed
  later, but this is **not** part of the v1 workshop. Keep the Dockerfile-bump note only as a
  future option.

---

## 8. Phasing

| Phase | Content | Exit criterion |
|-------|---------|----------------|
| P0 | WS1 + WS2 | Python client submits to TesseraCT, reads checkpoint, verifies a proof |
| P1 | WS3 + WS4 | Classical + ML-DSA PKI sizes measured; ML-DSA chain logged (Go 1.27) |
| P2 | WS5 + WS7 | Inclusion proofs verified; single-cert MTC bundle built + size comparison |
| P3 | WS6 | Checkpoint signature verified; native Tessera witness cosignature shown |
| P4 | WS9 + WS10 | End-to-end `make workshop` + tests + docs ready to teach |
| P5 | WS8 (optional, last) | Falcon sizes measured via oqs-provider, or demo recorded |

Rough effort (solo): P0–P2 ≈ 4–6 days, P3 ≈ 1 day, P4 ≈ 2 days, P5 ≈ 1–3 days (build-dependent).

---

## 9. Risks and blockers

| Risk / blocker | Severity | Mitigation |
|---|---|---|
| ML-DSA requires Go ≥ 1.27 (TesseraCT pins 1.25.8) | Medium | Pin Go 1.27.x; document. Verified working. |
| Go 1.27 is newer than TesseraCT's tested toolchain | Medium | Pin exact version; watch for build/test regressions; run TesseraCT's own tests. |
| SLH-DSA/Falcon cannot be logged | Low (by design) | Measurement-only; documented explicitly in workshop material. |
| oqs-provider build/ABI fragility (Falcon) | Medium | Optional last step; time-box; liboqs-python fallback; record demo if needed. |
| Checkpoint signature verification format (note) | Low | Implement/verify with `cryptography`; reference formats/note + x/mod/sumdb/note. |
| BadgerDB memory spikes (GOMEMLIMIT) | Low | Set `GOMEMLIMIT` in `run_tesseract.sh`; document. |
| Agenda drift (README/abstract say Trillian) | Low | Rewrite both; §4 of the agenda is already TesseraCT-correct. |

---

## 10. Acceptance criteria

- Fresh clone + documented prerequisites (`git submodule update --init`) → `make workshop` runs
  end-to-end with TesseraCT POSIX and the Python client, no Trillian, no committed binaries, no
  containers.
- ML-DSA certificates are accepted by the log (Go 1.27 build); size measurements are scripted.
- A Python verifier checks a Merkle inclusion proof against the signed checkpoint without Go.
- An MTC-shaped bundle is produced with a signed checkpoint + at least one native witness
  cosignature, and its single-certificate size is compared against a conventional PQC cert.
- `docs/mtc_workshop.md` matches the implementation; SLH-DSA and Falcon are documented as
  measurement-only (not logged).
- Facilitator can run the 90–120 min agenda from the notes.

---

## 11. Resolved decisions

1. **SLH-DSA in the log:** skipped. Only **ML-DSA** is logged. SLH-DSA stays in the
   size-measurement sections (1.3) as a contrast.
2. **Falcon:** optional **last step**, via **oqs-provider** (not wolfSSL); measurement-only.
3. **Containerization:** **container-free**. Run the TesseraCT binary directly; no podman/compose.
4. **TesseraCT delivery:** git **submodule** at commit `3f03bb6` (TesseraCT `30fd1469`).
5. **Section 2 lab:** **TLS demo only** — one `openssl s_server`, one `openssl s_client`.
6. **Witness demo:** **native Tessera witness** (policy file + `--additional_signer`); no custom
   cosigner.
7. **Scale test:** **none in v1.** Just build/examine the MTC bundle and compare its size to a
   conventional PQC certificate. Scaling may be added later.

---

## Appendix A — Verified commands and results

Build and run TesseraCT POSIX (Go 1.27 for ML-DSA):

```bash
cd impl/tesseract
GOTOOLCHAIN=go1.27.0 go build -o /tmp/tesseract-posix ./cmd/tesseract/posix/
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/logkey.pem
GOMEMLIMIT=2GiB /tmp/tesseract-posix \
  --http_endpoint=127.0.0.1:6962 \
  --storage_dir=/tmp/tctlog \
  --origin=example.com/test \
  --private_key=/tmp/logkey.pem \
  --roots_pem_file=/tmp/pqctest/root.crt \
  --checkpoint_interval=1s --enable_publication_awaiter=false
```

Submit a chain (EC or ML-DSA):

```bash
# chain = [leaf DER, intermediate DER, ...] base64-encoded
curl -s http://127.0.0.1:6962/ct/v1/add-chain \
  -H 'Content-Type: application/json' \
  -d "{\"chain\":[\"$LEAF_B64\",\"$INT_B64\"]}"
```

Signed checkpoint (native, note format):

```
example.com/test-mldsa2
1
9an5RiL+9LYI7TAtJ8NWX95hQBLCbQRTYE+lMCohaFU=

— example.com/test-mldsa2 vQhyHgAAAaCaygyhBAMARzBFAiBF4gVP2HIM1LkqhPn1lzUwm0obkb/fSH1KXcOhpJ2PLQIhAM7GuD2qXMq5MRhCmZ+pXiIVaXxypm9aOZYo37H85rrf
```

Pure-Python leaf-hash reproduction (matched the checkpoint root exactly):

```python
# MerkleTreeLeaf = version(0) || leaf_type(0) || timestamp(8) || entry_type(2)
#                  || uint24(cert) || uint16(ext) || ext
mtl = b'\x00\x00' + ts + etype + len(cert).to_bytes(3,'big') + cert \
      + len(ext).to_bytes(2,'big') + ext
leaf_hash = hashlib.sha256(b'\x00' + mtl).digest()
assert leaf_hash == base64.b64decode(checkpoint_root_b64)
```

PQC chain generation (OpenSSL 3.5; extensions required for valid CA):

```bash
export PATH="$HOME/ossl-3.5/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/ossl-3.5/lib64:$HOME/ossl-3.5/lib:$LD_LIBRARY_PATH"
openssl req -x509 -newkey ML-DSA-65 -keyout root.key -out root.crt \
  -days 3650 -nodes -subj "/CN=Workshop Root"
# intermediate/leaf signed with -extfile ca_ext.cnf / leaf_ext.cnf
openssl verify -CAfile root.crt -untrusted int.crt leaf.crt   # leaf.crt: OK
```

PQC support matrix evidence:

```
Go 1.25.0  ML-DSA CheckSignatureFrom -> x509: cannot verify signature: algorithm unimplemented
Go 1.26.5  ML-DSA CheckSignatureFrom -> x509: cannot verify signature: algorithm unimplemented
Go 1.27.0  ML-DSA CheckSignatureFrom -> OK (parsed sigalg=ML-DSA-65)
Go 1.27.0  SLH-DSA CheckSignatureFrom -> x509: cannot verify signature: algorithm unimplemented

TesseraCT(Go 1.25) + ML-DSA add-chain -> HTTP 400 (signed by unknown authority)
TesseraCT(Go 1.27) + ML-DSA add-chain -> HTTP 200, checkpoint tree size 1
TesseraCT(Go 1.27) + SLH-DSA add-chain -> HTTP 400 (signed by unknown authority)
```

Environment note (not used by the workshop — container-free by decision):

```bash
podman version          # 4.9.3, rootless
podman pull docker.io/library/golang:1.27-alpine   # works if ever needed
podman compose version  # fails: no compose provider installed
```
