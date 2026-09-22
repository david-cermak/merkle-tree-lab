# Merkle Tree Lab

A hands-on workshop exploring **Certificate Transparency**, **Merkle trees**, and
**post-quantum certificates**, built on [TesseraCT](https://github.com/transparency-dev/tesseract)
and a small Python client.

The lab lets you:

1. Generate classical (ECDSA/RSA) and post-quantum (ML-DSA, SLH-DSA) certificate chains and
   measure how much larger PQC signatures and public keys really are.
2. Build a private PQC PKI and use it over TLS — without Merkle Tree Certificates.
3. Run your own CT log locally with TesseraCT's POSIX backend (no database, no containers).
4. Submit certificates, read the signed checkpoint, and verify Merkle inclusion proofs from
   scratch in Python.

The workshop agenda lives in [`docs/mtc_workshop.md`](docs/mtc_workshop.md). The implementation
is documented step by step for students in [`IMPL.md`](IMPL.md), and the engineering plan is in
[`PLAN.md`](PLAN.md).

## Architecture

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

TesseraCT implements [static-ct-api](https://c2sp.org/static-ct-api) and
[tlog-tiles](https://c2sp.org/tlog-tiles): submissions go over HTTP, while the signed checkpoint
and Merkle tiles are read from storage.

## Prerequisites

- **Go 1.27.x** — required because ML-DSA certificate chain validation was added to Go's
  `crypto/x509` in 1.27. Earlier Go versions reject ML-DSA chains.
- **Python ≥ 3.10** with the `cryptography` package.
- **OpenSSL 3.5+** with ML-DSA/SLH-DSA support in the default provider.
  (The author's local build lives in `$HOME/ossl-3.5`; adjust `PATH`/`LD_LIBRARY_PATH` as needed.)
- `git` (to fetch the TesseraCT submodule).

No Docker or MySQL is required: the POSIX backend is a single binary.

## Quickstart

```bash
# 0. Fetch the pinned TesseraCT submodule and install Python deps
make submodules
python3 -m pip install -r requirements.txt

# 1. Generate an ML-DSA certificate chain and measure sizes
make pki ALG=mldsa65
make measure

# 2. Use the private PQC PKI over TLS (one server, one client)
make tls-demo

# 3. Build and start the local CT log
make lab-up

# 4. Submit a certificate, verify the proof, walk it, size a bundle
make demo
make walk INDEX=0
make bundle INDEX=0

# 5. Demonstrate native witnessing (log + witness + cosignature)
make witness-demo

# 6. Stop the log
make lab-down
```

Run `make help` to see all targets, or `make workshop` for the whole happy path
(which is also the smoke test).

## Workshop materials

- Agenda: [`docs/mtc_workshop.md`](docs/mtc_workshop.md)
- Facilitator notes and timing: [`docs/facilitator_notes.md`](docs/facilitator_notes.md)
- Student exercises: [`docs/exercises/`](docs/exercises/)
- Implementation walkthrough: [`IMPL.md`](IMPL.md)
- Engineering plan: [`PLAN.md`](PLAN.md)

## Repository layout

```
lab/                     Python client and tooling
  merkle.py              RFC6962 hashing, tree building, inclusion proofs
  certs.py               PEM/DER parsing and size measurement
  note.py                Signed-checkpoint parsing, ECDSA + cosignature verification
  staticct.py            static-ct-api HTTP client + tlog-tiles reader
  pki.py                 OpenSSL-based multi-algorithm PKI generation
  measure.py             Certificate/signature size measurement
  bundle.py              MTC-shaped bundle assembly and size comparison
  cli/                   Command-line entry points
scripts/                 Shell helpers (TesseraCT/witness runners, demos, OpenSSL configs)
tools/witness/           Minimal local tlog-witness server (Go)
tests/                   Unit tests (standard-library unittest)
docs/                    Agenda, facilitator notes, and student exercises
impl/tesseract/          TesseraCT git submodule (pinned)
```

## Notes

- **Only ML-DSA certificates are logged.** SLH-DSA and Falcon cannot be validated by Go's
  `crypto/x509`; they are used for size comparison only.
- The log's checkpoint is signed with an **ECDSA** key. Witnessing is TesseraCT-native and
  experimental.
- `make lab-up` runs the TesseraCT binary directly; no containers.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
