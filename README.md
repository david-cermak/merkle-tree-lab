opencode -s ses_f1931c327ffe0GaFOPmCMOmOw9
# Merkle Tree Lab

A hands-on workshop exploring **Certificate Transparency**, **Merkle trees**, and
**post-quantum certificates**, built on [TesseraCT](https://github.com/transparency-dev/tesseract)
and a small Python client.

The lab has two halves. The first is a real CT log: you submit certificates to a
local TesseraCT, read its signed checkpoint, and verify Merkle inclusion proofs
from scratch. The second is a **Merkle Tree Certificate simulator**, which needs
no server at all and is where the workshop spends its second hour: one issuance
log produces all four certificate shapes, they are measured against each other,
and a relying party is shown exactly what it can check with what it already
knows.

The lab lets you:

1. Generate classical (ECDSA/RSA) and post-quantum (ML-DSA, SLH-DSA) certificate chains and
   measure how much larger PQC signatures and public keys really are.
2. Build a private PQC PKI and use it over TLS — without Merkle Tree Certificates.
3. Run your own CT log locally with TesseraCT's POSIX backend (no database, no containers).
4. Submit certificates, read the signed checkpoint, and verify Merkle inclusion proofs from
   scratch in Python.
5. Build an MTC issuance log and cut all four certificate shapes from one entry — directly
   signed, standalone, checkpoint-relative, and landmark-relative — with real ML-DSA
   cosignatures, then run the verification walk at four levels of client knowledge.

The workshop agenda lives in [`docs/mtc_workshop.md`](docs/mtc_workshop.md). The implementation
is documented step by step for students in [`IMPL.md`](IMPL.md), and the engineering plan is in
[`PLAN-update.md`](PLAN-update.md).

## Architecture

Two independent halves that share the Merkle-tree vocabulary.

**The CT log half** talks to a real TesseraCT:

```
        Python client (lab/)
   add-chain │  HTTP JSON          ┌───────────────────────────────┐
             └────────────────────►│  TesseraCT POSIX (Go 1.27)    │
                                   │  storage: ./log               │
   checkpoint + entry records      │  roots:   ./out/pki/.../root  │
              ◄────────────────────┤  key:     ./out/log-key.pem   │
                                   └───────────────┬───────────────┘
                                                   │
                                                   ▼
                    log/checkpoint  +  log/tile/data/*  +  log/tile/*
```

TesseraCT implements [static-ct-api](https://c2sp.org/static-ct-api) and
[tlog-tiles](https://c2sp.org/tlog-tiles): submissions go over HTTP, while the signed checkpoint
and Merkle tiles are read from storage.

**The MTC half** has no server and no network. It is `lab/mtc/` in full:

```
   make mtc-lab ──► scenario.json ──┬──► mtc shapes ──► four certificates + size table
     log, checkpoints, landmark     │
     real ML-DSA keys, persisted    └──► mtc verify ──► the §7.2 walk at four levels
```

Everything the MTC half needs is in that one file, which is why `mtc shapes`
can produce certificates that `mtc verify` then checks: ML-DSA signatures depend
on a random nonce, so the keys have to be the *same* keys, not freshly generated
ones.

## Prerequisites

- **Go 1.27.x** — required because ML-DSA certificate chain validation was added to Go's
  `crypto/x509` in 1.27. Earlier Go versions reject ML-DSA chains.
- **Python ≥ 3.10** with `cryptography ≥ 46`, which is where ML-DSA landed. The
  MTC lab generates real ML-DSA keys, so an older `cryptography` will not work;
  use a virtualenv (`.venv` is picked up by the `Makefile` automatically).
- **OpenSSL 3.5+** with ML-DSA/SLH-DSA support in the default provider.
  (The author's local build lives in `$HOME/ossl-3.5`; adjust `PATH`/`LD_LIBRARY_PATH` as needed.)
- `git` (to fetch the TesseraCT submodule).

No Docker or MySQL is required: the POSIX backend is a single binary.

**The MTC half needs none of the above.** `make mtc-lab` and everything after it
run offline on Python alone — no Go, no OpenSSL, no log server.

## Quickstart

```bash
# 0. Fetch the pinned TesseraCT submodule and install Python deps.
#    Use a venv: the MTC lab needs cryptography >= 46 for ML-DSA.
make submodules
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 1. Generate an ML-DSA certificate chain and measure sizes
make pki ALG=mldsa65
make measure

# 2. Use the private PQC PKI over TLS (one server, one client)
make tls-demo

# 3. Build and start the local CT log
make lab-up

# 4. Submit a certificate, verify the proof, and walk it hash by hash
make demo
make walk INDEX=0

# add VERBOSE=1 to trace the HTTP POST and the storage reads
make demo VERBOSE=1
make walk INDEX=0 VERBOSE=1

# 5. Give the log a real tree: N distinct certificates
#    `make demo` re-submits the same leaf, and the log deduplicates it, so the
#    tree stays at size 1 and every proof has no siblings. `fill` issues new
#    leaves from the same intermediate, which is what makes the walk interesting.
make fill N=8
make walk INDEX=2
make walk INDEX=7

# 6. Stop the log
make lab-down
```

The Merkle Tree Certificate half needs no server. Run these in order; the first
command builds the log and the other two read it back:

```bash
# build the CA: issuance log, two checkpoints, one landmark
make mtc-lab

# cut all four certificate shapes from entry 3 and size them
make mtc-shapes

# ask what a relying party can check, with and without a landmark
python3 -m lab.cli mtc verify --knows cosigners
python3 -m lab.cli mtc verify --knows landmark
python3 -m lab.cli mtc verify --knows all --tamper
```

The measured table, which is the point of the whole workshop:

| shape | subtree | signatures | signature bytes | proof hashes | landmark-dependent | total bytes |
|---|---|---|---|---|---|---|
| directly signed | - | 1 | 3309 | 0 | no | 5439 |
| standalone (tree-relative) | [0, 20) | 2 | 4840 | 5 | no | 7165 |
| checkpoint-relative | [0, 8) | 2 | 4840 | 3 | no | 7101 |
| landmark-relative | [0, 16) | 0 | 0 | 4 | yes | 2269 |

Note that the cosigned MTC shapes are **larger** than the traditionally signed
one. MTC is not a way to shrink certificates; it is a way to make log membership
checkable without downloading the log. The storage win is in the log entry,
which is 131 bytes instead of the ~5 600 bytes (DER) a CT log would store.

Run `make help` to see all targets, or `make workshop` for the whole happy path
(which is also the smoke test).

## Workshop materials

- Agenda: [`docs/mtc_workshop.md`](docs/mtc_workshop.md)
- Facilitator notes and timing: [`docs/facilitator_notes.md`](docs/facilitator_notes.md)
- Student exercises: [`docs/exercises/`](docs/exercises/)
- Implementation walkthrough: [`IMPL.md`](IMPL.md)
- Engineering plan: [`PLAN-update.md`](PLAN-update.md)

## Repository layout

```
lab/                     Python client and tooling
  merkle.py              RFC6962 hashing, tree building, inclusion proofs
  certs.py               PEM/DER parsing and size measurement
  note.py                Signed-checkpoint parsing and ECDSA verification
  staticct.py            static-ct-api HTTP client + tlog-tiles reader
  pki.py                 OpenSSL-based multi-algorithm PKI generation
  measure.py             Certificate/signature size measurement
  cli/                   Command-line entry points
    mtc.py               The three MTC workshop commands
  mtc/                   Merkle Tree Certificate simulator
    tree.py              Section 4 primitives, validated against Appendix C
    wire.py              TLS presentation-language subset
    ids.py               CA / log / landmark / cosigner identifiers
    log.py               Issuance log, entries, extensions, checkpoints
    cosigners.py         ML-DSA subtree cosignatures and checkpoint signing
    landmarks.py         Landmark sequence, publication, client state
    certs.py             The four certificate shapes
    client.py            Relying-party state and the Section 7.2 walk
    scenario.py          The one fixed scenario the exercises share
scripts/                 Shell helpers (TesseraCT runner, workshop demo, OpenSSL configs)
tests/                   Unit tests (standard-library unittest)
docs/                    Agenda, facilitator notes, and student exercises
impl/tesseract/          TesseraCT git submodule (pinned)
```

## Notes

- **Only ML-DSA certificates are logged.** SLH-DSA and Falcon cannot be validated by Go's
  `crypto/x509`; they are used for size comparison only.
- The log's checkpoint is signed with an **ECDSA** key.
- `make lab-up` runs the TesseraCT binary directly; no containers.
- **The MTC lab is a teaching simulator, not an implementation.** It is faithful to the
  draft's field order, hash domains, serial layout, and subtree arithmetic — the tree code
  passes the draft's Appendix C vectors, and the cosignature messages really are signed
  with the draft's TLS presentation language. The log entries and certificates are a
  documented TLV encoding and dataclasses rather than DER and X.509. Nothing it produces
  interoperates with a real MTC deployment. See `docs/exercises/05_mtc_four_shapes.md`.
- The **witness architecture** from the draft is out of scope, and so is wire-format
  negotiation. Both are discussed rather than built; see `PLAN-update.md` §8.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
