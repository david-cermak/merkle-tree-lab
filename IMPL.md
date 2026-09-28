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
| **WS5** | Merkle proof walkthrough | `lab/merkle.py` `explain_inclusion`, `lab.cli walk`, `docs/exercises/04_*` |
| **WS6** | **Merkle Tree Certificates** | `lab/mtc/` (tree, wire, ids, log, cosigners, landmarks, certs, client, scenario), `lab/cli/mtc.py` |
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

A log's **origin is its submission prefix**, per the static-ct-api: the origin line must be
`$HOST/$PATH_PREFIX`, the schema-less URL that submissions arrive on. The client therefore
takes the origin and splits it two ways — the host goes into the `Host` header and the path
goes in front of `/ct/v1/...` — while still connecting to `127.0.0.1`. The server has to agree
on the path half via its `--path_prefix` flag; `scripts/run_tesseract.sh` derives that flag
from its own `ORIGIN` so the two ends cannot drift. This matters because TesseraCT reconstructs
the endpoint as `$HOST$PATH` and warns on every submission that does not start with its origin.
Ignoring the origin is why the lab used to log a warning per request.

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

### 2.6 Verbose tracing — seeing the HTTP and the storage

Every command accepts `-v`/`--verbose` (the Makefile passes it with `VERBOSE=1`). In verbose
mode the client writes a trace to **stderr** (so stdout stays parseable) showing exactly what
happens on the wire and on disk:

* the `POST` URL, the `Content-Type`, and the JSON body with long base64 blobs abbreviated;
* the HTTP status and the full SCT response JSON;
* each entry bundle read (`log/tile/data/...`, its size, and how many entries it contained);
* each checkpoint read, and for `walk` the parsed entry fields and the raw checkpoint.

This is the clearest way to see that submission is *JSON over HTTP* and that monitoring is
*reading files*. For example, `make demo VERBOSE=1` prints the two-element `chain` array (leaf
and issuer, base64), then the SCT with its `id`, `timestamp`, `extensions`, and `signature`.

Consecutive identical trace lines are collapsed, so the polling loop that waits for an entry to
be sequenced does not flood the terminal.

### 2.7 Tests

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

`scripts/workshop.sh` chains the smoke test in nine steps: measure, `lab-up`, `demo`, `walk`,
`checkpoint` verification, `lab-down` (via a trap), then the three MTC commands. The first six
prove the CT half works end to end; the last three prove the MTC half does.

Because the MTC half needs no log server, it can be run on its own from a clean
checkout — no Go, no OpenSSL, no network:

```bash
make mtc-lab && make mtc-shapes
```

That is the section to protect if a workshop room has one broken machine.

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

## WS6 — Merkle Tree Certificates: the simulator

This is the centrepiece, and it has no relationship to the CT log above. It
re-implements draft `draft-ietf-plants-merkle-tree-certs-06` in
`lab/mtc/`, offline, with real ML-DSA signatures.

The module reads in the order the workshop uses it.

### 6.1 `tree.py` — Section 4, and the reason to trust the rest

Subtree hashes, inclusion proofs, consistency proofs, and `is_valid_subtree`.
This is the only file in the lab that is validated against something external:
`tests/test_mtc_tree.py` runs the accumulated vectors in the draft's
Appendix C, plus Figure 7/8 cases and every valid subtree interval up to a
tree of 130 entries.

Two rules are worth reading the code for:

* `is_valid_subtree(start, end)` is `start % BIT_CEIL(end - start) == 0`
  (§4.1). The condition looks arbitrary until you know it exists so that
  consistency proofs can separate a subtree from its surroundings.
* `find_subtrees(start, end)` returns the *two* subtrees covering an
  interval (§4.5), which is what a landmark's subtrees and the CA's
  per-checkpoint signatures are both built from.

If this file is wrong, every printed hash after it is wrong, so it is tested
against the draft's own numbers rather than against itself.

### 6.2 `wire.py` and `ids.py` — encoding and names

A small TLS presentation-language subset: length-prefixed vectors with the
draft's `0x40`-prefixed long form, and a strict reader that rejects reserved
prefixes and trailing bytes. `ids.py` allocates the sub-arcs of §5.1 and
derives both the dotted form and the packed form of an OID.

`vector()` takes an iterable of elements, except for `bytes`, which is treated
as a *single* element. That exception looks like a wart and is the reason
`wire.vector(some_bytes)` does the obvious thing.

### 6.3 `log.py` — the issuance log (§5.2)

The core idea is in `TbsCertificateLogEntry`: it holds a **32-byte hash** of
the subject public key, not the key, and **no signature at all**. An entry is
119–131 bytes depending on the SAN list, against ~7 600 for a CT entry holding
an ML-DSA-65 certificate.

Also here: serial numbers (`(log << 48) | index`, §5.2), the null entry that
reserves an index without a certificate, subjectAltName extension encoding, and
`IssuanceLog` with its checkpoints.

A checkpoint is a cosignature over `[0, N)` — the *whole* tree — with a
timestamp, and it is the only place in the lab where a non-zero timestamp
appears (§5.3.2). `Checkpoint.signed_by()` is timestamp-aware for exactly that
reason.

### 6.4 `cosigners.py` — the `CosignedMessage` format (§5.3)

A cosigner signs a *subtree*, not a message about a certificate. What it signs
is 12 bytes of domain separation — `"subtree/v1\n\0"` — then the log ID, the
subtree interval, the subtree hash, and for a checkpoint a timestamp. The
`0x00`/`0x01` hash domains of §4 keep a leaf from being read as a node.

`Cosigner` wraps one ML-DSA-44 key; `ca_cosigner()` builds the CA's own, whose
ID is the CA ID (§5.4). `sort_signatures()` puts a proof's cosignatures in
cosigner-ID order and rejects duplicates, so a certificate has one canonical
byte encoding.

`CertificateSigner` is the ordinary ML-DSA-65 CA key used by the *directly
signed* shape. It is a different class on purpose: an ordinary signature is over
a message, and a cosignature is over a subtree.

### 6.5 `landmarks.py` — the landmark sequence (§6.4)

An append-only sequence of landmarks, each with a tree size, an expiry, and the
**two subtrees covering what was added since the previous landmark**
(`find_subtrees(prev, size)`). This is the detail that surprises people: a
landmark is not a snapshot of the tree, it is a record of a delta, and the
interval it covers is generally not itself a subtree.

`publish()` produces the text form and `parse_publication()` reads it back
strictly. `subtree_hashes_for()` produces exactly what a relying party
stores: two 32-byte hashes per active landmark.

### 6.6 `certs.py` — the four shapes (§6.2–6.4)

```
| shape                | what stands in for a signature      |
|----------------------|-------------------------------------|
| directly signed      | an ML-DSA-65 signature over the body |
| standalone           | 2 subtree cosignatures over [0, N)  |
| checkpoint-relative  | 2 subtree cosignatures over a batch |
| landmark-relative    | nothing; the client holds the hash  |
```

Both cosigners sign the *same* interval. That is what the draft requires — the
`Signatures` vector holds cosignatures over the proof's `start` and `end`, so
the two differ in who signed, not in what they cover.

The checkpoint-relative shape uses the covering subtree of the entries added
since the previous checkpoint, which is why it is measured against the size-12
checkpoint for entry 3 and not the size-20 one: the CA signs the new entries'
subtrees when it checkpoints (§6.1, steps 2–5).

`shape_sizes()` measures rather than assumes, because the direct certificate
is signed with ML-DSA-65 (3 309 B) while the cosigners use ML-DSA-44 (2 420 B),
and using one number for both would misstate the table.

`issued` fields are signed, including the **issuer**. That is not decoration:
the client selects the verifying key *by* the issuer, so an issuer outside the
signed body would let a certificate be re-issued under another CA's name.

### 6.7 `client.py` — the Section 7.2 walk

`ClientState` is what a relying party holds before any certificate arrives:
cosigner public keys, landmark subtree hashes, and (for the directly signed
shape) the CA key. `verify()` runs the checks in dependency order and returns
the **first** failure with a named step, so a caller can print one line.

The three paths differ only in where the trusted hash comes from:

* cosigned shapes — recompute the subtree, check both cosignatures;
* landmark-relative — recompute, compare against the stored hash, and check
  that the *named* landmark actually owns that interval;
* directly signed — check one ordinary signature.

`verify_direct()` is separate because that shape is not an MTC and has no
proof to walk.

### 6.8 `scenario.py` — the one fixed scenario

Log 8, 20 entries, a null entry at index 7, checkpoints at 12 and 20, a
landmark at 20, a certificate for index 3. Fixed so the printed hashes are the
same on every machine, which is what makes them discussable against a handout.

It also *persists the keys*, in `out/mtc/scenario.json`. ML-DSA signatures use
a random nonce, so a second run with fresh keys would produce different
cosignatures for the same subtree and a certificate written by `mtc shapes`
would not verify in `mtc verify`. The keys being saved is what makes the three
commands a pipeline.

### 6.9 The three commands — `lab/cli/mtc.py`

```bash
make mtc-lab      # build the CA, print the roots, save the scenario
make mtc-shapes   # cut all four shapes from one entry, size them
make mtc-verify   # the §7.2 walk for a client with some knowledge
```

`--knows` is the interesting one: `none`, `cosigners`, `landmark`, `all`. The
`landmark` level is the only difference between the third and fourth columns
of the knowledge table in the exercise, and the refusal message for the
landmark-relative shape at the `cosigners` level — *"becomes checkable when the
landmark arrives"* — is the distinction the workshop is built around.

`--tamper` changes one subjectAltName and checks that all four shapes notice.

Worksheet: `docs/exercises/05_mtc_four_shapes.md`.

### 6.10 What is not built

* **The witness architecture.** The draft's separate witness design is
  discussed, not implemented (`PLAN-update.md` D1). Cosigners are.
* **Negotiation.** The draft's §8 negotiation is a discussion table in
  exercise 05, not a simulation (D5).
* **The wire format.** The draft mixes two encodings, and the lab is honest about
  which is which. The `CosignedMessage` (§5.3.1) and the `MTCProof` (§6.1) really
  are TLS presentation language, and `lab/mtc/wire.py` implements the handful of
  primitives they are built from faithfully — fixed-width integers, length-prefixed
  opaque, length-prefixed vectors. The log entry and the certificate around them are
  ASN.1/DER in the draft, and those are a documented TLV here instead, emitted as
  dataclasses rather than X.509. Field order, the cosignature label, the serial
  layout, and the hash domains are faithful; the outer bytes are ours (D7). Nothing
  here interoperates with a real MTC deployment, and every module says so.
* **ACME.** Out of scope entirely.

---

## WS9 — Workshop materials and end-to-end flow

* `README.md` — prerequisites, quickstart, repository layout, materials index.
* `abstract.md` — the TesseraCT + Python + PQC + MTC story.
* `docs/facilitator_notes.md` — timing table, talking points, expected outputs, common failures,
  and what is intentionally out of scope.
* `docs/exercises/` — six worksheets (`01`–`06`) plus an index with the old → new
  numbering map. Exercise 05 is the MTC centrepiece and 06 is the design
  discussion.
* `scripts/workshop.sh` — the single end-to-end command (`make workshop`), also used as the
  smoke test.

## WS10 — Verification and CI

* `tests/` — 269 unit tests. The CT half covers hashing, proofs, note signatures, DER sizes,
  and PKI measurement. The MTC half is the interesting part:
  * `test_mtc_tree.py` runs the draft's Appendix C vectors, the Figure 7/8 cases, and every
    valid subtree interval up to a tree of 130 entries. If the tree is wrong, nothing downstream
    can be trusted.
  * `test_mtc_wire_ids.py` covers the encoding primitives and the OID arcs, including the
    draft's own examples.
  * `test_mtc_log_landmarks.py` covers the log, the checkpoints, the landmark sequence, active
    subtree filtering, and the strict entry decoders.
  * `test_mtc_certs.py` covers the four shapes, the size table, every field-tampering attack
    worth naming, the checkpoint-root semantics, and strict decode round-trips for every shape.
  * `test_mtc_cli.py` runs the three workshop commands end to end.
* `test_staticct.py` also covers `pki.issue_leaf()`, which is what `make fill` uses to give the
  CT log a tree with more than one leaf. A log deduplicates entries by certificate, so
  `make demo` can only ever produce a tree of size 1; without a way to issue *distinct* leaves,
  exercise 04 has no siblings to walk and `--index 2` does not exist.
* `make test` runs them with the standard-library `unittest` runner (no extra dependency).
* `make lint` runs `ruff check lab tests` (config in `pyproject.toml`).
* `.github/workflows/ci.yml` runs lint + unit tests on Python 3.12.
* `make workshop` is the manual smoke test. It needs Go 1.27 and OpenSSL 3.5 for the CT half, so
  it is not run in CI; `make mtc-lab && make mtc-shapes` is the part that always works.

---

## 5. End-to-end walkthrough

```bash
# one-time
make submodules
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# section 1: how big is PQC?
make measure
cat out/measurements.md

# section 2: a private PQC PKI over TLS
make pki ALG=mldsa65
make tls-demo

# sections 4-5: a CT log, submission, and the proof walk
make lab-up
make demo
make walk INDEX=0
python3 -m lab.cli verify --storage-dir log --index 0 --pubkey out/log-key.pem
make lab-down

# section 7: the MTC centrepiece. No log server, no Go, no OpenSSL.
make mtc-lab
make mtc-shapes
python3 -m lab.cli mtc verify --knows cosigners
python3 -m lab.cli mtc verify --knows landmark
python3 -m lab.cli mtc verify --knows all --tamper

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
| `cannot import name 'MLDSA65PrivateKey'` | `cryptography` older than 46 | use `.venv/bin/python`; the `Makefile` picks it up if it exists |
| `no scenario at out/mtc/scenario.json` | `mtc shapes` or `mtc verify` before `mtc lab` | the three MTC commands share state on disk; run `make mtc-lab` first |
| `entry 7 is a null entry and cannot be certified` | expected: index 7 is the scenario's null entry | choose another `--index` |
| `Permission denied` running a script | missing exec bit | `chmod +x scripts/*.sh` |
| stale PID / port in use | previous run not stopped | `make lab-down` |

---

## 7. Mapping to the workshop agenda

| Agenda section | Lab support |
|---|---|
| 1. Baseline PQC cost | `make measure`, `lab/certs.py`, `lab/pki.py` |
| 2. PQC X.509 without MTC | `make tls-demo` |
| 3. Algorithm landscape | measurement table; Falcon optional via oqs-provider (WS8, skipped) |
| 4. Run your own CT log | `make lab-up`, `make demo`, `lab/staticct.py` |
| 5. Merkle proofs | `lab/merkle.py`, `make walk`, `lab.cli proof`/`verify` |
| 6. Cosigners and the subtree | `lab/mtc/cosigners.py`, `lab/mtc/landmarks.py` |
| 7. One log, four certificates | `lab/mtc/`, `make mtc-lab`/`mtc-shapes`/`mtc-verify` |
| 8–9. Discussion | `docs/facilitator_notes.md`, `docs/exercises/06_where_to_use.md` |

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
