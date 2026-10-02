# Exercise 3 — Run your own CT log

**Goal:** submit a real certificate to a local Certificate Transparency log,
watch the Static CT API do its job, then see why PQC makes that job expensive.

You will run [TesseraCT](https://github.com/transparency-dev/tesseract) (POSIX
backend). Cloudflare's [Azul](https://github.com/cloudflare/azul) is another
Static CT API implementation — same protocol, different runtime; we do not run
it in this workshop.

## 0. Start from a clean log

A CT log is **append-only**. There is no "delete certificate" call. If the log
already has entries from a previous run (or a facilitator demo), wipe storage
and start empty:

```bash
make lab-reset
```

That stops TesseraCT, removes `log/` (checkpoint, tiles, antispam state), and
starts a fresh log. Use this whenever you restart the workshop.

First time only (or after `make lab-down`):

```bash
make lab-up
```

`lab-up` / `lab-reset` trust both the classical and ML-DSA workshop roots
(`out/pki/workshop-roots.pem`), so you can submit ECDSA and then ML-DSA without
restarting the server.

## 1. What is the Static CT API?

Old CT logs (RFC 6962) mixed **writes** and **reads** on one JSON RPC surface.
The [Static CT API](https://c2sp.org/static-ct-api) splits them:

| Half | How you talk to it | What it does |
|---|---|---|
| **Submission** | HTTP JSON `POST …/ct/v1/add-chain` | CA/client sends a chain; log returns an **SCT** (promise + leaf index) |
| **Monitoring** | Static files: `checkpoint`, `tile/*` | Anyone reads the signed tree head and the entry tiles — no RPC |

TesseraCT serves submissions on `http://127.0.0.1:6962/workshop/...`. Monitoring
files land under `./log/` on disk (in production they would be on object
storage / a CDN). That split is the whole idea: writes stay at the sequencer;
reads scale like any static website.

```
  you ──POST /workshop/ct/v1/add-chain──► TesseraCT ──writes──► log/
       ◄──────── SCT (JSON) ────────────┘                       │
                                                                │
  you ◄── read log/checkpoint, log/tile/... ────────────────────┘
```

## 2. Submit a classical certificate first

Start with something familiar — ECDSA P-256 — and turn tracing on so you see
the HTTP request and the storage reads:

```bash
make pki ALG=ecdsa-p256
make demo ALG=ecdsa-p256 VERBOSE=1
```

Or the same steps by hand:

```bash
python3 -m lab.cli submit --log http://127.0.0.1:6962 --origin example.com/workshop \
  --storage-dir log --verbose \
  --chain out/pki/ecdsa-p256/leaf.crt out/pki/ecdsa-p256/int.crt
```

**What just happened**

1. The client `POST`s JSON `{"chain":[<leaf DER b64>, <int DER b64>]}` to
   `/workshop/ct/v1/add-chain` (Host: `example.com`).
2. TesseraCT checks the chain against its trusted roots, assigns a leaf index,
   and returns an **SCT** (timestamp + log id + signature + extensions that
   carry the leaf index).
3. Shortly after, the entry is sequenced into Merkle tiles and the signed
   **checkpoint** advances.

Ask the log which roots it trusts:

```bash
curl -s -H 'Host: example.com' \
  http://127.0.0.1:6962/workshop/ct/v1/get-roots | python3 -m json.tool | head
```

## 3. Where did it go on disk?

```bash
cat log/checkpoint
find log/tile -type f | head
ls -l log/tile/data/* 2>/dev/null | head
```

Read the checkpoint like the monitoring API would:

```bash
python3 -m lab.cli checkpoint --storage-dir log --pubkey out/log-key.pem
```

| Path | Role |
|---|---|
| `log/checkpoint` | Signed tree head: origin, size, root hash, ECDSA note signature |
| `log/tile/data/*` | Entry bundles — the actual certificate bytes the log stores forever |
| `log/tile/*` | Merkle tree tiles (sibling hashes for inclusion proofs) |
| `log/issuer/*` | Issuer fingerprints so monitors can reconstruct chains |

The first line of the checkpoint is the log's **origin**. Under the Static CT
API that origin *is* the submission prefix: here `example.com/workshop`, so
submissions must hit `/workshop/ct/v1/...` with `Host: example.com` while still
connecting to `127.0.0.1`. That is how a reverse proxy in front of a real log
behaves.

Submit the same certificate twice and compare the SCTs — same leaf index. The
log is a set, not a stream.

## 4. Now submit a post-quantum certificate

```bash
make demo ALG=mldsa65 VERBOSE=1
```

Compare what the log has to keep:

```bash
ls -l out/pki/ecdsa-p256/leaf.crt out/pki/mldsa65/leaf.crt
ls -l log/tile/data/* 2>/dev/null | head
make mtc-lab
```

An ML-DSA-65 leaf is about **5 600 bytes** DER (almost all public key +
signature). A CT log stores something that size, per certificate, forever. The
`.crt` files look larger because they are PEM (base64); use the DER sizes in
`out/measurements.md`. The MTC issuance log stores **131 bytes** for the same
certificate — a 32-byte hash of the key, no signature. That ratio (~43×) is the
storage argument for Merkle Tree Certificates.

## 5. (Optional) Off-origin warning

Change the host half of the origin; the path still matches, so the submission
succeeds, but the log warns it was not reached at its configured origin:

```bash
python3 -m lab.cli demo --algorithm ecdsa-p256 --storage-dir log \
  --log-key out/log-key.pem --origin other.example/workshop
grep 'not prefixed' log/tesseract.log
```

Drop the origin entirely and the path stops matching — the log cannot route the
request. The warn-not-reject behaviour exists because a reverse proxy owns the
hostname; hard-failing on `Host` would break every proxied deployment.

## Questions

1. What does the SCT contain? What is the log promising?
2. Which half of the Static CT API did `demo` use for the write, and which half
   did `checkpoint` / `find log/tile` use for the read?
3. Where are the certificates actually stored on disk?
4. Submitting the same certificate twice returns the same leaf index. Why?
5. TesseraCT only accepts chains rooted in `--roots_pem_file`. Why is that
   necessary for a CT log?
6. What happens if you submit an SLH-DSA certificate? (Try it.) Why?
7. A CT log must serve the log to anyone who asks. Who pays for that bandwidth,
   and what does it cost when each entry is ~7 kB instead of a few hundred bytes?
8. The log warns instead of rejecting a submission that arrives off its
   submission prefix. Is that a security problem? Who would notice?

## Takeaway

Static CT separates **submission** (small JSON write path) from **monitoring**
(static tiles anyone can fetch). A CT log is append-only and publicly auditable.
For PQC certificates the stored entries are much larger — that storage pressure
is what MTC is designed to reduce: keep the transparency property, shrink the
entry to a hash.
