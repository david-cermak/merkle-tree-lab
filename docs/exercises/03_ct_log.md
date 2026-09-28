# Exercise 3 — Run your own CT log

**Goal:** submit a real post-quantum certificate to a local Certificate
Transparency log and see what the log stores.

## Steps

```bash
make lab-up
python3 -m lab.cli demo --algorithm mldsa65 --storage-dir log --log-key out/log-key.pem
python3 -m lab.cli submit --log http://127.0.0.1:6962 --storage-dir log \
  --chain out/pki/mldsa65/leaf.crt out/pki/mldsa65/int.crt
```

Inspect the storage:

```bash
cat log/checkpoint
find log/tile -type f
```

Submit the same certificate twice and compare the SCTs.

## The submission prefix is the origin

```bash
head -1 log/checkpoint
python3 -m lab.cli demo --verbose --storage-dir log --log-key out/log-key.pem 2>&1 | head -4
```

The first line of the checkpoint is the log's **origin**, and by the
static-ct-api an origin *is* the submission prefix: the `https://$HOST/$PATH`
that submissions have to arrive on. Here that is `example.com/workshop`, so
`make lab-up` starts TesseraCT with `--path_prefix=/workshop` and the client
sends both halves — `Host: example.com` and a request to
`/workshop/ct/v1/add-chain` — while still connecting to 127.0.0.1.

Change one half of the origin — keep the path, change the host — and the
submission still succeeds, but the log says it was not reached at its origin:

```bash
python3 -m lab.cli demo --algorithm mldsa65 --storage-dir log --log-key out/log-key.pem \
  --origin other.example/workshop
grep 'not prefixed' log/tesseract.log
```

The log reports `other.example/workshop/ct/v1/add-chain, which does not start
with example.com/workshop`. Drop the origin entirely and the path stops matching
too, so the log cannot route the request at all:

```bash
python3 -m lab.cli demo --algorithm mldsa65 --storage-dir log --log-key out/log-key.pem --origin ''
```

The warning exists because in a real deployment a reverse proxy owns the
hostname. The log can see the path it was mounted at, but it cannot tell whether
the request really arrived on `example.com`. Hard-failing on the host would break
every deployment behind a proxy, so it warns instead — the check stays visible
without taking the log down.

## Measure what the log has to store

```bash
ls -l log/tile/*/* 2>/dev/null | head
ls -l out/pki/mldsa65/leaf.crt
make mtc-lab
```

An ML-DSA-65 leaf certificate is about **7 600 bytes**, almost all of it the
1 974-byte public key plus the 3 309-byte signature — and a CT log stores
something that size, per certificate, forever. The MTC issuance log stores
**131 bytes** for the same certificate, because the entry holds a 32-byte hash
of the key instead of the key, and no signature at all. `make mtc-lab` prints
both numbers.

That ratio — 7 600 bytes down to 131, about **58×** — is the storage argument
for Merkle Tree Certificates, and it is the number to remember from this
exercise. The price is that the client now has to get the key from somewhere
else: from the certificate itself, and proof that the certificate matches the
hash in the log.

## Questions

1. What does the SCT contain? What is the log promising?
2. Where are the certificates actually stored?
3. Submitting the same certificate twice returns the same leaf index. Why?
4. TesseraCT only accepts chains rooted in the configured `--roots_pem_file`.
   Why is that necessary for a CT log?
5. What happens if you submit an SLH-DSA certificate? (Try it.) Why?
6. A CT log must serve the log to anyone who asks. Who pays for that bandwidth,
   and what does it cost when each entry is 7 kB instead of a few hundred bytes?
7. The log warns instead of rejecting a submission that arrives off its
   submission prefix. Is that a security problem? Who would notice?

## Takeaway

A CT log is an append-only, publicly auditable list of certificates. For PQC
certificates the stored entries are much larger, which is the storage pressure
MTC is designed to reduce: keep the transparency property, shrink the entry to
a hash.
