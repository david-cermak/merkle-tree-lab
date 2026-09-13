# Exercise 4 — Run your own CT log

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

## Questions

1. What does the SCT contain? What is the log promising?
2. Where are the certificates actually stored?
3. Submitting the same certificate twice returns the same leaf index. Why?
4. TesseraCT only accepts chains rooted in the configured `--roots_pem_file`.
   Why is that necessary for a CT log?
5. What happens if you submit an SLH-DSA certificate? (Try it.) Why?

## Takeaway

A CT log is an append-only, publicly auditable list of certificates. For PQC
certificates the stored entries are much larger, which is the storage pressure
MTC is designed to reduce.
