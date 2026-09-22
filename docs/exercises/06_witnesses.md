# Exercise 6 — Witnesses and cosignatures

**Goal:** understand why an inclusion proof alone is not enough, and see a
witness cosignature appear on the log's checkpoint.

## Background

A log can sign two different checkpoints of the same size (a *split view*). A
**witness** is an independent party that checks the log's append-only behaviour
and cosigns the checkpoint. A verifier that trusts the witness is protected
against equivocation.

## Steps

First look at a normal (unwitnessed) checkpoint:

```bash
make lab-up
python3 -m lab.cli demo --storage-dir log --log-key out/log-key.pem
python3 -m lab.cli checkpoint --storage-dir log --pubkey out/log-key.pem
```

You should see **2 signatures**: the primary ECDSA signature and, because
TesseraCT always adds it, the log's additional Ed25519 signer.

Now enable witnessing with the local witness:

```bash
make witness-demo
```

The final `checkpoint` output should show **3 signatures**, including:

```
witness cosig  : VALID (witness.local)
```

## Questions

1. Which key signs the witness cosignature? Is it the log's key?
2. What exactly does the witness sign? (Read `lab/note.py` `verify_cosignature`.)
3. What stops the witness from blindly signing anything the log sends?
4. If the witness is offline, what happens? (TesseraCT's witnessing is
   *fail-open* — the checkpoint is still published.)
5. Why does an inclusion proof alone not protect against a split view?

## Takeaway

Inclusion proofs show a certificate is in *a* tree. A signed, witnessed
checkpoint pins *which* tree, and constrains the log to a single append-only
history.
