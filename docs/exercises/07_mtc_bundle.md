# Exercise 7 — The MTC-shaped bundle

**Goal:** assemble the pieces into an "MTC-shaped" artifact and reason about
when it beats a conventional PQC certificate.

## Steps

With the log running and a certificate submitted:

```bash
make bundle
cat out/mtc_bundle.json | python3 -m json.tool | head -40
```

The bundle contains:

* the certificate (base64),
* its inclusion proof (audit path),
* the signed checkpoint,
* the checkpoint's signatures (log + witness).

## Questions

1. What is in the bundle that a conventional certificate does **not** have?
2. What does a conventional certificate have that the bundle replaces with
   something shared?
3. Compare the bundle size with a single certificate and with the chain. Which
   is bigger? Why?
4. The bundle is JSON with a base64 certificate, which adds ~33%. What would a
   binary encoding do to the numbers?
5. For a tree with 1 000 000 certificates, roughly how many audit-path hashes
   would each bundle carry? (Hint: log₂.)

## The key question

It is **not** "is MTC smaller?" for one certificate. It is:

> At what scale does amortizing one large signature across many certificates
> become worthwhile?

The checkpoint signature is paid once per tree state and shared by every
certificate; each certificate then carries only a short audit path.

## Takeaway

MTC trades a large per-certificate signature for a small per-certificate proof
plus a shared, witnessed commitment. That trade is favourable when you have many
certificates and frequent re-signing — and unnecessary when you do not.
