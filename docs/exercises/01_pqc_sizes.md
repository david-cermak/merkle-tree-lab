# Exercise 1 — How expensive is PQC?

**Goal:** replace the vague statement "PQC signatures are bigger" with numbers
you measured yourself.

## Steps

```bash
make measure
cat out/measurements.md
cat out/measurements.json
```

Look inside one certificate:

```bash
openssl x509 -in out/pki/mldsa65/leaf.crt -noout -text | head -20
```

## Questions

1. Fill in the table from `out/measurements.md`:
   cert size, public-key size, signature size for ECDSA, RSA, ML-DSA-44,
   ML-DSA-65, SLH-DSA, and Falcon-512 (skipped if `oqs-provider` is not
   installed — see facilitator notes).
2. Where do the extra bytes come from — the public key, the signature, or both?
3. SLH-DSA has a tiny public key (50 bytes) but a huge signature. Falcon has a
   medium public key and a much smaller signature than ML-DSA. Why might each
   trade-off be an advantage for some use cases and a problem for others?
4. If a TLS handshake sends a certificate chain with two PQC signatures, how
   many bytes is that?
5. With Certificate Transparency, a client typically gets **two SCTs** plus the
   certificate's own signature. At ML-DSA-44 sizes, how many signature bytes is
   that? The draft's introduction (§1) does this arithmetic for a real
   deployment and arrives at **7 260 B**. Now do the same arithmetic for a
   *landmark-relative Merkle Tree Certificate* in the same deployment, which the
   draft's size estimates (§6.5) put at **736 B** with **no signatures at
   all**. Where does 736 come from, and what is the client giving up to get it?
   (Run `make mtc-lab` and `make mtc-shapes` in
   [exercise 5](05_mtc_four_shapes.md) and compare the *proof* bytes in the
   table against the signature bytes.)
6. Add a second axis: §6.5 assumes a **7-day** certificate lifetime renewed
   at 75% of the way through (§10.4), so each certificate is reissued every
   **126 hours**. How many signature bytes does one client fetch per year per
   certificate, at ML-DSA-44 and at ML-DSA-65 sizes? This is the pressure that
   motivates a design where the log stores a hash of the key instead of the key.

## Takeaway

"PQC signature size" is not one number. Different schemes make different
engineering trade-offs, and those trade-offs are exactly what motivates
Merkle Tree Certificates.
