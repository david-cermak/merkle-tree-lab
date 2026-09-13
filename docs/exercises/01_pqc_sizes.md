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
   ML-DSA-65, SLH-DSA.
2. Where do the extra bytes come from — the public key, the signature, or both?
3. SLH-DSA has a tiny public key (50 bytes) but a huge signature. Why might that
   be an advantage for some use cases and a problem for others?
4. If a TLS handshake sends a certificate chain with two PQC signatures, how
   many bytes is that?

## Takeaway

"PQC signature size" is not one number. Different schemes make different
engineering trade-offs, and those trade-offs are exactly what motivates
Merkle Tree Certificates.
