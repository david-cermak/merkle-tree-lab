# Exercise 2 — A private PQC PKI over TLS

**Goal:** show that you can use ordinary post-quantum X.509 certificates today,
without any Certificate Transparency log or browser root program.

## Steps

```bash
make pki ALG=mldsa65
make tls-demo
```

Expected output:

```
subject=CN=leaf.example (ML-DSA-65)
Peer signature type: mldsa65
Verification: OK
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Verify return code: 0 (ok)
```

## Questions

1. Who signs the leaf certificate? Who signs the intermediate?
2. The client trusted only `root.crt`. What did the server send in addition to
   the leaf so that the client could build the chain?
3. Who needs to trust your root certificate in this setup? (Hint: only the
   systems you distribute it to.)
4. What did you **not** need to use? (Google, Mozilla, Apple, a public CT log,
   a browser root program.)
5. **When is MTC unnecessary?** Concretely: the client trusted only `root.crt`,
   and no other client in this setup can observe what the CA issued. What
   transparency guarantee are you giving up, and who would have to be watching
   to notice a problem? When does MTC start to pay off — and see
   [exercise 6](06_where_to_use.md) question 3 for the deployment cases where the
   answer is "don't bother".

## Takeaway

If you control both ends, conventional PQC X.509 is the simplest path. MTC
becomes interesting when the scale and repeated-signature overhead justify the
extra machinery — which is what [exercise 5](05_mtc_four_shapes.md) measures.
