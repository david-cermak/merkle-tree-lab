# Abstract: Post-Quantum Signatures and Merkle Tree Certificates, Today

Developers know how to stand up a local test PKI with self-signed certificates,
their own CI, and their own trust chain. But what if those signatures need to be
quantum-safe? Post-quantum cryptography is here, but the standards and tooling
are still moving. This workshop shows how far you can get **right now**, using
tools already on your laptop: OpenSSL 3.5, Go, and Python.

We build two things:

1. **A private post-quantum PKI.** Using OpenSSL 3.5's built-in ML-DSA and
   SLH-DSA support, we generate root → intermediate → leaf chains, measure how
   large PQC certificates really are, and use an ML-DSA certificate over TLS 1.3.
   The lesson: if you control both ends, conventional PQC X.509 works today and
   may be all you need.

2. **A local Certificate Transparency log.** Using
   [TesseraCT](https://github.com/transparency-dev/tesseract)'s POSIX backend —
   a single binary, no database, no containers — we run a CT log, submit
   post-quantum certificates, and read its signed checkpoint and Merkle tiles.
   A small Python client then rebuilds the Merkle tree, produces inclusion
   proofs, verifies them against the checkpoint, and checks the checkpoint's
   signature.

Finally we add a **witness** that cosigns the checkpoint, and assemble an
**MTC-shaped bundle**: certificate + inclusion proof + signed, witnessed
checkpoint. We compare its size against a conventional PQC certificate and ask
the engineering question that matters:

> At what scale does amortizing one large signature across many certificates
> become worthwhile?

By the end you will have generated PQC chains, logged certificates into your own
transparency log, verified inclusion and cosignatures from scratch, and a clear
mental model of when to use conventional PQC X.509 versus Merkle Tree
Certificates.
