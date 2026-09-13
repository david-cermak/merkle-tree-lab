# Abstract: Post-Quantum Signatures, Today

Add devs know how to create a local test environment using self-signed certs, your own CI and trust chain, but what if we need PQsafe signatures? Let's go over step by step how we could make it and how we can benefit from the merkle tree idea presented by Google.

Post-quantum cryptography is coming, but standards are slow. We don't have to wait. This workshop shows how to roll out quantum-resistant signatures in your own infrastructure right now, using the tools already on our laptops: OpenSSL, Docker, and Go.

We'll build a mini Certificate Transparency log with [Trillian](https://github.com/google/trillian) — Google's Merkle tree implementation — and turn it into a practical, PQsafe signing chain:

1. **Why Merkle trees?** A single signed tree root authenticates an unlimited number of leaves, so one trusted key can vouch for many certificates — a natural fit for hash-based, post-quantum schemes.
2. **Local-first setup.** Spin up the log server and signer in Docker, then watch certificates flow in as leaves.
3. **Proofs, not trust.** An inclusion proof lets any verifier confirm a certificate is part of the tree without trusting the log operator. Add a STH (signed tree head) and you have an audit trail anyone can check.
4. **Bringing it to PQ.** Combine hash-based signatures with the log's root signatures so the chain stays quantum-safe — no new PKI, no waiting on a standard.

By the end you'll have a working lab, a merkle certificate bundle you generated yourself, and a clear path to start experimenting with PQsafe signatures in your own environments today.
