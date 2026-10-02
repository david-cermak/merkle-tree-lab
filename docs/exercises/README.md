# Exercises

Short, hands-on worksheets, one per section of the workshop. Each assumes the
one-time setup in the [README](../../README.md), and each says what it needs.

## Core path (about 60 minutes)

| # | Exercise | Time | Needs | Section |
|---|---|---:|---|---|
| 01 | [How expensive is PQC?](01_pqc_sizes.md) | 15 min | `make measure` | Baseline sizes |
| 02 | [A private PQC PKI over TLS](02_private_pki_tls.md) | 10 min | the generated PKIs | PQC without MTC |
| 03 | [Run your own CT log](03_ct_log.md) | 15 min | `make lab-reset` | Certificate Transparency / Static CT API |
| 04 | [Merkle proofs, step by step](04_merkle_proofs.md) | 10 min | a running log | Inclusion proofs |
| **05** | **[One log, four certificates](05_mtc_four_shapes.md)** | **30 min** | `make mtc-lab` | **Merkle Tree Certificates** |
| 06 | [Where would I actually use this?](06_where_to_use.md) | 10 min | exercise 05 | Choosing a design |

**Exercise 05 is the centrepiece.** It is the only exercise that needs no log
server and no network, so if you run one thing, run that.

## Full path (about 120 minutes)

Exercises 01–04 build up the vocabulary: what a post-quantum signature costs,
what transparency costs, and what an inclusion proof actually is. Exercise 05
assumes all of it. Exercise 06 is a discussion and can be run as a wrap-up
without a terminal.

## If you are short on time

Do **05** alone, and do Step 1, 2, and 4 of it. That gives the four shapes, the
size table, and the client-knowledge table — the three things the rest of the
workshop refers back to.

## What changed, and the old numbering

The exercises were renumbered so that 05 is the MTC centrepiece, and the witness
and bundle exercises were deleted rather than moved. If you have older notes:

| Was | Is now | |
|---|---|---|
| 01 PQC sizes | 01 PQC sizes | unchanged |
| 02 private PKI | 02 private PKI | unchanged |
| 04 CT log | **03** CT log | moved up |
| 05 Merkle proofs | **04** Merkle proofs | moved up |
| 06 witnesses and cosignatures | — | **deleted** |
| 07 the MTC bundle | — | **deleted** |
| — | **05** one log, four certificates | new, replaces 06 + 07 |
| — | **06** where would I use this | new |

The witness exercise went because the draft's witness architecture is a separate
design (see `PLAN-update.md` D1), and the bundle went because its content — the
size of what a log has to store — is now measured directly in exercise 03 and
exercise 05. Both decisions are recorded in `PLAN-update.md` §8.

## Facilitators

See [facilitator_notes.md](../facilitator_notes.md) for timings, expected
output, and the failure modes worth watching for.
