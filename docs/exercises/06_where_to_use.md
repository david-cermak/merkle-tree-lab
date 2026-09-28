# Exercise 6 — Where would I actually use this?

**Goal:** stop measuring bytes and start choosing a design. By this point you
have four shapes, one log, and a table of what each costs and what each needs.

**Time:** 10 minutes. Discussion, with the lab open if you want to check a claim.

**Prerequisites:** exercise 5, or at least the four-row table from it.

---

## The three strategies

| | PQC X.509 | PQC + CT | MTC |
|---|---|---|---|
| log stores | nothing | the certificate | a hash of the key |
| client needs the CA key | yes | no (gets an SCT) | no, for the MTC shapes |
| client needs a log or cosigners | no | the log | cosigners and/or landmarks |
| verifies *membership* | no | yes, with the log | yes, with hashes or keys |
| best when | the client already trusts the CA | bytes in the log are affordable | the log's storage is the problem |

## Questions

1. **Revocation by serial range.** A log can revoke everything after index *k*
   in one statement. What does that let an operator do that per-certificate
   revocation cannot — and why does it need a *stable* index space? (Hint: what
   would happen to a null entry if indices could be reused?)

2. **Log window retention.** Because a client needs only a subtree hash, a log
   could in principle stop serving old entries. What would a client still need
   in order to verify a certificate issued years ago, and which design choice in
   exercise 5 makes that possible?

3. **When is MTC unnecessary?** Some deployments do not need any of this: an
   internal PKI with a handful of long-lived roots, where every client is
   configured with the root directly. Name a case where you would *not* deploy
   MTC, and say what the cost of deploying it would be.

4. **The optional ACME link.** The draft mentions an optional link between
   ordinary certificate management (ACME) and the issuance log. What would that
   link buy, and what would it cost? (Consider who runs the log: a CA already
   controls its own issuance, so the transparency argument is weaker than it is
   for a public log.)

5. **Renewal overlap.** A client is told to rotate around 75% of the way through
   a certificate's life. How does that interact with the landmark model, where a
   client holds hashes for a bounded number of active landmarks? Does the
   renewal cadence have to change?

6. **Your call.** Pick a deployment you know — a web PKI, a code-signing service,
   a device fleet, an internal mesh — and choose a row of the table. Defend it in
   two sentences, then name the one fact that would change your mind.

## Takeaway

Every design decision in this workshop has been about *who holds what state* and
*how much of it*. MTC moves the cost from the log's storage to the client's
out-of-band state, and from "the client downloads the log" to "the client holds
a few hashes and some public keys". That is a good trade when the log is large
and the keys are post-quantum; it is a bad trade when the client already trusts
the CA and nobody is watching for equivocation.

## Further reading

* `docs/mtc-draft.txt` §1 (motivation) and §7.5 (revocation) — the arguments
  this exercise is paraphrasing.
* `PLAN-update.md` §11 — what is deliberately out of scope, including
  negotiation and the witness architecture.
