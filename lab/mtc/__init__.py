"""Merkle Tree Certificates workshop lab.

This package is a **teaching simulator** of the Merkle Tree Certificate
construction in ``draft-ietf-plants-merkle-tree-certs-06``. It is not an
interoperable implementation of the draft and produces no wire-compatible
certificates; it exists so a workshop attendee can watch the four certificate
shapes come out of one issuance log and measure them.

Modules:

``tree``
    The Merkle primitives of draft Section 4: subtree validity, subtree
    hashes, subtree inclusion proofs, subtree consistency proofs, and the two
    subtrees that cover an arbitrary interval. Validated against the
    accumulated test vectors in draft Appendix C.
``wire``
    A small TLS presentation-language reader and writer, enough to encode the
    identifiers and the extensions without hand-rolling length prefixes.
``ids``
    CA, issuance-log, landmark, and cosigner identifiers, and the arcs the
    draft reserves for each.
``log``
    The CA's issuance log (Section 5.2): log entries that carry a hash of the
    subject public key instead of the key and no signature at all, plus the
    checkpoints the CA signs over them (Section 5.4).
``cosigners``
    The ``CosignedMessage`` subtree-signature format (Section 5.3), the CA
    cosigner, one external cosigner, and the ordinary CA signing key used by
    the directly signed shape.
``landmarks``
    The landmark sequence and its landmark subtrees (Section 6.4).
``certs``
    The four certificate shapes (Sections 6.2-6.4), measured so the exercises
    can print a table that cannot drift from the code.
``client``
    The relying party's state and the Section 7.2 verification walk.
``scenario``
    The one fixed scenario the exercises and the CLI share: log 8, 20 entries,
    checkpoints at 12 and 20, a landmark at 20, and a certificate for index 3.

Deviations from the draft, all deliberate and all teaching-motivated:

* Entry, proof, and signature encodings follow the draft's *structure* (field
  order, the 12-byte ``"subtree/v1\\n\\0"`` cosignature label, the
  ``(log_number << 48) | index`` serial layout, the ``0x00``/``0x01`` hash
  domains) but use a compact documented TLV encoding instead of the TLS
  presentation language. They do not interoperate.
* ``TBSCertificateLogEntry`` is a TLV structure, not DER, and the entries are
  real SHA-256 leaf hashes of that structure, so the tree arithmetic is exact.
* Certificates are held as dataclasses and printed, not encoded as X.509.
* No ACME, no TLS wire format, no trust-anchor negotiation.
"""

from __future__ import annotations
