"""Trust anchor IDs: the CA ID, log IDs, landmarks, and cosigner IDs.

Section 5.1 of the draft gives every Merkle Tree CA a *CA ID*, which is a trust
anchor ID -- that is, an object identifier -- and then allocates sub-arcs of it
for the things a client has to name::

    {caID logs(0) N}            issuance log N                    Section 5.2
    {caID landmarks(1) N L}     landmark L of log N              Section 6.4.1
    {caID landmarkGroups(2) N L} landmark L of log N and earlier   Section 8.2.1

Those three IDs are the vocabulary of the whole design. The *log ID* tells a
cosigner which log a subtree signature is about; the *landmark ID* and
*landmark group ID* are what a client advertises in the TLS handshake to say
which landmark state it already has.

The draft writes trust anchor IDs in the abbreviated form ``32473.100``, which
is the display form for a CA that has been allocated an arc under
``1.3.6.1.4.1``. :meth:`TrustAnchorID.parse` accepts either spelling and
:meth:`~TrustAnchorID.dotted` always returns the full one, which is what
Section 5.3.1 puts inside a cosignature::

    32473.100            ->  oid/1.3.6.1.4.1.32473.100
    32473.100.2.8.1      ->  oid/1.3.6.1.4.1.32473.100.2.8.1

Two encodings are derived from the arcs, both of which the lab needs:

``relative_oid``
    The DER content octets of the arcs *below* ``1.3.6.1.4.1``, which is what
    goes in the ``id-rdna-trustAnchorID`` attribute of a PKIX distinguished
    name (Section 5.1). The draft's example
    ``1.3.6.1.4.1.44363.47.3=#0d0481fd5901`` decodes to exactly the content
    octets of ``32473.1``, which is what this returns.
``packed``
    The DER content octets of the *full* OID, which is the lab's stand-in for
    the binary representation that Section 6.2 sorts ``cosigner_id`` values by.
    The real binary form is defined in Section 4 of the trust-anchor-ids draft,
    which this lab does not implement; the sort *rule* is implemented exactly
    (shorter before longer, then lexicographic).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

#: The arc that the IETF's trust-anchor-ids work hangs CA IDs off. The draft's
#: own example is "32473.1", i.e. Cloudflare's private enterprise number.
PRIVATE_ARC: Tuple[int, ...] = (1, 3, 6, 1, 4, 1)

#: The sub-arcs allocated by Section 5.1.
LOGS = 0
LANDMARKS = 1
LANDMARK_GROUPS = 2

#: The experimental ``id-rdna-trustAnchorID`` OID from Section 5.1, for the
#: days before the real one is registered.
RDNA_TRUST_ANCHOR_ID = (1, 3, 6, 1, 4, 1, 44363, 47, 3)


@dataclass(frozen=True)
class TrustAnchorID:
    """An object identifier naming a CA, a log, a landmark, or a cosigner."""

    arcs: Tuple[int, ...]

    def __post_init__(self) -> None:
        if not self.arcs:
            raise ValueError("a trust anchor ID needs at least one arc")
        if any(arc < 0 for arc in self.arcs):
            raise ValueError(f"negative arc in {self.arcs}")

    @classmethod
    def parse(cls, text: str) -> "TrustAnchorID":
        """Parse ``"32473.100"`` or the full ``"1.3.6.1.4.1.32473.100"``.

        The abbreviated form is expanded with :data:`PRIVATE_ARC`, matching how
        the draft and the audio book write CA IDs.
        """
        parts = [part for part in text.strip().split(".") if part]
        if not parts:
            raise ValueError("empty trust anchor ID")
        try:
            arcs = tuple(int(part) for part in parts)
        except ValueError as exc:
            raise ValueError(f"malformed trust anchor ID {text!r}") from exc
        if arcs[: len(PRIVATE_ARC)] != PRIVATE_ARC:
            arcs = PRIVATE_ARC + arcs
        return cls(arcs)

    @property
    def dotted(self) -> str:
        """The full OID in dotted decimal notation."""
        return ".".join(str(arc) for arc in self.arcs)

    @property
    def short(self) -> str:
        """The abbreviated form, with :data:`PRIVATE_ARC` stripped if present."""
        if self.arcs[: len(PRIVATE_ARC)] == PRIVATE_ARC:
            return ".".join(str(arc) for arc in self.arcs[len(PRIVATE_ARC) :])
        return self.dotted

    def child(self, *arcs: int) -> "TrustAnchorID":
        """Return this ID extended with more arcs."""
        return TrustAnchorID(self.arcs + tuple(arcs))

    def log(self, number: int) -> "TrustAnchorID":
        """Return the ID of issuance log ``number`` (Section 5.2)."""
        return self.child(LOGS, number)

    @property
    def log_number(self) -> Optional[int]:
        """Return this ID's log number if it names a log, else ``None``.

        The inverse of :meth:`log`: the last arc when the one before it is
        :data:`LOGS`. A decoder uses it to check that a proof's ``log_number``
        and the log ID it was read against are the same log.
        """
        if len(self.arcs) >= 2 and self.arcs[-2] == LOGS:
            return self.arcs[-1]
        return None

    def landmark(self, log_number: int, landmark_number: int) -> "TrustAnchorID":
        """Return the ID of a single landmark (Section 5.1)."""
        return self.child(LANDMARKS, log_number, landmark_number)

    def landmark_group(self, log_number: int, landmark_number: int) -> "TrustAnchorID":
        """Return the ID of a landmark group: landmark L and its predecessors."""
        return self.child(LANDMARK_GROUPS, log_number, landmark_number)

    def name_bytes(self) -> bytes:
        """Return the ``oid/...`` form used in a ``CosignedMessage``.

        Section 5.3.1: the ASCII string ``oid/`` followed by the trust anchor
        ID as a full OID in dotted decimal notation.
        """
        return b"oid/" + self.dotted.encode("ascii")

    def packed(self) -> bytes:
        """Return the DER content octets of the full OID.

        This is the lab's stand-in for the binary representation that Section
        6.2 orders ``cosigner_id`` values by; see the module docstring.
        """
        return _pack_arcs(self.arcs)

    def relative_oid(self) -> bytes:
        """Return the DER content octets of the arcs below the private arc.

        This is the value of the ``id-rdna-trustAnchorID`` attribute in a
        distinguished name (Section 5.1). A *relative* OID has no first-arc
        combining, so each arc is base 128 on its own: the draft's example
        ``1.3.6.1.4.1.44363.47.3=#0d0481fd5901`` for CA ``32473.1`` is this
        method returning ``81fd5901``.
        """
        arcs = self.arcs
        if arcs[: len(PRIVATE_ARC)] == PRIVATE_ARC:
            arcs = arcs[len(PRIVATE_ARC) :]
        if not arcs:
            raise ValueError("a relative OID needs at least one arc")
        return b"".join(_base128(arc) for arc in arcs)

    @classmethod
    def from_relative_oid(cls, encoded: bytes) -> "TrustAnchorID":
        """Rebuild an ID from the DER octets :meth:`relative_oid` produces.

        The inverse of :meth:`relative_oid`: a relative OID is a bare run of
        base-128 subidentifiers, so each one is one arc, and the private arc is
        put back in front. Needed by the entry decoder, since that is where an
        issuer comes back from bytes.
        """
        if not encoded:
            raise ValueError("an empty relative OID has no arcs")
        arcs: List[int] = []
        value = 0
        for offset, byte in enumerate(encoded):
            value = (value << 7) | (byte & 0x7F)
            if not byte & 0x80:
                arcs.append(value)
                value = 0
            elif offset == len(encoded) - 1:
                raise ValueError("relative OID ends in the middle of a subidentifier")
        if value:
            raise ValueError("relative OID ends in the middle of a subidentifier")
        return cls(PRIVATE_ARC + tuple(arcs))

    def distinguished_name(self) -> str:
        """Return the RFC 4514 rendering of the CA's distinguished name.

        Section 5.1: a single RDN whose type is ``id-rdna-trustAnchorID`` and
        whose value is a DER OID. The draft's example for CA ``32473.1`` is
        ``1.3.6.1.4.1.44363.47.3=#0d0481fd5901``.
        """
        oid = ".".join(str(arc) for arc in RDNA_TRUST_ANCHOR_ID)
        value = b"\x0d" + bytes([len(self.relative_oid())]) + self.relative_oid()
        return f"{oid}=#{value.hex()}"

    def __str__(self) -> str:
        return self.short


def _pack_arcs(arcs: Tuple[int, ...]) -> bytes:
    """Encode OID arcs as DER content octets (base 128, high bit continues).

    X.690 packs the first two arcs into one subidentifier, ``40 * X + Y`` with
    ``X`` clamped to 2, so ``1.3.6`` is the single byte ``2b 06``.
    """
    if len(arcs) < 2:
        raise ValueError("an OID needs at least two arcs to encode")
    if arcs[1] > 0x7F or arcs[0] < 0:
        raise ValueError(f"arc out of range in {arcs}")
    combined = 40 * min(arcs[0], 2) + arcs[1]
    return _base128(combined) + b"".join(_base128(arc) for arc in arcs[2:])


def _base128(value: int) -> bytes:
    """Encode one arc in base 128, most significant group first."""
    if value == 0:
        return b"\x00"
    groups = []
    while value:
        groups.append(value & 0x7F)
        value >>= 7
    groups.reverse()
    return bytes([group | 0x80 for group in groups[:-1]] + [groups[-1]])
