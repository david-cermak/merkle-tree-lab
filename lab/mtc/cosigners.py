"""Cosigners: signing a subtree instead of signing a certificate.

Section 5.3 is where MTC inverts CT. A CT log signs a *checkpoint* and a
certificate carries a *signature* over itself. An MTC cosigner signs *subtrees
of the CA's own issuance log*, and the log was written first, so a
cosignature is an assertion about a range of entries the cosigner has already
seen -- never a promise about one certificate.

What a cosigner signs is a ``CosignedMessage`` (Section 5.3.1)::

    struct {
        uint8 label[12] = "subtree/v1\n\0";
        opaque cosigner_name<1..2^8-1>;
        uint64 timestamp;
        opaque log_origin<1..2^8-1>;
        uint64 start;
        uint64 end;
        HashValue subtree_hash;
    } CosignedMessage;

The leading 12-byte label is domain separation: it is what stops a subtree
signature from ever being mistaken for a signature over anything else the
cosigner might be asked to sign. The draft notes the format is designed to be
compatible with the ML-DSA-44 cosignature construction in
[draft-ietf-tlog-cosignature]; this lab uses the same label and the same field
order with the presentation-language encoding of :mod:`lab.mtc.wire`, and real
ML-DSA keys from ``cryptography``.

``timestamp`` is always zero in a certificate (Section 6.2: "The timestamp field
used when computing the signature MUST be zero"). A non-zero timestamp is the
*checkpoint* cosignature of Section 5.3.2 -- it asserts the complete state of
the cosigner's view, and then Section 5.3.1 constrains ``start`` to be zero and
``end`` to be the largest tree the cosigner has seen. This lab supports that
case for completeness, and the MTC path never uses it.

Two cosigner roles appear in the lab:

* the **CA cosigner** (Section 5.4), whose cosigner ID *is* the CA ID. Signing
  a subtree asserts the CA certified every entry in it, which is the entire
  statement the relying party needs.
* an **external witness cosigner**, standing in for the "sufficient cosigners"
  a relying party's policy demands (Section 7.3). It is not a tlog-witness: it
  signs the CA's issuance log, not an independent CT log's checkpoint.

Section 5.4 also states the rule that motivates keeping this key separate from
any X.509 signing key: a cosigner key issues certificates by signing subtrees,
and MUST NOT sign a TBSCertificate directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Tuple

from cryptography.hazmat.primitives import serialization

from . import tree, wire
from .ids import TrustAnchorID

#: The fixed domain-separation label of Section 5.3.1: "subtree/v1", a newline,
#: and a zero byte. Exactly 12 bytes, so a cosignature is domain-separated from
#: every other structure a cosigner might sign.
COSIGNATURE_LABEL = b"subtree/v1\n\0"
assert len(COSIGNATURE_LABEL) == 12

HASH_SIZE = 32

#: How a public key is measured, and how a signature is produced, once.
_SPKI_ARGS = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
_MEASURED_SIZES: Dict[str, Tuple[int, int]] = {}

#: The ML-DSA parameter sets the lab uses, keyed by the draft's algorithm
#: choices: ML-DSA-44 for cosigners (Section 5.3.1 is built around it) and
#: ML-DSA-65 for the "directly signed" comparison certificate. Filled in by
#: :func:`_load_mldsa`.
Mldsa44PrivateKey = None
Mldsa65PrivateKey = None


def _load_mldsa():
    """Import the ML-DSA key classes, with a clear error on old cryptography.

    Decision D4 in ``PLAN-update.md``: the lab signs for real. ML-DSA landed in
    ``cryptography`` 46, so an older install gets this message rather than an
    ``ImportError`` from somewhere deep in the tree code.
    """
    global Mldsa44PrivateKey, Mldsa65PrivateKey
    if Mldsa44PrivateKey is not None:
        return
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise RuntimeError(
            "the MTC lab needs ML-DSA, which requires cryptography >= 46; "
            "install it with: python3 -m pip install -r requirements.txt"
        ) from exc
    if not hasattr(mldsa, "MLDSA44PrivateKey"):  # pragma: no cover
        raise RuntimeError(
            "the installed cryptography has no ML-DSA support (need >= 46): "
            f"{__import__('cryptography').__version__}"
        )
    Mldsa44PrivateKey = mldsa.MLDSA44PrivateKey
    Mldsa65PrivateKey = mldsa.MLDSA65PrivateKey


def _key_class(parameter_set: str):
    """Return the ML-DSA private key class for a parameter set name."""
    _load_mldsa()
    return {"mldsa44": Mldsa44PrivateKey, "mldsa65": Mldsa65PrivateKey}[parameter_set]


def _new_private_key(parameter_set: str) -> Any:
    return _key_class(parameter_set).generate()


@dataclass(frozen=True)
class CosignedMessage:
    """The bytes a cosigner signs to assert something about a subtree."""

    cosigner_id: TrustAnchorID
    log_id: TrustAnchorID
    start: int
    end: int
    subtree_hash: bytes
    timestamp: int = 0

    def __post_init__(self) -> None:
        if len(self.subtree_hash) != HASH_SIZE:
            raise ValueError(f"subtree hash must be {HASH_SIZE} bytes")
        if self.timestamp < 0:
            raise ValueError("timestamp cannot be negative")
        if self.timestamp and (self.start != 0 or self.end < self.start):
            raise ValueError("a timestamped cosignature covers a prefix of the log")

    def encode(self) -> bytes:
        """Encode the message exactly as it is handed to the signature algorithm."""
        return (
            wire.opaque(COSIGNATURE_LABEL)
            + wire.opaque_var(self.cosigner_id.name_bytes(), 1)
            + wire.uint(self.timestamp, 8)
            + wire.opaque_var(self.log_id.name_bytes(), 1)
            + wire.uint(self.start, 8)
            + wire.uint(self.end, 8)
            + wire.opaque(self.subtree_hash)
        )

    @classmethod
    def decode(cls, data: bytes) -> "CosignedMessage":
        """Decode a message, rejecting a wrong label or trailing bytes."""
        reader = wire.Reader(data, "CosignedMessage")
        label = reader.opaque(len(COSIGNATURE_LABEL))
        if label != COSIGNATURE_LABEL:
            raise wire.DecodeError(
                f"cosignature label must be {COSIGNATURE_LABEL!r}, got {label!r}"
            )
        cosigner_name = reader.opaque_var(1)
        timestamp = reader.uint(8)
        log_origin = reader.opaque_var(1)
        start = reader.uint(8)
        end = reader.uint(8)
        subtree_hash = reader.opaque(HASH_SIZE)
        reader.expect_end()
        return cls(
            cosigner_id=_parse_name(cosigner_name, "cosigner_name"),
            log_id=_parse_name(log_origin, "log_origin"),
            start=start,
            end=end,
            subtree_hash=subtree_hash,
            timestamp=timestamp,
        )


def _parse_name(raw: bytes, field: str) -> TrustAnchorID:
    """Parse the ``oid/1.2.3.4`` form from Section 5.3.1."""
    if not raw.startswith(b"oid/"):
        raise wire.DecodeError(f"{field} must start with 'oid/', got {raw!r}")
    try:
        text = raw[4:].decode("ascii")
    except UnicodeDecodeError as exc:
        raise wire.DecodeError(f"{field} is not ASCII: {raw!r}") from exc
    return TrustAnchorID(tuple(int(part) for part in text.split(".")))


@dataclass(frozen=True)
class SubtreeSignature:
    """A cosignature, as it appears in an ``MTCProof`` (Section 6.2)."""

    cosigner_id: TrustAnchorID
    signature: bytes

    def encode(self) -> bytes:
        # Self-delimiting: a one-byte cosigner-ID length, the packed ID, then a
        # two-byte signature length and the signature. Nothing says how many
        # cosignatures there are *inside* one, which is why the proof's vector
        # prefix is the only count -- a decoder reads elements until the body
        # runs out.
        return (
            wire.opaque_var(self.cosigner_id.packed(), 1)
            + wire.opaque_var(self.signature, 2)
        )

    @classmethod
    def decode(cls, reader: wire.Reader) -> "SubtreeSignature":
        cosigner_id = _decode_packed(reader.opaque_var(1))
        return cls(cosigner_id=cosigner_id, signature=reader.opaque_var(2))

    def sort_key(self) -> bytes:
        """The Section 6.2 ordering key for a ``cosigner_id``.

        Shorter byte strings first, then lexicographic -- which the ordinary
        ``bytes`` comparison already does.
        """
        return self.cosigner_id.packed()

    def __str__(self) -> str:
        return f"{self.cosigner_id.short}:{len(self.signature)}B"


def _decode_packed(raw: bytes) -> TrustAnchorID:
    """Decode DER OID content octets back into arcs."""
    if not raw:
        raise wire.DecodeError("empty cosigner_id")
    arcs: List[int] = []
    value = 0
    started = False
    for byte in raw:
        value = (value << 7) | (byte & 0x7F)
        started = True
        if not byte & 0x80:
            arcs.append(value)
            value = 0
            started = False
    if started:
        raise wire.DecodeError("cosigner_id ends mid-arc")
    if not arcs:
        raise wire.DecodeError("cosigner_id has no arcs")
    return TrustAnchorID(_uncombine_first(arcs))


def _uncombine_first(arcs: Sequence[int]) -> Tuple[int, ...]:
    """Undo the DER first-arc combining so a packed OID round-trips.

    ``arcs`` here are the *subidentifiers* read off the wire, where the first
    one is the packed pair ``40 * X + Y`` with ``X`` clamped to 2.
    """
    if len(arcs) < 2:
        raise wire.DecodeError("cosigner_id is too short to be an OID")
    combined = arcs[0]
    first = min(combined // 40, 2)
    return (first, combined - 40 * first) + tuple(arcs[1:])


def sort_signatures(signatures: Sequence[SubtreeSignature]) -> List[SubtreeSignature]:
    """Order signatures per Section 6.2 and reject duplicate cosigner IDs.

    "Each element of the signatures field MUST have a unique cosigner_id.
    Elements MUST be ordered by cosigner_id (excluding length prefix) as
    follows: shorter byte strings are ordered before longer byte strings; byte
    strings of the same length are ordered lexicographically."
    """
    ordered = sorted(signatures, key=lambda sig: sig.sort_key())
    for previous, current in zip(ordered, ordered[1:]):
        if previous.sort_key() == current.sort_key():
            raise ValueError(f"duplicate cosigner_id {current.cosigner_id.short}")
    return ordered


class Cosigner:
    """A key that signs subtrees of a log it has a view of."""

    def __init__(
        self, cosigner_id: TrustAnchorID, private_key: Any, role: str, parameter_set: str
    ) -> None:
        self.cosigner_id = cosigner_id
        self.private_key = private_key
        self.role = role
        self.parameter_set = parameter_set
        self._signed: List[Tuple[int, int]] = []

    @property
    def public_key(self) -> Any:
        return self.private_key.public_key()

    def public_bytes(self) -> bytes:
        """Return the DER SubjectPublicKeyInfo of this cosigner's key."""
        return self.public_key.public_bytes(*_SPKI_ARGS)

    def message_for(
        self,
        log_id: TrustAnchorID,
        start: int,
        end: int,
        subtree_hash: bytes,
        timestamp: int = 0,
    ) -> CosignedMessage:
        """Build the message this cosigner would sign for that subtree."""
        return CosignedMessage(
            cosigner_id=self.cosigner_id,
            log_id=log_id,
            start=start,
            end=end,
            subtree_hash=subtree_hash,
            timestamp=timestamp,
        )

    def sign_subtree(
        self,
        log_id: TrustAnchorID,
        start: int,
        end: int,
        subtree_hash: bytes,
        timestamp: int = 0,
    ) -> SubtreeSignature:
        """Sign a subtree, recording it in this cosigner's own consistency set.

        Section 5.3.2 holds a cosigner responsible for *both* the subtree being
        consistent with its other signatures and its role-specific statements.
        Recording the interval here is how the lab makes that visible: a
        cosigner that is handed an inconsistent subtree should complain, and
        the workshop can watch it do so.
        """
        if not tree.is_valid_subtree(start, end):
            raise ValueError(f"[{start}, {end}) is not a valid subtree of the log")
        if not _intervals_consistent(self._signed, start, end):
            raise ValueError(
                f"{self.cosigner_id.short} has already signed a subtree that "
                f"conflicts with [{start}, {end})"
            )
        message = self.message_for(log_id, start, end, subtree_hash, timestamp)
        self._signed.append((start, end))
        return SubtreeSignature(
            cosigner_id=self.cosigner_id, signature=self.private_key.sign(message.encode())
        )

    def verify_subtree(
        self,
        log_id: TrustAnchorID,
        start: int,
        end: int,
        subtree_hash: bytes,
        signature: bytes,
        timestamp: int = 0,
    ) -> bool:
        """Check a cosignature, as the relying party does in Section 7.2 step 12.

        ``timestamp`` must match the value the cosigner signed with. It is zero
        for every cosignature inside a certificate (Section 6.2) and non-zero
        only for a checkpoint cosignature (Section 5.3.2).
        """
        from cryptography.exceptions import InvalidSignature

        message = self.message_for(log_id, start, end, subtree_hash, timestamp)
        try:
            self.public_key.verify(signature, message.encode())
        except InvalidSignature:
            return False
        return True

    def __str__(self) -> str:
        return f"{self.role} cosigner {self.cosigner_id.short}"


def _intervals_consistent(
    signed: Sequence[Tuple[int, int]], start: int, end: int
) -> bool:
    """Return ``True`` if the new interval is consistent with what was signed.

    Subtrees of one log are consistent when they are equal or disjoint, or when
    one contains the other -- that is, when the two intervals are nested or
    apart. Two valid subtrees can still overlap without nesting (in a 20-entry
    log, ``[0, 12)`` and ``[8, 16)`` both qualify and disagree about entries 8
    through 11), and signing both is exactly what Section 5.3.2 forbids: the
    cosigner would be held responsible for its statements on entries in an
    inconsistent subtree.
    """
    for other_start, other_end in signed:
        nested = (other_start <= start and end <= other_end) or (
            start <= other_start and other_end <= end
        )
        disjoint = end <= other_start or other_end <= start
        if not (nested or disjoint):
            return False
    return True


def generate_cosigner(
    cosigner_id: TrustAnchorID, role: str = "external", parameter_set: str = "mldsa44"
) -> Cosigner:
    """Generate a cosigner with a real ML-DSA key.

    ``parameter_set`` is ``mldsa44`` (the draft's cosignature default) or
    ``mldsa65``.
    """
    _load_mldsa()
    return Cosigner(
        cosigner_id=cosigner_id,
        private_key=_new_private_key(parameter_set),
        role=role,
        parameter_set=parameter_set,
    )


def load_public_key(algorithm: str, spki: bytes) -> Any:
    """Load a DER public key for a parameter set name, or ``None`` if unknown.

    A client's cosigner table stores ``(algorithm, key)`` pairs rather than live
    key objects, so this is how a stored key becomes something it can verify
    with. Returning ``None`` for an unknown name is deliberate: an algorithm this
    lab does not implement must fail as "cannot check" rather than as an
    exception, because a client that cannot verify has to refuse the
    certificate, not crash.
    """
    try:
        _key_class(algorithm)
    except (KeyError, RuntimeError):
        return None
    try:
        return load_public_key_bytes(spki)
    except Exception:  # pragma: no cover - malformed key bytes
        return None


def load_public_key_bytes(spki: bytes) -> Any:
    """Load any DER SubjectPublicKeyInfo into a verifying key object."""
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    return load_der_public_key(spki)


def ca_cosigner(ca_id: TrustAnchorID, parameter_set: str = "mldsa44") -> Cosigner:
    """Generate the CA's own cosigner (Section 5.4).

    "Each CA MUST operate a CA cosigner whose cosigner ID is the same as its CA
    ID."
    """
    return generate_cosigner(ca_id, role="CA", parameter_set=parameter_set)


class CertificateSigner:
    """The CA's ordinary certificate-signing key, for the directly signed shape.

    This is a *different* key from the cosigner above, and the distinction is
    the point of the workshop. A cosigner key may only sign subtree hashes
    (Section 5.3.1) and a cosigner client may only verify against subtrees it
    holds; an ordinary CA key signs certificate bodies and is verified through
    the normal PKI. MTC certificates remove the need for this key to be checked
    at all, which is why the landmark-relative shape ends up with no signature
    to hold.
    """

    def __init__(self, ca_id: TrustAnchorID, parameter_set: str = "mldsa65") -> None:
        self.ca_id = ca_id
        self.parameter_set = parameter_set
        self.private_key = _new_private_key(parameter_set)

    @property
    def public_key(self) -> Any:
        return self.private_key.public_key()

    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(*_SPKI_ARGS)

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature

        try:
            self.public_key.verify(signature, message)
        except InvalidSignature:
            return False
        return True

    def __str__(self) -> str:
        return f"certificate signing key for {self.ca_id.short} ({self.parameter_set})"


def certificate_signer(ca_id: TrustAnchorID, parameter_set: str = "mldsa65") -> CertificateSigner:
    """Generate the CA's ordinary certificate-signing key."""
    return CertificateSigner(ca_id, parameter_set)


def signature_sizes(parameter_set: str = "mldsa44") -> Tuple[int, int]:
    """Measure the ``(public key, signature)`` byte sizes for a parameter set.

    Measured, not asserted: the size table in exercise 05 is supposed to be
    the lab's own output, so this generates a throwaway key and signs a byte
    with it. ML-DSA-44 comes out at 1 334 + 2 420 bytes and ML-DSA-65 at
    1 974 + 3 309.
    """
    if parameter_set in _MEASURED_SIZES:
        return _MEASURED_SIZES[parameter_set]
    _load_mldsa()
    key_class = {"mldsa44": Mldsa44PrivateKey, "mldsa65": Mldsa65PrivateKey}[parameter_set]
    private = key_class.generate()
    sizes = (len(private.public_key().public_bytes(*_SPKI_ARGS)), len(private.sign(b"")))
    _MEASURED_SIZES[parameter_set] = sizes
    return sizes


def verify_with_public_key(
    log_id: TrustAnchorID,
    cosigner_id: TrustAnchorID,
    public_key: Any,
    start: int,
    end: int,
    subtree_hash: bytes,
    signature: bytes,
) -> bool:
    """Verify a cosignature with a bare public key, as a client would.

    This is the relying-party side of :meth:`Cosigner.verify_subtree`: the
    client knows the cosigner ID and the key it resolves to, and nothing else.
    """
    from cryptography.exceptions import InvalidSignature

    message = CosignedMessage(
        cosigner_id=cosigner_id,
        log_id=log_id,
        start=start,
        end=end,
        subtree_hash=subtree_hash,
    )
    try:
        public_key.verify(signature, message.encode())
    except InvalidSignature:
        return False
    return True


def describe_cosignatures(signatures: Sequence[SubtreeSignature]) -> str:
    """One-line summary of a cosignature set, for the exercise output."""
    if not signatures:
        return "none"
    return ", ".join(str(sig) for sig in signatures)
