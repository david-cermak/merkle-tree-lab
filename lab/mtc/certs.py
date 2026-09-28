"""The three certificate shapes, and what a client needs to check each (Section 6).

Everything else in this package exists to produce one of these. Section 6.1
covers a certificate with a conventional signature; Section 6.3 gives it a
proof and two cosignatures instead; Section 6.4 removes the signatures by
pointing at a hash the client already has. The workshop compares all three, so
this module builds all three and :func:`shape_sizes` measures them.

The shapes differ in exactly two places, and both are visible in the structures
below.

**The proof.** Every shape has an :class:`MTCProof`, holding the log ID, the
subtree interval, the inclusion proof, and the extensions. What differs is the
tail: two :class:`SubtreeSignature` objects for the checkpoint-relative forms,
or a landmark number for the landmark-relative form. The ASN.1 makes this a
``CHOICE``, so a proof is in exactly one of the two forms, and
:class:`MTCProof` refuses to construct one that is in both or neither.

**The signature.** Only the directly signed certificate has
``SignatureAlgorithm`` and ``SignatureValue``. A Merkle Tree Certificate has
neither, and that is not an omission in this lab -- it is the claim the whole
design makes. The 2 420 bytes of an ML-DSA-44 cosignature are the single
largest thing in a certificate, so removing them is where the size win comes
from.

One consequence is worth naming, because it decides the structure above. In
Section 6.1 the ``MTCProof`` sits *inside* the signed body, so
:meth:`MerkleTreeCertificate.tbs_encoded_for_signing` includes it. A client
therefore cannot drop the proof to save space: the cosignature covers it, so
removing it invalidates the certificate. Exercise 03 walks through that.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from . import wire
from .cosigners import HASH_SIZE, CertificateSigner, Cosigner, SubtreeSignature, sort_signatures
from .ids import LOGS, TrustAnchorID
from .landmarks import Landmark
from .log import IssuanceLog, encode_extensions, parse_extensions
from .tree import covering_subtree, is_valid_subtree

#: Proof forms. These name the ASN.1 CHOICE alternatives in Section 6.1.
CHECKPOINT_RELATIVE = "checkpoint_relative"
LANDMARK_RELATIVE = "landmark_relative"

#: Field identifiers for the encoded certificate body, in declaration order.
#: The two shapes share a prefix on purpose: they have the same version, serial,
#: issuer, validity, subject, and subject public key, and differ only in what
#: stands in for a signature -- ``C_PROOF`` for the MTC shapes,
#: ``C_SIGNATURE_ALGORITHM`` plus a signature for the directly signed one. That
#: is the whole comparison, visible in the bytes.
C_VERSION = 1
C_SERIAL = 2
C_ISSUER = 3
C_SUBJECT = 4
C_SPKI_ALGORITHM = 5
C_SPKI_HASH = 6
C_SPKI = 7
C_VALIDITY = 8
C_EXTENSIONS = 9
C_PROOF = 10
C_SIGNATURE_ALGORITHM = 11


@dataclass(frozen=True)
class MTCProof:
    """The proof carried by every Merkle Tree Certificate (Section 6.1).

    The interval is the *subtree* the proof is about, not the log: for a
    tree-relative certificate it is the whole tree ``[0, N)``, and for a
    landmark-relative one it is the landmark subtree holding the entry. The
    ``landmark`` field is what tells them apart, and the invariant is that
    checkpoint-relative means two cosignatures and landmark-relative means none.
    """

    log_id: TrustAnchorID
    log_number: int
    entry_index: int
    subtree_start: int
    subtree_end: int
    inclusion_proof: Tuple[bytes, ...]
    #: The *log entry's* extension list, already length-prefixed. Not the
    #: certificate's own SANs -- Section 6.2 copies the entry's extensions into
    #: the proof, and conflating the two is the mistake exercise 05 asks
    #: students to make on purpose.
    extensions: bytes = b""
    subtree_cosignatures: Tuple[SubtreeSignature, ...] = ()
    landmark: Optional[int] = None

    def __post_init__(self) -> None:
        if self.subtree_end <= self.subtree_start:
            raise ValueError(
                f"subtree [{self.subtree_start}, {self.subtree_end}) is empty or inverted"
            )
        if not is_valid_subtree(self.subtree_start, self.subtree_end):
            # Section 4.1: start must be a multiple of BIT_CEIL(end - start),
            # which is what makes MTH(D[start:end]) aligned enough to support
            # subtree consistency proofs. Note that every [0, x) is valid --
            # zero is a multiple of everything -- so the rejected intervals are
            # the misaligned ones like [5, 8) or [17, 20), not short prefixes.
            # A proof over a misaligned interval claims a shape the tree cannot
            # produce, and the client would reject it later for no visible
            # reason.
            raise ValueError(
                f"[{self.subtree_start}, {self.subtree_end}) is not a subtree; "
                "subtree intervals are built up from powers of two (Section 4.1)"
            )
        if not self.subtree_start <= self.entry_index < self.subtree_end:
            raise ValueError(
                f"index {self.entry_index} is outside [{self.subtree_start}, {self.subtree_end})"
            )
        if self.landmark is None and len(self.subtree_cosignatures) != 2:
            raise ValueError(
                "a checkpoint-relative proof needs exactly two subtree cosignatures, "
                f"got {len(self.subtree_cosignatures)}"
            )
        if self.landmark is not None and self.subtree_cosignatures:
            raise ValueError("a landmark-relative proof carries no subtree cosignatures")
        if self.log_id.arcs[-2:] != (LOGS, self.log_number):
            # The proof names a log by number, and the log ID it was built
            # against has to be *that* log's ID. A mismatch means the proof was
            # assembled from two different logs, and every later check would
            # then be treating them as one tree.
            raise ValueError(
                f"proof is for log {self.log_number}, but the log ID is "
                f"{self.log_id.dotted}"
            )

    @property
    def is_landmark_relative(self) -> bool:
        return self.landmark is not None

    def interval(self) -> Tuple[int, int]:
        return self.subtree_start, self.subtree_end

    def encoded(self) -> bytes:
        """Encode as ``MTCProof``, following the CHOICE in Section 6.1.

        A leading tag byte distinguishes the two forms so a decoder never has
        to guess, then the landmark number in the landmark-relative case, then
        the shared fields, then the cosignatures (none, in the landmark case).

        Each cosignature is encoded in full, cosigner ID and all. Dropping the
        ID would leave a signature a client cannot attribute to anybody, which
        is the one thing the ``Signatures`` vector of Section 6.1 exists to
        prevent.
        """
        shared = wire.uint(self.log_number, 2) + wire.uint(self.entry_index, 6)
        shared += wire.uint(self.subtree_start, 4) + wire.uint(self.subtree_end, 4)
        shared += wire.vector(self.inclusion_proof)
        # The field is already a length-prefixed vector, because it is the
        # log entry's own extension list copied across verbatim. Re-wrapping it
        # would add a second length prefix, and the two would disagree.
        shared += self.extensions
        if self.landmark is None:
            cosignatures = wire.vector(
                signature.encode() for signature in self.subtree_cosignatures
            )
            return wire.uint(0, 1) + shared + cosignatures
        return wire.uint(1, 1) + wire.uint(self.landmark, 4) + shared + wire.vector(())

    @classmethod
    def decode(cls, data: bytes, log_id: TrustAnchorID) -> "MTCProof":
        """Read a proof back, choosing the form from its leading tag.

        The tag is what stops a decoder from guessing between the two forms of
        the Section 6.1 CHOICE. Each cosignature is decoded through
        :meth:`SubtreeSignature.decode`, so a cosigner ID comes back with it,
        and the count is checked against the form: the draft requires cosignatures
        on a checkpoint-relative proof and none at all on a landmark-relative
        one.
        """
        reader = wire.Reader(data)
        form = reader.uint(1)
        if form not in (0, 1):
            raise ValueError(f"unknown MTCProof form {form}")
        landmark = reader.uint(4) if form == 1 else None
        log_number = reader.uint(2)
        entry_index = reader.uint(6)
        subtree_start = reader.uint(4)
        subtree_end = reader.uint(4)
        inclusion_proof = _read_hashes(reader)
        # Already length-prefixed, so read the whole vector rather than a body.
        extensions = reader.vector_bytes()
        cosignatures = tuple(_read_cosignatures(reader))
        reader.expect_end()
        if landmark is None and not cosignatures:
            raise ValueError("a checkpoint-relative proof must carry its cosignatures")
        if landmark is not None and cosignatures:
            raise ValueError(
                f"a landmark-relative proof must carry no cosignatures, got "
                f"{len(cosignatures)}"
            )
        # The log ID is not in the proof's own bytes -- only the log *number*
        # is, since that is what the serial already encodes (Section 6.2). So
        # the ID is a parameter rather than a decoded field.
        return cls(
            log_id=log_id,
            log_number=log_number,
            entry_index=entry_index,
            subtree_start=subtree_start,
            subtree_end=subtree_end,
            inclusion_proof=inclusion_proof,
            subtree_cosignatures=cosignatures,
            landmark=landmark,
            extensions=extensions,
        )

    @classmethod
    def decode_for_log(cls, data: bytes, log_id: TrustAnchorID) -> "MTCProof":
        """Decode a proof against the log the caller already knows it is from.

        Section 6.1 puts ``log_number`` in the proof, not the full log ID: a
        client reading a certificate has already decided which log it is asking
        about, and the two have to agree. ``__post_init__`` is what checks that,
        so passing the wrong log here fails loudly instead of producing a proof
        that hashes against the wrong tree.
        """
        return cls.decode(data, log_id)

    def __str__(self) -> str:
        form = LANDMARK_RELATIVE if self.is_landmark_relative else CHECKPOINT_RELATIVE
        target = f"landmark {self.landmark}" if self.landmark is not None else "checkpoint"
        return (
            f"{form} proof, {target}, index {self.entry_index} "
            f"in [{self.subtree_start}, {self.subtree_end}), "
            f"{len(self.inclusion_proof)} proof hashes, "
            f"{len(self.subtree_cosignatures)} cosignatures"
        )


def _body_fields(
    serial_number: int,
    issuer: TrustAnchorID,
    subject: str,
    algorithm: str,
    spki: bytes,
    validity: Tuple[int, int],
    subject_alt_names: Sequence[str] = (),
) -> List[Tuple[int, bytes]]:
    """The certificate body fields shared by every shape.

    The issuer is in here because the client looks up the CA key *by* the
    issuer: if the issuer were not covered by what is signed, a certificate
    could be re-issued under a different name and the signature would still
    verify. For the directly signed shape that is a live attack, so the field
    has to be inside the signed body rather than beside it.

    The SPKI appears twice on purpose: hashed (so it can be compared against
    the log entry without a parser) and in full (so the certificate is usable
    on its own). The entry has only the hash, which is why the certificate is
    larger than the log entry it points at.

    ``subject_alt_names`` is the certificate's *own* extension, and it is a
    different extension list from ``MTCProof.extensions``: the proof carries the
    log entry's extensions, while these are what a client reads to rebuild the
    entry. Both are hashed, and getting the distinction backwards produces an
    entry that hashes wrong -- which is exactly the mistake exercise 05 asks
    students to make on purpose.
    """
    return [
        (C_VERSION, wire.uint(2, 1)),
        (C_SERIAL, wire.uint(serial_number, 8)),
        (C_ISSUER, issuer.relative_oid()),
        (C_SUBJECT, subject.encode("utf-8")),
        (C_SPKI_ALGORITHM, algorithm.encode("ascii")),
        (C_SPKI_HASH, hashlib.sha256(spki).digest()),
        (C_SPKI, spki),
        (
            C_VALIDITY,
            wire.uint(validity[0], 8) + wire.uint(validity[1], 8),
        ),
        (C_EXTENSIONS, encode_extensions(subject_alt_names)),
    ]


def _peek_proof_log_number(proof_bytes: bytes) -> int:
    """Return the log number a proof names, without parsing the whole proof.

    Needed before the proof can be decoded, because decoding it needs the log ID
    and the two have to agree. The offset depends on the form: the landmark-relative
    one carries a four-byte landmark number where the other carries nothing, so
    the fixed-width fields start in different places.
    """
    reader = wire.Reader(proof_bytes)
    form = reader.uint(1)
    if form not in (0, 1):
        raise ValueError(f"unknown MTCProof form {form}")
    if form == 1:
        reader.skip(4)  # landmark number
    return reader.uint(2)


def _read_hashes(reader: wire.Reader) -> Tuple[bytes, ...]:
    """Read the inclusion proof's vector of fixed-size hashes.

    Fixed at :data:`HASH_SIZE` rather than a variable-length ``opaque`` because
    the proof's length has to be checkable: a 31-byte hash would otherwise
    decode happily and fail later, against a hash the client computed.
    """
    body = wire.Reader(reader.vector_body())
    hashes = []
    while not body.at_end():
        hashes.append(body.opaque(HASH_SIZE))
    return tuple(hashes)


def _read_cosignatures(reader: wire.Reader) -> List[SubtreeSignature]:
    """Decode the ``Signatures`` vector of Section 6.1.

    Split out because the vector holds elements that are not ``opaque``, and
    :mod:`lab.mtc.wire` should not have to know what a cosignature is. Each
    element reads until it is done, so they are parsed in order from the shared
    body rather than split by a length prefix the encoding does not have.
    """
    body = wire.Reader(reader.vector_body())
    signatures = []
    while not body.at_end():
        before = body.remaining
        signatures.append(SubtreeSignature.decode(body))
        if body.remaining == before:
            raise ValueError("a cosignature consumed no bytes; the encoding is not aligned")
    return signatures


def _encode_body(fields: Sequence[Tuple[int, bytes]]) -> bytes:
    return wire.vector(wire.uint(field, 1) + wire.opaque_var(value, 2) for field, value in fields)


def _decode_body_fields(reader: wire.Reader) -> Dict[int, bytes]:
    """Read the body's ``(identifier, value)`` pairs, rejecting disorder.

    The identifiers ascend on the wire because :func:`_body_fields` emits them in
    declaration order, and a decoder that accepted any order would accept a
    layout the lab never produces -- one where two fields had traded places
    while the signed bytes stayed the same length.
    """
    fields: Dict[int, bytes] = {}
    body = wire.Reader(reader.vector_body())
    previous = 0
    while not body.at_end():
        field = body.uint(1)
        if field <= previous:
            raise ValueError(
                f"certificate field {field} is out of order or repeated "
                f"(previous was {previous})"
            )
        previous = field
        fields[field] = body.opaque_var(2)
    return fields


def _require(fields: Dict[int, bytes], field: int, name: str) -> bytes:
    if field not in fields:
        raise ValueError(f"certificate is missing its {name} field")
    return fields[field]


def _decode_validity(fields: Dict[int, bytes]) -> Tuple[int, int]:
    reader = wire.Reader(_require(fields, C_VALIDITY, "validity"))
    not_before = reader.uint(8)
    not_after = reader.uint(8)
    if not reader.at_end():
        raise ValueError("trailing bytes in the validity field")
    if not_after < not_before:
        raise ValueError("validity ends before it starts")
    version = _require(fields, C_VERSION, "version")
    if version != wire.uint(2, 1):
        raise ValueError(f"unsupported certificate version {version!r}, expected 2")
    return not_before, not_after


def _decode_spki_hash(fields: Dict[int, bytes]) -> bytes:
    """Check that the stored SPKI hash still matches the SPKI beside it.

    Both are inside the signed body, so a mismatch is not an encoding problem:
    it means the certificate carries a key and a hash of a *different* key, and
    the reconstruction would fail on the entry hash with nothing to point at
    the real cause.
    """
    spki = _require(fields, C_SPKI, "subjectPublicKeyInfo")
    stored = _require(fields, C_SPKI_HASH, "subjectPublicKeyInfoHash")
    if stored != hashlib.sha256(spki).digest():
        raise ValueError("subjectPublicKeyInfoHash does not match subjectPublicKeyInfo")
    return stored


@dataclass(frozen=True)
class MerkleTreeCertificate:
    """A Merkle Tree Certificate: a body, a proof, and no signature.

    The absence of ``SignatureAlgorithm`` and ``SignatureValue`` is the design,
    not an omission. :meth:`tbs_encoded_for_signing` still exists because a
    cosigner signs the certificate body *including* the proof; that is what ties
    the proof to the certificate without the certificate having a signature of
    its own.
    """

    serial_number: int
    subject: str
    subject_public_key_algorithm: str
    subject_public_key_info: bytes
    validity: Tuple[int, int]
    subject_alt_names: Tuple[str, ...]
    issuer: TrustAnchorID
    mtc_proof: MTCProof

    def subject_public_key_info_hash(self) -> bytes:
        return hashlib.sha256(self.subject_public_key_info).digest()

    def tbs_encoded(self) -> bytes:
        return _encode_body(
            _body_fields(
                self.serial_number,
                self.issuer,
                self.subject,
                self.subject_public_key_algorithm,
                self.subject_public_key_info,
                self.validity,
                self.subject_alt_names,
            )
        )

    def tbs_encoded_for_signing(self) -> bytes:
        """Return what a cosigner signs: the body with the proof inside it."""
        return self.tbs_encoded() + self.mtc_proof.encoded()

    def encoded(self) -> bytes:
        return self.tbs_encoded_for_signing()

    @classmethod
    def decode(
        cls, data: bytes, log_id: Optional[TrustAnchorID] = None
    ) -> "MerkleTreeCertificate":
        """Read a certificate back out of the bytes a cosigner signed.

        The proof is a tail with no length prefix -- it is the last field, and
        Section 6.1 puts the cosignatures inside it -- so the body is read from
        its own length prefix and the proof is whatever follows. Getting that
        boundary wrong would move one byte between the two, and the entry
        reconstruction would then fail on a hash rather than on a parse.

        ``log_id`` is the log this certificate is about. It is not in the
        certificate's bytes: the serial encodes ``(log_number, index)`` and
        Section 6.1 puts only the log *number* in the proof. A client knows
        which log it is asking about, so it supplies the ID. When it is omitted
        the ID is rebuilt from the issuer and the proof's log number, which is
        the reconstruction a CA-side reader would do.
        """
        reader = wire.Reader(data)
        fields = _decode_body_fields(reader)
        proof_bytes = reader.rest()
        if not proof_bytes:
            raise ValueError("a Merkle Tree Certificate needs an MTCProof")
        spki = _require(fields, C_SPKI, "subjectPublicKeyInfo")
        _decode_spki_hash(fields)
        issuer = TrustAnchorID.from_relative_oid(_require(fields, C_ISSUER, "issuer"))
        proof_log_number = _peek_proof_log_number(proof_bytes)
        if log_id is None:
            log_id = issuer.log(proof_log_number)
        elif log_id.log_number != proof_log_number:
            raise ValueError(
                f"certificate is for log {proof_log_number}, but was decoded "
                f"against log {log_id.log_number}"
            )
        return cls(
            serial_number=int.from_bytes(
                _require(fields, C_SERIAL, "serialNumber"), "big"
            ),
            issuer=issuer,
            subject=_require(fields, C_SUBJECT, "subject").decode("utf-8"),
            subject_public_key_algorithm=_require(
                fields, C_SPKI_ALGORITHM, "subjectPublicKeyAlgorithm"
            ).decode("ascii"),
            subject_public_key_info=spki,
            validity=_decode_validity(fields),
            subject_alt_names=parse_extensions(
                _require(fields, C_EXTENSIONS, "extensions")
            ),
            mtc_proof=MTCProof.decode_for_log(proof_bytes, log_id),
        )

    def __str__(self) -> str:
        return f"MTC certificate for {self.subject}, serial {self.serial_number}, {self.mtc_proof}"


@dataclass(frozen=True)
class DirectCertificate:
    """An ordinary certificate: the same body, plus a real signature.

    Shape 1 in the workshop. It exists so the other shapes have something to be
    measured against -- same key, same subject, same validity, and the only
    difference is the signature at the end.
    """

    serial_number: int
    subject: str
    subject_public_key_algorithm: str
    subject_public_key_info: bytes
    validity: Tuple[int, int]
    subject_alt_names: Tuple[str, ...]
    issuer: TrustAnchorID
    signature: bytes

    def subject_public_key_info_hash(self) -> bytes:
        return hashlib.sha256(self.subject_public_key_info).digest()

    def tbs_encoded(self) -> bytes:
        """Return the body, and for this shape the signature algorithm with it.

        An ordinary certificate has to name the algorithm that made its
        signature, because the key is chosen by whoever receives the
        certificate. A Merkle Tree Certificate does not: the cosigners are named
        in the proof instead, which is why :meth:`signature_algorithm` is a
        report about the subject key rather than a field in the bytes.
        """
        return _encode_body(
            _body_fields(
                self.serial_number,
                self.issuer,
                self.subject,
                self.subject_public_key_algorithm,
                self.subject_public_key_info,
                self.validity,
                self.subject_alt_names,
            )
            + [(C_SIGNATURE_ALGORITHM, self.signature_algorithm().encode("ascii"))]
        )

    def signature_algorithm(self) -> str:
        return self.subject_public_key_algorithm

    def tbs_encoded_for_signing(self) -> bytes:
        return self.tbs_encoded()

    def encoded(self) -> bytes:
        return self.tbs_encoded() + wire.opaque_var(self.signature, 2)

    @classmethod
    def decode(cls, data: bytes) -> "DirectCertificate":
        """Read a directly signed certificate back out of its DER.

        The body here is the same ``(identifier, value)`` vector the other
        shapes use, plus the signature algorithm and then the signature itself
        as a trailing opaque. The two differ in layout at exactly the end: an
        MTCProof is unframed because its cosignatures are inside it, so a
        decoder for one cannot be reused for the other without knowing which
        shape it is looking at first.
        """
        reader = wire.Reader(data)
        fields = _decode_body_fields(reader)
        algorithm = _require(fields, C_SIGNATURE_ALGORITHM, "signatureAlgorithm")
        signature = reader.opaque_var(2)
        reader.expect_end()
        _decode_validity(fields)
        _decode_spki_hash(fields)
        subject_key_algorithm = _require(
            fields, C_SPKI_ALGORITHM, "subjectPublicKeyAlgorithm"
        ).decode("ascii")
        if algorithm.decode("ascii") != subject_key_algorithm:
            # This shape is signed by the subject's own key, so the two
            # algorithms have to name the same thing. A client that believed
            # the signatureAlgorithm field would try to verify an ML-DSA-65
            # signature with an Ed25519 key, or the other way round.
            raise ValueError(
                f"signatureAlgorithm is {algorithm.decode('ascii')!r} but the "
                f"subject key is {subject_key_algorithm!r}"
            )
        return cls(
            serial_number=int.from_bytes(
                _require(fields, C_SERIAL, "serialNumber"), "big"
            ),
            subject=_require(fields, C_SUBJECT, "subject").decode("utf-8"),
            subject_public_key_algorithm=_require(
                fields, C_SPKI_ALGORITHM, "subjectPublicKeyAlgorithm"
            ).decode("ascii"),
            subject_public_key_info=_require(fields, C_SPKI, "subjectPublicKeyInfo"),
            validity=_decode_validity(fields),
            subject_alt_names=parse_extensions(
                _require(fields, C_EXTENSIONS, "extensions")
            ),
            issuer=TrustAnchorID.from_relative_oid(_require(fields, C_ISSUER, "issuer")),
            signature=signature,
        )

    def __str__(self) -> str:
        return f"directly signed certificate for {self.subject}, serial {self.serial_number}"


def _cosign_subtree(
    log: IssuanceLog, cosigners: Sequence[Cosigner], interval: Tuple[int, int]
) -> Tuple[SubtreeSignature, SubtreeSignature]:
    """Cosign one subtree with two cosigners, ordered by cosigner ID.

    Both cosigners sign the *same* interval, which is what
    ``docs/mtc-draft.txt`` requires: every element of ``MTCProof.signatures`` is
    a cosignature over the proof's ``start`` and ``end``, so the two signatures
    differ in who made them, not in what they cover.

    One cosignature covers many certificates, though, which is the point of
    Section 6.3 step 5. A batch of certificates added since the last checkpoint
    all live inside the same two covering subtrees, so this runs twice per batch
    and every certificate in the batch reuses the results.

    The ordering rule is not cosmetic: a parser MUST reject an unordered list
    (Section 6.2), and :func:`sort_signatures` is where the lab enforces it.
    """
    if len(cosigners) != 2:
        raise ValueError(f"expected 2 cosigners, got {len(cosigners)}")
    start, end = interval
    signatures = [
        cosigner.sign_subtree(log.log_id, start, end, log.subtree_hash(start, end))
        for cosigner in cosigners
    ]
    return tuple(sort_signatures(signatures))  # type: ignore[return-value]


def _cert_from_entry(
    log: IssuanceLog, index: int, proof: MTCProof, spki: bytes, algorithm: str
) -> MerkleTreeCertificate:
    """Build a certificate from a logged entry and a proof.

    The subject's key is passed in rather than read out of the log, because the
    log does not have it -- that is the point of ``subjectPublicKeyInfoHash``.
    A client holding a certificate therefore learns its key from the
    certificate, and the log's job is only to attest that this key belongs to
    this name.
    """
    entry = log.entries[index]
    if entry.tbs_certificate is None:
        raise ValueError(f"entry {index} is a null entry and certifies nothing")
    tbs = entry.tbs_certificate
    if hashlib.sha256(spki).digest() != tbs.subject_public_key_info_hash:
        raise ValueError("the supplied key is not the one this entry attests")
    return MerkleTreeCertificate(
        serial_number=log.serial(index),
        subject=tbs.subject,
        subject_public_key_algorithm=algorithm,
        subject_public_key_info=spki,
        validity=(tbs.not_before, tbs.not_after),
        subject_alt_names=tbs.subject_alt_names,
        issuer=log.ca_id,
        mtc_proof=proof,
    )


def issue_tree_relative(
    log: IssuanceLog,
    index: int,
    spki: bytes,
    algorithm: str,
    cosigners: Sequence[Cosigner],
    interval: Optional[Tuple[int, int]] = None,
) -> MerkleTreeCertificate:
    """Issue a certificate valid against the whole tree (Section 6.3).

    ``interval`` defaults to the whole log, ``[0, N)``, which is the standalone
    form: the proof has ``log2(N)`` hashes and the two cosignatures cover the
    entire tree. A checkpoint-relative certificate is the same construction with
    ``interval`` set to the covering subtree that holds the entry, which is what
    a client with a recent checkpoint in hand needs.
    """
    if interval is None:
        interval = (0, log.size)
    start, end = interval
    signatures = _cosign_subtree(log, cosigners, interval)
    proof = MTCProof(
        log_id=log.log_id,
        log_number=log.log_number,
        entry_index=index,
        subtree_start=start,
        subtree_end=end,
        inclusion_proof=tuple(log.inclusion_proof(start, end, index)),
        extensions=log.entries[index].encoded_extensions(),
        subtree_cosignatures=signatures,
    )
    return _cert_from_entry(log, index, proof, spki, algorithm)


def issue_landmark_relative(
    log: IssuanceLog,
    index: int,
    spki: bytes,
    algorithm: str,
    landmark: Optional[Landmark] = None,
) -> MerkleTreeCertificate:
    """Issue a certificate that depends only on a landmark (Section 6.4).

    The two cosignatures are gone, so this function takes no cosigners: the
    client supplies the landmark subtree hash instead, out of band. The
    certificate is smaller by exactly the size of two cosignatures, which is
    the number the workshop asks students to compute rather than read off a
    slide.
    """
    if landmark is None:
        raise ValueError("a landmark-relative certificate needs its landmark")
    start, end = landmark.subtree_for(index)
    if end > log.size:
        raise ValueError(
            f"landmark {landmark.number} covers [{start}, {end}) "
            f"but the log has only {log.size} entries"
        )
    proof = MTCProof(
        log_id=log.log_id,
        log_number=log.log_number,
        entry_index=index,
        subtree_start=start,
        subtree_end=end,
        inclusion_proof=tuple(log.inclusion_proof(start, end, index)),
        extensions=log.entries[index].encoded_extensions(),
        landmark=landmark.number,
    )
    return _cert_from_entry(log, index, proof, spki, algorithm)


def direct_certificate_for_entry(
    log: IssuanceLog,
    index: int,
    spki: bytes,
    algorithm: str,
    signer: CertificateSigner,
) -> DirectCertificate:
    """Sign a directly signed certificate for an entry that is already logged.

    This is the one shape with no MTC proof, so it is also the only one where
    the certificate's validity rests entirely on the signature. Note that the
    serial number is still the log's ``(log_number, index)`` pair: a client
    holding this certificate can still ask the log about it, which is how a CA
    that issues both shapes stays consistent.
    """
    entry = log.entries[index]
    if entry.tbs_certificate is None:
        raise ValueError(f"entry {index} is a null entry and certifies nothing")
    tbs = entry.tbs_certificate
    cert = DirectCertificate(
        serial_number=log.serial(index),
        subject=tbs.subject,
        subject_public_key_algorithm=algorithm,
        subject_public_key_info=spki,
        validity=(tbs.not_before, tbs.not_after),
        subject_alt_names=tbs.subject_alt_names,
        issuer=log.ca_id,
        signature=b"",
    )
    if cert.subject_public_key_info_hash() != tbs.subject_public_key_info_hash:
        raise ValueError("the supplied key is not the one this entry attests")
    return DirectCertificate(
        serial_number=cert.serial_number,
        subject=cert.subject,
        subject_public_key_algorithm=cert.subject_public_key_algorithm,
        subject_public_key_info=cert.subject_public_key_info,
        validity=cert.validity,
        subject_alt_names=cert.subject_alt_names,
        issuer=cert.issuer,
        signature=signer.sign(cert.tbs_encoded_for_signing()),
    )


def issue_all_four(
    log: IssuanceLog,
    index: int,
    spki: bytes,
    algorithm: str,
    cosigners: Sequence[Cosigner],
    signer: CertificateSigner,
    landmark: Landmark,
    checkpoint_size: Optional[int] = None,
) -> Dict[str, object]:
    """Cut all four shapes from the entry at ``index`` and return them by name.

    The keys are the names the exercises use: ``direct``, ``standalone``,
    ``checkpoint``, and ``landmark``. The four ``checkpoints`` results are
    deliberately produced from the *same* entry, so comparing their sizes
    compares shapes rather than certificates.
    """
    if checkpoint_size is None:
        checkpoint_size = log.size
    if not 0 < checkpoint_size <= log.size:
        raise ValueError(f"checkpoint size {checkpoint_size} outside [1, {log.size}]")
    covering = covering_subtree(log.leaf_hashes(), 0, checkpoint_size, index)
    return {
        "direct": direct_certificate_for_entry(log, index, spki, algorithm, signer),
        "standalone": issue_tree_relative(log, index, spki, algorithm, cosigners),
        "checkpoint": issue_tree_relative(
            log, index, spki, algorithm, cosigners, interval=covering
        ),
        "landmark": issue_landmark_relative(
            log, index, spki, algorithm, landmark=landmark
        ),
    }


def shape_sizes(
    log: IssuanceLog,
    index: int,
    spki: bytes,
    algorithm: str,
    cosigners: Sequence[Cosigner],
    signer: CertificateSigner,
    landmark: Landmark,
    checkpoint_size: Optional[int] = None,
) -> List[Dict[str, object]]:
    """Return one row per shape with measured sizes, for the workshop's table.

    The table in the exercises is generated from this function, so the numbers
    cannot drift away from the code that produced them. Nothing here appends to
    the log: all four shapes are cut from the same entry, which is the only way
    the comparison is honest. ``signature_bytes`` is reported per shape because
    it is the whole difference between them.

    ``checkpoint_size`` picks which checkpoint the checkpoint-relative shape is
    measured against; it defaults to the whole log, which makes that row
    identical to the standalone one. Pass a real checkpoint size to see the
    proof shrink, which is the point of the shape.
    """
    entry = log.entries[index]
    if entry.tbs_certificate is None:
        raise ValueError(f"entry {index} is a null entry")

    if checkpoint_size is None:
        checkpoint_size = log.size
    if not 0 < checkpoint_size <= log.size:
        raise ValueError(f"checkpoint size {checkpoint_size} outside [1, {log.size}]")
    if checkpoint_size <= index:
        raise ValueError(
            f"index {index} is not inside a checkpoint of size {checkpoint_size}"
        )
    # The checkpoint-relative shape proves against the subtree the *checkpoint*
    # covers. That is the subtree a cosigner signed when the batch of new
    # entries was checkpointed, and it is the only one a client holding that
    # checkpoint can check without a landmark -- the whole point of the shape.
    issued = issue_all_four(
        log, index, spki, algorithm, cosigners, signer, landmark,
        checkpoint_size=checkpoint_size,
    )
    direct = issued["direct"]
    standalone = issued["standalone"]
    checkpoint_relative = issued["checkpoint"]
    landmark_relative = issued["landmark"]

    # Signatures are measured, not assumed: the direct certificate is signed by
    # the CA's ML-DSA-65 key while the cosigners use ML-DSA-44, so the two
    # numbers are different and using one for both would misstate the table.
    def cosignature_bytes(cert: MerkleTreeCertificate) -> int:
        return sum(len(s.signature) for s in cert.mtc_proof.subtree_cosignatures)

    rows = []
    for label, cert, signatures, proof_hashes, needs_landmark in (
        ("directly signed", direct, 1, 0, False),
        ("standalone (tree-relative)", standalone, 2,
         len(standalone.mtc_proof.inclusion_proof), False),
        ("checkpoint-relative", checkpoint_relative, 2,
         len(checkpoint_relative.mtc_proof.inclusion_proof), False),
        ("landmark-relative", landmark_relative, 0,
         len(landmark_relative.mtc_proof.inclusion_proof), True),
    ):
        if isinstance(cert, DirectCertificate):
            signature_bytes = len(cert.signature)
        else:
            signature_bytes = cosignature_bytes(cert)
        rows.append(
            {
                "shape": label,
                "interval": (
                    f"[{cert.mtc_proof.subtree_start}, {cert.mtc_proof.subtree_end})"
                    if not isinstance(cert, DirectCertificate)
                    else "-"
                ),
                "signatures": signatures,
                "signature_bytes": signature_bytes,
                "proof_hashes": proof_hashes,
                "proof_bytes": proof_hashes * 32,
                "landmark_dependent": needs_landmark,
                "bytes": len(cert.encoded()),
                "certificate": str(cert),
            }
        )
    return rows


def format_shape_table(rows: Sequence[Dict[str, object]]) -> str:
    """Render :func:`shape_sizes` output as the markdown table the exercises use."""
    header = (
        "| shape | subtree | signatures | signature bytes | proof hashes | "
        "landmark-dependent | total bytes |"
    )
    rule = "|---|---|---|---|---|---|---|"
    lines = [header, rule]
    for row in rows:
        lines.append(
            f"| {row['shape']} | {row['interval']} | {row['signatures']} | "
            f"{row['signature_bytes']} | {row['proof_hashes']} | "
            f"{'yes' if row['landmark_dependent'] else 'no'} | {row['bytes']} |"
        )
    return "\n".join(lines)
