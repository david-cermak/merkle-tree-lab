"""The CA's issuance log: entries, checkpoints, and serial numbers.

This is the object the whole MTC design exists to build. Section 5.2.1 of the
draft says an entry is a ``TBSCertificateLogEntry``, and the two fields that
distinguish it from an ordinary certificate body are the ones that are *not*
there:

* there is **no signature** -- the entry is an assertion waiting to be covered
  by a subtree signature (Section 5.3);
* there is **no public key** -- only ``subjectPublicKeyInfoHash``, a hash of the
  subject's key, so the log never stores a key it might have to serve later.

So an MTC log entry is *smaller* than the certificate it justifies, and a CT
log entry is *bigger*, because a CT leaf carries the full SPKI and the full
signature. That comparison is the storage-pressure argument in exercise 03, and
this module is where both numbers come from.

The entry is hashed as RFC 6962 hashes a leaf, and the draft's single-pass
recipe in Section 7.2 says exactly what goes in::

    entry_hash = SHA256(0x00 || extensions || uint16(type) || tbs_certificate_log_entry)

Note what is *not* in that list: the identifier and length octets of the
``TBSCertificateLogEntry``. Section 5.2.1 omits them on purpose ("Equivalently,
tbs_cert_entry_data contains the DER encodings of each field of
TBSCertificateLogEntry, concatenated. This construction allows a single-pass
implementation in Section 7.2"), which is why a client can hash a certificate it
is already holding without reassembling the structure.
:meth:`MTCLogEntry.encoded` produces precisely that byte string and nothing else.

**Encoding deviation (D7).** The real structure is DER. This lab encodes the
same fields in the same order as a length-prefixed vector of tagged fields, and
says so, because the workshop needs to *rebuild* an entry and watch its hash
change (exercise 05, question 7) -- an ASN.1 library would hide that. The
serial-number layout, the hash domains, and the leaf construction are exact.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .. import merkle
from . import wire
from .cosigners import Cosigner, SubtreeSignature, sort_signatures
from .ids import TrustAnchorID
from .tree import find_subtrees, subtree_consistency_proof, subtree_hash, subtree_inclusion_proof

#: A fixed "now" so every run of the lab prints the same bytes. A real CA would
#: call ``time.time()``; a workshop that produced a different entry hash on every
#: run could not be discussed against a shared handout. The value is a round
#: number of seconds in the lab's compressed validity encoding, so the printed
#: timestamps are easy to read out loud.
LAB_EPOCH = 1_788_000_000  # 2026-08-29T10:40:00Z

#: The log's hash function is SHA-256 throughout (Section 5).
HASH_SIZE = 32

#: ``MTCLogEntryType`` from Section 5.2.1.
NULL_ENTRY = 0
TBS_CERT_ENTRY = 1

#: Field identifiers for the encoded ``TBSCertificateLogEntry``, in the order the
#: draft's SEQUENCE declares them. ``issuerUniqueID`` and ``subjectUniqueID``
#: are numbered here but the lab never sets them, which is how the "absent in
#: the entry means absent in the certificate" rule of Section 6.2 stays visible.
F_VERSION = 1
F_ISSUER = 2
F_VALIDITY = 3
F_SUBJECT = 4
F_SPKI_ALGORITHM = 5
F_SPKI_HASH = 6
F_ISSUER_UNIQUE_ID = 7
F_SUBJECT_UNIQUE_ID = 8
F_EXTENSIONS = 9

MAX_LOG_NUMBER = 2**16 - 1
MAX_INDEX = 2**48 - 1

#: ``subjectAltName`` from the PKIX extension registry, the only extension the
#: lab puts in an entry. A real CA would copy whatever extensions it put in the
#: certificate; Section 5.2.1 keeps them in the entry, and Section 6.2 copies
#: them into the certificate, which is what lets a client rebuild the entry.
SUBJECT_ALT_NAME = 2


def encode_extensions(subject_alt_names: Sequence[str]) -> bytes:
    """Encode an entry's extension list, with the SANs as one extension.

    The result is what both the entry and the certificate's ``MTCProof`` carry,
    which is what makes a client able to rebuild the entry from the certificate
    alone.
    """
    if not subject_alt_names:
        return wire.vector(())
    data = wire.vector(wire.opaque_var(name.encode("ascii"), 1) for name in subject_alt_names)
    return wire.vector(wire.uint(SUBJECT_ALT_NAME, 2) + wire.opaque_var(data, 2))


def parse_extensions(encoded: bytes) -> Tuple[str, ...]:
    """Read subjectAltNames back out of an encoded extension list.

    Extensions the lab does not model are kept out of the way rather than
    rejected: the draft says a client ignores extensions it does not recognise,
    and a decoder that raised on them would not model that.
    """
    reader = wire.Reader(encoded)
    sans: List[str] = []
    for extension in read_elements(reader, parse_extension):
        if extension[0] == SUBJECT_ALT_NAME:
            sans.extend(parse_subject_alt_names(extension[1]))
    return tuple(sans)


def parse_extension(reader: wire.Reader) -> Tuple[int, bytes]:
    return reader.uint(2), reader.opaque_var(2)


def parse_subject_alt_names(data: bytes) -> Tuple[str, ...]:
    reader = wire.Reader(data)
    return tuple(
        name.decode("ascii") for name in read_elements(reader, lambda r: r.opaque_var(1))
    )


def parse_entry_extensions(encoded: bytes) -> Tuple[MTCLogEntryExtension, ...]:
    """Read the log entry's own extension list.

    The lab issues entries with an empty one, but a client still has to carry it
    across: it is hashed into the leaf before anything else, so a client that
    dropped it would compute a different entry hash. Decoding rather than
    ignoring is what keeps that failure a hash mismatch instead of a wrong
    answer.
    """
    return _read_entry_extensions(wire.Reader(encoded))


def _read_entry_extensions(reader: wire.Reader) -> Tuple[MTCLogEntryExtension, ...]:
    return tuple(read_elements(reader, parse_entry_extension))


def parse_entry_extension(reader: wire.Reader) -> MTCLogEntryExtension:
    return MTCLogEntryExtension(reader.uint(2), reader.opaque_var(2))


def read_elements(reader: wire.Reader, parse) -> List:
    """Parse elements from a vector prefix, in the order they were encoded.

    Keeping the prefix reading here means :mod:`lab.mtc.wire` never has to know
    what a DNS name is, and the strict "no trailing bytes" rule lands on the
    element parser rather than on the whole document.
    """
    body = wire.Reader(reader.vector_body())
    elements = []
    while not body.at_end():
        elements.append(parse(body))
    return elements


def serial_number(log_number: int, index: int) -> int:
    """Return ``(log_number << 48) | index`` (Section 6.2).

    "The serialNumber MUST be equal to (log_number << 48) | index. All serial
    numbers constructed in this way will be positive and at most 2^64-1." This
    is how a client that has never heard of this CA learns which log to ask
    about: the serial number *is* the (log, index) pair.
    """
    if not 1 <= log_number <= MAX_LOG_NUMBER:
        raise ValueError(f"log number {log_number} out of range 1..{MAX_LOG_NUMBER}")
    if not 0 <= index <= MAX_INDEX:
        raise ValueError(f"index {index} out of range 0..{MAX_INDEX}")
    return (log_number << 48) | index


def split_serial(serial: int) -> Tuple[int, int]:
    """Split a serial number into ``(log_number, index)`` (Section 7.2 step 5).

    A negative serial, or one above 2^64-1, is not a Merkle Tree Certificate
    serial at all. A serial with a zero log number is rejected by the caller:
    there is no log zero, so it is a foreign serial wearing this layout.
    """
    if serial < 0 or serial > 2**64 - 1:
        raise ValueError(f"serial {serial} is not in 0..{MAX_LOG_NUMBER}")
    return serial >> 48, serial & MAX_INDEX


@dataclass(frozen=True)
class TbsCertificateLogEntry:
    """The ``TBSCertificateLogEntry`` of Section 5.2.1: no key, no signature.

    The field order follows the draft's SEQUENCE. ``issuer`` is the CA ID as a
    PKIX distinguished name, kept here as the :class:`TrustAnchorID` itself and
    rendered on demand; Section 5.2.1 is explicit that this field "is not
    human-readable".
    """

    issuer: TrustAnchorID
    subject: str
    subject_public_key_algorithm: str
    subject_public_key_info_hash: bytes
    not_before: int
    not_after: int
    subject_alt_names: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if len(self.subject_public_key_info_hash) != HASH_SIZE:
            raise ValueError(f"subjectPublicKeyInfoHash must be {HASH_SIZE} bytes")
        if self.not_after < self.not_before:
            raise ValueError("validity ends before it starts")

    def extensions(self) -> bytes:
        """Encode the extension list, the SANs in it.

        Exercise 05 asks what breaks when this is dropped while rebuilding an
        entry. The answer is this byte string, and with it the entry hash --
        which is why the client's reconstructed entry has to match the CA's
        field for field.
        """
        return encode_extensions(self.subject_alt_names)

    def sans(self) -> Tuple[str, ...]:
        """Return the subjectAltNames, read back out of the extension list."""
        return parse_extensions(self.extensions())

    def encoded(self) -> bytes:
        """Encode the entry's fields, in declaration order.

        Each field is a one-byte identifier plus a two-byte length, all inside
        one vector prefix: a documented stand-in for the DER SEQUENCE.
        """
        validity = wire.uint(self.not_before, 8) + wire.uint(self.not_after, 8)
        fields = (
            (F_VERSION, wire.uint(2, 1)),
            (F_ISSUER, self.issuer.relative_oid()),
            (F_VALIDITY, validity),
            (F_SUBJECT, self.subject.encode("utf-8")),
            (F_SPKI_ALGORITHM, self.subject_public_key_algorithm.encode("ascii")),
            (F_SPKI_HASH, self.subject_public_key_info_hash),
            (F_EXTENSIONS, self.extensions()),
        )
        return wire.vector(
            wire.uint(field_id, 1) + wire.opaque_var(value, 2) for field_id, value in fields
        )

    def without_san(self) -> "TbsCertificateLogEntry":
        """Return a copy with the SANs dropped, for exercise 05 question 7.

        Same subject, same key, same validity -- and a different entry hash.
        """
        return TbsCertificateLogEntry(
            issuer=self.issuer,
            subject=self.subject,
            subject_public_key_algorithm=self.subject_public_key_algorithm,
            subject_public_key_info_hash=self.subject_public_key_info_hash,
            not_before=self.not_before,
            not_after=self.not_after,
            subject_alt_names=(),
        )

    @classmethod
    def decode(cls, data: bytes) -> "TbsCertificateLogEntry":
        """Read an entry body back out of its encoding.

        The counterpart to :meth:`encoded`, and the reason a client's rebuilt
        entry can be compared to the CA's field for field: a decoder that
        silently defaulted a missing field would hash to something the CA never
        signed. Every field must be present exactly once, in the encoding's own
        order, and nothing may follow.
        """
        reader = wire.Reader(data)
        fields = cls._decode_fields(reader)
        trailing = reader.rest()
        if trailing:
            raise ValueError(f"trailing bytes after TBSCertificateLogEntry: {trailing!r}")
        for name, field_id in (
            ("version", F_VERSION),
            ("issuer", F_ISSUER),
            ("validity", F_VALIDITY),
            ("subject", F_SUBJECT),
            ("subjectPublicKeyAlgorithm", F_SPKI_ALGORITHM),
            ("subjectPublicKeyInfoHash", F_SPKI_HASH),
            ("extensions", F_EXTENSIONS),
        ):
            if field_id not in fields:
                raise ValueError(f"TBSCertificateLogEntry is missing its {name} field")
        for field_id in (F_ISSUER_UNIQUE_ID, F_SUBJECT_UNIQUE_ID):
            if field_id in fields:
                raise ValueError(
                    f"TBSCertificateLogEntry must not carry the unique-ID field "
                    f"{field_id}; the lab never issues one"
                )
        if len(fields) != 7:
            raise ValueError(
                f"TBSCertificateLogEntry has {len(fields)} fields, expected 7"
            )

        validity = wire.Reader(fields[F_VALIDITY])
        not_before = validity.uint(8)
        not_after = validity.uint(8)
        if not validity.at_end():
            raise ValueError("trailing bytes in the validity field")

        # ``encoded`` writes the lab's one version, 2. A decoder that accepted
        # any version would hand back an entry the CA never signed, since the
        # version is inside the hashed body.
        version = fields[F_VERSION]
        if version != wire.uint(2, 1):
            raise ValueError(f"unsupported entry version {version!r}, expected 2")

        return cls(
            issuer=TrustAnchorID.from_relative_oid(fields[F_ISSUER]),
            subject=fields[F_SUBJECT].decode("utf-8"),
            subject_public_key_algorithm=fields[F_SPKI_ALGORITHM].decode("ascii"),
            subject_public_key_info_hash=fields[F_SPKI_HASH],
            not_before=not_before,
            not_after=not_after,
            subject_alt_names=parse_extensions(fields[F_EXTENSIONS]),
        )

    @staticmethod
    def _decode_fields(reader: wire.Reader) -> Dict[int, bytes]:
        """Read the ``(identifier, value)`` pairs, rejecting a duplicate.

        ``encoded`` writes them in declaration order, so a decoder that accepted
        them in any order would accept a layout the lab never produces. The
        identifiers are ascending on the wire, which is what makes "same fields,
        different order" a detectable difference.
        """
        fields: Dict[int, bytes] = {}
        body = wire.Reader(reader.vector_body())
        previous = 0
        while not body.at_end():
            field_id = body.uint(1)
            if field_id <= previous:
                raise ValueError(
                    f"entry field {field_id} is out of order or repeated "
                    f"(previous was {previous})"
                )
            previous = field_id
            fields[field_id] = body.opaque_var(2)
        return fields

    def __str__(self) -> str:
        return f"{self.subject} ({self.subject_public_key_algorithm})"


@dataclass(frozen=True)
class MTCLogEntryExtension:
    """One entry extension (Section 5.2.1). The lab leaves the list empty.

    The extension list is still hashed, and still has to be copied into the
    certificate's ``MTCProof`` (Section 6.2), so it is modelled rather than
    dropped. A CT precertificate has to carry a poison extension here for the
    same structural reason: the entry is the thing that is hashed.
    """

    extension_type: int
    data: bytes

    def encoded(self) -> bytes:
        return wire.uint(self.extension_type, 2) + wire.opaque_var(self.data, 2)


@dataclass(frozen=True)
class MTCLogEntry:
    """An ``MTCLogEntry``: the extensions, the type, and the entry body."""

    type: int
    tbs_certificate: Optional[TbsCertificateLogEntry] = None
    extensions: Tuple[MTCLogEntryExtension, ...] = ()

    def encoded(self) -> bytes:
        """Encode the entry exactly as Section 7.2 hashes it.

        ``extensions || uint16(type) || tbs_certificate_log_entry``, with no
        identifier or length octets around the last field.
        """
        if self.type == NULL_ENTRY:
            if self.tbs_certificate is not None:
                raise ValueError("a null_entry carries no TBSCertificateLogEntry")
            return self.encoded_extensions() + wire.uint(NULL_ENTRY, 2)
        if self.type != TBS_CERT_ENTRY or self.tbs_certificate is None:
            raise ValueError(f"entry of type {self.type} needs a TBSCertificateLogEntry")
        return (
            self.encoded_extensions()
            + wire.uint(TBS_CERT_ENTRY, 2)
            + self.tbs_certificate.encoded()
        )

    def encoded_extensions(self) -> bytes:
        return wire.vector(extension.encoded() for extension in self.extensions)

    def entry_hash(self) -> bytes:
        """Return ``MTH({entry}) = SHA256(0x00 || entry)`` (Section 7.2 step 9)."""
        return merkle.hash_leaf(self.encoded())

    @classmethod
    def decode(cls, data: bytes) -> "MTCLogEntry":
        """Read a whole entry back, in the layout Section 7.2 hashes.

        ``extensions || uint16(type) || tbs_certificate_log_entry``. Neither the
        type nor the body is length-prefixed, so the type comes from the two
        bytes between the extension vector and the body, and everything after it
        belongs to the body. A ``null_entry`` has no body, so nothing may follow
        it.
        """
        reader = wire.Reader(data)
        extensions = _read_entry_extensions(reader)
        entry_type = reader.uint(2)
        if entry_type == NULL_ENTRY:
            if not reader.at_end():
                raise ValueError("a null_entry must be the whole encoding")
            return cls(type=NULL_ENTRY, extensions=extensions)
        if entry_type != TBS_CERT_ENTRY:
            raise ValueError(f"unknown MTCLogEntryType {entry_type}")
        body = reader.rest()
        if not body:
            raise ValueError("a tbs_cert_entry needs a TBSCertificateLogEntry")
        return cls(
            type=TBS_CERT_ENTRY,
            tbs_certificate=TbsCertificateLogEntry.decode(body),
            extensions=extensions,
        )

    def __str__(self) -> str:
        if self.type == NULL_ENTRY:
            return "null_entry"
        assert self.tbs_certificate is not None
        return f"tbs_cert_entry {self.tbs_certificate}"


@dataclass(frozen=True)
class Checkpoint:
    """A snapshot of the log: a tree size, a root hash, and cosignatures.

    A checkpoint is the Merkle Tree CA's answer to a CT checkpoint, and the
    draft's cosignature format covers it directly: a *timestamped* cosignature
    with ``start = 0`` and ``end`` equal to the largest tree the cosigner has
    seen asserts the complete state of its view (Section 5.3.2). That is the
    only place in the lab where a non-zero timestamp appears.
    """

    log_id: TrustAnchorID
    tree_size: int
    root_hash: bytes
    signatures: Tuple[SubtreeSignature, ...] = ()
    timestamp: int = 0

    def signed_by(self, cosigners: Sequence[Cosigner]) -> bool:
        """Return ``True`` if every given cosigner signed this checkpoint."""
        return all(
            any(
                cosigner.verify_subtree(
                    self.log_id,
                    0,
                    self.tree_size,
                    self.root_hash,
                    sig.signature,
                    self.timestamp,
                )
                for sig in self.signatures
            )
            for cosigner in cosigners
        )

    def __str__(self) -> str:
        return f"checkpoint(size={self.tree_size}, root={self.root_hash.hex()[:16]}...)"


class IssuanceLog:
    """A CA's issuance log: an append-only sequence of :class:`MTCLogEntry`.

    Section 5.2 makes two points that shape this class. There is **no public
    submission interface** -- the CA is the only writer, so the log records what
    the CA itself asserted and monitoring it is a transparency property rather
    than a public good. And a CA **MUST NOT append to any log that is not the
    current log**, which is why :meth:`append` is the only way in and the log
    number is fixed at construction.
    """

    def __init__(self, ca_id: TrustAnchorID, log_number: int) -> None:
        if not 1 <= log_number <= MAX_LOG_NUMBER:
            raise ValueError(f"log number {log_number} out of range 1..{MAX_LOG_NUMBER}")
        self.ca_id = ca_id
        self.log_number = log_number
        self.entries: List[MTCLogEntry] = []

    @property
    def log_id(self) -> TrustAnchorID:
        """The log ID: the CA ID, the constant 0, and the log number."""
        return self.ca_id.log(self.log_number)

    @property
    def size(self) -> int:
        return len(self.entries)

    def append(self, entry: MTCLogEntry) -> int:
        """Append an entry and return its index."""
        if len(self.entries) > MAX_INDEX:
            raise ValueError("log is full")
        self.entries.append(entry)
        return len(self.entries) - 1

    def _prefix(self, tree_size: Optional[int]) -> Sequence[MTCLogEntry]:
        if tree_size is None:
            return self.entries
        if not 0 <= tree_size <= self.size:
            raise ValueError(f"tree size {tree_size} is not inside a log of {self.size} entries")
        return self.entries[:tree_size]

    def leaf_hashes(self, tree_size: Optional[int] = None) -> List[bytes]:
        """Return the leaf hashes of the first ``tree_size`` entries."""
        return [entry.entry_hash() for entry in self._prefix(tree_size)]

    def root(self, tree_size: Optional[int] = None) -> bytes:
        """Return the Merkle tree hash over the first ``tree_size`` entries."""
        return merkle.root_from_hashes(self.leaf_hashes(tree_size))

    def entry_hash(self, index: int) -> bytes:
        """Return the leaf hash of one entry."""
        return self.entries[index].entry_hash()

    def subtree_hash(self, start: int, end: int) -> bytes:
        """Return ``MTH(D[start:end])`` for a subtree of this log."""
        return subtree_hash(self.leaf_hashes(), start, end)

    def inclusion_proof(self, start: int, end: int, index: int) -> List[bytes]:
        """Return a subtree inclusion proof for ``index`` in ``[start, end)``."""
        return subtree_inclusion_proof(self.leaf_hashes(), start, end, index)

    def consistency_proof(self, start: int, end: int) -> List[bytes]:
        """Return a subtree consistency proof against the whole log."""
        return subtree_consistency_proof(self.leaf_hashes(), start, end)

    def serial(self, index: int) -> int:
        """Return the serial number a certificate for ``index`` must carry."""
        return serial_number(self.log_number, index)

    def covering_subtrees(
        self, previous_size: int, tree_size: int
    ) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """Return the two subtrees covering ``[previous_size, tree_size)``.

        This is Section 4.5's covering algorithm applied to the entries added
        since the last checkpoint, which is step 2 of the standalone
        certificate procedure in Section 6.3. It is why a CA covers a whole
        batch of certificates with one signature per subtree instead of one
        signature per certificate.
        """
        if not 0 <= previous_size <= tree_size <= self.size:
            raise ValueError(
                f"[{previous_size}, {tree_size}) is not inside a log of {self.size} entries"
            )
        return find_subtrees(previous_size, tree_size)

    def checkpoint(
        self, tree_size: Optional[int] = None, cosigners: Sequence[Cosigner] = ()
    ) -> Checkpoint:
        """Mint a checkpoint over the first ``tree_size`` entries.

        Each cosigner signs it as a timestamped cosignature over
        ``[0, tree_size)``, the largest tree it has seen, which is what makes
        a checkpoint cosignature a statement about the whole log rather than
        about one subtree.
        """
        size = self.size if tree_size is None else tree_size
        if not 0 <= size <= self.size:
            raise ValueError(f"tree size {size} is not inside a log of {self.size} entries")
        root = self.root(size)
        signatures = [
            cosigner.sign_subtree(self.log_id, 0, size, root, timestamp=LAB_EPOCH)
            for cosigner in cosigners
        ]
        return Checkpoint(
            log_id=self.log_id,
            tree_size=size,
            root_hash=root,
            signatures=tuple(sort_signatures(signatures)),
            timestamp=LAB_EPOCH,
        )

    def __str__(self) -> str:
        return f"issuance log {self.log_id.short} with {self.size} entries"


def issue(
    log: IssuanceLog,
    subject: str,
    public_key_der: bytes,
    algorithm: str,
    not_before: int,
    not_after: int,
    subject_alt_names: Iterable[str] = (),
) -> Tuple[MTCLogEntry, int]:
    """Log a validated certificate and return its entry and index.

    The subject's key is hashed, not stored: this returns the entry and its
    index, and the log holds no copy of the key or of any signature. Comparing
    the size of the returned entry with the size of the certificate the client
    will hold is the measurement exercise 05 is built around.
    """
    entry = MTCLogEntry(
        type=TBS_CERT_ENTRY,
        tbs_certificate=TbsCertificateLogEntry(
            issuer=log.ca_id,
            subject=subject,
            subject_public_key_algorithm=algorithm,
            subject_public_key_info_hash=hashlib.sha256(public_key_der).digest(),
            not_before=not_before,
            not_after=not_after,
            subject_alt_names=tuple(subject_alt_names),
        ),
    )
    return entry, log.append(entry)


def null_entry() -> MTCLogEntry:
    """Return a ``null_entry``: a log position that asserts nothing.

    Section 5.2.1 allows entries at any index to be null, and a CA may certify
    one "without being held responsible for any validation". The lab keeps the
    type so a subtree can cover a range that includes positions no certificate
    ever landed on.
    """
    return MTCLogEntry(type=NULL_ENTRY)
