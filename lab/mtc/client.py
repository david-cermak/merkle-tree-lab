"""The relying party's side: rebuild the entry, then check the proof (Section 7).

This is where the design pays off or does not, so it is the part of the lab
worth reading. A client's job for a Merkle Tree Certificate is Section 7.2, and
the steps fit in one sentence: **rebuild the log entry from the certificate,
hash it, and check that the hash is in a subtree the client already trusts.**

That first step is the one people expect to be impossible and is not. The entry
carries no signature and no public key, and every field of it is either in the
certificate or derivable from it (Section 7.2 step 2):

======================  =====================================================
``issuer``              the certificate's issuer
``subject``             the certificate's subject
``subjectPublicKey...`` SHA-256 of the certificate's own SPKI
``notBefore``/          the certificate's validity
``notAfter``
``subjectAltName``      parsed back out of the ``MTCProof``'s extensions
``issuerUniqueID``/     absent in the certificate, so absent in the entry
``subjectUniqueID``
======================  =====================================================

Rebuilding works precisely because Section 5.2.1 left the identifier and length
octets out of the hashed form. An ASN.1 implementation would have to re-encode
the whole structure to hash it; here the client concatenates fields it already
has. :func:`reconstruct_entry` is that concatenation.

The rest differs per shape only in where the *trusted* subtree hash comes from:

* **tree-relative and checkpoint-relative**: the client recomputes the subtree
  hash from the proof, then verifies the two cosignatures against that
  recomputed value. The order is not a detail. Verifying the cosignatures first
  would mean verifying them against a value the certificate itself supplied.
* **landmark-relative**: there is no signature, so the client compares against
  the landmark hash it already holds. Not holding it is the expected, correct
  outcome -- the certificate is not yet verifiable, and no amount of work on the
  certificate itself will change that.

Failures are reported as a :class:`VerificationResult` naming the step that
failed, because "did not verify" is not a useful thing to tell someone trying to
work out which of five things went wrong.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .certs import DirectCertificate, MerkleTreeCertificate
from .cosigners import Cosigner, load_public_key, verify_with_public_key
from .ids import TrustAnchorID
from .landmarks import LandmarkSequence, subtree_hashes_for
from .log import (
    TBS_CERT_ENTRY,
    MTCLogEntry,
    TbsCertificateLogEntry,
    parse_entry_extensions,
    split_serial,
)
from .tree import evaluate_subtree_inclusion_proof, is_valid_subtree

#: The checks of Section 7.2, named so a failure can point at one.
STEP_SERIAL = "the serial number names the log and index the proof commits to"
STEP_INTERVAL = "the subtree interval is valid and contains the index"
STEP_RECONSTRUCT = "the rebuilt entry hashes into a well-formed subtree"
STEP_COSIGNATURE = "both cosignatures verify against known cosigner keys"
STEP_CHECKPOINT = "the entry hashes into a subtree this client already has from a checkpoint"
STEP_LANDMARK = "the client holds this landmark's subtree hash, and it matches"
STEP_SIGNATURE = "the certificate signature verifies under the CA key"

PASSED = "ok"


@dataclass(frozen=True)
class VerificationResult:
    """The outcome of one check, with the step that decided it."""

    ok: bool
    step: str = PASSED
    detail: str = ""
    #: What the client expected and what it computed, when it had an opinion.
    #: "computed X, expected Y" is a better bug report than "failed".
    expected: Optional[bytes] = None
    computed: Optional[bytes] = None

    def __str__(self) -> str:
        if self.ok:
            return f"ok ({self.step})"
        if self.expected is not None and self.computed is not None:
            return (
                f"FAILED at {self.step}: expected {self.expected.hex()[:16]}..., "
                f"computed {self.computed.hex()[:16]}... ({self.detail})"
            )
        return f"FAILED at {self.step}: {self.detail}"


def ok(step: str = PASSED) -> VerificationResult:
    return VerificationResult(ok=True, step=step)


def fail(
    step: str, detail: str, expected: bytes = None, computed: bytes = None
) -> VerificationResult:
    return VerificationResult(
        ok=False, step=step, detail=detail, expected=expected, computed=computed
    )


@dataclass
class ClientState:
    """What a relying party has before any certificate arrives (Section 7.4).

    Two kinds of thing, and the whole design is about the second being small
    enough to keep: cosigner public keys, and landmark subtree hashes. A
    tree-relative client needs only the first; a landmark-relative client needs
    only the second. Neither needs the log's contents, and neither needs to talk
    to the CA during the handshake.
    """

    #: cosigner ID -> (algorithm, DER public key)
    cosigners: Dict[str, Tuple[str, bytes]] = field(default_factory=dict)
    #: (log ID, start, end) -> subtree hash
    landmarks: Dict[Tuple[str, int, int], bytes] = field(default_factory=dict)
    #: (log ID, landmark number) -> the two subtree intervals of that landmark
    landmark_intervals: Dict[Tuple[str, int], Tuple[Tuple[int, int], ...]] = field(
        default_factory=dict
    )
    #: CA ID -> (algorithm, DER public key), for the directly signed shape
    ca_keys: Dict[str, Tuple[str, bytes]] = field(default_factory=dict)
    #: (log ID, start, end) -> root of a checkpoint the client verified itself
    checkpoints: Dict[Tuple[str, int, int], bytes] = field(default_factory=dict)

    def add_cosigner(self, cosigner: Cosigner) -> None:
        """Trust a cosigner key. A client that trusts no cosigner can verify nothing."""
        self.cosigners[cosigner.cosigner_id.dotted] = (
            cosigner.parameter_set,
            cosigner.public_bytes(),
        )

    def add_ca_key(self, ca_id: TrustAnchorID, algorithm: str, spki: bytes) -> None:
        self.ca_keys[ca_id.dotted] = (algorithm, spki)

    def add_landmark_hash(
        self, log_id: TrustAnchorID, start: int, end: int, subtree_hash: bytes
    ) -> None:
        self.landmarks[(log_id.dotted, start, end)] = subtree_hash

    def take_checkpoint(self, checkpoint) -> None:
        """Record a checkpoint the client has verified for itself.

        This is what a client that monitors the log but has not seen a landmark
        yet knows: a signed root over the prefix ``[0, tree_size)``.

        Note what this does *not* enable. Section 6.3 step 2 has the CA sign the
        subtrees covering the entries added *between* two checkpoints, so a
        checkpoint-relative proof's interval is a proper subtree such as
        ``[0, 8)`` -- never the checkpoint's own ``[0, 12)``. A checkpoint root
        is a hash of a prefix, and comparing it against a subtree hash would be
        comparing two different things that happen to be 32 bytes long. Turning
        a checkpoint root into a subtree hash needs a subtree consistency proof
        (Section 4.4) plus the log, which is why the landmark-relative shape
        exists at all: it hands the client the subtree hash directly.

        The recorded root is therefore useful for auditing, and for a client
        that wants to confirm the whole log it has read, but it does not
        shortcut ``verify()``.
        """
        self.checkpoints[(checkpoint.log_id.dotted, 0, checkpoint.tree_size)] = (
            checkpoint.root_hash
        )

    def checkpoint_root_for(
        self, log_id: TrustAnchorID, start: int, end: int
    ) -> Optional[bytes]:
        """Return a recorded checkpoint root for exactly this interval, or ``None``.

        Only ever non-``None`` for a proof over a whole checkpoint prefix. See
        ``take_checkpoint`` for why that is a narrow case.
        """
        return self.checkpoints.get((log_id.dotted, start, end))

    def note_landmark_intervals(self, sequence: LandmarkSequence) -> None:
        """Record which intervals belong to which landmark number.

        The hashes alone are enough to check a proof, and storing the mapping as
        well lets the client notice a certificate that names one landmark and
        proves against another's subtree. Section 6.4.4 ties the two together --
        the landmark is chosen because its subtree contains the index -- so a
        mismatch is a certificate the CA should not have issued.
        """
        for landmark in sequence:
            self.landmark_intervals[(sequence.log_id.dotted, landmark.number)] = (
                landmark.subtrees
            )

    def landmark_number_agrees(
        self, cert: MerkleTreeCertificate
    ) -> Optional[bool]:
        """Return whether the named landmark owns the proof's subtree.

        ``None`` when the client has not seen that landmark, which is a different
        situation from disagreement and is reported as "not yet checkable".
        """
        proof = cert.mtc_proof
        if proof.landmark is None:
            return None
        intervals = self.landmark_intervals.get((proof.log_id.dotted, proof.landmark))
        if intervals is None:
            return None
        return proof.interval() in intervals

    def take_landmarks(
        self, sequence: LandmarkSequence, leaf_hashes: Sequence[bytes]
    ) -> List[Tuple[int, int, bytes]]:
        """Take the landmark subtree hashes out of a published sequence.

        This is the client-side half of Section 6.4.1, and it is where a
        landmark-relative certificate stops needing the log: after this call the
        client holds two hashes per landmark and needs no further contact with
        the CA.
        """
        taken = []
        self.note_landmark_intervals(sequence)
        for row in subtree_hashes_for(sequence, leaf_hashes):
            self.add_landmark_hash(row["log_id"], row["start"], row["end"], row["hash"])
            taken.append((row["start"], row["end"], row["hash"]))
        return taken

    def __str__(self) -> str:
        return (
            f"client with {len(self.cosigners)} cosigner keys, "
            f"{len(self.checkpoints)} checkpointed subtrees, "
            f"{len(self.landmarks)} landmark subtree hashes, "
            f"{len(self.ca_keys)} CA keys"
        )


def reconstruct_entry(cert: MerkleTreeCertificate) -> MTCLogEntry:
    """Rebuild the log entry the certificate implies (Section 7.2 step 2).

    ``issuerUniqueID`` and ``subjectUniqueID`` are left out because they are
    absent from the certificate, and that is the rule rather than an oversight:
    an entry's field is present exactly when the certificate's is. The SANs come
    from the certificate's own extensions -- *not* from the proof's, which carry
    the log entry's extension list, a different thing (Section 6.1).
    """
    tbs = TbsCertificateLogEntry(
        issuer=cert.issuer,
        subject=cert.subject,
        subject_public_key_algorithm=cert.subject_public_key_algorithm,
        subject_public_key_info_hash=cert.subject_public_key_info_hash(),
        not_before=cert.validity[0],
        not_after=cert.validity[1],
        subject_alt_names=cert.subject_alt_names,
    )
    return MTCLogEntry(
        type=TBS_CERT_ENTRY,
        tbs_certificate=tbs,
        extensions=parse_entry_extensions(cert.mtc_proof.extensions),
    )


def check_serial(cert: MerkleTreeCertificate) -> VerificationResult:
    """Check the serial number against the proof's ``(log, index)`` (Section 7.2 step 1).

    The serial is the only place the client is told which log and which index,
    so this is what stops a proof from a different log being replayed here. It is
    cheap and it is the check most often forgotten.
    """
    try:
        log_number, index = split_serial(cert.serial_number)
    except ValueError as exc:
        return fail(STEP_SERIAL, str(exc))
    proof = cert.mtc_proof
    if (log_number, index) != (proof.log_number, proof.entry_index):
        return fail(
            STEP_SERIAL,
            f"serial says (log {log_number}, index {index}) but the proof says "
            f"(log {proof.log_number}, index {proof.entry_index})",
        )
    return ok(STEP_SERIAL)


def check_interval(cert: MerkleTreeCertificate) -> VerificationResult:
    """Check the subtree interval is a real subtree and holds the index.

    This is the check on untrusted input, so it has to be strict: an interval
    that is not a subtree is a proof whose shape is meaningless, and
    :func:`evaluate_subtree_inclusion_proof` would refuse it anyway.
    """
    proof = cert.mtc_proof
    start, end = proof.subtree_start, proof.subtree_end
    if not is_valid_subtree(start, end):
        return fail(STEP_INTERVAL, f"[{start}, {end}) is not a valid subtree")
    if not start <= proof.entry_index < end:
        return fail(STEP_INTERVAL, f"index {proof.entry_index} is outside [{start}, {end})")
    return ok(STEP_INTERVAL)


def evaluate(cert: MerkleTreeCertificate, entry: MTCLogEntry) -> Optional[bytes]:
    """Recompute the subtree hash from the rebuilt entry and the proof.

    ``None`` means the proof is structurally wrong -- the wrong number of hashes
    for this subtree -- as opposed to proving something false, which yields a
    *different* hash. The two cases are worth telling apart, so this returns
    ``None`` only for the first.
    """
    proof = cert.mtc_proof
    return evaluate_subtree_inclusion_proof(
        proof.inclusion_proof,
        proof.subtree_start,
        proof.subtree_end,
        proof.entry_index,
        entry.entry_hash(),
    )


def check_cosignatures(
    cert: MerkleTreeCertificate, state: ClientState, subtree_hash: bytes
) -> VerificationResult:
    """Verify both cosignatures against ``subtree_hash`` using known cosigner keys.

    The cosignature message binds the cosigner ID, the log ID, the interval, and
    the hash, so a signature from an unknown key over a different interval fails
    even though it verifies cryptographically. Both halves matter: the client
    must know the key, and the key must have signed *this* subtree.
    """
    proof = cert.mtc_proof
    if len(proof.subtree_cosignatures) != 2:
        return fail(
            STEP_COSIGNATURE, f"expected 2 cosignatures, got {len(proof.subtree_cosignatures)}"
        )
    for signature in proof.subtree_cosignatures:
        known = state.cosigners.get(signature.cosigner_id.dotted)
        if known is None:
            return fail(
                STEP_COSIGNATURE,
                f"this client does not trust cosigner {signature.cosigner_id.short}",
            )
        algorithm, spki = known
        public_key = load_public_key(algorithm, spki)
        if public_key is None:
            return fail(STEP_COSIGNATURE, f"cannot load a {algorithm} public key")
        if not verify_with_public_key(
            proof.log_id,
            signature.cosigner_id,
            public_key,
            proof.subtree_start,
            proof.subtree_end,
            subtree_hash,
            signature.signature,
        ):
            return fail(
                STEP_COSIGNATURE,
                f"the cosignature from {signature.cosigner_id.short} does not verify "
                f"over [{proof.subtree_start}, {proof.subtree_end})",
                expected=subtree_hash,
            )
    return ok(STEP_COSIGNATURE)


def stored_landmark_hash(
    cert: MerkleTreeCertificate, state: ClientState
) -> Optional[bytes]:
    """Return the landmark subtree hash the client holds, or ``None``."""
    proof = cert.mtc_proof
    return state.landmarks.get((proof.log_id.dotted, proof.subtree_start, proof.subtree_end))


def verify(cert: MerkleTreeCertificate, state: ClientState) -> VerificationResult:
    """Run the Section 7.2 checks for whichever shape this certificate is.

    The order follows the dependencies: the serial is checked before anything is
    hashed, the entry is rebuilt exactly once and reused, and the shape only
    decides where the trusted subtree hash comes from. The first failure is
    returned, so a caller can print one line and stop.
    """
    result = check_serial(cert)
    if not result.ok:
        return result
    result = check_interval(cert)
    if not result.ok:
        return result

    entry = reconstruct_entry(cert)
    proof = cert.mtc_proof

    if proof.is_landmark_relative:
        agrees = state.landmark_number_agrees(cert)
        if agrees is False:
            return fail(
                STEP_LANDMARK,
                f"landmark {proof.landmark} does not own subtree "
                f"[{proof.subtree_start}, {proof.subtree_end})",
            )
        trusted = stored_landmark_hash(cert, state)
        if trusted is None:
            return fail(
                STEP_LANDMARK,
                f"this client holds no hash for landmark {proof.landmark}'s subtree "
                f"[{proof.subtree_start}, {proof.subtree_end}), so the certificate "
                "cannot be checked yet; it becomes checkable when the landmark arrives",
            )
        computed = evaluate(cert, entry)
        if computed is None:
            return fail(STEP_RECONSTRUCT, "the inclusion proof is the wrong shape for this subtree")
        if computed != trusted:
            return fail(
                STEP_LANDMARK,
                f"the entry hashes to a value outside landmark {proof.landmark}'s subtree",
                expected=trusted,
                computed=computed,
            )
        return ok(STEP_LANDMARK)

    computed = evaluate(cert, entry)
    if computed is None:
        return fail(STEP_RECONSTRUCT, "the inclusion proof is the wrong shape for this subtree")
    root = state.checkpoint_root_for(proof.log_id, proof.subtree_start, proof.subtree_end)
    if root is not None:
        # The proof covers a whole checkpoint prefix and the client already
        # holds that root. This is reachable only for a proof against a
        # checkpoint's own [0, N) interval; for the shapes Section 6.3
        # describes, the interval is a proper subtree and the cosigners below
        # are what decide.
        if computed != root:
            return fail(
                STEP_CHECKPOINT,
                f"the entry does not hash into the checkpointed subtree "
                f"[{proof.subtree_start}, {proof.subtree_end})",
                expected=root,
                computed=computed,
            )
        return ok(STEP_CHECKPOINT)
    return check_cosignatures(cert, state, computed)


def verify_direct(cert: DirectCertificate, state: ClientState) -> VerificationResult:
    """Check the directly signed shape: an ordinary signature and no proof.

    Included so the workshop can show what a client does when none of the MTC
    machinery is involved. The comparison is not "one check instead of five" --
    it is that this check says nothing about transparency, and needs a key the
    client already trusts for other reasons.
    """
    known = state.ca_keys.get(cert.issuer.dotted)
    if known is None:
        return fail(STEP_SIGNATURE, f"this client does not trust a key for {cert.issuer.short}")
    algorithm, spki = known
    public_key = load_public_key(algorithm, spki)
    if public_key is None:
        return fail(STEP_SIGNATURE, f"cannot load a {algorithm} public key")
    from cryptography.exceptions import InvalidSignature

    try:
        public_key.verify(cert.signature, cert.tbs_encoded_for_signing())
    except InvalidSignature:
        return fail(STEP_SIGNATURE, "the signature does not verify under the CA key")
    return ok(STEP_SIGNATURE)


def verify_all(cert: object, state: ClientState) -> VerificationResult:
    """Check a certificate of any shape in this lab."""
    if isinstance(cert, DirectCertificate):
        return verify_direct(cert, state)
    if isinstance(cert, MerkleTreeCertificate):
        return verify(cert, state)
    return fail(STEP_SIGNATURE, f"do not know how to check a {type(cert).__name__}")
