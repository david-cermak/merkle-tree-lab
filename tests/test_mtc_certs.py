"""Tests for the certificate shapes and the client's checks.

This is the file that tests the *design claims*, so the negative cases matter
more than the positive ones. A test that only shows a well-formed certificate
verifying proves that the happy path runs; what a reader wants to know is
whether a certificate the CA would never have issued also fails, and at which
step.

The tamper cases are all done by rebuilding a certificate with one field
changed and nothing else, so a failure can only come from the thing that was
changed. That is the same discipline Section 7.2 imposes on a client.
"""

import dataclasses
import hashlib
import unittest

from lab.mtc import certs, client, wire
from lab.mtc import landmarks as lm
from lab.mtc import log as issuance
from lab.mtc.certs import (
    DirectCertificate,
    MerkleTreeCertificate,
    MTCProof,
    direct_certificate_for_entry,
    encode_extensions,
    format_shape_table,
    issue_landmark_relative,
    issue_tree_relative,
    shape_sizes,
)
from lab.mtc.cosigners import ca_cosigner, certificate_signer, generate_cosigner
from lab.mtc.ids import TrustAnchorID
from lab.mtc.log import LAB_EPOCH, IssuanceLog, null_entry
from lab.mtc.tree import covering_subtree

CA = TrustAnchorID.parse("1.3.6.1.4.1.32473.100")
SUBJECT = "www3.example"
INDEX = 3
LANDMARK_EXPIRY = LAB_EPOCH + 3600


def subject_key(index=INDEX):
    """A stand-in for a subject's DER SubjectPublicKeyInfo.

    A real key would be 1 974 bytes of ML-DSA, which the log then hashes into 32
    bytes; using a short deterministic value keeps the tests about the
    certificate logic rather than about key generation time.
    """
    return bytes([index + 1]) * 32


def build(count=20, null_at=7):
    log = IssuanceLog(CA, 8)
    for index in range(count):
        if index == null_at:
            log.append(null_entry())
        else:
            issuance.issue(
                log,
                f"www{index}.example",
                subject_key(index),
                "ML-DSA-65",
                LAB_EPOCH,
                LAB_EPOCH + 126 * 3600,
                [f"www{index}.example", "example.com"],
            )
    return log


class MTCFixture(unittest.TestCase):
    def setUp(self):
        self.log = build()
        self.leaf_hashes = self.log.leaf_hashes()
        self.ca_cosigner = ca_cosigner(CA)
        self.witness = generate_cosigner(CA.landmark(8, 1), role="witness")
        self.signer = certificate_signer(CA)
        self.sequence = lm.LandmarkSequence(self.log.log_id)
        self.landmark = lm.allocate(self.sequence, 20, LANDMARK_EXPIRY)
        self.cosigners = [self.ca_cosigner, self.witness]
        self.key = subject_key()

    def tree_relative(self, index=INDEX, interval=None):
        return issue_tree_relative(
            self.log, index, subject_key(index), "ML-DSA-65", self.cosigners, interval
        )

    def landmark_relative(self, index=INDEX):
        return issue_landmark_relative(
            self.log, index, subject_key(index), "ML-DSA-65", landmark=self.landmark
        )

    def direct(self, index=INDEX):
        return direct_certificate_for_entry(
            self.log, index, subject_key(index), "ML-DSA-65", self.signer
        )

    def client(self, with_landmarks=True, with_ca_key=True):
        state = client.ClientState()
        state.add_cosigner(self.ca_cosigner)
        state.add_cosigner(self.witness)
        if with_ca_key:
            state.add_ca_key(CA, "mldsa65", self.signer.public_bytes())
        if with_landmarks:
            state.take_landmarks(self.sequence, self.leaf_hashes)
        return state


class TestMTCProofShape(unittest.TestCase):
    def test_a_checkpoint_relative_proof_has_two_cosignatures(self):
        log = build()
        proof = issue_tree_relative(
            log, INDEX, subject_key(), "ML-DSA-65",
            [ca_cosigner(CA), generate_cosigner(CA.landmark(8, 1))],
        ).mtc_proof
        self.assertIsNone(proof.landmark)
        self.assertEqual(len(proof.subtree_cosignatures), 2)
        self.assertFalse(proof.is_landmark_relative)

    def test_a_landmark_relative_proof_has_none(self):
        log = build()
        sequence = lm.LandmarkSequence(log.log_id)
        landmark = lm.allocate(sequence, 20, LANDMARK_EXPIRY)
        proof = issue_landmark_relative(
            log, INDEX, subject_key(), "ML-DSA-65", landmark=landmark
        ).mtc_proof
        self.assertEqual(proof.landmark, landmark.number)
        self.assertEqual(proof.subtree_cosignatures, ())

    def test_a_proof_cannot_be_both_kinds(self):
        with self.assertRaises(ValueError):
            MTCProof(
                log_id=CA.log(8), log_number=8, entry_index=3, subtree_start=0,
                subtree_end=16, inclusion_proof=(), landmark=1,
                subtree_cosignatures=(object(), object()),
            )

    def test_a_checkpoint_relative_proof_needs_two_cosignatures(self):
        with self.assertRaises(ValueError):
            MTCProof(
                log_id=CA.log(8), log_number=8, entry_index=3, subtree_start=0,
                subtree_end=16, inclusion_proof=(),
            )

    def test_the_index_must_be_inside_the_subtree(self):
        with self.assertRaises(ValueError):
            MTCProof(
                log_id=CA.log(8), log_number=8, entry_index=16, subtree_start=0,
                subtree_end=16, inclusion_proof=(), landmark=1,
            )

    def test_an_empty_subtree_is_refused(self):
        with self.assertRaises(ValueError):
            MTCProof(
                log_id=CA.log(8), log_number=8, entry_index=0, subtree_start=4,
                subtree_end=4, inclusion_proof=(), landmark=1,
            )


class TestTheFourShapes(MTCFixture):
    def test_tree_relative_verifies(self):
        self.assertTrue(client.verify(self.tree_relative(), self.client()).ok)

    def test_checkpoint_relative_verifies(self):
        interval = covering_subtree(self.leaf_hashes, 0, self.log.size, INDEX)
        cert = self.tree_relative(interval=interval)
        self.assertEqual(cert.mtc_proof.interval(), interval)
        self.assertTrue(client.verify(cert, self.client()).ok)

    def test_landmark_relative_needs_the_landmark_first(self):
        cert = self.landmark_relative()
        result = client.verify(cert, self.client(with_landmarks=False))
        self.assertFalse(result.ok)
        self.assertIn("landmark", result.step)
        self.assertTrue(client.verify(cert, self.client()).ok)

    def test_directly_signed_verifies_under_the_ca_key(self):
        self.assertTrue(client.verify_direct(self.direct(), self.client()).ok)

    def test_directly_signed_fails_without_a_trusted_ca_key(self):
        result = client.verify_direct(self.direct(), self.client(with_ca_key=False))
        self.assertFalse(result.ok)
        self.assertIn("does not trust a key", result.detail)

    def test_the_serials_all_name_the_same_entry(self):
        for cert in (
            self.tree_relative(),
            self.landmark_relative(),
            self.direct(),
        ):
            self.assertEqual(cert.serial_number, self.log.serial(INDEX))

    def test_shapes_carry_the_subjects_own_key(self):
        for cert in (self.tree_relative(), self.landmark_relative(), self.direct()):
            self.assertEqual(cert.subject, f"www{INDEX}.example")
            self.assertEqual(cert.subject_public_key_info, self.key)
            self.assertEqual(cert.subject_alt_names, (SUBJECT, "example.com"))

    def test_a_landmark_certificate_beyond_the_landmark_is_refused(self):
        # A landmark at tree size 12 cannot cover index 15.
        short = lm.LandmarkSequence(self.log.log_id)
        landmark = lm.allocate(short, 12, LAB_EPOCH + 7200)
        with self.assertRaises(ValueError):
            issue_landmark_relative(
                self.log, 15, subject_key(15), "ML-DSA-65", landmark=landmark
            )

    def test_issuing_against_the_wrong_key_is_refused(self):
        with self.assertRaises(ValueError):
            issue_tree_relative(
                self.log, INDEX, b"x" * 32, "ML-DSA-65", self.cosigners
            )

    def test_a_null_entry_certifies_nothing(self):
        with self.assertRaises(ValueError):
            issue_tree_relative(self.log, 7, bytes(32), "ML-DSA-65", self.cosigners)


class TestCheckpointRoots(MTCFixture):
    """A checkpoint root is a prefix hash, not a subtree hash.

    Section 6.3 step 2 has the CA sign the subtrees covering the entries added
    between two checkpoints, so a checkpoint-relative proof's interval is always
    a proper subtree. ``ClientState`` records the root under the checkpoint's own
    ``[0, N)`` interval, and the two must not be confused -- a prefix root and a
    subtree hash are different values that both happen to be 32 bytes.
    """

    def test_a_checkpoint_is_recorded_under_its_own_prefix(self):
        state = client.ClientState()
        checkpoint = self.log.checkpoint(12, self.cosigners)
        state.take_checkpoint(checkpoint)
        self.assertIsNotNone(state.checkpoint_root_for(self.log.log_id, 0, 12))
        self.assertEqual(
            state.checkpoint_root_for(self.log.log_id, 0, 12), checkpoint.root_hash
        )

    def test_a_checkpoint_root_never_answers_a_proper_subtree(self):
        # Every proof the lab issues for a checkpoint batch is over a proper
        # subtree, so the recorded prefix root must not be offered for it.
        state = client.ClientState()
        state.take_checkpoint(self.log.checkpoint(12, self.cosigners))
        interval = covering_subtree(self.leaf_hashes, 0, 12, INDEX)
        self.assertEqual(interval, (0, 8))
        self.assertIsNone(state.checkpoint_root_for(self.log.log_id, *interval))

    def test_a_proper_subtree_still_needs_the_cosigners(self):
        # The point of the previous test: a client holding the checkpoint cannot
        # verify a checkpoint-relative certificate on its own.
        state = client.ClientState()
        state.take_checkpoint(self.log.checkpoint(12, self.cosigners))
        cert = self.tree_relative(interval=(0, 8))
        result = client.verify(cert, state)
        self.assertFalse(result.ok)
        self.assertEqual(result.step, client.STEP_COSIGNATURE)

        state.add_cosigner(self.ca_cosigner)
        state.add_cosigner(self.witness)
        self.assertTrue(client.verify(cert, state).ok)


class TestSizes(MTCFixture):
    def test_the_measured_table(self):
        rows = shape_sizes(
            self.log, INDEX, self.key, "ML-DSA-65", self.cosigners,
            self.signer, self.landmark,
        )
        self.assertEqual(
            [row["shape"] for row in rows],
            [
                "directly signed",
                "standalone (tree-relative)",
                "checkpoint-relative",
                "landmark-relative",
            ],
        )
        self.assertEqual([row["signatures"] for row in rows], [1, 2, 2, 0])
        self.assertEqual([row["landmark_dependent"] for row in rows], [False, False, False, True])

    def test_measuring_shapes_does_not_change_the_log(self):
        size = self.log.size
        shape_sizes(
            self.log, INDEX, self.key, "ML-DSA-65", self.cosigners,
            self.signer, self.landmark,
        )
        self.assertEqual(self.log.size, size)

    def test_removing_the_cosignatures_is_the_whole_difference(self):
        rows = shape_sizes(
            self.log, INDEX, self.key, "ML-DSA-65", self.cosigners,
            self.signer, self.landmark,
        )
        standalone, landmark_relative = rows[1], rows[3]
        self.assertEqual(standalone["signature_bytes"], 2 * 2420)
        self.assertEqual(landmark_relative["signature_bytes"], 0)
        # The landmark-relative certificate is smaller by at least the two
        # cosignatures, since everything else is the same or smaller.
        self.assertLess(
            landmark_relative["bytes"],
            standalone["bytes"] - standalone["signature_bytes"],
        )

    def test_the_table_renders_as_markdown(self):
        rows = shape_sizes(
            self.log, INDEX, self.key, "ML-DSA-65", self.cosigners,
            self.signer, self.landmark, checkpoint_size=8,
        )
        rendered = format_shape_table(rows)
        lines = rendered.splitlines()
        # A header, a rule, and one row per shape.
        self.assertEqual(len(lines), 6)
        columns = lines[0].count("|") - 1
        for line in lines:
            self.assertEqual(line.count("|") - 1, columns)
        self.assertIn("| shape | subtree | signatures |", lines[0])
        # The subtree column is what makes the table worth printing: it is the
        # only place the four shapes' intervals can be compared. Rows are
        # direct, standalone, checkpoint-relative, landmark-relative.
        self.assertIn(f"| [0, {self.log.size}) |", lines[3])
        expected = covering_subtree(self.log.leaf_hashes(), 0, 8, INDEX)
        self.assertIn(f"| [{expected[0]}, {expected[1]}) |", lines[4])

    def test_landmark_relative_is_smaller_than_directly_signed(self):
        rows = shape_sizes(
            self.log, INDEX, self.key, "ML-DSA-65", self.cosigners,
            self.signer, self.landmark,
        )
        self.assertLess(rows[3]["bytes"], rows[0]["bytes"])


class TestRebuildingTheEntry(MTCFixture):
    def test_the_client_rebuilds_the_log_entry_byte_for_byte(self):
        cert = self.tree_relative()
        rebuilt = client.reconstruct_entry(cert)
        self.assertEqual(rebuilt.encoded(), self.log.entries[INDEX].encoded())
        self.assertEqual(rebuilt.entry_hash(), self.log.entry_hash(INDEX))

    def test_the_rebuild_matches_for_every_shape(self):
        for cert in (self.tree_relative(), self.landmark_relative()):
            self.assertEqual(
                client.reconstruct_entry(cert).entry_hash(), self.log.entry_hash(INDEX)
            )

    def test_the_unique_id_fields_are_absent(self):
        rebuilt = client.reconstruct_entry(self.tree_relative())
        encoded = rebuilt.tbs_certificate.encoded()
        # No field identifiers 7 or 8 (issuerUniqueID, subjectUniqueID).
        self.assertNotIn(bytes([7, 0, 0]), encoded)
        self.assertNotIn(bytes([8, 0, 0]), encoded)


class TestTampering(MTCFixture):
    def replace(self, cert, **fields):
        return dataclasses.replace(cert, **fields)

    def assertFails(self, cert, step_word, state=None):
        result = client.verify(cert, state if state is not None else self.client())
        self.assertFalse(result.ok, f"expected a failure, got {result}")
        self.assertIn(step_word, result.step)
        return result

    def test_a_swapped_key_is_caught(self):
        self.assertFails(
            self.replace(self.tree_relative(), subject_public_key_info=bytes(9) * 32),
            "cosignature",
        )

    def test_a_swapped_subject_is_caught(self):
        self.assertFails(
            self.replace(self.tree_relative(), subject="evil.example"), "cosignature"
        )

    def test_dropping_a_san_is_caught(self):
        self.assertFails(
            self.replace(self.tree_relative(), subject_alt_names=(SUBJECT,)), "cosignature"
        )

    def test_adding_a_san_is_caught(self):
        self.assertFails(
            self.replace(
                self.tree_relative(), subject_alt_names=(SUBJECT, "example.com", "extra.example")
            ),
            "cosignature",
        )

    def test_extending_the_validity_is_caught(self):
        self.assertFails(
            self.replace(
                self.tree_relative(), validity=(LAB_EPOCH, LAB_EPOCH + 10**9)
            ),
            "cosignature",
        )

    def test_a_swapped_serial_is_caught_by_the_serial_check(self):
        self.assertFails(
            self.replace(self.tree_relative(), serial_number=self.log.serial(5)),
            "serial number",
        )

    def test_a_serial_from_another_log_is_caught(self):
        self.assertFails(
            self.replace(self.tree_relative(), serial_number=issuance.serial_number(9, INDEX)),
            "serial number",
        )

    def test_moving_the_index_is_caught_by_the_serial_check(self):
        cert = self.tree_relative()
        moved = self.replace(
            cert, mtc_proof=dataclasses.replace(cert.mtc_proof, entry_index=5)
        )
        self.assertFails(moved, "serial number")

    def test_a_proof_for_another_interval_is_caught(self):
        cert = self.tree_relative()
        broken = self.replace(
            cert,
            mtc_proof=dataclasses.replace(
                cert.mtc_proof,
                subtree_end=16,
                inclusion_proof=tuple(
                    self.log.inclusion_proof(0, 16, INDEX)
                ),
            ),
        )
        self.assertFails(broken, "cosignature")

    def test_a_truncated_inclusion_proof_is_caught(self):
        cert = self.tree_relative()
        broken = self.replace(
            cert,
            mtc_proof=dataclasses.replace(
                cert.mtc_proof, inclusion_proof=cert.mtc_proof.inclusion_proof[:-1]
            ),
        )
        result = client.verify(broken, self.client())
        self.assertFalse(result.ok)
        self.assertIn("wrong shape", result.detail)

    def test_a_landmark_certificate_with_a_swapped_key_is_caught(self):
        self.assertFails(
            self.replace(self.landmark_relative(), subject_public_key_info=bytes(9) * 32),
            "landmark",
        )

    def test_a_landmark_certificate_with_dropped_sans_is_caught(self):
        self.assertFails(
            self.replace(self.landmark_relative(), subject_alt_names=()), "landmark"
        )

    def test_a_landmark_certificate_borrowing_another_landmark_number_is_caught(self):
        # The interval is right, so the hash lookup succeeds; the number is what
        # gives it away, because landmark 2 does not own [0, 16).
        cert = self.landmark_relative()
        other = lm.allocate(self.sequence, 24, LAB_EPOCH + 7200)
        moved = self.replace(
            cert, mtc_proof=dataclasses.replace(cert.mtc_proof, landmark=other.number)
        )
        result = self.assertFails(moved, "landmark")
        self.assertIn("does not own subtree", result.detail)

    def test_a_proof_with_one_cosignature_cannot_even_be_built(self):
        # The invariant is enforced at construction, so a client never has to
        # handle this case; a parser on the wire would have to.
        cert = self.tree_relative()
        with self.assertRaises(ValueError):
            dataclasses.replace(
                cert,
                mtc_proof=dataclasses.replace(
                    cert.mtc_proof,
                    subtree_cosignatures=cert.mtc_proof.subtree_cosignatures[:1],
                ),
            )

    def test_a_cosignature_from_an_unknown_cosigner_is_caught(self):
        cert = self.tree_relative()
        stranger = generate_cosigner(CA.landmark(8, 2), role="stranger")
        signature = stranger.sign_subtree(
            self.log.log_id,
            cert.mtc_proof.subtree_start,
            cert.mtc_proof.subtree_end,
            self.log.subtree_hash(*cert.mtc_proof.interval()),
        )
        forged = self.replace(
            cert,
            mtc_proof=dataclasses.replace(
                cert.mtc_proof,
                subtree_cosignatures=(signature,) + cert.mtc_proof.subtree_cosignatures[:1],
            ),
        )
        self.assertFails(forged, "cosignature")

    def test_a_client_that_trusts_no_cosigners_verifies_nothing(self):
        result = client.verify(self.tree_relative(), client.ClientState())
        self.assertFalse(result.ok)
        self.assertIn("does not trust", result.detail)

    def test_a_client_with_only_the_ca_cosigner_still_refuses(self):
        state = client.ClientState()
        state.add_cosigner(self.ca_cosigner)
        result = client.verify(self.tree_relative(), state)
        self.assertFalse(result.ok)
        self.assertIn("does not trust", result.detail)

    def test_a_direct_certificate_with_a_broken_signature_is_caught(self):
        cert = self.direct()
        broken = self.replace(cert, signature=bytes(len(cert.signature)))
        self.assertFalse(client.verify_direct(broken, self.client()).ok)

    def test_the_issuer_is_covered_by_the_direct_signature(self):
        """Re-issuing a certificate under another CA's name must not verify.

        The client picks the verifying key *by* the issuer, so an issuer outside
        the signed body would let anyone hand a client a certificate signed by
        one CA and labelled with another. This is the one field where the
        directly signed shape has no second line of defence: the cosigned
        shapes would also catch it through the entry hash, but this one is
        protected by the signature alone.
        """
        cert = self.direct()
        relabelled = self.replace(
            cert, issuer=TrustAnchorID.parse("1.3.6.1.4.1.32473.101")
        )
        state = self.client()
        # Give the client a key for the new issuer, so the refusal has to come
        # from the signature rather than from a missing key.
        state.add_ca_key(
            TrustAnchorID.parse("1.3.6.1.4.1.32473.101"),
            self.signer.parameter_set,
            self.signer.public_bytes(),
        )
        self.assertTrue(client.verify_direct(cert, state).ok)
        result = client.verify_direct(relabelled, state)
        self.assertFalse(result.ok)
        self.assertIn("signature", result.step)

    def test_the_issuer_is_covered_by_the_mtc_shapes_too(self):
        for name, cert in (
            ("standalone", self.tree_relative()),
            ("landmark", self.landmark_relative()),
        ):
            with self.subTest(shape=name):
                relabelled = self.replace(
                    cert, issuer=TrustAnchorID.parse("1.3.6.1.4.1.32473.101")
                )
                self.assertFalse(client.verify(relabelled, self.client()).ok)


class TestDecoding(MTCFixture):
    """The encoding has to be readable, not just writable.

    Encoding a dataclass is the easy half; the other half is that a client
    holding only bytes gets back the same object. The negative cases matter
    more here than in most of this file: a decoder that accepts a reordered
    field or a trailing byte will hand a caller a certificate whose signed
    bytes are not the ones the signer produced.
    """

    def shapes(self):
        return {
            "direct": self.direct(),
            "standalone": self.tree_relative(),
            "landmark": self.landmark_relative(),
        }

    def repack(self, encoded, patch, swap=()):
        """Return ``encoded`` with a body field's value replaced.

        Rebuilds the body's field list rather than editing bytes in place, so a
        test can change a value and have the result still be a well-formed
        encoding. ``swap`` is a pair of positions to emit in the opposite
        order. What neither can do is make the certificate still *correct* --
        that is the point: the decoder has to reject it.
        """
        reader = wire.Reader(encoded)
        body = wire.Reader(reader.vector_body())
        fields = []
        while not body.at_end():
            fields.append((body.uint(1), body.opaque_var(2)))
        if swap:
            first, second = swap
            fields[first], fields[second] = fields[second], fields[first]
        rebuilt = bytearray()
        for identifier, value in fields:
            if identifier in patch:
                value = patch[identifier]
            rebuilt += wire.uint(identifier, 1) + wire.opaque_var(value, 2)
        return wire.vector(bytes(rebuilt)) + reader.rest()

    def test_every_shape_round_trips(self):
        for name, cert in self.shapes().items():
            with self.subTest(shape=name):
                cls = DirectCertificate if name == "direct" else MerkleTreeCertificate
                decoded = cls.decode(cert.encoded())
                self.assertEqual(decoded, cert)
                self.assertEqual(decoded.encoded(), cert.encoded())

    def test_a_proof_round_trips_and_keeps_its_cosigner_ids(self):
        """Each cosignature is decoded in full, cosigner ID included.

        Dropping the ID would leave a signature nobody can attribute, which is
        the one thing the Signatures vector of Section 6.2 exists to prevent.
        """
        proof = self.tree_relative().mtc_proof
        decoded = MTCProof.decode_for_log(proof.encoded(), self.log.log_id)
        self.assertEqual(decoded, proof)
        self.assertEqual(
            [c.cosigner_id for c in decoded.subtree_cosignatures],
            [c.cosigner_id for c in proof.subtree_cosignatures],
        )

    def test_the_proof_carries_the_log_entrys_extensions_not_the_certificates(self):
        """The distinction exercise 05 asks students to confuse on purpose.

        Section 6.2 copies the *entry's* extension list into the proof. A
        decoder that rebuilt it from the certificate's own SANs would produce a
        proof that looks right and reconstructs the wrong entry.
        """
        cert = self.tree_relative()
        proof = MTCProof.decode_for_log(cert.mtc_proof.encoded(), self.log.log_id)
        entry = self.log.entries[INDEX]
        self.assertEqual(proof.extensions, entry.encoded_extensions())
        self.assertNotEqual(
            proof.extensions, encode_extensions(cert.subject_alt_names)
        )

    def test_the_log_id_comes_from_the_caller_and_must_agree(self):
        """A proof names its log by number, so the client supplies the ID.

        Decoding the same bytes against another log has to fail rather than
        yield a proof that hashes against the wrong tree.
        """
        cert = self.tree_relative()
        with self.assertRaises(ValueError) as caught:
            MerkleTreeCertificate.decode(cert.encoded(), CA.log(9))
        self.assertIn("log 8", str(caught.exception))
        self.assertEqual(
            MerkleTreeCertificate.decode(cert.encoded(), self.log.log_id), cert
        )

    def test_the_log_id_is_rebuilt_from_the_issuer_when_omitted(self):
        """Without a log ID, the issuer and log number are enough to name the log.

        That is the CA-side reading: whoever holds the CA knows its own issuer
        and the log it issued for, so the ID need not travel in the bytes.
        """
        cert = self.tree_relative()
        decoded = MerkleTreeCertificate.decode(cert.encoded())
        self.assertEqual(decoded.mtc_proof.log_id, self.log.log_id)
        self.assertEqual(decoded, cert)

    def test_a_proof_for_a_log_its_id_does_not_name_is_refused(self):
        with self.assertRaises(ValueError):
            MTCProof(
                log_id=CA.log(9), log_number=8, entry_index=INDEX,
                subtree_start=0, subtree_end=16, inclusion_proof=(), landmark=1,
            )

    def test_an_unknown_proof_form_is_refused(self):
        encoded = bytearray(self.tree_relative().mtc_proof.encoded())
        encoded[0] = 2
        with self.assertRaises(ValueError) as caught:
            MTCProof.decode_for_log(bytes(encoded), self.log.log_id)
        self.assertIn("form", str(caught.exception))

    def test_a_truncated_certificate_is_refused(self):
        with self.assertRaises(ValueError):
            MerkleTreeCertificate.decode(self.tree_relative().encoded()[:-40])

    def test_trailing_bytes_are_refused(self):
        """Nothing may follow the last field.

        A trailing byte is not a longer certificate, it is a second object glued
        to the first, and a caller that ignored it would be verifying something
        other than what it was handed.
        """
        with self.assertRaises(ValueError):
            MerkleTreeCertificate.decode(self.tree_relative().encoded() + b"\x00")

    def test_a_reordered_field_is_refused(self):
        """Identifiers must ascend, because that is the order the signature covers.

        Two fields trading places leaves the signed bytes the same length, so
        both the length check and the entry hash would pass. Only the order
        check catches it.
        """
        # C_VERSION and C_SERIAL are the first two fields, so swapping them is
        # the cheapest reordering that still leaves a decodable body.
        swapped = self.repack(self.tree_relative().encoded(), {}, swap=(0, 1))
        with self.assertRaises(ValueError) as caught:
            MerkleTreeCertificate.decode(swapped)
        self.assertIn("out of order", str(caught.exception))

    def test_a_missing_field_is_refused(self):
        cert = self.tree_relative()
        reader = wire.Reader(cert.encoded())
        body = wire.Reader(reader.vector_body())
        rebuilt = bytearray()
        while not body.at_end():
            identifier = body.uint(1)
            value = body.opaque_var(2)
            if identifier != certs.C_SPKI_ALGORITHM:
                rebuilt += wire.uint(identifier, 1) + wire.opaque_var(value, 2)
        without = wire.vector(bytes(rebuilt)) + reader.rest()
        with self.assertRaises(ValueError) as caught:
            MerkleTreeCertificate.decode(without)
        self.assertIn("subjectPublicKeyAlgorithm", str(caught.exception))

    def test_an_spki_hash_that_disagrees_with_its_spki_is_refused(self):
        """Both sit inside the signed body, so a mismatch is not an encoding bug.

        A certificate carrying one key and the hash of another would fail
        reconstruction on the entry hash with nothing pointing at the cause.
        """
        cert = self.tree_relative()
        rebuilt = self.repack(
            cert.encoded(), {certs.C_SPKI_HASH: hashlib.sha256(b"another key").digest()}
        )
        with self.assertRaises(ValueError) as caught:
            MerkleTreeCertificate.decode(rebuilt)
        self.assertIn("subjectPublicKeyInfoHash", str(caught.exception))

    def test_an_unsupported_version_is_refused(self):
        rebuilt = self.repack(
            self.tree_relative().encoded(), {certs.C_VERSION: wire.uint(3, 1)}
        )
        with self.assertRaises(ValueError) as caught:
            MerkleTreeCertificate.decode(rebuilt)
        self.assertIn("version", str(caught.exception))

    def test_validity_that_ends_before_it_starts_is_refused(self):
        rebuilt = self.repack(
            self.tree_relative().encoded(),
            {certs.C_VALIDITY: wire.uint(LAB_EPOCH + 3600, 8) + wire.uint(LAB_EPOCH, 8)},
        )
        with self.assertRaises(ValueError) as caught:
            MerkleTreeCertificate.decode(rebuilt)
        self.assertIn("before it starts", str(caught.exception))

    def test_a_signature_algorithm_that_contradicts_the_subject_key_is_refused(self):
        """The two have to name the same algorithm, and the decoder says so.

        This shape is signed by the subject's own key, so believing the
        signatureAlgorithm field alone would mean trying to check an ML-DSA-65
        signature with an Ed25519 key and reporting it as a signature failure
        rather than as a certificate that never made sense.
        """
        rebuilt = self.repack(
            self.direct().encoded(), {certs.C_SIGNATURE_ALGORITHM: b"Ed25519"}
        )
        with self.assertRaises(ValueError) as caught:
            DirectCertificate.decode(rebuilt)
        self.assertIn("Ed25519", str(caught.exception))

    def test_the_direct_shape_needs_its_signature_algorithm(self):
        """A Merkle Tree Certificate has no such field; the other shape must.

        The cosigned shapes name their cosigners in the proof, so the algorithm
        is a report about the subject key rather than a field. Dropping it from
        a directly signed certificate leaves nothing to say which key verifies
        the signature, so the decoder has to refuse rather than guess.
        """
        cert = self.direct()
        reader = wire.Reader(cert.encoded())
        body = wire.Reader(reader.vector_body())
        rebuilt = bytearray()
        while not body.at_end():
            identifier = body.uint(1)
            value = body.opaque_var(2)
            if identifier != certs.C_SIGNATURE_ALGORITHM:
                rebuilt += wire.uint(identifier, 1) + wire.opaque_var(value, 2)
        without = wire.vector(bytes(rebuilt)) + reader.rest()
        with self.assertRaises(ValueError) as caught:
            DirectCertificate.decode(without)
        self.assertIn("signatureAlgorithm", str(caught.exception))


class TestEntryHashIsTheBindingConstraint(MTCFixture):
    def test_every_field_of_the_entry_is_covered_by_its_hash(self):
        """The Section 5.2.1 property the whole design rests on.

        Change any one field and the entry hash changes, so no field can be
        altered without the cosignature or the landmark hash failing. This is the
        test to read first when the lab is extended with a new entry field.
        """
        original = self.log.entries[INDEX].tbs_certificate
        base = self.log.entry_hash(INDEX)
        variants = {
            "subject": {"subject": "evil.example"},
            "key hash": {"subject_public_key_info_hash": bytes(range(32))},
            "not_before": {"not_before": LAB_EPOCH - 1},
            "not_after": {"not_after": LAB_EPOCH + 10**9},
            "algorithm": {"subject_public_key_algorithm": "Ed25519"},
            "issuer": {"issuer": TrustAnchorID.parse("1.3.6.1.4.1.32473.101")},
            "sans": {"subject_alt_names": (SUBJECT,)},
        }
        for name, change in variants.items():
            with self.subTest(field=name):
                tbs = dataclasses.replace(original, **change)
                entry = client.MTCLogEntry(
                    type=issuance.TBS_CERT_ENTRY, tbs_certificate=tbs
                )
                self.assertNotEqual(entry.entry_hash(), base)

    def test_the_log_entry_is_smaller_than_the_certificate(self):
        entry_size = len(self.log.entries[INDEX].encoded())
        cert_size = len(self.tree_relative().encoded())
        self.assertLess(entry_size, cert_size)


if __name__ == "__main__":
    unittest.main()
