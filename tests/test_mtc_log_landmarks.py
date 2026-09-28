"""Tests for the issuance log, the landmark sequence, and the cosigners.

These are the Section 5 structures. The tests are organised so that each class
maps onto one thing a reader of the draft will look up, and the negative cases
get as much attention as the positive ones: a log that accepts a malformed entry
is a log whose leaf hashes mean nothing.
"""

import unittest

from lab import merkle
from lab.mtc import wire
from lab.mtc.cosigners import (
    COSIGNATURE_LABEL,
    ca_cosigner,
    generate_cosigner,
    signature_sizes,
    sort_signatures,
)
from lab.mtc.ids import TrustAnchorID
from lab.mtc.landmarks import (
    LandmarkSequence,
    allocate,
    landmark_subtrees,
    parse_publication,
    publish,
    subtree_hashes_for,
)
from lab.mtc.log import (
    F_EXTENSIONS,
    F_ISSUER_UNIQUE_ID,
    F_SPKI_HASH,
    F_VERSION,
    LAB_EPOCH,
    NULL_ENTRY,
    TBS_CERT_ENTRY,
    IssuanceLog,
    MTCLogEntry,
    TbsCertificateLogEntry,
    encode_extensions,
    issue,
    null_entry,
    parse_extensions,
    serial_number,
    split_serial,
)

CA = TrustAnchorID.parse("1.3.6.1.4.1.32473.100")
KEY_HASH = bytes(range(32))


def entry(subject="www3.example", sans=("www3.example",), not_after=LAB_EPOCH + 3600):
    return MTCLogEntry(
        type=TBS_CERT_ENTRY,
        tbs_certificate=TbsCertificateLogEntry(
            issuer=CA,
            subject=subject,
            subject_public_key_algorithm="ML-DSA-65",
            subject_public_key_info_hash=KEY_HASH,
            not_before=LAB_EPOCH,
            not_after=not_after,
            subject_alt_names=tuple(sans),
        ),
    )


def new_log(log_number=8):
    """Return an empty issuance log for the workshop's CA."""
    return IssuanceLog(CA, log_number)


def log_with(count=20, null_at=7, log_number=8):
    """Return a log of ``count`` entries, with a null entry at ``null_at``."""
    log = new_log(log_number)
    for index in range(count):
        log.append(null_entry() if index == null_at else entry(f"www{index}.example"))
    return log


class TestSerialNumbers(unittest.TestCase):
    def test_serial_is_the_log_and_index_pair(self):
        self.assertEqual(serial_number(8, 3), (8 << 48) | 3)
        self.assertEqual(split_serial(serial_number(8, 3)), (8, 3))

    def test_serials_are_positive_and_fit_in_64_bits(self):
        for log_number, index in ((1, 0), (65535, 2**48 - 1), (8, 19)):
            serial = serial_number(log_number, index)
            self.assertGreater(serial, 0)
            self.assertLessEqual(serial, 2**64 - 1)

    def test_round_trip_over_a_range(self):
        for log_number in (1, 2, 255, 256, 65535):
            for index in (0, 1, 15, 16, 2**20, 2**48 - 1):
                self.assertEqual(split_serial(serial_number(log_number, index)),
                                 (log_number, index))

    def test_rejects_out_of_range_parts(self):
        for log_number, index in ((0, 0), (65536, 0), (1, 2**48), (8, -1)):
            with self.assertRaises(ValueError):
                serial_number(log_number, index)

    def test_splits_a_serial_from_another_protocol(self):
        with self.assertRaises(ValueError):
            split_serial(2**64)
        with self.assertRaises(ValueError):
            split_serial(-1)


class TestLogEntries(unittest.TestCase):
    def test_leaf_hash_is_the_rfc6962_leaf_hash(self):
        one = entry()
        self.assertEqual(one.entry_hash(), merkle.hash_leaf(one.encoded()))

    def test_entry_encoding_is_extensions_type_body(self):
        encoded = entry().encoded()
        self.assertTrue(encoded.endswith(
            one_tbs := entry().tbs_certificate.encoded()))
        self.assertIn(one_tbs, encoded)
        # the two-byte type sits immediately before the TBS body
        offset = encoded.index(one_tbs)
        self.assertEqual(encoded[offset - 2:offset], b"\x00\x01")

    def test_null_entry_carries_no_body(self):
        self.assertEqual(null_entry().encoded(), b"\x00" + wire.uint(NULL_ENTRY, 2))
        self.assertNotEqual(null_entry().entry_hash(), entry().entry_hash())

    def test_null_entry_rejects_a_body(self):
        with self.assertRaises(ValueError):
            MTCLogEntry(type=NULL_ENTRY, tbs_certificate=entry().tbs_certificate).encoded()

    def test_tbs_entry_requires_a_body(self):
        with self.assertRaises(ValueError):
            MTCLogEntry(type=TBS_CERT_ENTRY).encoded()
        with self.assertRaises(ValueError):
            MTCLogEntry(type=7, tbs_certificate=entry().tbs_certificate).encoded()

    def test_validity_must_not_run_backwards(self):
        with self.assertRaises(ValueError):
            TbsCertificateLogEntry(
                CA, "a", "ML-DSA-65", KEY_HASH, not_before=10, not_after=9
            )

    def test_key_hash_must_be_32_bytes(self):
        for wrong in (b"", bytes(31), bytes(33)):
            with self.assertRaises(ValueError):
                TbsCertificateLogEntry(CA, "a", "ML-DSA-65", wrong, 1, 2)

    def test_a_different_field_changes_the_hash(self):
        base = entry().entry_hash()
        self.assertNotEqual(base, entry(subject="evil.example").entry_hash())
        self.assertNotEqual(base, entry(sans=("a.example", "b.example")).entry_hash())
        self.assertNotEqual(base, entry(not_after=LAB_EPOCH + 1).entry_hash())
        self.assertNotEqual(base, entry().tbs_certificate.without_san().encoded()
                            and MTCLogEntry(
                                type=TBS_CERT_ENTRY,
                                tbs_certificate=entry().tbs_certificate.without_san(),
                            ).entry_hash())

    def test_sans_round_trip_through_the_extension_list(self):
        sans = ("www3.example", "example.com")
        self.assertEqual(parse_extensions(encode_extensions(sans)), sans)
        self.assertEqual(parse_extensions(encode_extensions(())), ())

    def test_unrecognised_extensions_are_ignored_not_fatal(self):
        unknown = wire.vector(wire.uint(9999, 2) + wire.opaque_var(b"whatever", 2))
        self.assertEqual(parse_extensions(unknown), ())

    def test_sans_read_back_from_the_tbs(self):
        self.assertEqual(entry(sans=("a.example", "b.example")).tbs_certificate.sans(),
                         ("a.example", "b.example"))


def entry_fields(tbs):
    """Return an entry body's ``(identifier, value)`` pairs, in wire order."""
    reader = wire.Reader(tbs)
    body = wire.Reader(reader.vector_body())
    fields = []
    while not body.at_end():
        fields.append((body.uint(1), body.opaque_var(2)))
    return fields


def reencode(fields):
    return wire.vector(
        wire.uint(field_id, 1) + wire.opaque_var(value, 2) for field_id, value in fields
    )


def with_body(tbs):
    """Wrap a TBS body the way ``MTCLogEntry.encoded`` wraps one."""
    return wire.vector(b"") + wire.uint(TBS_CERT_ENTRY, 2) + tbs


class TestDecodingEntries(unittest.TestCase):
    """A decoder that guesses is a decoder that can be made to agree.

    Every field is inside the hashed body, so a decoder that filled in a default
    for a missing field would produce an entry the CA never signed -- and the
    mismatch would show up as a hash disagreement rather than as a parse error,
    which is the harder failure to debug and the easier one to miss.
    """

    def test_round_trips_every_shape_of_entry(self):
        for one in (entry(), entry(sans=()), entry(sans=("a.example",)), null_entry()):
            decoded = MTCLogEntry.decode(one.encoded())
            self.assertEqual(decoded, one)
            self.assertEqual(decoded.encoded(), one.encoded())

    def test_round_trips_a_whole_log(self):
        log = log_with(20)
        for index in range(log.size):
            decoded = MTCLogEntry.decode(log.entries[index].encoded())
            self.assertEqual(decoded, log.entries[index])
            self.assertEqual(decoded.entry_hash(), log.entry_hash(index))

    def test_a_decoded_entry_keeps_the_issuer(self):
        self.assertEqual(MTCLogEntry.decode(entry().encoded()).tbs_certificate.issuer, CA)

    def test_rejects_trailing_bytes(self):
        with self.assertRaisesRegex(ValueError, "trailing"):
            MTCLogEntry.decode(entry().encoded() + b"\x00")

    def test_rejects_a_truncated_body(self):
        with self.assertRaises(wire.DecodeError):
            MTCLogEntry.decode(entry().encoded()[:-1])

    def test_rejects_an_unknown_entry_type(self):
        encoded = entry().encoded()
        with self.assertRaisesRegex(ValueError, "unknown MTCLogEntryType"):
            MTCLogEntry.decode(encoded[:1] + wire.uint(7, 2) + encoded[3:])

    def test_rejects_a_null_entry_with_a_body(self):
        with self.assertRaisesRegex(ValueError, "null_entry must be the whole"):
            MTCLogEntry.decode(null_entry().encoded() + b"\x00\x01")

    def test_rejects_a_missing_field(self):
        fields = entry_fields(entry().tbs_certificate.encoded())
        without = [pair for pair in fields if pair[0] != 4]  # subject
        with self.assertRaisesRegex(ValueError, "missing its subject field"):
            MTCLogEntry.decode(with_body(reencode(without)))

    def test_rejects_fields_out_of_order(self):
        fields = entry_fields(entry().tbs_certificate.encoded())
        swapped = [fields[1], fields[0]] + fields[2:]
        with self.assertRaisesRegex(ValueError, "out of order or repeated"):
            MTCLogEntry.decode(with_body(reencode(swapped)))

    def test_rejects_an_unexpected_field_count(self):
        fields = entry_fields(entry().tbs_certificate.encoded())
        with self.assertRaisesRegex(ValueError, "expected 7"):
            MTCLogEntry.decode(with_body(reencode(fields + [(10, b"\x01")])))

    def test_rejects_a_unique_id_field_the_lab_never_issues(self):
        # Placed in identifier order, between the key hash and the extensions,
        # so the ordering check passes and the field is judged on its own. The
        # lab issues neither unique ID; Section 6.2 copies an entry's fields into
        # the certificate "if and only if" the certificate has them, so a
        # decoded one is an entry from somewhere else.
        fields = entry_fields(entry().tbs_certificate.encoded())
        with_id = [
            (fid, value) if fid != F_EXTENSIONS
            else (F_ISSUER_UNIQUE_ID, b"\x01\x02")
            for fid, value in fields
        ] + [(F_EXTENSIONS, next(v for f, v in fields if f == F_EXTENSIONS))]
        with self.assertRaisesRegex(ValueError, "unique-ID"):
            MTCLogEntry.decode(with_body(reencode(with_id)))

    def test_rejects_an_unsupported_version(self):
        fields = entry_fields(entry().tbs_certificate.encoded())
        changed = [(F_VERSION, wire.uint(3, 1)) if fid == F_VERSION else (fid, value)
                   for fid, value in fields]
        with self.assertRaisesRegex(ValueError, "unsupported entry version"):
            MTCLogEntry.decode(with_body(reencode(changed)))

    def test_rejects_validity_that_runs_backwards(self):
        fields = entry_fields(entry().tbs_certificate.encoded())
        reversed_time = [(3, wire.uint(LAB_EPOCH + 7200, 8) + wire.uint(LAB_EPOCH, 8))
                         if fid == 3 else (fid, value) for fid, value in fields]
        with self.assertRaisesRegex(ValueError, "ends before it starts"):
            MTCLogEntry.decode(with_body(reencode(reversed_time)))

    def test_rejects_a_short_key_hash(self):
        fields = entry_fields(entry().tbs_certificate.encoded())
        short = [(F_SPKI_HASH, value[:-1]) if fid == F_SPKI_HASH else (fid, value)
                 for fid, value in fields]
        with self.assertRaisesRegex(ValueError, "must be 32 bytes"):
            MTCLogEntry.decode(with_body(reencode(short)))

    def test_rejects_trailing_bytes_inside_validity(self):
        fields = entry_fields(entry().tbs_certificate.encoded())
        fields = dict(fields)
        fields[3] = fields[3] + b"\x00"
        with self.assertRaisesRegex(ValueError, "trailing bytes in the validity"):
            MTCLogEntry.decode(with_body(reencode(list(fields.items()))))


class TestIssuanceLog(unittest.TestCase):
    def test_log_id_comes_from_the_ca_id(self):
        self.assertEqual(log_with(0).log_id.dotted, "1.3.6.1.4.1.32473.100.0.8")

    def test_index_of_every_entry(self):
        log = log_with(5, null_at=None)
        for index in range(5):
            self.assertEqual(log.entries[index].subject if hasattr(log.entries[index], "subject")
                             else log.entries[index].tbs_certificate.subject,
                             f"www{index}.example")

    def test_tree_size_zero_has_the_empty_root(self):
        self.assertEqual(log_with(0).root(), merkle.empty_root())

    def test_root_over_a_prefix(self):
        log = log_with(20)
        self.assertEqual(log.root(12), log.root(20)[:0] or log.root(12))
        prefixes = [log.root(size) for size in range(1, 21)]
        self.assertEqual(len(set(prefixes)), 20, "every prefix has a distinct root")

    def test_proofs_come_from_the_log(self):
        log = log_with(20)
        proof = log.inclusion_proof(0, 20, 3)
        self.assertTrue(
            merkle.verify_inclusion(
                log.entry_hash(3), 3, 20, proof, log.root(20)
            )
        )

    def test_covering_subtrees_cover_the_new_entries(self):
        log = log_with(20)
        for previous, size in ((0, 12), (12, 20), (0, 20), (7, 9)):
            left, right = log.covering_subtrees(previous, size)
            covered = list(range(*left)) + list(range(*right))
            self.assertEqual(covered, list(range(previous, size)))

    def test_covering_subtrees_reject_impossible_ranges(self):
        log = log_with(20)
        for previous, size in ((5, 4), (0, 21), (-1, 4)):
            with self.assertRaises(ValueError):
                log.covering_subtrees(previous, size)

    def test_covering_an_empty_range_is_degenerate(self):
        # [20, 20) is a valid empty interval, and Section 4.5 gives two empty
        # subtrees back rather than an error.
        self.assertEqual(log_with(20).covering_subtrees(20, 20), ((20, 20), (20, 20)))

    def test_null_entries_occupy_a_position(self):
        log = log_with(20)
        self.assertEqual(log.entries[7].type, NULL_ENTRY)
        self.assertEqual(log.size, 20)
        self.assertEqual(str(log.entries[7]), "null_entry")

    def test_issue_returns_the_entry_and_index(self):
        log = log_with(0)
        added, index = issue(
            log, "www0.example", b"spki-bytes", "ML-DSA-65", LAB_EPOCH,
            LAB_EPOCH + 3600, ("www0.example",),
        )
        self.assertEqual(index, 0)
        self.assertEqual(log.size, 1)
        import hashlib

        self.assertEqual(
            added.tbs_certificate.subject_public_key_info_hash,
            hashlib.sha256(b"spki-bytes").digest(),
        )

    def test_serial_matches_the_index(self):
        log = log_with(20)
        self.assertEqual(split_serial(log.serial(3)), (8, 3))

    def test_log_number_must_be_positive(self):
        with self.assertRaises(ValueError):
            new_log(0)


class TestCheckpoints(unittest.TestCase):
    def test_checkpoint_covers_the_requested_prefix(self):
        log = log_with(20)
        checkpoint = log.checkpoint(12)
        self.assertEqual(checkpoint.tree_size, 12)
        self.assertEqual(checkpoint.root_hash, log.root(12))
        self.assertEqual(checkpoint.log_id, log.log_id)

    def test_no_cosigners_means_no_signatures(self):
        self.assertEqual(log_with(20).checkpoint(12).signatures, ())

    def test_cosigners_sign_the_whole_prefix(self):
        log = log_with(20)
        cosigner = ca_cosigner(CA)
        checkpoint = log.checkpoint(12, [cosigner])
        self.assertTrue(checkpoint.signed_by([cosigner]))
        self.assertEqual(len(checkpoint.signatures), 1)
        self.assertEqual(checkpoint.timestamp, LAB_EPOCH)

    def test_a_checkpoint_from_another_cosigner_does_not_verify(self):
        log = log_with(20)
        signer = ca_cosigner(CA)
        other = generate_cosigner(CA.landmark(8, 1))
        checkpoint = log.checkpoint(12, [signer])
        self.assertFalse(checkpoint.signed_by([other]))

    def test_a_checkpoint_over_a_different_root_does_not_verify(self):
        log = log_with(20)
        cosigner = ca_cosigner(CA)
        checkpoint = log.checkpoint(12, [cosigner])
        wrong = log.checkpoint(13, [cosigner])
        self.assertFalse(
            cosigner.verify_subtree(
                checkpoint.log_id, 0, checkpoint.tree_size,
                wrong.root_hash, checkpoint.signatures[0].signature, checkpoint.timestamp,
            )
        )

    def test_every_requested_cosigner_must_have_signed(self):
        log = log_with(20)
        one, two = ca_cosigner(CA), generate_cosigner(CA.landmark(8, 1))
        checkpoint = log.checkpoint(12, [one])
        self.assertFalse(checkpoint.signed_by([one, two]))


class TestCosigners(unittest.TestCase):
    def setUp(self):
        self.log = log_with(20)
        self.ca = ca_cosigner(CA)
        self.witness = generate_cosigner(CA.landmark(8, 1), role="witness")

    def test_the_label_is_twelve_bytes(self):
        self.assertEqual(len(COSIGNATURE_LABEL), 12)
        self.assertTrue(COSIGNATURE_LABEL.startswith(b"subtree/v1"))

    def test_a_cosignature_verifies(self):
        signature = self.ca.sign_subtree(self.log.log_id, 0, 20, self.log.subtree_hash(0, 20))
        self.assertTrue(
            self.ca.verify_subtree(
                self.log.log_id, 0, 20, self.log.subtree_hash(0, 20), signature.signature
            )
        )

    def test_a_signature_from_another_log_does_not_verify(self):
        other_log = new_log(9)
        signature = self.ca.sign_subtree(self.log.log_id, 0, 20, self.log.subtree_hash(0, 20))
        self.assertFalse(
            self.ca.verify_subtree(
                other_log.log_id, 0, 20, self.log.subtree_hash(0, 20), signature.signature
            )
        )

    def test_a_signature_over_another_interval_does_not_verify(self):
        signature = self.ca.sign_subtree(self.log.log_id, 0, 20, self.log.subtree_hash(0, 20))
        self.assertFalse(
            self.ca.verify_subtree(
                self.log.log_id, 0, 16, self.log.subtree_hash(0, 16), signature.signature
            )
        )

    def test_a_signature_over_another_hash_does_not_verify(self):
        signature = self.ca.sign_subtree(self.log.log_id, 0, 20, self.log.subtree_hash(0, 20))
        self.assertFalse(
            self.ca.verify_subtree(self.log.log_id, 0, 20, bytes(32), signature.signature)
        )

    def test_invalid_subtree_is_refused(self):
        # Section 4.1's test is "start is a multiple of BIT_CEIL(end - start)",
        # so only a negative start or an inverted interval can fail it.
        for start, end in ((-1, 4), (4, 2), (0, -1)):
            with self.assertRaises(ValueError):
                self.ca.sign_subtree(self.log.log_id, start, end, bytes(32))

    def test_an_odd_sized_subtree_is_still_valid_by_the_drafts_rule(self):
        # [0, 3) passes Section 4.1 because BIT_CEIL(3) is 4 and 0 % 4 == 0.
        signature = self.ca.sign_subtree(self.log.log_id, 0, 3, bytes(32))
        self.assertEqual(signature.cosigner_id, CA)

    def test_inconsistent_subtrees_are_refused(self):
        # [0, 12) and [8, 16) are both valid subtrees of a 20-entry log, they
        # overlap, and neither contains the other -- so signing both is what
        # Section 5.3.2 forbids.
        self.ca.sign_subtree(self.log.log_id, 0, 12, self.log.subtree_hash(0, 12))
        with self.assertRaises(ValueError):
            self.ca.sign_subtree(self.log.log_id, 8, 16, self.log.subtree_hash(8, 16))

    def test_nested_and_disjoint_subtrees_are_allowed(self):
        self.ca.sign_subtree(self.log.log_id, 0, 20, self.log.subtree_hash(0, 20))
        self.ca.sign_subtree(self.log.log_id, 0, 16, self.log.subtree_hash(0, 16))
        self.ca.sign_subtree(self.log.log_id, 16, 20, self.log.subtree_hash(16, 20))
        other = generate_cosigner(CA.landmark(8, 1))
        other.sign_subtree(self.log.log_id, 0, 12, self.log.subtree_hash(0, 12))
        other.sign_subtree(self.log.log_id, 8, 12, self.log.subtree_hash(8, 12))

    def test_signatures_sort_by_cosigner_id(self):
        first = self.ca.sign_subtree(self.log.log_id, 0, 20, self.log.subtree_hash(0, 20))
        second = self.witness.sign_subtree(self.log.log_id, 0, 20, self.log.subtree_hash(0, 20))
        for order in ([first, second], [second, first]):
            self.assertEqual(
                [s.cosigner_id for s in sort_signatures(order)],
                [self.ca.cosigner_id, self.witness.cosigner_id],
            )

    def test_duplicate_cosigner_ids_are_rejected(self):
        signature = self.ca.sign_subtree(self.log.log_id, 0, 20, self.log.subtree_hash(0, 20))
        with self.assertRaises(ValueError):
            sort_signatures([signature, signature])

    def test_a_signature_never_contains_the_subtree_hash(self):
        signature = self.ca.sign_subtree(self.log.log_id, 0, 20, self.log.subtree_hash(0, 20))
        self.assertNotIn(self.log.subtree_hash(0, 20), signature.signature)

    def test_signature_sizes_are_measured(self):
        # Measured, not asserted from a table: these are the DER SPKI and
        # signature lengths of the ML-DSA parameter sets.
        for parameter_set, expected in (("mldsa44", (1334, 2420)), ("mldsa65", (1974, 3309))):
            self.assertEqual(signature_sizes(parameter_set), expected)


class TestLandmarkSequence(unittest.TestCase):
    def setUp(self):
        self.log = log_with(20)
        self.sequence = LandmarkSequence(self.log.log_id)

    def test_landmark_zero_is_the_degenerate_start(self):
        zero = self.sequence[0]
        self.assertEqual((zero.tree_size, zero.expiry), (0, 0))
        self.assertEqual(zero.subtrees, ((0, 0), (0, 0)))
        self.assertFalse(zero.contains(0))

    def test_the_first_landmark_covers_the_whole_log(self):
        landmark = allocate(self.sequence, 20, LAB_EPOCH + 3600)
        self.assertEqual(landmark.number, 1)
        self.assertEqual(landmark.subtrees, ((0, 16), (16, 20)))
        self.assertTrue(landmark.contains(3))
        self.assertTrue(landmark.contains(19))
        self.assertEqual(landmark.subtree_for(3), (0, 16))
        self.assertEqual(landmark.subtree_for(19), (16, 20))

    def test_later_landmarks_cover_only_the_new_entries(self):
        allocate(self.sequence, 20, LAB_EPOCH + 3600)
        second = allocate(self.sequence, 24, LAB_EPOCH + 7200)
        # Section 4.5's covering of [20, 24), which is two leaves plus two.
        self.assertEqual(second.subtrees, ((20, 22), (22, 24)))
        self.assertFalse(second.contains(3))
        self.assertTrue(second.contains(20))

    def test_tree_size_must_strictly_increase(self):
        allocate(self.sequence, 20, LAB_EPOCH + 3600)
        for bad in (20, 19, 0):
            with self.assertRaises(ValueError):
                allocate(self.sequence, bad, LAB_EPOCH + 7200)

    def test_expiry_must_not_decrease(self):
        allocate(self.sequence, 20, LAB_EPOCH + 3600)
        with self.assertRaises(ValueError):
            allocate(self.sequence, 24, LAB_EPOCH - 1)

    def test_active_landmarks_expire(self):
        first = allocate(self.sequence, 20, LAB_EPOCH + 3600)
        self.assertEqual(self.sequence.active(LAB_EPOCH), [first])
        self.assertEqual(self.sequence.active(LAB_EPOCH + 7200), [])
        self.assertFalse(self.sequence.covers(3, LAB_EPOCH + 7200))
        self.assertTrue(self.sequence.covers(3, LAB_EPOCH))

    def test_lowest_above_picks_the_earliest_landmark_that_covers_the_index(self):
        allocate(self.sequence, 12, LAB_EPOCH + 3600)
        allocate(self.sequence, 20, LAB_EPOCH + 7200)
        self.assertEqual(self.sequence.lowest_above(3, LAB_EPOCH).number, 1)
        self.assertEqual(self.sequence.lowest_above(15, LAB_EPOCH).number, 2)
        self.assertIsNone(self.sequence.lowest_above(20, LAB_EPOCH))

    def test_subtree_for_an_index_outside_every_subtree(self):
        landmark = allocate(self.sequence, 20, LAB_EPOCH + 3600)
        with self.assertRaises(ValueError):
            landmark.subtree_for(20)

    def test_check_reports_a_healthy_sequence_as_clean(self):
        allocate(self.sequence, 12, LAB_EPOCH + 3600)
        allocate(self.sequence, 20, LAB_EPOCH + 7200)
        self.assertEqual(self.sequence.check(), [])

    def test_client_state_is_one_row_per_subtree(self):
        landmark = allocate(self.sequence, 20, LAB_EPOCH + 3600)
        rows = subtree_hashes_for(self.sequence, self.log.leaf_hashes())
        self.assertEqual(len(rows), 2)
        self.assertEqual(
            [(row["start"], row["end"]) for row in rows], list(landmark.subtrees)
        )
        for row in rows:
            self.assertEqual(
                row["hash"], self.log.subtree_hash(row["start"], row["end"])
            )

    def test_only_active_landmarks_contribute_trusted_subtrees(self):
        # Section 7.4: "Trusted subtrees for a CA are determined by its active
        # landmark subtrees." An expired landmark must stop being trusted,
        # otherwise the expiry is decorative.
        allocate(self.sequence, 20, LAB_EPOCH + 3600)
        fresh = subtree_hashes_for(self.sequence, self.log.leaf_hashes())
        self.assertEqual(len(fresh), 2)

        after_expiry = subtree_hashes_for(
            self.sequence, self.log.leaf_hashes(), now=LAB_EPOCH + 3600
        )
        self.assertEqual(after_expiry, [])

    def test_a_second_landmark_still_counts_while_the_first_is_active(self):
        first = allocate(self.sequence, 12, LAB_EPOCH + 3600)
        second = allocate(self.sequence, 20, LAB_EPOCH + 7200)
        # Strictly before the first expires: a landmark is active while
        # expiry > now, so at exactly its expiry it is already gone.
        rows = subtree_hashes_for(
            self.sequence, self.log.leaf_hashes(), now=LAB_EPOCH + 3599
        )
        self.assertEqual(
            sorted((row["start"], row["end"]) for row in rows),
            sorted(list(first.subtrees) + list(second.subtrees)),
        )

    def test_landmark_zero_never_contributes(self):
        # Landmark zero is [0, 0) twice, and is never active. Without the
        # number check it would contribute two degenerate zero-length rows.
        rows = subtree_hashes_for(self.sequence, self.log.leaf_hashes())
        self.assertTrue(all(row["start"] < row["end"] for row in rows))

    def test_landmark_subtrees_helper(self):
        self.assertEqual(landmark_subtrees(12, 20), ((12, 16), (16, 20)))
        with self.assertRaises(ValueError):
            landmark_subtrees(20, 20)


class TestLandmarkPublication(unittest.TestCase):
    def setUp(self):
        self.log = log_with(20)
        self.sequence = LandmarkSequence(self.log.log_id)

    def test_publication_lists_active_landmarks_newest_first(self):
        allocate(self.sequence, 12, LAB_EPOCH + 3600)
        allocate(self.sequence, 20, LAB_EPOCH + 7200)
        document = publish(self.sequence, LAB_EPOCH)
        self.assertEqual(
            document,
            f"2\n20 {LAB_EPOCH + 7200}\n12 {LAB_EPOCH + 3600}\n0 0\n",
        )

    def test_publication_stops_at_the_first_expired_landmark(self):
        allocate(self.sequence, 12, LAB_EPOCH + 3600)
        allocate(self.sequence, 20, LAB_EPOCH + 7200)
        # At t+4000 only landmark 2 is active, and landmark 1 is the required
        # expired line that ends the document.
        self.assertEqual(
            publish(self.sequence, LAB_EPOCH + 4000),
            f"2\n20 {LAB_EPOCH + 7200}\n12 {LAB_EPOCH + 3600}\n",
        )

    def test_publication_of_a_log_with_one_landmark(self):
        allocate(self.sequence, 20, LAB_EPOCH + 3600)
        self.assertEqual(
            publish(self.sequence, LAB_EPOCH),
            f"1\n20 {LAB_EPOCH + 3600}\n0 0\n",
        )

    def test_publication_round_trips(self):
        allocate(self.sequence, 12, LAB_EPOCH + 3600)
        allocate(self.sequence, 20, LAB_EPOCH + 7200)
        parsed = parse_publication(publish(self.sequence, LAB_EPOCH), LAB_EPOCH)
        self.assertEqual(
            [(lm.number, lm.tree_size, lm.expiry) for lm in parsed],
            [(2, 20, LAB_EPOCH + 7200), (1, 12, LAB_EPOCH + 3600), (0, 0, 0)],
        )

    def test_a_malformed_publication_is_refused(self):
        # The first two embed LAB_EPOCH, the rest are deliberately malformed
        # in ways that have nothing to do with the current epoch.
        new, old = LAB_EPOCH + 7200, LAB_EPOCH + 3600
        bad_documents = [
            f"2\n20 {new}\n12 {old}\n",  # no expired landmark
            f"2\n20 {new}\n20 {old}\n0 0\n",  # sizes do not decrease
            "x\n20 1\n0 0\n",  # header is not a number
            "2\n20  1\n0 0\n",  # double space
            "2\n20 1\n 0 0\n",  # leading space
            "1\n20 1",  # no trailing newline
            "0\n",  # no landmark lines
            "2\n20 1\n12 2\n0 0\n",  # expiries increase down the document
        ]
        for document in bad_documents:
            with self.assertRaises(ValueError, msg=document):
                parse_publication(document, LAB_EPOCH)


if __name__ == "__main__":
    unittest.main()
