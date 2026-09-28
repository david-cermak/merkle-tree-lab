"""Tests for the presentation-language subset and the trust anchor IDs.

The wire tests are mostly about the strict decoder, because that is where a
subtle bug turns into a security bug: a decoder that ignores trailing bytes
accepts a proof with a valid prefix and anything after it.
"""

import unittest

from lab.mtc import wire
from lab.mtc.ids import TrustAnchorID


class TestIntegers(unittest.TestCase):
    def test_big_endian_widths(self):
        self.assertEqual(wire.uint(0, 2), b"\x00\x00")
        self.assertEqual(wire.uint(1, 1), b"\x01")
        self.assertEqual(wire.uint(0x0102, 2), b"\x01\x02")
        self.assertEqual(wire.uint((8 << 48) | 3, 8), ((8 << 48) | 3).to_bytes(8, "big"))

    def test_width_is_enforced(self):
        for value, width in ((256, 1), (65536, 2), (-1, 1)):
            with self.assertRaises(ValueError):
                wire.uint(value, width)

    def test_round_trip_through_reader(self):
        for value, width in ((0, 1), (255, 1), (64, 1), (16383, 2), (65535, 2)):
            self.assertEqual(wire.Reader(wire.uint(value, width)).uint(width), value)


class TestOpaque(unittest.TestCase):
    def test_variable_length_prefixes(self):
        self.assertEqual(wire.opaque_var(b"", 2), b"\x00\x00")
        self.assertEqual(wire.opaque_var(b"ab", 2), b"\x00\x02ab")
        self.assertEqual(wire.opaque_var(b"a" * 300, 2)[:2], b"\x01\x2c")
        self.assertEqual(wire.opaque_var(b"a" * 200, 1)[:1], b"\xc8")

    def test_one_byte_prefix_cannot_hold_more_than_255(self):
        with self.assertRaises(ValueError):
            wire.opaque_var(b"a" * 256, 1)

    def test_fixed_width_opaque_has_no_prefix(self):
        self.assertEqual(wire.opaque(b"12345678"), b"12345678")

    def test_reader_rejects_short_data(self):
        with self.assertRaises(wire.DecodeError):
            wire.Reader(b"\x00\x05ab").opaque_var(2)


class TestVector(unittest.TestCase):
    def test_short_vector_uses_one_byte_prefix(self):
        self.assertEqual(wire.vector([b"ab", b"cd"]), b"\x04abcd")

    def test_long_vector_uses_two_byte_prefix(self):
        body = b"x" * 100
        encoded = wire.vector(body)
        self.assertEqual(encoded[0], 0x40)
        self.assertEqual(encoded[1], 100)
        self.assertEqual(encoded[2:], body)

    def test_boundary_at_63_and_64(self):
        self.assertEqual(wire.vector(b"x" * 63)[0], 63)
        self.assertEqual(wire.vector(b"x" * 64)[0], 0x40)

    def test_single_element_is_one_element(self):
        self.assertEqual(wire.vector(b"ab"), wire.vector([b"ab"]))

    def test_empty(self):
        self.assertEqual(wire.vector(()), b"\x00")
        self.assertEqual(wire.Reader(b"\x00").vector_body(), b"")

    def test_vector_too_large_for_two_byte_prefix(self):
        with self.assertRaises(ValueError):
            wire.vector(b"x" * 0x4000)

    def test_round_trip(self):
        body = b"".join(wire.opaque_var(bytes([i]) * (i + 1), 2) for i in range(5))
        reader = wire.Reader(wire.vector(body))
        self.assertEqual(reader.vector_body(), body)

    def test_reserved_prefix_is_rejected(self):
        for first in (b"\x80", b"\xc0", b"\xe0", b"\xff"):
            with self.assertRaises(wire.DecodeError):
                wire.Reader(first + b"\x00" * 8).vector_body()

    def test_vector_bytes_hands_back_the_prefix_and_the_body(self):
        """An opaque vector is re-handed as bytes, prefix included.

        The extension list in an MTCProof is already length-prefixed because it
        is the log entry's own, copied across verbatim. A decoder that returned
        the body without the prefix would produce a proof that re-encodes to
        different bytes than it was parsed from -- the same class of bug as
        re-wrapping it in a second length prefix on the way out.
        """
        for length in (0, 1, 63, 64, 200, 4867):
            with self.subTest(length=length):
                body = bytes(range(256)) * (length // 256 + 1)
                body = body[:length]
                encoded = wire.vector(body)
                reader = wire.Reader(encoded)
                self.assertEqual(reader.vector_bytes(), encoded)
                self.assertTrue(reader.at_end())

    def test_vector_bytes_does_not_eat_the_next_field(self):
        """The bug this guards against is a one-byte overshoot.

        Reading the prefix and then the body in one step -- ``1 + length``
        rather than the prefix *plus* a two-byte prefix *plus* the body --
        swallows the first byte of whatever follows, so every field after a
        vector decodes shifted and the failure surfaces somewhere unrelated.
        """
        body = b"\xaa" * 4867
        reader = wire.Reader(wire.vector(body) + b"\x2a\x2b")
        self.assertEqual(reader.vector_bytes(), wire.vector(body))
        self.assertEqual(reader.remaining, 2)
        self.assertEqual(reader.rest(), b"\x2a\x2b")

    def test_vector_bytes_rejects_a_reserved_prefix(self):
        for first in (b"\x80", b"\xc0", b"\xe0", b"\xff"):
            with self.subTest(first=first):
                with self.assertRaises(wire.DecodeError):
                    wire.Reader(first + b"\x00" * 8).vector_bytes()


class TestReader(unittest.TestCase):
    def test_trailing_bytes_are_reported(self):
        reader = wire.Reader(b"\x01\x02")
        self.assertEqual(reader.uint(2), 0x0102)
        self.assertTrue(reader.at_end())
        reader.expect_end()

        reader = wire.Reader(b"\x01\x02\xff")
        reader.uint(2)
        with self.assertRaises(wire.DecodeError):
            reader.expect_end()

    def test_truncation_names_what_was_missing(self):
        with self.assertRaises(wire.DecodeError) as caught:
            wire.Reader(b"\x01").uint(4)
        self.assertIn("more bytes", str(caught.exception))

    def test_empty_read(self):
        with self.assertRaises(wire.DecodeError):
            wire.Reader(b"").uint(1)

    def test_skip_is_bounds_checked(self):
        reader = wire.Reader(b"\x01\x02\x03")
        reader.skip(2)
        self.assertEqual(reader.remaining, 1)
        with self.assertRaises(wire.DecodeError):
            reader.skip(2)

    def test_rest_returns_everything_left(self):
        reader = wire.Reader(b"\x01\x02\x03")
        reader.uint(1)
        self.assertEqual(reader.rest(), b"\x02\x03")
        self.assertTrue(reader.at_end())


class TestTrustAnchorIDs(unittest.TestCase):
    def test_the_drafts_packed_example(self):
        self.assertEqual(TrustAnchorID.parse("32473.1").packed().hex(), "2b0601040181fd5901")

    def test_the_drafts_distinguished_name_example(self):
        self.assertEqual(
            TrustAnchorID.parse("32473.1").distinguished_name(),
            "1.3.6.1.4.1.44363.47.3=#0d0481fd5901",
        )

    def test_a_deeper_id_uses_a_longer_length_octet(self):
        parsed = TrustAnchorID.parse("1.3.6.1.4.1.32473.100.0.8")
        self.assertEqual(parsed.packed().hex(), "2b0601040181fd59640008")

    def test_short_form_is_expanded_with_the_private_arc(self):
        parsed = TrustAnchorID.parse("32473.1")
        self.assertEqual(parsed.arcs[:7], (1, 3, 6, 1, 4, 1, 32473))
        self.assertEqual(parsed.arcs, (1, 3, 6, 1, 4, 1, 32473, 1))

    def test_dotted_form_round_trips(self):
        parsed = TrustAnchorID.parse("1.3.6.1.4.1.32473.100.0.8")
        self.assertEqual(parsed.dotted, "1.3.6.1.4.1.32473.100.0.8")
        self.assertEqual(TrustAnchorID.parse(parsed.dotted), parsed)

    def test_relative_oid_strips_the_private_arc(self):
        self.assertEqual(TrustAnchorID.parse("32473.1").relative_oid().hex(), "81fd5901")

    def test_name_bytes_are_the_cosigner_message_form(self):
        self.assertEqual(
            TrustAnchorID.parse("32473.1").name_bytes(), b"oid/1.3.6.1.4.1.32473.1"
        )

    def test_rejects_empty_and_negative(self):
        with self.assertRaises(ValueError):
            TrustAnchorID.parse("")
        with self.assertRaises(ValueError):
            TrustAnchorID(())
        with self.assertRaises(ValueError):
            TrustAnchorID((1, -2))

    def test_equality_and_hashing(self):
        one = TrustAnchorID.parse("1.3.6.1.4.1.32473.100.0.8")
        two = TrustAnchorID.parse("1.3.6.1.4.1.32473.100.0.8")
        self.assertEqual(one, two)
        self.assertEqual(len({one, two}), 1)

    def test_der_packing_of_large_arcs(self):
        packed = TrustAnchorID((1, 3, 6, 1, 4, 1, 32473, 1000)).packed()
        self.assertTrue(packed.endswith(b"\x87\x68"))  # 1000 == 0b1111101000

    def test_short_display_name(self):
        self.assertEqual(TrustAnchorID.parse("32473.1.0.8").short, "32473.1.0.8")
        self.assertEqual(str(TrustAnchorID.parse("1.3.6.1.4.1.32473.1")), "32473.1")

    def test_child_extends_the_arcs(self):
        self.assertEqual(
            TrustAnchorID.parse("32473.1").child(0, 8).dotted, "1.3.6.1.4.1.32473.1.0.8"
        )


class TestDerivedIDs(unittest.TestCase):
    def setUp(self):
        self.ca = TrustAnchorID.parse("1.3.6.1.4.1.32473.100")

    def test_log_id_appends_zero_and_the_log_number(self):
        self.assertEqual(self.ca.log(8).dotted, "1.3.6.1.4.1.32473.100.0.8")
        self.assertEqual(self.ca.log(8).arcs[-2:], (0, 8))

    def test_landmark_id_is_caID_landmarks_log_landmark(self):
        # {caID landmarks(1) N L} from Section 5.1.
        self.assertEqual(self.ca.landmark(8, 1).dotted, "1.3.6.1.4.1.32473.100.1.8.1")
        self.assertEqual(self.ca.landmark(8, 1).arcs[-3:], (1, 8, 1))

    def test_landmark_group_id_uses_two_as_the_first_appended_arc(self):
        self.assertEqual(self.ca.landmark_group(8, 1).dotted, "1.3.6.1.4.1.32473.100.2.8.1")

    def test_derived_ids_sort_after_their_parent(self):
        self.assertLess(self.ca.packed(), self.ca.log(8).packed())
        self.assertLess(self.ca.log(8).packed(), self.ca.landmark(8, 1).packed())

    def test_log_number_is_the_inverse_of_log(self):
        self.assertEqual(self.ca.log(8).log_number, 8)

    def test_only_log_ids_carry_a_log_number(self):
        for other in (self.ca, self.ca.landmark(8, 1), self.ca.landmark_group(8, 1)):
            with self.subTest(id=other.dotted):
                self.assertIsNone(other.log_number)

    def test_a_deeper_id_is_not_mistaken_for_a_log(self):
        """The last two arcs are checked, not just the last one.

        A cosigner ID ends in ``(8, 1)`` too, so a decoder that only looked at
        the final arc would read it as log 1 and check a proof against a log
        that does not exist.
        """
        self.assertIsNone(self.ca.landmark(8, 1).child(1, 1).log_number)


if __name__ == "__main__":
    unittest.main()
