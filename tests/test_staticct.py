"""Unit tests for static-ct entry-bundle parsing and Merkle leaf construction."""

import unittest

from lab import merkle, staticct


def _x509_entry(timestamp: int, cert: bytes, leaf_index: int, fingerprints: bytes = b"") -> bytes:
    extensions = b"\x00" + (5).to_bytes(2, "big") + leaf_index.to_bytes(5, "big")
    out = bytearray()
    out += timestamp.to_bytes(8, "big")
    out += (0).to_bytes(2, "big")
    out += len(cert).to_bytes(3, "big") + cert
    out += len(extensions).to_bytes(2, "big") + extensions
    out += len(fingerprints).to_bytes(2, "big") + fingerprints
    return bytes(out)


class TestEntryBundle(unittest.TestCase):
    def test_parse_single_x509_entry(self):
        cert = b"\x30\x03\x02\x01\x05"  # arbitrary DER-looking bytes
        bundle = _x509_entry(1234, cert, leaf_index=9)
        entries = staticct.parse_entry_bundle(bundle)
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.timestamp, 1234)
        self.assertFalse(entry.is_precert)
        self.assertEqual(entry.certificate, cert)
        self.assertEqual(entry.leaf_index, 9)

    def test_parse_multiple_entries(self):
        bundle = _x509_entry(1, b"cert-a", 0) + _x509_entry(2, b"cert-b", 1)
        entries = staticct.parse_entry_bundle(bundle)
        self.assertEqual([e.leaf_index for e in entries], [0, 1])
        self.assertEqual([e.certificate for e in entries], [b"cert-a", b"cert-b"])

    def test_merkle_leaf_layout_and_hash(self):
        cert = b"certificate-bytes"
        entry = staticct.parse_entry_bundle(_x509_entry(42, cert, 3))[0]
        leaf = entry.merkle_tree_leaf()
        expected = (
            b"\x00\x00"
            + (42).to_bytes(8, "big")
            + (0).to_bytes(2, "big")
            + len(cert).to_bytes(3, "big")
            + cert
            + (8).to_bytes(2, "big")
            + b"\x00" + (5).to_bytes(2, "big") + (3).to_bytes(5, "big")
        )
        self.assertEqual(leaf, expected)
        self.assertEqual(entry.leaf_hash(), merkle.hash_leaf(expected))

    def test_parse_ct_extensions(self):
        extensions = b"\x00" + (5).to_bytes(2, "big") + (0x0102030405).to_bytes(5, "big")
        self.assertEqual(staticct.parse_ct_extensions(extensions), 0x0102030405)

    def test_format_n(self):
        self.assertEqual(staticct.format_n(0), "000")
        self.assertEqual(staticct.format_n(255), "255")
        self.assertEqual(staticct.format_n(1000), "x001/000")


if __name__ == "__main__":
    unittest.main()
