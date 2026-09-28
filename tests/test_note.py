"""Unit tests for signed-checkpoint (note) parsing and verification."""

import base64
import hashlib
import unittest

from lab import note


def _make_checkpoint(origin: str, size: int, root: bytes, private_key) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

    timestamp = 1_700_000_000_000
    key_hash = note.compute_key_hash(origin, private_key.public_key())
    sth = note.tree_head_signature_input(timestamp, size, root)
    digest = hashlib.sha256(sth).digest()
    signature = private_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))

    body = f"{origin}\n{size}\n{base64.b64encode(root).decode()}\n"
    raw_sig = (
        key_hash.to_bytes(4, "big")
        + timestamp.to_bytes(8, "big")
        + bytes([0x04, 0x03])
        + len(signature).to_bytes(2, "big")
        + signature
    )
    sig_line = f"\u2014 {origin} {base64.b64encode(raw_sig).decode()}"
    return f"{body}\n{sig_line}\n".encode()


class TestNote(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.origin = "example.com/test"
        self.root = hashlib.sha256(b"root").digest()

    def test_parse(self):
        raw = _make_checkpoint(self.origin, 7, self.root, self.private_key)
        checkpoint = note.parse_checkpoint(raw)
        self.assertEqual(checkpoint.origin, self.origin)
        self.assertEqual(checkpoint.size, 7)
        self.assertEqual(checkpoint.root_hash, self.root)
        self.assertEqual(len(checkpoint.signatures), 1)

    def test_verify(self):
        raw = _make_checkpoint(self.origin, 7, self.root, self.private_key)
        checkpoint = note.parse_checkpoint(raw)
        self.assertTrue(note.verify_checkpoint(checkpoint, self.private_key.public_key()))

    def test_verify_rejects_wrong_key(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        raw = _make_checkpoint(self.origin, 7, self.root, self.private_key)
        checkpoint = note.parse_checkpoint(raw)
        other = ec.generate_private_key(ec.SECP256R1())
        self.assertFalse(note.verify_checkpoint(checkpoint, other.public_key()))

    def test_verify_rejects_tampered_size(self):
        raw = _make_checkpoint(self.origin, 7, self.root, self.private_key)
        checkpoint = note.parse_checkpoint(raw)
        checkpoint.size = 8  # tamper
        self.assertFalse(note.verify_checkpoint(checkpoint, self.private_key.public_key()))


if __name__ == "__main__":
    unittest.main()

