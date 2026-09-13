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


def _make_witness_vkey(name: str, public_bytes: bytes) -> str:
    alg_key = bytes([0x01]) + public_bytes
    key_hash = int.from_bytes(hashlib.sha256(name.encode() + b"\n" + alg_key).digest()[:4], "big")
    return f"{name}+{key_hash:08x}+{base64.b64encode(alg_key).decode()}"


def _cosign(checkpoint_text: bytes, name: str, private_key) -> bytes:
    import time

    from cryptography.hazmat.primitives import serialization

    timestamp = int(time.time())
    signed = b"cosignature/v1\ntime %d\n" % timestamp + checkpoint_text
    signature = private_key.sign(signed)
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    key_hash = note.cosignature_key_hash(name, public_bytes)
    raw = key_hash.to_bytes(4, "big") + timestamp.to_bytes(8, "big") + signature
    return checkpoint_text + b"\n" + "\u2014 ".encode() + name.encode() + b" " + base64.b64encode(raw) + b"\n"


class TestWitnessCosignature(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        self.witness_key = ed25519.Ed25519PrivateKey.generate()
        self.witness_name = "witness.local"
        self.origin = "example.com/test"
        self.root = hashlib.sha256(b"root").digest()
        self.text = f"{self.origin}\n3\n{base64.b64encode(self.root).decode()}\n".encode()

    def _vkey(self) -> str:
        from cryptography.hazmat.primitives import serialization

        public_bytes = self.witness_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return _make_witness_vkey(self.witness_name, public_bytes)

    def test_cosignature_verifies(self):
        raw = _cosign(self.text, self.witness_name, self.witness_key)
        checkpoint = note.parse_checkpoint(raw)
        self.assertTrue(note.verify_cosignature(checkpoint, self._vkey()))

    def test_cosignature_rejects_wrong_key(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        raw = _cosign(self.text, self.witness_name, self.witness_key)
        checkpoint = note.parse_checkpoint(raw)
        other = ed25519.Ed25519PrivateKey.generate()
        from cryptography.hazmat.primitives import serialization

        other_pub = other.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.assertFalse(
            note.verify_cosignature(checkpoint, _make_witness_vkey(self.witness_name, other_pub))
        )

    def test_cosignature_rejects_tampered_text(self):
        raw = _cosign(self.text, self.witness_name, self.witness_key)
        checkpoint = note.parse_checkpoint(raw)
        # The witness signs the note text; changing it must invalidate the cosignature.
        checkpoint.text = checkpoint.text.replace(b"\n3\n", b"\n4\n")
        self.assertFalse(note.verify_cosignature(checkpoint, self._vkey()))


if __name__ == "__main__":
    unittest.main()
