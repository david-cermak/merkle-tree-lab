"""Unit tests for MTC-shaped bundle assembly and sizing."""

import base64
import hashlib
import unittest

from lab import bundle, note


def _checkpoint(origin="example.com/test", size=2, root=None, signature=b"\x00" * 76):
    root = root or hashlib.sha256(b"root").digest()
    text = f"{origin}\n{size}\n{base64.b64encode(root).decode()}\n"
    raw = (
        text.encode()
        + b"\n"
        + "\u2014 ".encode()
        + origin.encode()
        + b" "
        + base64.b64encode(signature)
        + b"\n"
    )
    return note.parse_checkpoint(raw), raw


class TestBundle(unittest.TestCase):
    def test_build_and_size(self):
        checkpoint, raw = _checkpoint()
        b = bundle.build_bundle(
            certificate=b"CERTIFICATE",
            leaf_index=1,
            tree_size=2,
            leaf_hash=hashlib.sha256(b"leaf").digest(),
            audit_path=[hashlib.sha256(b"sibling").digest()],
            checkpoint=checkpoint,
            checkpoint_raw=raw,
        )
        self.assertEqual(b["leaf"]["leaf_index"], 1)
        self.assertEqual(b["inclusion_proof"]["tree_size"], 2)
        self.assertEqual(len(b["inclusion_proof"]["audit_path"]), 1)
        self.assertGreater(bundle.bundle_size(b), 0)

    def test_signature_roles(self):
        checkpoint, raw = _checkpoint()
        b = bundle.build_bundle(
            certificate=b"CERTIFICATE",
            leaf_index=0,
            tree_size=2,
            leaf_hash=hashlib.sha256(b"leaf").digest(),
            audit_path=[],
            checkpoint=checkpoint,
            checkpoint_raw=raw,
        )
        roles = [sig["role"] for sig in b["checkpoint"]["signatures"]]
        self.assertEqual(roles, ["log"])

    def test_comparison_mentions_both_baselines(self):
        checkpoint, raw = _checkpoint()
        b = bundle.build_bundle(
            certificate=b"C" * 100,
            leaf_index=0,
            tree_size=1,
            leaf_hash=hashlib.sha256(b"leaf").digest(),
            audit_path=[],
            checkpoint=checkpoint,
            checkpoint_raw=raw,
        )
        report = bundle.format_comparison(b, b"C" * 100, b"C" * 200)
        self.assertIn("conventional leaf certificate", report)
        self.assertIn("conventional chain", report)
        self.assertIn("MTC-shaped bundle", report)


if __name__ == "__main__":
    unittest.main()
