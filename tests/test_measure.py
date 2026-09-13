"""Unit test for PKI generation and size measurement (requires OpenSSL)."""

import shutil
import tempfile
import unittest
from pathlib import Path

from lab import measure, pki


@unittest.skipIf(shutil.which("openssl") is None, "openssl not installed")
class TestMeasure(unittest.TestCase):
    def test_generate_and_measure_ecdsa(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = pki.generate("ecdsa-p256", Path(tmp))
            self.assertTrue(paths.leaf_crt.exists())
            self.assertTrue(paths.root_crt.exists())
            results = measure.measure_directory(Path(tmp))
            self.assertEqual(len(results), 1)
            m = results[0]
            self.assertEqual(m.algorithm, "ecdsa-p256")
            self.assertEqual(m.cert_algorithm, "ecdsa-with-SHA256")
            self.assertGreater(m.cert_der, m.spki)
            self.assertGreater(m.signature, 0)
            self.assertGreater(m.chain_der, m.cert_der)


if __name__ == "__main__":
    unittest.main()
