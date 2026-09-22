"""Unit tests for certificate loading and DER size parsing."""

import os
import shutil
import subprocess
import tempfile
import unittest

from lab import certs


class TestCerts(unittest.TestCase):
    def test_der_to_pem_round_trip(self):
        der = b"\x30\x03\x02\x01\x05"
        pem = certs.der_to_pem(der)
        self.assertEqual(certs.pem_blocks(pem, "CERTIFICATE"), [("CERTIFICATE", der)])

    @unittest.skipIf(shutil.which("openssl") is None, "openssl not installed")
    def test_ec_certificate_sizes(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert_path = os.path.join(tmp, "ec.crt")
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "ec",
                    "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-keyout", os.path.join(tmp, "ec.key"),
                    "-out", cert_path,
                    "-days", "1", "-nodes", "-subj", "/CN=test",
                ],
                check=True,
                capture_output=True,
            )
            der = certs.read_certificate(cert_path)
            sizes = certs.certificate_sizes(der)
            self.assertGreater(sizes.der_size, 0)
            self.assertGreater(sizes.spki_size, 0)
            self.assertGreater(sizes.signature_size, 0)
            self.assertEqual(sizes.signature_algorithm, "ecdsa-with-SHA256")
            self.assertEqual(sizes.public_key_algorithm, "EC")


if __name__ == "__main__":
    unittest.main()
