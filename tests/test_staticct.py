"""Unit tests for static-ct entry-bundle parsing and Merkle leaf construction."""

import io
import shutil
import tempfile
import unittest
import urllib.error
from pathlib import Path

from lab import merkle, pki, staticct


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


class TestIssuingExtraLeaves(unittest.TestCase):
    """Why `lab.cli fill` exists at all.

    A CT log deduplicates entries by certificate, so resubmitting the one leaf in
    `out/pki` integrates one entry and leaves a tree of size 1 — no siblings, and
    an inclusion proof that proves nothing interesting. Building a real tree
    means submitting genuinely distinct certificates, which means issuing new
    leaves from the same intermediate.

    These tests use ECDSA rather than ML-DSA because they shell out to OpenSSL,
    and a stock OpenSSL 3.0 has no post-quantum keygen. The behaviour under test
    is algorithm-independent; only the key type changes.
    """

    ALGORITHM = "ecdsa-p256"

    def setUp(self):
        self.outdir = Path(tempfile.mkdtemp(prefix="pki-leaves-"))
        self.addCleanup(shutil.rmtree, self.outdir, ignore_errors=True)
        try:
            self.paths = pki.generate(self.ALGORITHM, self.outdir)
        except pki.PkiError as exc:  # pragma: no cover - depends on the host
            self.skipTest(f"OpenSSL cannot generate a PKI here: {exc}")

    def test_a_second_leaf_is_a_different_certificate(self):
        extra = pki.issue_leaf(self.ALGORITHM, self.outdir, "www0")
        self.assertNotEqual(extra.read_bytes(), self.paths.leaf_crt.read_bytes())

    def test_the_new_leaf_carries_its_own_subject(self):
        """Different subject, so the DER differs and the leaf hash differs."""
        import subprocess

        extra = pki.issue_leaf(self.ALGORITHM, self.outdir, "www7")
        subject = subprocess.run(
            [pki.openssl_binary(), "x509", "-in", str(extra), "-noout", "-subject"],
            capture_output=True,
            check=True,
        ).stdout.decode()
        self.assertIn("www7.example", subject)
        self.assertNotIn("leaf.example", subject)

    def test_the_root_and_intermediate_are_left_alone(self):
        """Leaves issued before and after must be interchangeable to a client.

        The point is that the tree can grow without rotating the trust anchor,
        so the root and intermediate bytes have to be byte-identical afterwards.
        """
        directory = self.paths.directory
        before = {
            name: (directory / name).read_bytes()
            for name in ("root.crt", "int.crt", "root.key", "int.key")
        }
        pki.issue_leaf(self.ALGORITHM, self.outdir, "www1")
        for name, contents in before.items():
            with self.subTest(file=name):
                self.assertEqual((directory / name).read_bytes(), contents)

    def test_the_new_leaf_verifies_against_the_same_root(self):
        import subprocess

        extra = pki.issue_leaf(self.ALGORITHM, self.outdir, "www2")
        result = subprocess.run(
            [
                pki.openssl_binary(), "verify",
                "-CAfile", str(self.paths.root_crt),
                "-untrusted", str(self.paths.int_crt),
                str(extra),
            ],
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_two_leaves_never_collide(self):
        """Re-running must produce a fresh key, or `fill` would stop growing the tree.

        The subject is the same, so only the freshly generated key makes the two
        certificates differ. A CT log deduplicates by certificate, so a repeated
        `fill` that returned byte-identical leaves would integrate nothing and
        the tree would never pass 8.
        """
        first = pki.issue_leaf(self.ALGORITHM, self.outdir, "www3").read_bytes()
        second = pki.issue_leaf(self.ALGORITHM, self.outdir, "www3").read_bytes()
        self.assertNotEqual(first, second)

    def test_issuing_without_an_intermediate_is_an_error(self):
        with tempfile.TemporaryDirectory() as empty:
            with self.assertRaises(pki.PkiError) as caught:
                pki.issue_leaf(self.ALGORITHM, Path(empty), "www0")
        self.assertIn("pki --algorithm", str(caught.exception))

    def test_an_unknown_algorithm_is_rejected(self):
        with self.assertRaises(pki.PkiError):
            pki.issue_leaf("no-such-algorithm", self.outdir, "www0")


class TestTheSubmissionPrefix(unittest.TestCase):
    """A log's origin is its submission prefix, and the client has to honour it.

    A CT log reconstructs the endpoint it thinks it was reached on as
    `$HOST$PATH` and warns when that does not start with its configured origin.
    Honouring the origin takes two things, not one: the host goes in the `Host`
    header, and the path goes in front of `/ct/v1/...`. The server has to agree
    on the path half via `--path_prefix`.

    Getting this wrong is not hypothetical. The client used to post to
    `/ct/v1/add-chain` while the log was configured for `example.com/workshop`,
    so every single submission in the workshop drew a warning.
    """

    def test_an_origin_splits_into_a_host_and_a_path_prefix(self):
        client = staticct.StaticCTClient("http://127.0.0.1:6962", origin="example.com/workshop")
        self.assertEqual(client.host_header, "example.com")
        self.assertEqual(client.path_prefix, "/workshop")

    def test_the_host_is_sent_as_a_header_not_as_the_connection_target(self):
        """The URL still points at 127.0.0.1; only the Host header changes."""
        client = staticct.StaticCTClient("http://127.0.0.1:6962", origin="example.com/workshop")
        self.assertEqual(client.base_url, "http://127.0.0.1:6962")
        self.assertEqual(client._headers()["Host"], "example.com")

    def test_a_bare_origin_has_no_path_prefix(self):
        client = staticct.StaticCTClient("http://127.0.0.1:6962", origin="example.com")
        self.assertEqual(client.host_header, "example.com")
        self.assertEqual(client.path_prefix, "")

    def test_a_trailing_slash_does_not_create_an_empty_segment(self):
        client = staticct.StaticCTClient("http://127.0.0.1:6962", origin="example.com/workshop/")
        self.assertEqual(client.path_prefix, "/workshop")

    def test_a_root_origin_has_no_path_prefix(self):
        client = staticct.StaticCTClient("http://127.0.0.1:6962", origin="example.com/")
        self.assertEqual(client.path_prefix, "")

    def test_no_origin_means_no_prefix_and_no_host_header(self):
        client = staticct.StaticCTClient("http://127.0.0.1:6962")
        self.assertEqual(client.path_prefix, "")
        self.assertIsNone(client.host_header)
        self.assertNotIn("Host", client._headers())

    def test_a_404_under_a_prefix_explains_the_missing_server_flag(self):
        """A bare 404 is unfalsifiable; this has to say what to actually do."""
        client = staticct.StaticCTClient("http://127.0.0.1:6962", origin="example.com/workshop")
        error = urllib.error.HTTPError(
            "http://127.0.0.1:6962/workshop/ct/v1/add-chain",
            404, "Not Found", {}, io.BytesIO(b"404 page not found\n"),
        )
        message = str(client._fail("/ct/v1/add-chain", error))
        self.assertIn("--path_prefix=/workshop", message)
        self.assertIn("run_tesseract.sh restart", message)
        self.assertIn("example.com/workshop", message)

    def test_a_404_without_a_prefix_reports_the_plain_error(self):
        client = staticct.StaticCTClient("http://127.0.0.1:6962")
        error = urllib.error.HTTPError(
            "http://127.0.0.1:6962/ct/v1/add-chain",
            404, "Not Found", {}, io.BytesIO(b"nope"),
        )
        message = str(client._fail("/ct/v1/add-chain", error))
        self.assertIn("HTTP 404", message)
        self.assertIn("nope", message)
        self.assertNotIn("--path_prefix", message)


class TestFillingTheLog(unittest.TestCase):
    """`lab.cli fill`, without a live log.

    The interesting behaviour of `fill` is arithmetic and error handling, not
    HTTP, so the client is faked: `add_chain` hands back an SCT with a leaf
    index, and `checkpoint_bytes` reports whatever tree size the test wants.
    """

    def setUp(self):
        self.outdir = Path(tempfile.mkdtemp(prefix="fill-"))
        self.addCleanup(shutil.rmtree, self.outdir, ignore_errors=True)
        try:
            pki.generate("ecdsa-p256", self.outdir)
        except pki.PkiError as exc:  # pragma: no cover - depends on the host
            self.skipTest(f"OpenSSL cannot generate a PKI here: {exc}")

    def install_fake_log(self, size=8, indices=None):
        """Patch the client so no server is involved.

        `indices` overrides the leaf index each successive submission reports;
        by default the counter walks up from whatever the fake is told.
        """
        import lab.cli.__main__ as cli

        self.addCleanup(setattr, cli, "_client", cli._client)
        state = {"next": 0, "submitted": []}
        submitted = indices

        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            def add_chain(self, chain):
                state["submitted"].append(chain)
                index = (
                    submitted[len(state["submitted"]) - 1]
                    if submitted is not None
                    else state["next"]
                )
                if index is not None:
                    state["next"] = index + 1
                return {"extensions": _ct_extensions(index) if index is not None else ""}

            def checkpoint_bytes(self):
                return b"" if size == 0 else _fake_checkpoint(size)

        cli._client = lambda args: FakeClient()
        return state

    def run_fill(self, *argv, **defaults):
        import contextlib
        import io

        import lab.cli.__main__ as cli

        options = {
            "--algorithm": "ecdsa-p256",
            "--pki-dir": str(self.outdir),
            "--storage-dir": str(self.outdir / "storage"),
            "--log": "http://127.0.0.1:6962",
            "--timeout": "1",
            **defaults,
        }
        flags = [flag for pair in options.items() for flag in pair]
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            status = cli.main(["fill", *argv, *flags])
        return status, out.getvalue()

    def test_it_reports_the_indices_and_the_tree_size(self):
        self.install_fake_log(size=4)
        status, printed = self.run_fill("--count", "4")
        self.assertEqual(status, 0)
        self.assertIn("4 distinct ecdsa-p256 leaves", printed)
        self.assertIn("leaf indices  : 0, 1, 2, 3", printed)
        self.assertIn("tree size     : 4", printed)

    def test_it_suggests_an_index_that_really_has_siblings(self):
        """The newest leaf can still be a lone leaf, so don't suggest it."""
        self.install_fake_log(size=2)
        _, printed = self.run_fill("--count", "2")
        self.assertIn("--index 0", printed)

    def test_a_zero_count_is_rejected_before_touching_the_pki(self):
        self.install_fake_log(size=0)
        status, printed = self.run_fill("--count", "0")
        self.assertEqual(status, 1)
        self.assertIn("--count must be at least 1", printed)

    def test_a_negative_count_is_rejected(self):
        self.install_fake_log(size=0)
        status, printed = self.run_fill("--count", "-1")
        self.assertEqual(status, 1)
        self.assertIn("--count must be at least 1", printed)

    def test_submissions_without_a_parseable_leaf_index_are_an_error(self):
        """A log that never returns a leaf index is not a slow checkpoint."""
        self.install_fake_log(size=8, indices=[None, None])
        status, printed = self.run_fill("--count", "2")
        self.assertEqual(status, 1)
        self.assertIn("parseable SCT leaf index", printed)

    def test_an_uncovered_checkpoint_is_a_failure_not_a_pass(self):
        """The tree must actually grow, or the exercise has nothing to walk."""
        self.install_fake_log(size=1, indices=[0, 1, 2])
        status, printed = self.run_fill("--count", "3", "--timeout", "0.1")
        self.assertEqual(status, 1)
        self.assertIn("has not published a checkpoint covering them yet", printed)

    def test_it_issues_a_distinct_chain_per_leaf(self):
        state = self.install_fake_log(size=4)
        self.run_fill("--count", "4")
        self.assertEqual(len(state["submitted"]), 4)
        first = b"".join(state["submitted"][0])
        self.assertNotEqual(first, b"".join(state["submitted"][1]))


def _ct_extensions(index: int) -> str:
    """The CT extension carrying a log's own leaf index, base64 for the API."""
    import base64

    raw = b"\x00" + (5).to_bytes(2, "big") + index.to_bytes(5, "big")
    return base64.b64encode(raw).decode()


def _fake_checkpoint(size: int) -> bytes:
    """An unsigned checkpoint note, which is all `fill` reads out of it."""
    import base64

    root = base64.b64encode(bytes(32)).decode()
    return f"example.com/workshop\n{size}\n{root}\n".encode()


if __name__ == "__main__":
    unittest.main()
