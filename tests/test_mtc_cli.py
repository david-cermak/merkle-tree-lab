"""Tests for the three MTC workshop commands.

These are the commands the exercises tell people to run, so a change that breaks
the flow should fail here rather than halfway through a workshop. They share one
scenario built once, because generating twenty ML-DSA keys per test would make
the suite slow enough to be skipped.
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from lab.cli.__main__ import main
from lab.mtc import scenario as mtc_scenario


class TestTheWorkshopCommands(unittest.TestCase):
    """The lab, shapes, and verify commands, end to end."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.outdir = Path(tempfile.mkdtemp(prefix="mtc-cli-"))
        cls.scenario = mtc_scenario.build()
        mtc_scenario.save(cls.scenario, cls.outdir)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.outdir, ignore_errors=True)

    def run_cli(self, *argv: str) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            status = main(["mtc", *argv, "--outdir", str(self.outdir)])
        return status, out.getvalue()

    def test_lab_builds_the_scenario_and_says_where_it_saved_it(self):
        with tempfile.TemporaryDirectory() as fresh:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                status = main(["mtc", "lab", "--outdir", fresh])
            self.assertEqual(status, 0)
            printed = out.getvalue()
            self.assertTrue((Path(fresh) / "scenario.json").exists())
        self.assertIn("1.3.6.1.4.1.32473.100", printed)
        self.assertIn("entries              20", printed)
        self.assertIn("[0, 16)", printed)

    def test_a_saved_scenario_keeps_its_leaf_hashes_and_landmarks(self):
        reloaded = mtc_scenario.load(self.outdir)
        for index in range(reloaded.log.size):
            self.assertEqual(
                reloaded.log.entry_hash(index), self.scenario.log.entry_hash(index)
            )
        self.assertEqual(reloaded.landmark.subtrees, self.scenario.landmark.subtrees)
        self.assertEqual(reloaded.sequence.latest.expiry, self.scenario.landmark.expiry)

    def test_shapes_prints_the_workshop_table(self):
        status, printed = self.run_cli("shapes", "--index", "3")
        self.assertEqual(status, 0)
        self.assertIn("| shape | subtree | signatures |", printed)
        self.assertIn("checkpoint-relative", printed)
        self.assertIn("| [0, 8) |", printed)
        # The landmark shape is the only one with no signatures at all.
        self.assertIn("| landmark-relative | [0, 16) | 0 | 0 |", printed)

    def test_shapes_writes_one_json_file_per_shape(self):
        self.run_cli("shapes", "--index", "3")
        for name in ("direct", "standalone", "checkpoint", "landmark"):
            path = self.outdir / f"certificate-{name}.json"
            self.assertTrue(path.exists(), f"{name} was not written")
            data = json.loads(path.read_text())
            self.assertIn("shape", data)
            self.assertIn("bytes", data)

    def test_a_null_entry_cannot_be_certified(self):
        status, printed = self.run_cli("shapes", "--index", "7")
        self.assertEqual(status, 2)
        self.assertIn("null entry", printed)

    def test_an_index_past_the_log_is_refused(self):
        status, printed = self.run_cli("shapes", "--index", "99")
        self.assertEqual(status, 2)
        self.assertIn("outside the log", printed)

    def test_a_known_cosigner_verifies_the_cosigned_shapes_but_not_the_landmark(self):
        status, printed = self.run_cli("verify", "--index", "3", "--knows", "cosigners")
        self.assertEqual(status, 0)
        self.assertEqual(printed.count("verified"), 2)
        self.assertIn("becomes checkable", printed)
        self.assertIn("both cosignatures verify", printed)

    def test_a_landmark_client_verifies_all_three_mtc_shapes(self):
        status, printed = self.run_cli("verify", "--index", "3", "--knows", "landmark")
        self.assertEqual(status, 0)
        self.assertEqual(printed.count("verified"), 3)
        self.assertIn("the client holds this landmark's subtree hash", printed)
        # The directly signed shape is the exception: it never used a cosigner
        # or a landmark, so it still needs the CA's own key.
        self.assertIn("directly signed             refused", printed)
        self.assertIn("does not trust a key for 32473.100", printed)

    def test_a_client_with_nothing_verifies_nothing(self):
        status, printed = self.run_cli("verify", "--index", "3", "--knows", "none")
        self.assertEqual(status, 0)
        self.assertEqual(printed.count("refused"), 4)

    def test_a_client_with_everything_verifies_the_direct_shape_too(self):
        status, printed = self.run_cli("verify", "--index", "3", "--knows", "all")
        self.assertEqual(status, 0)
        self.assertNotIn("refused", printed)

    def test_tampering_with_a_field_is_refused_for_every_shape(self):
        status, printed = self.run_cli(
            "verify", "--index", "3", "--knows", "all", "--tamper"
        )
        self.assertEqual(status, 0)
        self.assertIn("every tampered certificate was refused", printed)
        self.assertNotIn("still verified", printed)

    def test_verify_refuses_an_unknown_knowledge_level(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                main(
                    ["mtc", "verify", "--outdir", str(self.outdir), "--knows", "everything"]
                )


if __name__ == "__main__":
    unittest.main()
