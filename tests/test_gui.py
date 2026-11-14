"""Headless-safe tests for the GUI scan controller and onboarding copy."""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from repoguard.detectors import Finding
from repoguard.gui import ScanController, USAGE_GUIDE, export_result_json
from repoguard.scanner import ScanResult


class ScanControllerTests(unittest.TestCase):
    def test_poll_drains_all_queued_outcomes(self) -> None:
        controller = ScanController()
        received: list[str] = []
        controller.on_error = lambda message: received.append("error:" + message)
        controller.on_traceback = lambda trace: received.append("trace:" + trace)
        controller.queue.put(("error", "synthetic error"))
        controller.queue.put(("traceback", "synthetic traceback"))
        more = controller.poll()
        self.assertFalse(more)
        self.assertEqual(received, [
            "error:synthetic error",
            "trace:synthetic traceback",
        ])

    def test_usage_guide_covers_core_workflows(self) -> None:
        for phrase in (
            "WORKING TREE VS STAGED",
            "SEVERITY",
            "IGNORE RULES",
            "PRIVACY AND SAFETY",
            "Exit codes",
            "revoke/rotate",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, USAGE_GUIDE)

    def test_export_result_json(self) -> None:
        res = ScanResult(
            root="/dummy",
            mode="working-tree",
            findings=[
                Finding(
                    rule_id="github-token",
                    severity="high",
                    path="secret.txt",
                    line=10,
                    snippet="ghp_***abc",
                    fix="Rotate token",
                )
            ],
            warnings=(),
            duration_s=0.1,
        )
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "out.json")
            export_result_json(res, out_path)
            self.assertTrue(os.path.isfile(out_path))
            with open(out_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["tool"], "repoguard")
            self.assertEqual(data["summary"]["high"], 1)
            self.assertEqual(len(data["findings"]), 1)


if __name__ == "__main__":
    unittest.main()
