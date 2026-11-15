"""CLI smoke tests: JSON, exit codes, ignore patterns, missing Git."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

FAKE_TOKEN = "gh" + "p_" + "1234567890abcdef" + "1234567890abcdef" + "1234abcd"
FAKE_PASSWORD = "pass" + "word = " + "a1b2c3d4e5f6g7h8"


def run_cli(args: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "repoguard"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
    )


class CLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.root = Path(self.tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_version(self) -> None:
        res = run_cli(["--version"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("repoguard", res.stdout)

    def test_clean_repo_exit_zero(self) -> None:
        (self.root / "README.md").write_text("# hi\n")
        (self.root / "LICENSE").write_text("MIT\n")
        (self.root / ".gitignore").write_text("*.pyc\n")
        (self.root / "main.py").write_text("print(1)\n")
        res = run_cli(["scan", str(self.root)])
        self.assertEqual(res.returncode, 0)

    def test_high_finding_exit_one(self) -> None:
        (self.root / "README.md").write_text("# hi\n")
        (self.root / "LICENSE").write_text("MIT\n")
        (self.root / ".gitignore").write_text("*.pyc\n")
        (self.root / "cfg.py").write_text(f'token = "{FAKE_TOKEN}"\n')
        res = run_cli(["scan", str(self.root)])
        self.assertEqual(res.returncode, 1)

    def test_json_output(self) -> None:
        (self.root / "cfg.py").write_text(f'token = "{FAKE_TOKEN}"\n')
        res = run_cli(["scan", "--format", "json", str(self.root)])
        self.assertEqual(res.returncode, 1)
        data = json.loads(res.stdout)
        self.assertIn("summary", data)
        self.assertIn("findings", data)
        self.assertEqual(data["summary"]["high"], 1)
        secret = data["findings"][0]
        self.assertNotIn("ghp_", secret["snippet"])

    def test_fail_on_low_catches_medium(self) -> None:
        (self.root / "cfg.py").write_text(FAKE_PASSWORD + "\n")
        res = run_cli(["scan", "--fail-on", "low", str(self.root)])
        self.assertEqual(res.returncode, 1)

    def test_max_size_flag(self) -> None:
        big = self.root / "big.log"
        big.write_bytes(b"0" * (6 * 1024 * 1024))
        res = run_cli(["scan", "--fail-on", "medium", "--max-size-mb", "5", str(self.root)])
        self.assertEqual(res.returncode, 1)
        self.assertIn("oversized-file", res.stdout)

    def test_ignore_file(self) -> None:
        (self.root / "README.md").write_text("# hi\n")
        (self.root / "LICENSE").write_text("MIT\n")
        (self.root / ".gitignore").write_text("*.pyc\n")
        (self.root / "secret.env").write_text("token = " + FAKE_TOKEN + "\n")
        (self.root / ".repoguardignore").write_text("secret.env\n")
        res = run_cli(["scan", str(self.root)])
        self.assertEqual(res.returncode, 0)
        self.assertNotIn("secret.env", res.stdout)

    def test_missing_readme_license_low(self) -> None:
        res = run_cli(["scan", str(self.root)])
        self.assertEqual(res.returncode, 0)  # default fail-on high, low findings OK

    def test_readme_variants_no_missing_readme(self) -> None:
        for variant in ("README.md", "README.rst", "README.txt", "README"):
            root = Path(tempfile.mkdtemp())
            try:
                (root / variant).write_text("# hi\n")
                (root / "LICENSE").write_text("MIT\n")
                (root / ".gitignore").write_text("*.pyc\n")
                res = run_cli(["scan", str(root)])
                self.assertEqual(res.returncode, 0, msg=variant)
                self.assertNotIn("missing-readme", res.stdout)
            finally:
                shutil.rmtree(root, ignore_errors=True)

    def test_no_readme_still_flagged(self) -> None:
        res = run_cli(["scan", str(self.root)])
        self.assertEqual(res.returncode, 0)  # default fail-on high
        self.assertIn("missing-readme", res.stdout)

    def test_max_size_mb_zero_rejected(self) -> None:
        res = run_cli(["scan", "--max-size-mb", "0", str(self.root)])
        self.assertEqual(res.returncode, 2)
        self.assertIn("positive", res.stderr.lower())

    def test_max_size_mb_negative_rejected(self) -> None:
        res = run_cli(["scan", "--max-size-mb", "-1", str(self.root)])
        self.assertEqual(res.returncode, 2)

    def test_max_size_mb_nan_rejected(self) -> None:
        res = run_cli(["scan", "--max-size-mb", "nan", str(self.root)])
        self.assertEqual(res.returncode, 2)

    def test_max_size_mb_inf_rejected(self) -> None:
        res = run_cli(["scan", "--max-size-mb", "inf", str(self.root)])
        self.assertEqual(res.returncode, 2)

    def test_max_size_mb_unreasonable_rejected(self) -> None:
        res = run_cli(["scan", "--max-size-mb", "999999", str(self.root)])
        self.assertEqual(res.returncode, 2)

    def test_invalid_root_exit_two(self) -> None:
        res = run_cli(["scan", "/nonexistent/path/xyz"])
        self.assertEqual(res.returncode, 2)

    def test_file_root_exit_two(self) -> None:
        f = self.root / "afile.txt"
        f.write_text("x\n")
        res = run_cli(["scan", str(f)])
        self.assertEqual(res.returncode, 2)

    def test_usage_error_exit_two(self) -> None:
        res = run_cli(["--bogus"])
        self.assertEqual(res.returncode, 2)

    def test_missing_git_staged_exit_two(self) -> None:
        res = run_cli(["scan", "--staged", str(self.root)])
        self.assertEqual(res.returncode, 2)

    def test_license_variants_recognized(self) -> None:
        """Verify scanner recognizes all LICENSE variants."""
        license_variants = ("LICENSE", "LICENSE.md", "LICENSE.txt",
                          "LICENCE", "LICENCE.md", "copying", "copying.md",
                          "copyright")
        for variant in license_variants:
            root = Path(tempfile.mkdtemp())
            try:
                (root / variant).write_text("MIT\n")
                (root / "README.md").write_text("# hi\n")
                res = run_cli(["scan", str(root)])
                self.assertNotIn("missing-license", res.stdout, msg=variant)
            finally:
                shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()