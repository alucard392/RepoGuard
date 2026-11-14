"""Tests for staged Git scan semantics using a temporary Git repo."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from repoguard.staged import GitError, iter_staged, staged_paths
from repoguard.scanner import scan_repository

FAKE_TOKEN = "gh" + "p_" + "1234567890abcdef" + "1234567890abcdef" + "1234abcd"

FAKE_TOKEN = "gh" + "p_" + "1234567890abcdef" + "1234567890abcdef" + "1234abcd"


def run(cmd: list[str], cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


class StagedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.root = Path(self.tmp)
        run(["git", "init"], str(self.root))
        run(["git", "config", "user.email", "t@t"], str(self.root))
        run(["git", "config", "user.name", "t"], str(self.root))

    def _commit(self, message: str = "c") -> None:
        run(["git", "commit", "--allow-empty", "-m", message], str(self.root))

    def test_staged_blob_not_working_tree(self) -> None:
        (self.root / "a.txt").write_text("staged content\n")
        run(["git", "add", "a.txt"], str(self.root))
        # Change working tree AFTER staging: staged scan must see staged content.
        (self.root / "a.txt").write_text("working tree content\n")
        staged = dict(iter_staged(str(self.root)))
        self.assertIn("a.txt", staged)
        self.assertEqual(staged["a.txt"], "staged content\n")

    def test_unstaged_change_ignored(self) -> None:
        self._commit()
        (self.root / "b.txt").write_text("untracked\n")
        staged = dict(iter_staged(str(self.root)))
        self.assertNotIn("b.txt", staged)

    def test_empty_index(self) -> None:
        staged = dict(iter_staged(str(self.root)))
        self.assertEqual(staged, {})

    def test_path_with_spaces(self) -> None:
        (self.root / "my file.txt").write_text(FAKE_TOKEN + "\n")
        run(["git", "add", "my file.txt"], str(self.root))
        staged = dict(iter_staged(str(self.root)))
        self.assertIn("my file.txt", staged)

    def test_deleted_staged_entry_skipped(self) -> None:
        self._commit()
        (self.root / "c.txt").write_text("gone\n")
        run(["git", "add", "c.txt"], str(self.root))
        run(["git", "rm", "--cached", "c.txt"], str(self.root))
        staged = dict(iter_staged(str(self.root)))
        self.assertNotIn("c.txt", staged)

    def test_git_not_found(self) -> None:
        with self.assertRaises(GitError):
            staged_paths("/nonexistent")

    def test_staged_sensitive_filename(self) -> None:
        (self.root / ".env").write_text("SECRET=1\n")
        run(["git", "add", ".env"], str(self.root))
        staged = dict(iter_staged(str(self.root)))
        self.assertIn(".env", staged)


    def test_scanner_detects_secret_in_staged_blob_not_working_copy(self) -> None:
        (self.root / "config.py").write_text("token = " + FAKE_TOKEN + "\n")
        run(["git", "add", "config.py"], str(self.root))
        (self.root / "config.py").write_text("token = harmless\n")
        result = scan_repository(str(self.root), staged=True)
        self.assertTrue(any(
            finding.rule_id == "github-token" and finding.path == "config.py"
            for finding in result.findings
        ))

    def test_scanner_ignores_unstaged_secret(self) -> None:
        (self.root / "config.py").write_text("token = harmless\n")
        run(["git", "add", "config.py"], str(self.root))
        (self.root / "config.py").write_text("token = " + FAKE_TOKEN + "\n")
        result = scan_repository(str(self.root), staged=True)
        self.assertFalse(any(
            finding.rule_id == "github-token" and finding.path == "config.py"
            for finding in result.findings
        ))

    def test_staged_oversized_blob(self) -> None:
        big = "x" * (6 * 1024 * 1024)
        (self.root / "big.log").write_text(big)
        run(["git", "add", "big.log"], str(self.root))
        staged = dict(iter_staged(str(self.root)))
        self.assertEqual(len(staged["big.log"]), 6 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
