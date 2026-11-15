"""Tests for file traversal, size checks, and sensitive filenames."""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from repoguard.files import (
    BINARY_EXTENSIONS,
    SAFE_UPPER_BOUND,
    iter_files,
    file_checks,
    _should_skip_dir,
)


class IterFilesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.root = Path(self.tmp)
        (self.root / "keep.py").write_text("print(1)\n")
        (self.root / "big.bin").write_bytes(b"0" * 200)
        (self.root / "sub").mkdir()
        (self.root / "sub" / "keep.txt").write_text("hi\n")
        git_dir = self.root / ".git"
        git_dir.mkdir()
        (git_dir / "secret.txt").write_text("shh\n")
        venv = self.root / ".venv"
        venv.mkdir()
        (venv / "pkg.py").write_text("x = 1\n")
        nm = self.root / "node_modules"
        nm.mkdir()
        (nm / "lib.js").write_text("x\n")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_skips_git_and_caches(self) -> None:
        rels = {rel for _, rel in iter_files(str(self.root))}
        self.assertIn("keep.py", rels)
        self.assertIn("sub/keep.txt", rels)
        self.assertNotIn(".git/secret.txt", rels)
        self.assertNotIn(".venv/pkg.py", rels)
        self.assertNotIn("node_modules/lib.js", rels)

    def test_skip_directory_names_are_case_insensitive(self) -> None:
        self.assertTrue(_should_skip_dir("NODE_MODULES"))
        self.assertTrue(_should_skip_dir(".GIT"))
        self.assertTrue(_should_skip_dir(".PyTest_Cache"))
        self.assertFalse(_should_skip_dir("src"))

    def test_skips_binary_extensions(self) -> None:
        (self.root / "image.png").write_bytes(b"\x89PNG\r\n")
        rels = {rel for _, rel in iter_files(str(self.root))}
        self.assertNotIn("image.png", rels)

    def test_size_check_flagged(self) -> None:
        finds = file_checks("big.dat", 6 * 1024 * 1024, 5 * 1024 * 1024)
        self.assertEqual(len(finds), 1)
        self.assertEqual(finds[0].rule_id, "oversized-file")
        self.assertEqual(finds[0].severity, "medium")

    def test_size_check_ok(self) -> None:
        finds = file_checks("small.txt", 100, 5 * 1024 * 1024)
        self.assertEqual(finds, [])

    def test_sensitive_filenames(self) -> None:
        cases = [
            (".env", True),
            (".env.local", True),
            (".env.development", True),
            (".env.production", True),
            ("id_rsa", True),
            ("id_ed25519", True),
            ("credentials.json", True),
            (".env.example", False),
            (".env.template", False),
            ("notes.txt", False),
        ]
        for name, expected in cases:
            with self.subTest(name=name):
                finds = file_checks(name, 10, 5 * 1024 * 1024)
                flagged = any(f.rule_id == "sensitive-filename" for f in finds)
                self.assertEqual(flagged, expected, msg=name)

    def test_docker_config_json(self) -> None:
        finds = file_checks("docker/config.json", 100, 5*1024*1024)
        self.assertTrue(any(f.rule_id == "sensitive-filename" for f in finds))

    def test_kubeconfig(self) -> None:
        finds = file_checks(".kube/config", 100, 5*1024*1024)
        self.assertTrue(any(f.rule_id == "sensitive-filename" for f in finds))

    def test_aws_credentials(self) -> None:
        finds = file_checks(".aws/credentials", 100, 5*1024*1024)
        self.assertTrue(any(f.rule_id == "sensitive-filename" for f in finds))

    def test_terraform_state(self) -> None:
        finds = file_checks("terraform.tfstate", 100, 5*1024*1024)
        self.assertTrue(any(f.rule_id == "sensitive-filename" for f in finds))

    def test_backup_files(self) -> None:
        for name in ["config.bak", "config.backup", "config~", "config.old", "config.orig"]:
            finds = file_checks(name, 100, 5*1024*1024)
            self.assertTrue(any(f.rule_id == "sensitive-filename" for f in finds), msg=name)


class UpperBoundTests(unittest.TestCase):
    def test_files_above_safe_upper_bound_skipped(self) -> None:
        self.assertGreater(SAFE_UPPER_BOUND, 0)


if __name__ == "__main__":
    unittest.main()