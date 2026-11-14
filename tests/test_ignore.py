"""Tests for .repoguardignore matching."""

from __future__ import annotations

import unittest

from repoguard.ignore import IgnoreMatcher


class IgnoreMatcherTests(unittest.TestCase):
    def test_glob_pattern(self) -> None:
        m = IgnoreMatcher(["*.log"])
        self.assertTrue(m.matches("app.log"))
        self.assertTrue(m.matches("sub/app.log"))
        self.assertFalse(m.matches("app.txt"))

    def test_comment_and_blank_lines(self) -> None:
        m = IgnoreMatcher(["", "# comment", "*.tmp"])
        self.assertTrue(m.matches("x.tmp"))
        self.assertFalse(m.matches("x.log"))

    def test_directory_prefix(self) -> None:
        m = IgnoreMatcher(["build/"])
        self.assertTrue(m.matches("build/out.js"))
        self.assertTrue(m.matches("build/sub/deep.js"))
        self.assertFalse(m.matches("other.js"))

    def test_exact_path(self) -> None:
        # A pattern without a slash matches at any depth (gitignore semantics).
        m = IgnoreMatcher(["secrets.json"])
        self.assertTrue(m.matches("secrets.json"))
        self.assertTrue(m.matches("other/secrets.json"))
        m2 = IgnoreMatcher(["**/secrets.json"])
        self.assertTrue(m2.matches("other/secrets.json"))

    def test_double_star(self) -> None:
        m = IgnoreMatcher(["**/secrets.json"])
        self.assertTrue(m.matches("secrets.json"))
        self.assertTrue(m.matches("a/b/secrets.json"))


if __name__ == "__main__":
    unittest.main()
