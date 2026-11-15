"""Conservative, documented .repoguardignore matching.

Supported: comments/blank lines, basename globs at any depth, root-anchored
patterns, directory prefixes, and leading **/ patterns. Negation is not
supported. This is a useful subset, not full gitignore compatibility.
"""
from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Sequence

__all__ = ["IgnoreMatcher", "load_ignore_file", "load_ignore_from_dir"]


class IgnoreMatcher:
    """Match ignore patterns against normalized root-relative file paths."""

    def __init__(self, patterns: Sequence[str]) -> None:
        self.directory_prefixes: list[str] = []
        self.rooted_patterns: list[str] = []
        self.path_patterns: list[str] = []
        self.basename_patterns: list[str] = []
        self.deep_path_patterns: list[str] = []  # For **/ prefix patterns

        for raw in patterns:
            pattern = raw.strip().replace("\\", "/")
            if not pattern or pattern.startswith("#") or pattern.startswith("!"):
                continue
            if pattern.endswith("/"):
                prefix = pattern.strip("/")
                if prefix:
                    self.directory_prefixes.append(prefix)
                continue
            if pattern.startswith("/"):
                self.rooted_patterns.append(pattern.lstrip("/"))
                continue
            double_star_glob = pattern.startswith("**/")
            if pattern.startswith("**/"):
                pattern = pattern[3:]
            if "/" in pattern:
                if double_star_glob:
                    # **/sub/pattern should match at any depth
                    self.deep_path_patterns.append(pattern)
                else:
                    self.path_patterns.append(pattern)
            else:
                self.basename_patterns.append(pattern)

    def matches(self, rel_path: str) -> bool:
        """Return True if a normalized relative path matches an ignore rule."""
        path = Path(rel_path).as_posix().removeprefix("./").lstrip("/")
        if not path or path == ".":
            return False

        for prefix in self.directory_prefixes:
            if path == prefix or path.startswith(prefix + "/"):
                return True

        for pattern in self.rooted_patterns:
            if fnmatch.fnmatchcase(path, pattern):
                return True
            if pattern.endswith("/**") and path.startswith(pattern[:-3].rstrip("/") + "/"):
                return True

        for pattern in self.path_patterns:
            if fnmatch.fnmatchcase(path, pattern):
                return True

        for pattern in self.deep_path_patterns:
            # **/sub/pattern: check if path ends with /sub/pattern or matches exactly
            if path == pattern or path.endswith("/" + pattern):
                return True
            if fnmatch.fnmatchcase(path, pattern):
                return True

        name = path.rsplit("/", 1)[-1]
        return any(fnmatch.fnmatchcase(name, pattern) for pattern in self.basename_patterns)


def load_ignore_file(path: str) -> IgnoreMatcher:
    """Load patterns from a file; unreadable/missing files mean no ignores."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return IgnoreMatcher(handle.read().splitlines())
    except OSError:
        return IgnoreMatcher([])


def load_ignore_from_dir(root: str) -> IgnoreMatcher:
    """Load .repoguardignore from the scan root."""
    return load_ignore_file(str(Path(root) / ".repoguardignore"))