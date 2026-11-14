"""Staged Git blob inspection.

Uses ``git diff --cached --name-status -z`` (NUL-safe) to enumerate changed
paths and ``git cat-file`` to read staged blob content and sizes without
touching the working tree. Never uses ``shell=True``. Works on Windows when
Git is on PATH.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Iterator

GIT_NOT_FOUND = "git is not installed or not on PATH"


class GitError(RuntimeError):
    """Raised when Git is unavailable or a Git command fails."""


@dataclass(frozen=True)
class StagedEntry:
    """A path changed in the index, relative to the repository top level."""

    path: str
    status: str  # single-letter status, e.g. "A", "M", "D", "R"


def run_git(args: list[str], cwd: str) -> str:
    """Run a Git command and return stdout as text.

    ``surrogateescape`` keeps unusual (non-UTF-8) path bytes round-trippable.
    Raises GitError on failure or when Git is unavailable.
    """

    if not os.path.isdir(cwd):
        raise GitError(f"not a directory: {cwd}")

    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            check=False,
        )
    except (FileNotFoundError, OSError) as exc:
        raise GitError(GIT_NOT_FOUND) from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or f"git {' '.join(args)} failed"
        raise GitError(detail)
    return result.stdout


def is_git_repo(path: str) -> bool:
    """Return True when *path* is inside a Git work tree."""

    try:
        return run_git(["rev-parse", "--is-inside-work-tree"], path).strip() == "true"
    except GitError:
        return False


def repo_top_level(path: str) -> str:
    """Return the absolute top-level directory of the repository containing *path*."""

    out = run_git(["rev-parse", "--show-toplevel"], path).strip()
    if not out:
        raise GitError("not inside a Git repository")
    return out


def _parse_name_status(out: str) -> list[StagedEntry]:
    """Parse ``git diff --cached --name-status -z`` output."""

    entries: list[StagedEntry] = []
    parts = out.split("\0")
    if parts and parts[-1] == "":
        parts.pop()
    index = 0
    while index < len(parts):
        status = parts[index].strip()
        index += 1
        if not status or index >= len(parts):
            break
        code = status[0].upper()
        if code in ("R", "C"):
            # Rename/copy: old path then new path.
            if index + 1 >= len(parts):
                break
            entries.append(StagedEntry(parts[index + 1].replace("\\", "/"), code))
            index += 2
        else:
            entries.append(StagedEntry(parts[index].replace("\\", "/"), code))
            index += 1
    return entries


def staged_entries(cwd: str) -> list[StagedEntry]:
    """Return staged entries with their status letters."""

    out = run_git(["diff", "--cached", "--name-status", "-z"], cwd)
    if not out:
        return []
    return _parse_name_status(out)


def staged_paths(cwd: str) -> list[str]:
    """Return the NUL-safe list of staged (added/modified) paths."""

    return [entry.path for entry in staged_entries(cwd) if entry.status != "D"]


def staged_size(cwd: str, path: str) -> int:
    """Return the size in bytes of the staged blob for *path*."""

    out = run_git(["cat-file", "-s", f":{path}"], cwd).strip()
    try:
        return int(out)
    except ValueError as exc:
        raise GitError(f"cannot determine staged size for {path}") from exc


def staged_blob(cwd: str, path: str) -> str:
    """Return the staged blob content for *path* as UTF-8 text."""

    return run_git(["cat-file", "blob", f":{path}"], cwd)


def staged_blob_bytes(cwd: str, path: str) -> bytes:
    """Return the staged blob content for *path* as bytes."""

    if not os.path.isdir(cwd):
        raise GitError(f"not a directory: {cwd}")
    try:
        result = subprocess.run(
            ["git", "cat-file", "blob", f":{path}"],
            cwd=cwd,
            capture_output=True,
            check=False,
        )
    except (FileNotFoundError, OSError) as exc:
        raise GitError(GIT_NOT_FOUND) from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise GitError(detail or f"cannot read staged blob {path}")
    return result.stdout


def iter_staged(cwd: str) -> Iterator[tuple[str, str]]:
    """Yield ``(path, content)`` for each readable staged blob.

    Deleted or otherwise unreadable staged entries are skipped.
    """

    for entry in staged_entries(cwd):
        if entry.status == "D":
            continue
        try:
            content = staged_blob(cwd, entry.path)
        except GitError:
            continue
        yield entry.path, content