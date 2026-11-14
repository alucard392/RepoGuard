"""Shared scan engine for the CLI and the GUI.

Both front ends call :func:`scan_repository` so detector logic and finding
semantics cannot drift between them.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import DEFAULT_MAX_SIZE_MB, READ_LIMIT_BYTES, validate_max_size_mb
from .detectors import Finding, detect_secrets
from .files import (
    BINARY_SNIFF_BYTES,
    file_checks,
    is_binary_path,
    read_text,
    walk_files,
)
from .ignore import IgnoreMatcher, load_ignore_file
from .staged import (
    GitError,
    repo_top_level,
    staged_blob_bytes,
    staged_entries,
    staged_size,
)

__all__ = [
    "ScanCancelled",
    "ScanError",
    "ScanResult",
    "scan_repository",
]

README_VARIANTS = (
    "readme",
    "readme.md",
    "readme.rst",
    "readme.txt",
    "readme.markdown",
    "readme.mdx",
    "readme.adoc",
)
LICENSE_VARIANTS = (
    "license",
    "license.md",
    "license.txt",
    "licence",
    "licence.md",
    "copying",
    "copying.md",
    "copyright",
)


class ScanError(RuntimeError):
    """A predictable scan failure (invalid path, missing Git, ...)."""


class ScanCancelled(RuntimeError):
    """Raised when a cancelled scan stops early."""


@dataclass
class ScanResult:
    """The complete result of one scan."""

    root: str
    mode: str  # "working-tree" or "staged"
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duration_s: float = 0.0

    @property
    def counts(self) -> dict[str, int]:
        counts = {"total": len(self.findings), "high": 0, "medium": 0, "low": 0}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts


def _check_cancel(cancel_event: threading.Event | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise ScanCancelled("scan cancelled")


def _finding_sort_key(finding: Finding) -> tuple[str, int, str, str]:
    return (
        finding.path,
        finding.line if finding.line is not None else 0,
        finding.rule_id,
        finding.severity,
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int | None, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.path, finding.line, finding.snippet)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _root_file_names(root: str, warnings: list[str]) -> set[str] | None:
    try:
        with os.scandir(root) as entries:
            return {
                entry.name.lower()
                for entry in entries
                if entry.is_file(follow_symlinks=False)
            }
    except OSError as exc:
        warnings.append(f"cannot list {root}: {exc.strerror or exc}")
        return None


def _hygiene_findings(root: str, warnings: list[str]) -> list[Finding]:
    """Checks rooted at the scan root. Parent directories are never inspected."""

    names = _root_file_names(root, warnings)
    if names is None:
        return []

    findings: list[Finding] = []
    if not any(name in names for name in README_VARIANTS):
        findings.append(
            Finding(
                rule_id="missing-readme",
                severity="low",
                path="README",
                line=None,
                snippet="missing README (looked for README, README.md, README.rst, ...)",
                fix="Add a README (or README.md/.rst/.txt) to the repository root",
            )
        )
    if not any(name in names for name in LICENSE_VARIANTS):
        findings.append(
            Finding(
                rule_id="missing-license",
                severity="low",
                path="LICENSE",
                line=None,
                snippet="missing LICENSE (looked for LICENSE, LICENSE.md, LICENSE.txt, ...)",
                fix="Add a LICENSE file to the repository root",
            )
        )
    if ".gitignore" not in names:
        findings.append(
            Finding(
                rule_id="missing-gitignore",
                severity="medium",
                path=".gitignore",
                line=None,
                snippet="missing .gitignore at the scan root",
                fix="Add a .gitignore file at the scan root",
            )
        )
    return findings


def _scan_working_tree(
    root: str,
    ignore: IgnoreMatcher,
    max_size_bytes: int,
    warnings: list[str],
    cancel_event: threading.Event | None,
) -> list[Finding]:
    findings: list[Finding] = []
    for entry in walk_files(root, warnings):
        _check_cancel(cancel_event)
        if ignore.matches(entry.rel_path):
            continue
        findings.extend(file_checks(entry.rel_path, entry.size, max_size_bytes))
        if is_binary_path(entry.rel_path):
            continue
        content = read_text(entry.abs_path, entry.size, warnings)
        if content is not None:
            findings.extend(detect_secrets(entry.rel_path, content))
    return findings


def _relative_prefix(root: str, top: str) -> str:
    relative = os.path.relpath(root, top)
    if relative == os.pardir or relative.startswith(os.pardir + os.sep):
        raise ScanError(f"scan root is outside the Git repository: {root}")
    return "" if relative == "." else Path(relative).as_posix()


def _scan_staged(
    root: str,
    ignore: IgnoreMatcher,
    max_size_bytes: int,
    warnings: list[str],
    cancel_event: threading.Event | None,
) -> list[Finding]:
    top = repo_top_level(root)
    prefix = _relative_prefix(root, top)
    findings: list[Finding] = []

    for entry in staged_entries(top):
        if entry.status == "D":
            continue
        path = entry.path
        if prefix:
            if not (path == prefix or path.startswith(prefix + "/")):
                continue
            rel_path = path[len(prefix) + 1 :]
        else:
            rel_path = path
        if not rel_path:
            continue
        _check_cancel(cancel_event)
        if ignore.matches(rel_path):
            continue

        try:
            size = staged_size(top, path)
        except GitError as exc:
            warnings.append(f"cannot size staged file {path}: {exc}")
            continue

        findings.extend(file_checks(rel_path, size, max_size_bytes))

        if size > READ_LIMIT_BYTES or is_binary_path(rel_path):
            continue
        try:
            data = staged_blob_bytes(top, path)
        except GitError as exc:
            warnings.append(f"cannot read staged file {path}: {exc}")
            continue
        if b"\x00" in data[:BINARY_SNIFF_BYTES]:
            continue
        findings.extend(
            detect_secrets(rel_path, data.decode("utf-8", errors="replace"))
        )
    return findings


def scan_repository(
    path: str = ".",
    *,
    staged: bool = False,
    max_size_mb: float = DEFAULT_MAX_SIZE_MB,
    ignore_file: str = ".repoguardignore",
    cancel_event: threading.Event | None = None,
) -> ScanResult:
    """Scan *path* and return a :class:`ScanResult`.

    Raises :class:`ScanError` for invalid paths, bad options, or Git errors
    (when *staged* is true). Raises :class:`ScanCancelled` if *cancel_event*
    is set during the scan.
    """

    try:
        max_size_mb = validate_max_size_mb(max_size_mb)
    except ValueError as exc:
        raise ScanError(str(exc)) from exc

    root = os.path.abspath(os.path.expanduser(os.fspath(path)))
    if not os.path.exists(root):
        raise ScanError(f"path does not exist: {path}")
    if not os.path.isdir(root):
        raise ScanError(f"not a directory: {path}")
    if not os.access(root, os.R_OK):
        raise ScanError(f"permission denied: {path}")

    warnings: list[str] = []
    max_size_bytes = int(max_size_mb * 1024 * 1024)
    ignore = load_ignore_file(os.path.join(root, ignore_file))
    started = time.monotonic()

    try:
        if staged:
            findings = _scan_staged(
                root, ignore, max_size_bytes, warnings, cancel_event
            )
        else:
            findings = _scan_working_tree(
                root, ignore, max_size_bytes, warnings, cancel_event
            )
            findings.extend(_hygiene_findings(root, warnings))
    except GitError as exc:
        raise ScanError(str(exc)) from exc

    findings = _dedupe(findings)
    findings.sort(key=_finding_sort_key)
    return ScanResult(
        root=root,
        mode="staged" if staged else "working-tree",
        findings=findings,
        warnings=warnings,
        duration_s=time.monotonic() - started,
    )