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
    staged_ignore_patterns,
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
    # Track incomplete scan conditions
    skipped_files: list[dict] = field(default_factory=list)  # Files skipped with reason
    incomplete: bool = False  # True if scan was incomplete

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
    skipped_files: list[dict] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for entry in walk_files(root, warnings):
        _check_cancel(cancel_event)
        if ignore.matches(entry.rel_path):
            # Intentionally ignored files don't count as incomplete scan
            continue
        findings.extend(file_checks(entry.rel_path, entry.size, max_size_bytes))
        if is_binary_path(entry.rel_path):
            if skipped_files is not None:
                skipped_files.append({
                    "path": entry.rel_path,
                    "reason": "binary file extension",
                    "size": entry.size,
                    "incomplete": False,
                })
            continue
        warning_count = len(warnings)
        content = read_text(entry.abs_path, entry.size, warnings)
        if content is not None:
            findings.extend(detect_secrets(entry.rel_path, content))
        else:
            if skipped_files is not None:
                if entry.size > READ_LIMIT_BYTES:
                    skipped_files.append({
                        "path": entry.rel_path,
                        "reason": "file size exceeds content read limit",
                        "size": entry.size,
                        "incomplete": True,
                    })
                else:
                    read_failed = len(warnings) > warning_count
                    skipped_files.append({
                        "path": entry.rel_path,
                        "reason": (
                            "file could not be read"
                            if read_failed
                            else "binary content (NUL byte in first 8192 bytes)"
                        ),
                        "size": entry.size,
                        "incomplete": read_failed,
                    })
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
    skipped_files: list[dict] | None = None,
) -> list[Finding]:
    top = repo_top_level(root)
    prefix = _relative_prefix(root, top)

    # Load ignore patterns from staged .repoguardignore (index version)
    # Staged scans MUST use the staged ignore file, not the working-tree version
    staged_ignore = IgnoreMatcher(staged_ignore_patterns(top))

    # Warn if working-tree .repoguardignore differs from staged
    if staged_ignore != ignore:
        # Only warn if there are actual differences
        working_patterns = ignore.rooted_patterns + ignore.path_patterns + ignore.directory_prefixes + ignore.basename_patterns + ignore.deep_path_patterns
        staged_patterns_list = staged_ignore.rooted_patterns + staged_ignore.path_patterns + staged_ignore.directory_prefixes + staged_ignore.basename_patterns + staged_ignore.deep_path_patterns
        if working_patterns != staged_patterns_list:
            warnings.append("staged scan uses .repoguardignore from Git index; working-tree version differs")

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
        if staged_ignore.matches(rel_path):
            # Intentionally ignored files don't count as incomplete scan
            continue

        try:
            size = staged_size(top, path)
        except GitError as exc:
            warnings.append(f"cannot size staged file {path}: {exc}")
            if skipped_files is not None:
                skipped_files.append({
                    "path": rel_path,
                    "reason": f"cannot determine size: {exc}",
                    "size": 0,
                    "incomplete": True,
                })
            continue

        findings.extend(file_checks(rel_path, size, max_size_bytes))

        if is_binary_path(rel_path) or size > READ_LIMIT_BYTES:
            if skipped_files is not None:
                if is_binary_path(rel_path):
                    skipped_files.append({
                        "path": rel_path,
                        "reason": "binary file extension",
                        "size": size,
                        "incomplete": False,
                    })
                else:
                    skipped_files.append({
                        "path": rel_path,
                        "reason": "file size exceeds content read limit",
                        "size": size,
                        "incomplete": True,
                    })
            continue
        try:
            data = staged_blob_bytes(top, path)
        except GitError as exc:
            warnings.append(f"cannot read staged file {path}: {exc}")
            if skipped_files is not None:
                skipped_files.append({
                    "path": rel_path,
                    "reason": f"cannot read content: {exc}",
                    "size": size,
                    "incomplete": True,
                })
            continue
        if b"\x00" in data[:BINARY_SNIFF_BYTES]:
            if skipped_files is not None:
                skipped_files.append({
                    "path": rel_path,
                    "reason": "binary content (NUL byte in first 8192 bytes)",
                    "size": size,
                    "incomplete": False,
                })
            continue
        findings.extend(
            detect_secrets(rel_path, data.decode("utf-8", errors="replace"))
        )

    # Staged hygiene checks against the Git index
    findings.extend(_staged_hygiene_findings(top, prefix, warnings))

    return findings


def _staged_hygiene_findings(top: str, prefix: str, warnings: list[str]) -> list[Finding]:
    """Check for README, LICENSE, .gitignore in the staged index."""
    findings: list[Finding] = []

    try:
        # List all staged files at the scan root
        staged_files = set()
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
            staged_files.add(rel_path.lower())
    except GitError as exc:
        warnings.append(f"cannot list staged files: {exc}")
        return findings

    # Check for README variants
    if not any(name in staged_files for name in README_VARIANTS):
        findings.append(
            Finding(
                rule_id="missing-readme",
                severity="low",
                path="README",
                line=None,
                snippet="missing README in staged snapshot (looked for README, README.md, README.rst, ...)",
                fix="Add a README (or README.md/.rst/.txt) to the repository root and stage it",
            )
        )
    # Check for LICENSE variants
    if not any(name in staged_files for name in LICENSE_VARIANTS):
        findings.append(
            Finding(
                rule_id="missing-license",
                severity="low",
                path="LICENSE",
                line=None,
                snippet="missing LICENSE in staged snapshot (looked for LICENSE, LICENSE.md, LICENSE.txt, ...)",
                fix="Add a LICENSE file to the repository root and stage it",
            )
        )
    # Check for .gitignore
    if ".gitignore" not in staged_files:
        findings.append(
            Finding(
                rule_id="missing-gitignore",
                severity="medium",
                path=".gitignore",
                line=None,
                snippet="missing .gitignore in staged snapshot",
                fix="Add a .gitignore file at the repository root and stage it",
            )
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
    skipped_files: list[dict] = []
    started = time.monotonic()

    try:
        if staged:
            findings = _scan_staged(
                root, ignore, max_size_bytes, warnings, cancel_event, skipped_files
            )
        else:
            findings = _scan_working_tree(
                root, ignore, max_size_bytes, warnings, cancel_event, skipped_files
            )
            findings.extend(_hygiene_findings(root, warnings))
    except GitError as exc:
        raise ScanError(str(exc)) from exc

    findings = _dedupe(findings)
    findings.sort(key=_finding_sort_key)

    # Determine if scan was incomplete
    incomplete_count = sum(1 for item in skipped_files if item.get("incomplete", True))
    incomplete = incomplete_count > 0 or any(
        warning.startswith("cannot ") for warning in warnings
    )
    if incomplete:
        if incomplete_count:
            warnings.append(
                f"scan incomplete: {incomplete_count} file(s) could not be fully inspected"
            )
        else:
            warnings.append("scan incomplete: one or more repository paths could not be inspected")

    return ScanResult(
        root=root,
        mode="staged" if staged else "working-tree",
        findings=findings,
        warnings=warnings,
        duration_s=time.monotonic() - started,
        skipped_files=skipped_files,
        incomplete=incomplete,
    )