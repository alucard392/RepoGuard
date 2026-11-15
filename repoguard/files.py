"""File-system traversal, content reading, and filename/size checks."""

from __future__ import annotations

import os
import stat as stat_module
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .config import READ_LIMIT_BYTES
from .detectors import Finding

# Directories skipped entirely while walking. These are dependency, cache and
# build directories; a directory literally named ".env" is treated the same way
# (common with virtual environments).
SKIP_DIRS = frozenset({
    ".git",
    "venv", ".venv", "env", ".env", "virtualenv", ".virtualenv",
    "__pycache__", ".cache", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "node_modules",
    "build", "dist", "bin", ".bin",
    ".tox", ".eggs",
})

# File extensions treated as binary; their content is never scanned.
BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp",
    ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar",
    ".pdf", ".exe", ".dll", ".so", ".dylib", ".bin", ".dat",
    ".pyc", ".pyd", ".class", ".o", ".a", ".lib",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".wmv",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
})

# Files above this size are not read at all; they still receive size and
# filename findings.
SAFE_UPPER_BOUND = READ_LIMIT_BYTES

# Bytes sniffed when deciding whether extensionless content is binary.
BINARY_SNIFF_BYTES = 8192

ALLOWED_ENV_FILES = frozenset({
    ".env.example", ".env.template", ".env.sample", ".env.dist",
})
ALLOWED_ENV_SUFFIXES = frozenset({".example", ".template", ".sample", ".dist"})

# Exact (case-insensitive) filenames that normally must not be committed.
SENSITIVE_FILENAMES = frozenset({
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "credentials.json", ".netrc", ".pgpass", ".npmrc", ".htpasswd",
    "secrets.json", "secrets.yaml", "secrets.yml",
    "terraform.tfstate", "terraform.tfstate.backup",
    ".aws/credentials", ".aws/config",
    ".kube/config",
    "docker/config.json", ".docker/config.json",
})


@dataclass(frozen=True)
class FileEntry:
    """A regular file discovered under a scan root."""

    abs_path: str
    rel_path: str
    size: int


def _should_skip_dir(name: str) -> bool:
    """Match generated/dependency directory names case-insensitively."""
    return name.casefold() in SKIP_DIRS


def _warn(warnings: list[str] | None, message: str) -> None:
    if warnings is not None:
        warnings.append(message)


def walk_files(
    root: str, warnings: list[str] | None = None
) -> Iterator[FileEntry]:
    """Yield regular files under *root* in deterministic order.

    Symlinked files and directories are skipped (never followed), which
    prevents loops and reading outside the scan root. Unreadable entries are
    reported through *warnings* and skipped. Files of any size are yielded so
    that size findings still work; callers decide whether to read content.
    """

    root_path = Path(root)
    if not root_path.is_dir():
        return

    def onerror(exc: OSError) -> None:
        _warn(
            warnings,
            f"cannot read directory {getattr(exc, 'filename', '?')}: "
            f"{exc.strerror or exc}",
        )

    for dirpath, dirnames, filenames in os.walk(
        root_path, topdown=True, onerror=onerror, followlinks=False
    ):
        kept: list[str] = []
        for name in sorted(dirnames):
            if _should_skip_dir(name):
                continue
            entry_path = Path(dirpath) / name
            try:
                if entry_path.is_symlink():
                    _warn(warnings, f"skipping symbolic link {entry_path}")
                    continue
            except OSError as exc:
                _warn(warnings, f"cannot inspect {entry_path}: {exc}")
                continue
            kept.append(name)
        dirnames[:] = kept

        for name in sorted(filenames):
            abs_path = Path(dirpath) / name
            try:
                if abs_path.is_symlink():
                    _warn(warnings, f"skipping symbolic link {abs_path}")
                    continue
                info = abs_path.stat()
            except OSError as exc:
                _warn(
                    warnings,
                    f"cannot stat {abs_path}: {exc.strerror or exc}",
                )
                continue
            if not stat_module.S_ISREG(info.st_mode):
                continue
            try:
                rel_path = abs_path.relative_to(root_path).as_posix()
            except ValueError:
                continue
            yield FileEntry(str(abs_path), rel_path, info.st_size)


def iter_files(root: str) -> Iterator[tuple[str, str]]:
    """Yield ``(absolute_path, relative_path)`` for scannable files under *root*.

    Binary extensions are skipped (they are never content-scanned); use
    :func:`walk_files` when size findings for every regular file are needed.
    """

    for entry in walk_files(root):
        if is_binary_path(entry.rel_path):
            continue
        yield entry.abs_path, entry.rel_path


def read_text(
    abs_path: str, size: int, warnings: list[str] | None = None
) -> str | None:
    """Read a text file, or return ``None`` when content should be skipped.

    Content is skipped for files above :data:`READ_LIMIT_BYTES` and for binary
    content (a NUL byte in the first :data:`BINARY_SNIFF_BYTES` bytes).
    Unreadable files are reported through *warnings*.
    """

    if size > READ_LIMIT_BYTES:
        return None
    try:
        with open(abs_path, "rb") as handle:
            data = handle.read(READ_LIMIT_BYTES)
    except OSError as exc:
        _warn(
            warnings,
            f"cannot read {abs_path}: {exc.strerror or exc}",
        )
        return None
    if b"\x00" in data[:BINARY_SNIFF_BYTES]:
        return None
    return data.decode("utf-8", errors="replace")


def is_binary_path(rel_path: str) -> bool:
    """Return True when the path has a known binary extension."""

    return Path(rel_path).suffix.lower() in BINARY_EXTENSIONS


def file_checks(rel_path: str, size: int, max_size_bytes: int) -> list[Finding]:
    """Return size and sensitive-filename findings for one file."""

    findings: list[Finding] = []
    findings.extend(_check_size(rel_path, size, max_size_bytes))
    findings.extend(_check_sensitive_filename(rel_path, rel_path.lower()))
    return findings


def _check_size(rel_path: str, size: int, max_size_bytes: int) -> list[Finding]:
    if size > max_size_bytes:
        return [Finding(
            rule_id="oversized-file",
            severity="medium",
            path=rel_path,
            line=None,
            snippet=(
                f"file size {size / 1024 / 1024:.2f} MiB exceeds "
                f"{max_size_bytes / 1024 / 1024:.2f} MiB"
            ),
            fix="Add the file to .gitignore or track it with Git LFS",
        )]
    return []


def _check_sensitive_filename(rel_path: str, rel_lower: str) -> list[Finding]:
    name = Path(rel_path).name.lower()
    if not name or not _is_sensitive_name(name, rel_lower):
        return []
    return [Finding(
        rule_id="sensitive-filename",
        severity="high",
        path=rel_path,
        line=None,
        snippet=f"sensitive file {name} should not be committed",
        fix=(
            "Remove the file from version control and add it to .gitignore; "
            "use .env.example/.template for templates"
        ),
    )]


def _is_sensitive_name(name: str, rel_lower: str) -> bool:
    if name in ALLOWED_ENV_FILES:
        return False
    if name == ".env":
        return True
    if name.startswith(".env."):
        # .env.local, .env.production, ... but not .env.example/.template.
        return name[len(".env"):] not in ALLOWED_ENV_SUFFIXES
    if name.endswith(".pem") or name.endswith(".key"):
        return True
    # Backup file patterns
    if name.endswith((".bak", ".backup", "~", ".old", ".orig")):
        return True
    if name in SENSITIVE_FILENAMES:
        return True
    # Full path matches for files in sensitive directories
    if rel_lower in SENSITIVE_FILENAMES:
        return True
    return False