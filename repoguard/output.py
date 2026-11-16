"""Output formatting: colorized text on TTY and stable JSON."""

from __future__ import annotations

import json
import os
import re
import sys

from .detectors import Finding
from .scanner import ScanResult

SEVERITY_COLOR = {
    "high": "\033[1;31m",    # bold red
    "medium": "\033[1;33m",  # bold yellow
    "low": "\033[1;32m",     # bold green
}
RESET = "\033[0m"

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _color(text: str, severity: str) -> str:
    if not _supports_color():
        return text
    return f"{SEVERITY_COLOR.get(severity, '')}{text}{RESET}"


def format_text(findings: list[Finding], root: str, summary_only: bool = False) -> str:
    if not findings:
        return f"Repoguard: no findings in {root}."
    if summary_only:
        # Count by severity
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        return f"Repoguard: {len(findings)} finding(s) in {root} (high: {high}, medium: {medium}, low: {low})"
    lines = [f"Repoguard: {len(findings)} finding(s) in {root}:"]
    for f in findings:
        sev = _color(f.severity.upper(), f.severity)
        where = f"{f.path}" + (f":{f.line}" if f.line is not None else "")
        lines.append(f"  [{sev}] {f.rule_id} :: {where}")
        lines.append(f"      {f.snippet}")
        lines.append(f"      fix: {f.fix}")
    return "\n".join(lines)


def format_result(result: ScanResult, summary_only: bool = False) -> str:
    return format_text(result.findings, result.root, summary_only=summary_only)


def format_json(findings: list[Finding], root: str, summary_only: bool = False) -> str:
    # Use a relative path for privacy - only the project directory name
    # unless the root is the current working directory
    try:
        cwd = os.getcwd()
        if os.path.commonpath([root, cwd]) == cwd:
            # root is inside cwd - use relative path
            display_root = os.path.relpath(root, cwd)
            if display_root == ".":
                display_root = os.path.basename(root) or "."
        else:
            # root is outside cwd - use just the basename
            display_root = os.path.basename(root) or "."
    except (ValueError, OSError):
        # Fallback to basename on any error
        display_root = os.path.basename(root) or "."

    data = {
        "tool": "repoguard",
        "root": display_root,
        "summary": {
            "total": len(findings),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
        },
    }
    if not summary_only:
        data["findings"] = [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "path": f.path,
                "line": f.line,
                "snippet": f.snippet,
                "fix": f.fix,
            }
            for f in findings
        ]
    return json.dumps(data, indent=2, sort_keys=True)


def _safe_root_label(root: str) -> str:
    """Return a non-identifying label for a scan root."""
    try:
        absolute = os.path.abspath(os.path.expanduser(root))
    except (OSError, TypeError, ValueError):
        absolute = root
    return os.path.basename(os.path.normpath(absolute)) or "."


def _sanitize_local_path_text(value: str, root: str) -> str:
    """Replace absolute scan-root references in diagnostics with a safe label."""
    try:
        absolute = os.path.abspath(os.path.expanduser(root))
    except (OSError, TypeError, ValueError):
        absolute = root
    result = value
    for candidate in sorted((item for item in {root, absolute} if item), key=len, reverse=True):
        normalized = os.path.normpath(candidate)
        if normalized:
            result = re.sub(
                re.escape(normalized), lambda _match: "<repo>", result,
                flags=re.IGNORECASE if os.name == "nt" else 0,
            )
    return result


def format_result_json(result: ScanResult, summary_only: bool = False) -> str:
    """Serialize a full ScanResult, including mode, warnings and duration."""

    data = json.loads(format_json(result.findings, result.root, summary_only=summary_only))
    data["mode"] = result.mode
    data["duration_seconds"] = round(result.duration_s, 6)
    data["warnings"] = [
        _sanitize_local_path_text(warning, result.root)
        for warning in result.warnings
    ]
    data["incomplete"] = result.incomplete
    if result.skipped_files:
        data["skipped_files"] = result.skipped_files
    return json.dumps(data, indent=2, sort_keys=True)


def format_error_json(message: str, root: str) -> str:
    """Return a valid JSON document describing a scan error (exit 2)."""

    return json.dumps(
        {
            "tool": "repoguard",
            "root": _safe_root_label(root),
            "error": _sanitize_local_path_text(message, root),
        },
        indent=2,
        sort_keys=True,
    )