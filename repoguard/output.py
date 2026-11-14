"""Output formatting: colorized text on TTY and stable JSON."""

from __future__ import annotations

import json
import os
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


def format_result_json(result: ScanResult, summary_only: bool = False) -> str:
    """Serialize a full ScanResult, including mode, warnings and duration."""

    data = json.loads(format_json(result.findings, result.root, summary_only=summary_only))
    data["mode"] = result.mode
    data["duration_seconds"] = round(result.duration_s, 6)
    data["warnings"] = list(result.warnings)
    return json.dumps(data, indent=2, sort_keys=True)


def format_error_json(message: str, root: str) -> str:
    """Return a valid JSON document describing a scan error (exit 2)."""

    return json.dumps(
        {"tool": "repoguard", "root": root, "error": message},
        indent=2,
        sort_keys=True,
    )