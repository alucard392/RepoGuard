"""RepoGuard command-line interface."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .config import DEFAULT_FAIL_ON, DEFAULT_MAX_SIZE_MB, SEVERITY_ORDER
from .output import format_error_json, format_result, format_result_json
from .scanner import ScanError, scan_repository

PROG = "repoguard"
VERSION = __version__


def _max_size_arg(value: str) -> float:
    from .config import validate_max_size_mb

    try:
        return validate_max_size_mb(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Catch accidental repository hygiene problems (secrets, sensitive "
            "files, oversized files, missing README/LICENSE/.gitignore) before "
            "you push to GitHub."
        ),
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a repository for hygiene issues")
    scan.add_argument(
        "path", nargs="?", default=".",
        help="directory to scan (default: .)",
    )
    scan.add_argument(
        "--staged", action="store_true",
        help="inspect staged Git blobs instead of the working tree",
    )
    scan.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="output format (default: text)",
    )
    scan.add_argument(
        "--max-size-mb", type=_max_size_arg, default=DEFAULT_MAX_SIZE_MB,
        metavar="N",
        help="files larger than this many MiB are flagged (default: 5)",
    )
    scan.add_argument(
        "--fail-on", choices=["low", "medium", "high"], default=DEFAULT_FAIL_ON,
        help="exit 1 when findings at or above this severity exist (default: high)",
    )
    scan.add_argument(
        "--verbose", action="store_true",
        help="show warnings and detailed scan progress",
    )
    scan.add_argument(
        "--quiet", action="store_true",
        help="suppress all output except findings and errors",
    )
    scan.add_argument(
        "--summary-only", action="store_true",
        help="show only summary counts, no finding details",
    )

    gui = sub.add_parser("gui", help="launch the desktop GUI (requires tkinter)")
    gui.add_argument(
        "path", nargs="?", default=".",
        help="initial folder to display (default: current directory)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "gui":
        from .gui import run_gui

        return run_gui(args.path)

    try:
        result = scan_repository(
            args.path,
            staged=args.staged,
            max_size_mb=args.max_size_mb,
        )
    except ScanError as exc:
        message = str(exc)
        if args.format == "json":
            # stdout stays a single valid JSON document on every exit path.
            print(format_error_json(message, args.path))
        else:
            print(f"{PROG}: {message}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(f"{PROG}: interrupted", file=sys.stderr)
        return 130

    if args.format == "json":
        if args.summary_only:
            # Summary-only JSON: include only summary, not findings
            print(format_result_json(result, summary_only=True))
        else:
            print(format_result_json(result))
    else:
        if not args.quiet:
            for warning in result.warnings:
                print(f"{PROG}: warning: {warning}", file=sys.stderr)
            if args.summary_only:
                print(format_result(result, summary_only=True))
            else:
                print(format_result(result))

    threshold = SEVERITY_ORDER[args.fail_on]
    relevant = [
        finding for finding in result.findings
        if SEVERITY_ORDER[finding.severity] >= threshold
    ]
    if relevant:
        if not args.quiet and not args.summary_only:
            # Don't print threshold message when --summary-only is used (redundant)
            print(
                f"\n{PROG}: {len(relevant)} finding(s) at or above "
                f"--fail-on {args.fail_on}",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())