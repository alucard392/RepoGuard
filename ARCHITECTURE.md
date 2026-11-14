# RepoGuard Architecture

## Overview

RepoGuard is a local, offline repository hygiene scanner implemented in Python 3.10+ using only the standard library. It provides both a Tkinter desktop GUI and a command-line interface.

## Main Modules

### `repoguard/__init__.py`
Package initialization. Exposes `__version__`.

### `repoguard/__main__.py`
CLI entry point. Uses `argparse` for command parsing.
- `scan` command: runs the scanner with options
- `gui` command: launches the Tkinter GUI

### `repoguard/config.py`
Centralized configuration and validation.
- Constants: `DEFAULT_MAX_SIZE_MB`, `DEFAULT_FAIL_ON`, `READ_LIMIT_BYTES`, `SAFE_UPPER_BOUND`, `SEVERITY_ORDER`
- Validation functions: `validate_max_size_mb`

### `repoguard/patterns.py`
All regex patterns for secret detection, extracted from detectors for maintainability.
- High-confidence token patterns (GitHub, AWS, OpenAI, Google, Stripe, Slack, Azure, GCP, DigitalOcean, Heroku)
- Database connection string patterns
- SSH private key patterns
- Generic secret assignment pattern
- Placeholder suppression patterns
- High-entropy fallback patterns (base64, hex)
- Non-secret exclusion patterns (UUID, hash lengths)

### `repoguard/detectors.py`
Secret detection engine.
- `Finding` dataclass: rule_id, severity, path, line, snippet (redacted), fix
- `detect_secrets(path, content) -> list[Finding]`: Main detection function
- `is_placeholder(value) -> bool`: Suppresses obvious placeholders
- `calculate_shannon_entropy(s) -> float`: Shannon entropy for high-entropy detection
- `is_likely_non_secret(value) -> bool`: Excludes UUIDs, common hashes
- Detection pipeline:
  1. Token pattern matching (high-confidence patterns)
  2. Generic secret assignments (key-value pairs)
  3. High-entropy fallback (base64/hex strings with entropy >= 4.0)
- `_redact_spans(line, spans) -> str`: Redacts matched regions

### `repoguard/files.py`
File system traversal and filename/size checks.
- `SKIP_DIRS`: Directories skipped entirely (.git, venv, node_modules, etc.)
- `BINARY_EXTENSIONS`: Extensions treated as binary (never scanned)
- `SENSITIVE_FILENAMES`: Exact filenames flagged (id_rsa, .env, .aws/credentials, docker/config.json, .kube/config, terraform.tfstate, backup patterns)
- `ALLOWED_ENV_FILES`: .env.example, .env.template (allowed)
- `iter_files(root) -> Iterator[tuple[Path, int]]`: Walks tree, yields (path, size)
- `file_checks(rel_path, size, max_size_bytes) -> list[Finding]`: Size and filename checks

### `repoguard/ignore.py`
`.repoguardignore` pattern matching.
- `IgnoreMatcher`: Supports `**/` (any depth), basename matching, root-anchored paths
- Pattern types: exact, glob, directory prefix, double-star

### `repoguard/scanner.py`
Shared scan engine for CLI and GUI.
- `scan_repository(root, staged=False, max_size_mb=5.0, cancel_event=None) -> ScanResult`
- `ScanResult` dataclass: root, mode, findings, warnings, duration_s, counts
- Orchestrates:
  1. File traversal (`files.iter_files`)
  2. Per-file checks (`files.file_checks`, `detectors.detect_secrets`)
  3. Missing metadata checks (README, LICENSE, .gitignore)
  4. Ignore filtering (`ignore.IgnoreMatcher`)
  5. Staged Git blob scanning (via `staged.py`)
- Cancellation support via `threading.Event`

### `repoguard/staged.py`
Git staged blob scanning.
- `get_staged_blobs(root) -> dict[str, bytes]`: Uses `git diff --cached --name-status -z` + `git cat-file`
- Integrates with scanner for staged mode

### `repoguard/output.py`
Output formatting.
- `format_text(findings, root, summary_only=False) -> str`: Colorized text for TTY
- `format_json(findings, root, summary_only=False) -> str`: JSON with summary
- `format_result(result, summary_only=False) -> str`: Convenience wrapper
- `format_result_json(result, summary_only=False) -> str`: Full ScanResult JSON
- `format_error_json(message, root) -> str`: Error JSON for exit 2
- `_supports_color() -> bool`: TTY + NO_COLOR check
- Severity colors: high=red, medium=yellow, low=green

### `repoguard/gui.py`
Tkinter desktop GUI.
- `ScanController`: Background thread + queue for scan results
- `RepoGuardApp`: Main window with:
  - Header (title, path selector)
  - Toolbar (scan buttons, filters, help)
  - Summary cards (total/high/medium/low counts)
  - Filters (severity dropdown, search)
  - Table (Treeview: severity, rule, path, line)
  - Detail panel (rich text with tags)
  - Status bar (message, progress)
- Visual design: consistent spacing, color-coded severities, responsive layout
- Dialogs: How to use, About, Export JSON

## Application Entry Points

### CLI (`python -m repoguard scan [path]`)
1. Parse arguments
2. Call `scanner.scan_repository()`
3. Format output via `output.format_result()` or `output.format_result_json()`
4. Exit with code based on `--fail-on` threshold

### GUI (`python -m repoguard gui [path]`)
1. Create `tk.Tk()` root window
2. Instantiate `RepoGuardApp`
3. User interacts → `ScanController.start()` → background thread
4. Controller polls queue → callbacks update UI
5. Results displayed in table and detail panel

## Scanner Pipeline

```
scan_repository(root, staged, max_size_mb, cancel_event)
    |
    +-- If staged: get_staged_blobs() → scan blobs
    |
    +-- If working tree: iter_files() → for each file:
    |       |
    |       +-- file_checks() → size, sensitive filename findings
    |       |
    |       +-- read_text() → content
    |       |
    |       +-- detect_secrets() → secret findings
    |       |
    |       +-- IgnoreMatcher filtering
    |
    +-- Missing metadata checks (README, LICENSE, .gitignore)
    |
    +-- Aggregate findings → ScanResult
```

## Detection Architecture

```
detect_secrets(path, content)
    |
    +-- For each line:
    |       |
    |       +-- Token patterns (GITHUB_CLASSIC, AWS_ACCESS_KEY, etc.)
    |       |       → Finding(rule_id, "high", ...)
    |       |
    |       +-- Generic secret (GENERIC_SECRET regex)
    |       |       → Finding("generic-secret", "medium", ...)
    |       |       → Suppressed if is_placeholder(value)
    |       |
    |       +-- High-entropy fallback (only if no token/generic on line)
    |               +-- HIGH_ENTROPY_BASE64 (32+ chars)
    |               +-- HIGH_ENTROPY_HEX (64+ chars)
    |               → Entropy >= 4.0, not UUID/hash
    |               → Finding("high-entropy-secret", "medium", ...)
    |
    +-- Merge overlapping spans → _redact_spans()
    |
    +-- Return list[Finding]
```

## Configuration

All configuration is in `config.py`:
- `DEFAULT_MAX_SIZE_MB = 5`: Files larger than this flagged
- `DEFAULT_FAIL_ON = "high"`: CLI exit threshold
- `READ_LIMIT_BYTES = 10 * 1024 * 1024`: Max content read per file
- `SAFE_UPPER_BOUND = 1000`: Max `--max-size-mb` value
- `SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}`: Severity ranking

## Testing Architecture

- `tests/test_detectors.py`: Unit tests for all detection patterns (38 tests)
- `tests/test_files.py`: File traversal and filename checks (11 tests)
- `tests/test_ignore.py`: Ignore pattern matching (6 tests)
- `tests/test_staged.py`: Git staged blob scanning (9 tests)
- `tests/test_cli.py`: CLI integration tests (18 tests)
- `tests/test_gui.py`: GUI controller and onboarding (3 tests)
- All tests use standard `unittest`, run with `pytest`
- TDD: every feature starts with failing test

## Packaging

- `pyproject.toml`: setuptools config, entry points (`repoguard`, `python -m repoguard`)
- `MANIFEST.in`: Includes package, tests, docs, license
- `py.typed`: PEP 561 marker for type hints
- Build: `python -m build --no-isolation`
- Output: wheel (any) + sdist
- Zero runtime dependencies (stdlib only)

## Security Model

- **Offline-first**: No network calls, no telemetry, no uploads
- **Read-only**: Never modifies scanned repository
- **Redaction mandatory**: Secret values never appear in findings (snippets always redacted)
- **Heuristic only**: No guarantee of completeness; false positives/negatives possible
- **Self-scan clean**: RepoGuard's own source passes with .repoguardignore for test fixtures