# Changelog

All notable user-visible changes are documented here.

## 0.1.0 (2026-11-15)

### Features
- Added a native Tkinter desktop interface with in-app usage guidance, a refined dark header, sortable findings, search reset, and horizontal path scrolling.
- Added an adjustable large-file threshold (0.1–1024 MB), keyboard shortcuts, and clearer scan-complete/warning states.
- CLI: `--verbose`, `--quiet`, `--summary-only` modes for CI integration.
- Supports a root-level `.repoguardignore` with glob patterns.

### Security Fixes
- Fixed AWS Secret Access Key detection: changed from `\b` word boundary to negative lookahead `(?![A-Za-z0-9/+=])` to properly detect keys ending in `/`, `+`, `=` characters.
- Fixed Generic Secret detection: added support for quoted keys in JSON (`"password": "value"`) and YAML (`api_key: "value"`).
- Fixed ignore pattern deep directory bypass: added `deep_path_patterns` handling for `**/` prefix patterns.
- Removed overly broad `*.md` exclusion from `.repoguardignore`; replaced with specific exclusions for test fixtures and development documentation.
- `ScanCancelled` exception now properly caught in CLI with graceful exit code 130.

### Improvements
- Made generated/dependency directory exclusions case-insensitive (`.git`, `venv`, `node_modules`, etc.).
- Improved ignore-pattern matching for basenames and recursive patterns.
- Improved package metadata and repository governance documentation.
- Added GitHub issue/PR templates and a static project landing page.
- Added tearDown() cleanup to all test classes using temporary directories.
- Suppressed unexpected exception details in the GUI to avoid echoing potentially sensitive scanned content.

### Detection Coverage
- Added 5 new high-severity detector categories: Azure Storage Key, GCP Service Account, DigitalOcean Token, Heroku API Key, Database Connection Strings (PostgreSQL, MySQL, MongoDB, Redis, MSSQL, Oracle).
- Added 3 SSH private key format verifications: OpenSSH, ECDSA, Ed25519 (PEM).
- High-entropy fallback detection (base64/hex strings with entropy >= 4.0, excluding UUIDs and common hash lengths).
- Expanded sensitive file detection: Docker, Kubernetes, AWS, Terraform configs, backup files.
- Generic secret now supports quoted keys in JSON and YAML formats.

### Tests
- Added 29 new tests (total: 94 passing, 1 skipped).
- New tests cover: license variants, README variants, staged rename/copy detection, AWS secret key edge cases, generic secret quoted keys, GUI error redaction.
- All tests pass on Python 3.10–3.13.

### Infrastructure
- Wheel and source distribution build successfully.
- No third-party runtime dependencies (stdlib only).
- CI workflow tests on Ubuntu, Windows, macOS × Python 3.10–3.13.
