# RepoGuard

**A local, offline repository hygiene scanner for Python 3.10+.** Find likely leaked credentials, sensitive files, oversized files and missing repository basics before you commit or push.

RepoGuard provides a desktop GUI (Tkinter) and a command-line interface. It is read-only: it does not rewrite files, upload content, or contact a service.

## Highlights

- Detects common GitHub, AWS, OpenAI, Google API, Stripe, Slack, Azure, GCP, DigitalOcean, Heroku secret token formats, PEM/OpenSSH/EC private-key headers, database connection strings, and suspicious generic/high-entropy secret assignments.
- Flags sensitive files such as environment files, private-key files, credential stores, Docker/Kubernetes/AWS/Terraform configs, and backup files.
- Checks file sizes and basic repository metadata (README, LICENSE, .gitignore).
- Scans either the working tree or the exact staged Git blobs.
- Redacts detected secret values in findings (never printed).
- Supports a root-level .repoguardignore with glob patterns.
- Native Tkinter GUI and CLI; no third-party runtime dependencies.
- Offline operation; no telemetry, analytics, or automatic remediation.
- CLI: `--verbose`, `--quiet`, `--summary-only` modes for CI integration.

## Screenshots

Capture screenshots from a real run and add them under docs/images/ before release. Do not use mock screenshots as evidence of working behavior.

## Requirements and installation

- Python 3.10 or newer.
- Tkinter is required for the desktop GUI (usually included with standard Windows Python; Linux distributions may package it separately).
- Git is required only for staged scans.

From a clone or downloaded source directory:

    python -m pip install .
    repoguard --version

Run without installing:

    python -m repoguard --version

## Desktop GUI

Launch:

    repoguard gui
    python -m repoguard gui

Optionally pass a repository path:

    repoguard gui ./my-project

Choose a folder, select Scan Working Tree or Scan Staged, then select a finding to inspect its redacted evidence and suggested fix. The How to use button contains the full in-app guide.

## Command-line usage

    repoguard scan .
    repoguard scan --staged .
    repoguard scan --format json .
    repoguard scan --max-size-mb 10 .
    repoguard scan --fail-on medium .
    repoguard scan --verbose .
    repoguard scan --quiet .
    repoguard scan --summary-only --format json .

| Exit code | Meaning |
|---|---|
| 0 | No findings at or above the selected --fail-on threshold |
| 1 | One or more findings at or above the threshold |
| 2 | Usage or scan error |
| 130 | Interrupted from the terminal |

The default threshold is --fail-on high. JSON mode writes one JSON document to stdout and sends diagnostics to stderr.

## What is checked

| Severity | Examples |
|---|---|
| High | GitHub (classic, PAT), AWS (access key, secret), OpenAI (sk, sk-proj), Google API, Stripe (sk_test/live), Slack webhooks, Azure Storage, GCP Service Account, DigitalOcean, Heroku tokens; PEM/OpenSSH/EC private keys; database connection strings (PostgreSQL, MySQL, MongoDB, Redis, MSSQL, Oracle); sensitive files (.env, .aws/credentials, .kube/config, docker/config.json, terraform.tfstate, backup files) |
| Medium | Heuristic generic secret assignments (password, api_key, token, secret keys); high-entropy base64/hex strings without known keys; oversized files; missing .gitignore |
| Low | Missing README or license |

The exact detector patterns are heuristic and may change between versions. A finding is a prompt to investigate, not proof that a value is active.

## Working tree vs staged scan

- Working tree reads current files on disk.
- Staged reads Git index blobs. If a file was staged and then edited again, the staged scan inspects the earlier staged content.
- Staged mode requires Git and a repository. Deleted staged files are not scanned.

## Ignore rules

Create .repoguardignore in the scan root. Supported examples:

    *.log
    build/
    /config/dev-settings.json
    **/secrets.json

Blank lines and lines beginning with # are ignored. Basename globs match at any depth; trailing slash ignores a directory and its contents; leading slash anchors a path at the scan root; leading **/ matches at any depth. Negation (!) and full Git ignore syntax are not supported.

## Privacy, security and limitations

RepoGuard operates locally and does not make network requests, send telemetry, upload files, or modify the scanned repository. Secret values are redacted in findings. Review all findings before acting.

No scanner can guarantee detection. Obfuscated, split, encoded, dynamically assembled, or unusual secrets may be missed. Generic-secret heuristics can produce false positives. Large files may be skipped for content scanning while still receiving filename/size checks.

**If a real credential may have been exposed, revoke or rotate it immediately.** Removing it from the latest file does not invalidate a leaked credential; review Git history and follow the provider's incident-response guidance. Never post actual secrets in public issues.

## Development

    python -m unittest discover -s tests -v
    python -m compileall -q repoguard tests
    python -m build

See CONTRIBUTING.md, SECURITY.md, SUPPORT.md, GUI_TESTING.md and RELEASE_CHECKLIST.md.

## Project governance

This project uses the MIT License, a Contributor Covenant Code of Conduct, and documented security reporting guidance. Repository owners should enable branch protection, required CI checks, Dependabot and private vulnerability reporting where available. These settings must be configured in GitHub; files in this repository do not enable them automatically.

## License

MIT. See LICENSE.
