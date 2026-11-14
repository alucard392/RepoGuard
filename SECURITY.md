# Security Policy

## Supported versions

Security fixes are applied to the latest maintained version on the default branch. There is no published release history yet; do not assume older builds receive fixes.

## Reporting a vulnerability

Use GitHub's Report a vulnerability / private vulnerability reporting feature if enabled. If it is not enabled, contact maintainers through a verified private contact channel listed on the repository profile before public disclosure.

Do not open a public issue for a detection bypass that could help attackers evade scanning. Never include real credentials, tokens, private keys, production data or unredacted repository content. Use synthetic reproductions.

Include the affected version or commit, operating system, Python version, scan mode, minimal synthetic reproduction, expected behavior and actual behavior.

## Scope and limitations

RepoGuard is a local defensive scanner. It does not upload scanned content or modify the repository. Detection is heuristic and cannot guarantee that all secrets are found. A clean scan is not a security certification.

If a real credential is discovered, revoke or rotate it immediately. Removing it from the current working tree does not remove it from Git history or invalidate it.

## Response expectations

Maintainers should acknowledge a report, assess impact, coordinate a fix, and publish an advisory when appropriate. No response-time commitment is made until a maintainer team and process exist.
