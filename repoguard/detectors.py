"""Secret and sensitive-content detection.

Findings are always redacted: secret values are never printed verbatim.
Detection is heuristic and intentionally does not claim completeness.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .config import SEVERITY_ORDER
from .patterns import (
    # Token patterns
    GITHUB_CLASSIC,
    GITHUB_PAT,
    AWS_ACCESS_KEY,
    OPENAI_PROJ,
    OPENAI_SK,
    PEM_PRIVATE_KEY,
    GOOGLE_API_KEY,
    STRIPE_SECRET_KEY,
    SLACK_WEBHOOK,
    DB_CONNECTION_STRING,
    AZURE_STORAGE_KEY,
    AWS_SECRET_ACCESS_KEY,
    GCP_SERVICE_ACCOUNT,
    DIGITALOCEAN_TOKEN,
    HEROKU_API_KEY,
    # Generic
    GENERIC_SECRET,
    PLACEHOLDER_WORDS,
    PLACEHOLDER_SUBSTRINGS,
    ANGLE_BRACKET,
    ENV_REF,
    CODE_LIKE,
    # High-entropy
    HIGH_ENTROPY_BASE64,
    HIGH_ENTROPY_HEX,
    UUID_PATTERN,
    HASH_PATTERN,
)

__all__ = ["Finding", "SEVERITY_ORDER", "detect_secrets", "is_placeholder"]


@dataclass(frozen=True)
class Finding:
    """One hygiene finding. ``snippet`` is always a redacted rendering."""

    rule_id: str
    severity: str
    path: str
    line: int | None
    snippet: str
    fix: str


def is_placeholder(value: str) -> bool:
    """Return True if *value* looks like a placeholder and should be suppressed."""

    lowered = value.strip().lower()
    if not lowered:
        return True
    if lowered in PLACEHOLDER_WORDS:
        return True
    if lowered.startswith(("$", "%", "<", "{{")):
        return True
    if ANGLE_BRACKET.search(value):
        return True
    if ENV_REF.match(value.strip()):
        return True
    if any(word in lowered for word in PLACEHOLDER_SUBSTRINGS):
        return True
    if CODE_LIKE.search(value):
        return True
    if len(set(lowered)) == 1:
        return True
    return False


def calculate_shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string (bits per character)."""
    import math
    if not s:
        return 0.0
    # Count frequency of each character
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    # Calculate entropy
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_likely_non_secret(value: str) -> bool:
    """Return True if high-entropy value is likely not a secret (UUID, hash, etc.)."""
    if UUID_PATTERN.match(value):
        return True
    # Common hash lengths (MD5=32, SHA1=40, SHA256=64)
    if HASH_PATTERN.match(value) and len(value) in (32, 40, 64):
        return True
    return False


def _redact_value(value: str) -> str:
    """Return a redacted rendering of *value* (never the raw secret)."""

    value = value.strip()
    if len(value) <= 8:
        return "[REDACTED]"
    return value[:3] + "***" + value[-3:]


def _merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not spans:
        return []
    ordered = sorted(spans)
    merged: list[list[int]] = [list(ordered[0])]
    for start, end in ordered[1:]:
        if start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(start, end) for start, end in merged]


def _redact_spans(line: str, spans: list[tuple[int, int]]) -> str:
    out: list[str] = []
    last = 0
    for start, end in _merge_spans(spans):
        if start < last:
            continue
        out.append(line[last:start])
        out.append("[REDACTED]")
        last = end
    out.append(line[last:])
    return "".join(out)


_TOKEN_SPECS = (
    (GITHUB_CLASSIC, "github-token", "high",
     "Remove the token and rotate it at https://github.com/settings/tokens"),
    (GITHUB_PAT, "github-pat", "high",
     "Remove the token and rotate it at https://github.com/settings/tokens"),
    (AWS_ACCESS_KEY, "aws-access-key", "high",
     "Remove the key and rotate it at https://console.aws.amazon.com/iam"),
    (OPENAI_PROJ, "openai-key", "high",
     "Remove the key and rotate it at https://platform.openai.com/api-keys"),
    (OPENAI_SK, "openai-key", "high",
     "Remove the key and rotate it at https://platform.openai.com/api-keys"),
    (PEM_PRIVATE_KEY, "private-key", "high",
     "Remove the private key; never commit PEM keys to version control"),
    (GOOGLE_API_KEY, "google-api-key", "high",
     "Remove the key and restrict or rotate it in Google Cloud Console"),
    (STRIPE_SECRET_KEY, "stripe-secret-key", "high",
     "Remove the Stripe secret key and roll it in the Stripe Dashboard"),
    (SLACK_WEBHOOK, "slack-webhook", "high",
     "Remove the webhook URL and revoke/regenerate it in Slack App settings"),
    (DB_CONNECTION_STRING, "db-connection-string", "high",
     "Remove the connection string and use environment variables for credentials"),
    (AZURE_STORAGE_KEY, "azure-storage-key", "high",
     "Remove the Azure storage key and regenerate it in Azure Portal"),
    (AWS_SECRET_ACCESS_KEY, "aws-secret-access-key", "high",
     "Remove the AWS secret access key and rotate it in AWS IAM Console"),
    (GCP_SERVICE_ACCOUNT, "gcp-service-account", "high",
     "Remove the GCP service account key and rotate it in Google Cloud Console"),
    (DIGITALOCEAN_TOKEN, "digitalocean-token", "high",
     "Remove the DigitalOcean token and revoke it in DigitalOcean Control Panel"),
    (HEROKU_API_KEY, "heroku-api-key", "high",
     "Remove the Heroku API key and rotate it in Heroku Dashboard"),
)


def detect_secrets(path: str, content: str) -> list[Finding]:
    """Scan *content* for secrets and return redacted findings.

    Every secret-looking span on a line is redacted in the emitted snippet,
    including multiple secrets on one line and quoted/assigned values.
    """

    findings: list[Finding] = []
    for lineno, line in enumerate(content.splitlines(), start=1):
        line_findings: list[Finding] = []
        token_spans: list[tuple[int, int]] = []

        for pattern, rule_id, severity, fix in _TOKEN_SPECS:
            for match in pattern.finditer(line):
                token_spans.append((match.start(), match.end()))
                line_findings.append(Finding(
                    rule_id=rule_id,
                    severity=severity,
                    path=path,
                    line=lineno,
                    snippet="",
                    fix=fix,
                ))

        generic_spans: list[tuple[int, int]] = []
        for match in GENERIC_SECRET.finditer(line):
            value_start, value_end = match.span("value")
            # Do not double-report a value already covered by a token rule.
            if any(start <= value_start and value_end <= end
                   for start, end in token_spans):
                continue
            value = match.group("value")
            if is_placeholder(value):
                continue
            generic_spans.append((value_start, value_end))
            line_findings.append(Finding(
                rule_id="generic-secret",
                severity="medium",
                path=path,
                line=lineno,
                snippet="",
                fix="Move the secret to an environment variable or secrets manager",
            ))

        # High-entropy fallback detection (only if no other findings on this line)
        entropy_spans: list[tuple[int, int]] = []
        if not token_spans and not generic_spans:
            # Check for high-entropy base64 strings
            for match in HIGH_ENTROPY_BASE64.finditer(line):
                value = match.group()
                if is_placeholder(value) or is_likely_non_secret(value):
                    continue
                if calculate_shannon_entropy(value) >= 4.0:
                    entropy_spans.append((match.start(), match.end()))
                    line_findings.append(Finding(
                        rule_id="high-entropy-secret",
                        severity="medium",
                        path=path,
                        line=lineno,
                        snippet="",
                        fix="Investigate this high-entropy value; it may be a secret",
                    ))
            # Check for high-entropy hex strings
            for match in HIGH_ENTROPY_HEX.finditer(line):
                value = match.group()
                if is_placeholder(value) or is_likely_non_secret(value):
                    continue
                if calculate_shannon_entropy(value) >= 4.0:
                    entropy_spans.append((match.start(), match.end()))
                    line_findings.append(Finding(
                        rule_id="high-entropy-secret",
                        severity="medium",
                        path=path,
                        line=lineno,
                        snippet="",
                        fix="Investigate this high-entropy value; it may be a secret",
                    ))

        if not line_findings:
            continue
        snippet = _redact_spans(line, token_spans + generic_spans + entropy_spans)
        findings.extend(replace(finding, snippet=snippet)
                        for finding in line_findings)
    return findings