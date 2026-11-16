"""Secret and sensitive-content detection.

Findings are always redacted: secret values are never printed verbatim.
Detection is heuristic and intentionally does not claim completeness.
"""

from __future__ import annotations

import re
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
    GENERIC_SECRET_YAML_BLOCK,
    GENERIC_SECRET_EXPORT,
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


def _redact_private_key_content(content: str) -> str:
    """Redact private key material in PEM blocks and JSON-escaped PEM blocks."""
    import re

    # Pattern for PEM private key blocks (including those with escaped newlines)
    pem_pattern = re.compile(
        r'(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\\n.*?-----END [A-Z0-9 ]*PRIVATE KEY-----)',
        re.DOTALL
    )

    # Pattern for JSON-escaped PEM (with \\n)
    json_pem_pattern = re.compile(
        r'(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\\\\n.*?-----END [A-Z0-9 ]*PRIVATE KEY-----)',
        re.DOTALL
    )

    result = content
    # Handle JSON-escaped PEM first
    result = json_pem_pattern.sub('[REDACTED PRIVATE KEY]', result)
    # Handle regular PEM
    result = pem_pattern.sub('[REDACTED PRIVATE KEY]', result)

    return result


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
    (DIGITALOCEAN_TOKEN, "digitalocean-token", "high",
     "Remove the DigitalOcean token and revoke it in DigitalOcean Control Panel"),
)


# Heroku-specific context patterns for higher confidence
_AWS_SECRET_CONTEXT = re.compile(
    r"(?i)(?:aws[._-]?secret(?:[._-]?access)?(?:[._-]?key)?|secret[._-]?access[._-]?key)\s*[:=]"
)

_HEROKU_CONTEXT_PATTERNS = [
    re.compile(r'(?i)(?:heroku[._-]?api[._-]?key|heroku[._-]?token|HEROKU[._-]?API[._-]?KEY|HEROKU[._-]?TOKEN)\s*[:=]'),
    re.compile(r'(?i)export\s+HEROKU[._-]?API[._-]?KEY\s*='),
    re.compile(r'(?i)HEROKU[._-]?API[._-]?KEY\s*='),
]


def detect_secrets(path: str, content: str) -> list[Finding]:
    """Scan *content* for secrets and return redacted findings.

    Every secret-looking span on a line is redacted in the emitted snippet,
    including multiple secrets on one line and quoted/assigned values.
    """

    findings: list[Finding] = []

    # Handle multiline patterns first (YAML block scalars)
    # Build a map of line_number -> list of (start_in_line, end_in_line) spans to redact
    yaml_block_spans_by_line: dict[int, list[tuple[int, int]]] = {}
    yaml_block_findings: list[tuple[int, Finding]] = []  # (lineno, finding)

    lines = content.splitlines(keepends=True)  # Keep newlines to calculate positions
    line_starts = [0]
    for line in lines[:-1]:
        line_starts.append(line_starts[-1] + len(line))

    for match in GENERIC_SECRET_YAML_BLOCK.finditer(content):
        value = match.group("value")
        if is_placeholder(value):
            continue
        value_start, value_end = match.span("value")
        # Find which lines this spans
        start_lineno = 1
        for i, ls in enumerate(line_starts):
            if ls <= value_start:
                start_lineno = i + 1
            else:
                break

        # Calculate the span within the first line
        line_start_pos = line_starts[start_lineno - 1]
        span_start_in_line = value_start - line_start_pos

        # The value spans to value_end - find the end line
        end_lineno = 1
        for i, ls in enumerate(line_starts):
            if ls <= value_end:
                end_lineno = i + 1
            else:
                break

        if start_lineno == end_lineno:
            # Single line
            span_end_in_line = value_end - line_start_pos
            yaml_block_spans_by_line.setdefault(start_lineno, []).append(
                (span_start_in_line, span_end_in_line)
            )
        else:
            # Multi-line: first line from span_start to end, middle lines entirely, last line from start to span_end
            yaml_block_spans_by_line.setdefault(start_lineno, []).append(
                (span_start_in_line, len(lines[start_lineno - 1]))
            )
            for ln in range(start_lineno + 1, end_lineno):
                yaml_block_spans_by_line.setdefault(ln, []).append(
                    (0, len(lines[ln - 1]))
                )
            last_line_start = line_starts[end_lineno - 1]
            span_end_in_line = value_end - last_line_start
            yaml_block_spans_by_line.setdefault(end_lineno, []).append(
                (0, span_end_in_line)
            )

        # Create finding at the start line
        yaml_block_findings.append((start_lineno, Finding(
            rule_id="generic-secret",
            severity="medium",
            path=path,
            line=start_lineno,
            snippet="",  # Will be filled after redaction
            fix="Move the secret to an environment variable or secrets manager",
        )))

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

        # Require an AWS secret/access-key assignment before treating a
        # 40-character Base64-like value as a high-confidence AWS credential.
        if _AWS_SECRET_CONTEXT.search(line):
            for match in AWS_SECRET_ACCESS_KEY.finditer(line):
                token_spans.append((match.start(), match.end()))
                line_findings.append(Finding(
                    rule_id="aws-secret-access-key",
                    severity="high",
                    path=path,
                    line=lineno,
                    snippet="",
                    fix="Remove the AWS secret access key and rotate it in AWS IAM Console",
                ))

        # The service_account type marker is metadata. Require a private_key
        # field somewhere in the same JSON document before reporting a key.
        if (
            GCP_SERVICE_ACCOUNT.search(line)
            and re.search(r"""["']private_key["']\s*:\s*["']""", content, re.IGNORECASE)
            and PEM_PRIVATE_KEY.search(content)
        ):
            for match in GCP_SERVICE_ACCOUNT.finditer(line):
                token_spans.append((match.start(), match.end()))
                line_findings.append(Finding(
                    rule_id="gcp-service-account",
                    severity="high",
                    path=path,
                    line=lineno,
                    snippet="",
                    fix="Remove the GCP service account key and rotate it in Google Cloud Console",
                ))

        generic_spans: list[tuple[int, int]] = []

        # Generic secret with quoted/unquoted values
        for match in GENERIC_SECRET.finditer(line):
            # Get the value span (either quoted or unquoted)
            if match.group("value") is not None:
                value_start, value_end = match.span("value")
                value = match.group("value")
            elif match.group("unquoted_value") is not None:
                value_start, value_end = match.span("unquoted_value")
                value = match.group("unquoted_value")
            else:
                continue
            # Do not double-report a value already covered by a token rule.
            if any(start <= value_start and value_end <= end
                   for start, end in token_spans):
                continue
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

        # Generic secret for YAML multiline block scalars
        for match in GENERIC_SECRET_YAML_BLOCK.finditer(line):
            # This pattern matches across lines, so we need to handle it differently
            # The match starts at the key and includes the block value
            value = match.group("value")
            if is_placeholder(value):
                continue
            # Redact the entire value block
            value_start, value_end = match.span("value")
            generic_spans.append((value_start, value_end))
            line_findings.append(Finding(
                rule_id="generic-secret",
                severity="medium",
                path=path,
                line=lineno,
                snippet="",
                fix="Move the secret to an environment variable or secrets manager",
            ))

        # Generic secret for export statements
        for match in GENERIC_SECRET_EXPORT.finditer(line):
            value_start, value_end = match.span("value")
            value = match.group("value")
            if any(start <= value_start and value_end <= end
                   for start, end in token_spans):
                continue
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

        # High-entropy fallback detection (scan all independent values on the line)
        entropy_spans: list[tuple[int, int]] = []
        # Check for high-entropy base64 strings (always scan, not just when no other findings)
        for match in HIGH_ENTROPY_BASE64.finditer(line):
            value = match.group()
            if is_placeholder(value) or is_likely_non_secret(value):
                continue
            # Don't double-report values already covered by token patterns
            if any(start <= match.start() and match.end() <= end for start, end in token_spans):
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
            # Don't double-report values already covered by token patterns
            if any(start <= match.start() and match.end() <= end for start, end in token_spans):
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

        # Heroku API Key with context awareness
        for match in HEROKU_API_KEY.finditer(line):
            value = match.group()
            if is_placeholder(value):
                continue
            # Heroku API keys ARE UUIDs, so skip is_likely_non_secret check
            # Check for Heroku-specific context
            if not any(ctx.search(line) for ctx in _HEROKU_CONTEXT_PATTERNS):
                continue
            entropy_spans.append((match.start(), match.end()))
            line_findings.append(Finding(
                rule_id="heroku-api-key",
                severity="high",
                path=path,
                line=lineno,
                snippet="",
                fix="Remove the Heroku API key and rotate it in Heroku Dashboard",
            ))

        # Get YAML block spans for this line
        yaml_spans_for_line = yaml_block_spans_by_line.get(lineno, [])

        if not line_findings and not yaml_spans_for_line:
            continue

        # Combine all spans for redaction
        all_spans = token_spans + generic_spans + entropy_spans
        all_spans.extend(yaml_spans_for_line)

        snippet = _redact_spans(line, all_spans)
        # Additional pass: redact private key content that might not be caught by spans
        snippet = _redact_private_key_content(snippet)

        # Apply snippet to line findings
        for finding in line_findings:
            findings.append(replace(finding, snippet=snippet))

        # Apply snippet to YAML block findings for this line
        for yaml_lineno, finding in yaml_block_findings:
            if yaml_lineno == lineno:
                findings.append(replace(finding, snippet=snippet))

    return findings