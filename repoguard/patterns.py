"""Regex patterns for secret detection.

Centralized pattern definitions for maintainability and testability.
"""

from __future__ import annotations

import re


# --- High-confidence token patterns -----------------------------------------
# Boundaries keep these from matching inside longer identifiers.

GITHUB_CLASSIC = re.compile(r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36,}")
GITHUB_PAT = re.compile(r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{20,}")
AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
OPENAI_PROJ = re.compile(r"(?<![A-Za-z0-9_])sk-proj-[A-Za-z0-9_-]{20,}")
OPENAI_SK = re.compile(r"(?<![A-Za-z0-9_])sk-[A-Za-z0-9]{20,}\b")
PEM_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
GOOGLE_API_KEY = re.compile(r"(?<![A-Za-z0-9_])AIzaSy[A-Za-z0-9_-]{33}\b")
STRIPE_SECRET_KEY = re.compile(r"(?<![A-Za-z0-9_])sk_(?:test|live)_[0-9a-zA-Z]{24,}\b")
SLACK_WEBHOOK = re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}\b")

# Database connection strings (postgresql, mysql, mongodb, redis, mssql, oracle)
DB_CONNECTION_STRING = re.compile(
    r"""(?xi)
    (?:postgresql|postgres|mysql|mongodb|redis|mssql|sqlserver|oracle)
    ://
    [^/:\s]*                # optional user
    :
    [^/:\s]{8,}             # password (at least 8 chars)
    @
    [^/:\s]+                # host
    (?::\d+)?               # optional port
    /[^\s]*                 # database/path
    """
)

# --- Cloud provider keys ------------------------------------------------------

# Azure Storage Account key (base64, 88 chars ending with ==)
AZURE_STORAGE_KEY = re.compile(
    r"(?<![A-Za-z0-9_])[A-Za-z0-9+/]{86}==(?![A-Za-z0-9_])"
)

# AWS Secret Access Key (40 chars, base64-like)
# Uses negative lookahead instead of \b to handle keys ending in /, +, =
AWS_SECRET_ACCESS_KEY = re.compile(
    r"(?<![A-Za-z0-9_])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"
)

# GCP Service Account JSON - detect by structure
GCP_SERVICE_ACCOUNT = re.compile(
    r'"type"\s*:\s*"service_account"'
)

# DigitalOcean Personal Access Token (dop_v1_ prefix, 64 chars total after prefix)
DIGITALOCEAN_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])dop_v1_[A-Za-z0-9]{64}\b"
)

# Heroku API Key (UUID v4 format) - match UUIDs, filter by context in detector
HEROKU_API_KEY = re.compile(
    r"(?<![A-Za-z0-9_])[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b"
)

# --- Generic secret assignments ---------------------------------------------
# Requires a recognized key, an assignment operator, and a value that is long
# enough to be interesting and does not look like source code.
# Supports:
#   - Unquoted keys: password = value
#   - Quoted keys in JSON: "password": "value"
#   - Quoted keys in YAML: api_key: "value"
#   - YAML multiline block scalars: password: |\\n  value
#   - Environment exports: export API_TOKEN=value
# Values may contain spaces when quoted.
GENERIC_SECRET = re.compile(
    r"""
    (?<![A-Za-z0-9_.-])
    (?P<key_quote>["']?)
    (?P<key>
        password|passwd|pwd|secret|token|api[._]?key|apikey|
        access[._]?token|auth[._]?token|refresh[._]?token|
        client[._]?secret|private[._]?key|secret[._]?key|
        signing[._]?key|encryption[._]?key|db[._]?password|
        database[._]?password
    )
    (?P=key_quote)
    \s*[:=]\s*
    (?:
        # Quoted value (single or double quotes) - can contain spaces
        (?P<quote>["'])
        (?P<value>[^"']{12,})
        (?P=quote)
      |
        # Unquoted value - no spaces, no code-like chars
        (?P<unquoted_value>[^\s"';,()\[\]{}<>]{12,})
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Generic secret for YAML multiline block scalars (key: |\\n  value)
GENERIC_SECRET_YAML_BLOCK = re.compile(
    r"""
    (?<![A-Za-z0-9_.-])
    (?P<key_quote>["']?)
    (?P<key>
        password|passwd|pwd|secret|token|api[._]?key|apikey|
        access[._]?token|auth[._]?token|refresh[._]?token|
        client[._]?secret|private[._]?key|secret[._]?key|
        signing[._]?key|encryption[._]?key|db[._]?password|
        database[._]?password
    )
    (?P=key_quote)
    \s*:\s*\|\s*\n
    (?P<value>
        (?:\s{2,}[^\n]+\n?)+
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Generic secret for export statements: export TOKEN=value
GENERIC_SECRET_EXPORT = re.compile(
    r"""
    \bexport\s+
    (?P<key>
        PASSWORD|PASSWD|PWD|SECRET|TOKEN|API[._]?KEY|APIKEY|
        ACCESS[._]?TOKEN|AUTH[._]?TOKEN|REFRESH[._]?TOKEN|
        CLIENT[._]?SECRET|PRIVATE[._]?KEY|SECRET[._]?KEY|
        SIGNING[._]?KEY|ENCRYPTION[._]?KEY|DB[._]?PASSWORD|
        DATABASE[._]?PASSWORD
    )
    \s*=\s*
    (?P<quote>["']?)
    (?P<value>[^"'\s]{12,})
    (?P=quote)
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Placeholder / environment-variable hints that must be suppressed.
PLACEHOLDER_WORDS = frozenset({
    "your_api_key", "yourapikey", "api_key", "apikey",
    "your_secret", "yoursecret", "yourpassword", "your-password",
    "example", "changeme", "change_me", "dummy", "test", "testing",
    "placeholder", "insert_here", "replace_me", "todo", "fixme",
    "none", "null", "nil", "undefined", "true", "false",
})
PLACEHOLDER_SUBSTRINGS = (
    "example", "changeme", "change_me", "dummy", "placeholder",
    "replace_me", "insert_here", "your_", "-your", "todo", "fixme",
)
ANGLE_BRACKET = re.compile(r"<[^>]*>")
ENV_REF = re.compile(
    r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$|^%[A-Za-z_][A-Za-z0-9_%]*%$"
)
CODE_LIKE = re.compile(r"[()\[\]{}<>]")


# High-entropy fallback detection for strings without recognizable keys
# Matches base64-like strings (32+ chars) or hex strings (64+ chars) with high entropy
HIGH_ENTROPY_BASE64 = re.compile(
    r"(?<![A-Za-z0-9_])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9_])"
)
HIGH_ENTROPY_HEX = re.compile(
    r"(?<![A-Za-z0-9_])[a-f0-9]{64,}(?![A-Za-z0-9_])"
)

# Known non-secret high-entropy patterns to exclude
UUID_PATTERN = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")
HASH_PATTERN = re.compile(r"^[a-f0-9]{32,}$")  # Common hash lengths


__all__ = [
    # Token patterns
    "GITHUB_CLASSIC",
    "GITHUB_PAT",
    "AWS_ACCESS_KEY",
    "OPENAI_PROJ",
    "OPENAI_SK",
    "PEM_PRIVATE_KEY",
    "GOOGLE_API_KEY",
    "STRIPE_SECRET_KEY",
    "SLACK_WEBHOOK",
    "DB_CONNECTION_STRING",
    "AZURE_STORAGE_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "GCP_SERVICE_ACCOUNT",
    "DIGITALOCEAN_TOKEN",
    "HEROKU_API_KEY",
    # Generic
    "GENERIC_SECRET",
    "GENERIC_SECRET_YAML_BLOCK",
    "GENERIC_SECRET_EXPORT",
    "PLACEHOLDER_WORDS",
    "PLACEHOLDER_SUBSTRINGS",
    "ANGLE_BRACKET",
    "ENV_REF",
    "CODE_LIKE",
    # High-entropy
    "HIGH_ENTROPY_BASE64",
    "HIGH_ENTROPY_HEX",
    "UUID_PATTERN",
    "HASH_PATTERN",
]