"""Configuration constants and validation for RepoGuard."""

from __future__ import annotations

import math
from dataclasses import dataclass, field

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

DEFAULT_MAX_SIZE_MB = 5.0
DEFAULT_FAIL_ON = "high"

# Defensive upper bound for reading file content. Files larger than this still
# receive size/filename findings; only content scanning is skipped.
READ_LIMIT_BYTES = 10 * 1024 * 1024  # 10 MiB

# A --max-size-mb value above this is almost certainly a mistake.
MAX_MAX_SIZE_MB = 100_000.0  # ~100 GiB


def validate_max_size_mb(value: object) -> float:
    """Return a finite, positive, sane maximum file size in MiB.

    Raises ``ValueError`` for non-numbers, NaN, infinities, zero, negatives,
    and absurdly large values. The CLI maps this to exit code 2.
    """

    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError("--max-size-mb must be a number") from exc
    if not math.isfinite(number):
        raise ValueError("--max-size-mb must be a finite number")
    if number <= 0:
        raise ValueError("--max-size-mb must be positive")
    if number > MAX_MAX_SIZE_MB:
        raise ValueError(
            f"--max-size-mb must not exceed {MAX_MAX_SIZE_MB:g} MiB"
        )
    return number


@dataclass
class Config:
    """Backward-compatible scan configuration used by the CLI."""

    paths: tuple[str, ...] = field(default_factory=lambda: (".",))
    staged: bool = False
    max_size_mb: float = DEFAULT_MAX_SIZE_MB
    fail_on: str = DEFAULT_FAIL_ON
    fmt: str = "text"
    ignore_file: str = ".repoguardignore"

    def __post_init__(self) -> None:
        if self.fail_on not in SEVERITY_ORDER:
            raise ValueError(
                f"--fail-on must be one of {', '.join(sorted(SEVERITY_ORDER))}"
            )
        if self.fmt not in {"text", "json"}:
            raise ValueError("--format must be text or json")
        self.max_size_mb = validate_max_size_mb(self.max_size_mb)

    @property
    def fail_on_level(self) -> int:
        return SEVERITY_ORDER[self.fail_on]

    @property
    def max_size_bytes(self) -> int:
        return int(self.max_size_mb * 1024 * 1024)