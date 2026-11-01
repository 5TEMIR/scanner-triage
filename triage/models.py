from __future__ import annotations

import hashlib
from dataclasses import dataclass

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")

_RANK = {name: index for index, name in enumerate(SEVERITIES)}

_ALIASES = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "ERROR": "HIGH",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "WARNING": "MEDIUM",
    "LOW": "LOW",
    "NOTE": "LOW",
    "INFO": "LOW",
    "UNKNOWN": "UNKNOWN",
}


def normalize_severity(value: str | None) -> str:
    """Bring scanner-specific severity labels to a single scale."""
    if not value:
        return "UNKNOWN"
    return _ALIASES.get(str(value).strip().upper(), "UNKNOWN")


@dataclass(frozen=True, slots=True)
class Finding:
    """A single normalized scanner result."""

    source: str
    rule_id: str
    title: str
    severity: str
    target: str
    line: int | None = None
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    description: str = ""

    def __post_init__(self) -> None:
        if not self.rule_id:
            raise ValueError("rule_id must not be empty")
        if not self.target:
            raise ValueError("target must not be empty")
        object.__setattr__(self, "severity", normalize_severity(self.severity))

    @property
    def rank(self) -> int:
        return _RANK[self.severity]

    @property
    def fingerprint(self) -> str:
        """Stable identifier used to deduplicate repeat findings between runs."""
        parts = [
            self.source,
            self.rule_id,
            self.target,
            str(self.line or 0),
            self.package or "",
            self.installed_version or "",
        ]
        digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
        return digest[:16]

    def is_at_least(self, threshold: str) -> bool:
        return self.rank <= _RANK[normalize_severity(threshold)]


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Drop duplicates, keeping the first occurrence."""
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        unique.append(finding)
    return unique


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.rank, f.source, f.rule_id, f.target))
