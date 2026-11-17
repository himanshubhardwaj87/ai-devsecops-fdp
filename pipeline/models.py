"""Shared, immutable data shapes passed between pipeline stages."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
PRIORITIES = ("P0", "P1", "P2", "P3")
CATEGORIES = ("secret", "sast", "sca", "iac")


@dataclass(frozen=True)
class Finding:
    """One normalised result from any scanner."""

    id: str
    tool: str
    category: str
    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    detail: str
    cwe: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class TriageItem:
    """The triage verdict for one finding."""

    finding_id: str
    priority: str
    exploitability: str
    rationale: str
    fix: str
    likely_false_positive: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class TriageReport:
    source: str
    executive_summary: str
    items: tuple[TriageItem, ...]

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "executive_summary": self.executive_summary,
            "items": [item.to_dict() for item in self.items],
        }


def make_finding(
    *,
    tool: str,
    category: str,
    rule_id: str,
    title: str,
    severity: str,
    file: str,
    line: int,
    detail: str,
    cwe: str = "",
) -> Finding:
    """Build a Finding with a short stable id, validating the enums."""
    if severity not in SEVERITIES:
        raise ValueError(f"unknown severity {severity!r} from {tool}")
    if category not in CATEGORIES:
        raise ValueError(f"unknown category {category!r} from {tool}")
    digest = hashlib.sha256(f"{tool}|{rule_id}|{file}|{line}".encode()).hexdigest()[:6]
    return Finding(
        id=f"{category.upper()}-{digest}",
        tool=tool,
        category=category,
        rule_id=rule_id,
        title=title,
        severity=severity,
        file=file,
        line=line,
        detail=detail,
        cwe=cwe,
    )
