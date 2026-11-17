"""Stage 5 - the release gate: policy as code, read from policy.yaml."""
from __future__ import annotations

from pathlib import Path

import yaml

from .models import Finding, TriageReport

DEFAULT_POLICY = {
    "max_allowed": {"P0": 0, "P1": 0},
    "block_on_any_secret": True,
    "max_failed_controls": 0,
}


class PolicyError(ValueError):
    """policy.yaml is missing required structure."""


def load_policy(path: Path) -> dict:
    if not path.exists():
        return dict(DEFAULT_POLICY)
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path.name} is not valid YAML: {exc}") from exc
    if not isinstance(loaded, dict):
        raise PolicyError(f"{path.name} must be a mapping")
    policy = {**DEFAULT_POLICY, **loaded}
    limits = policy["max_allowed"]
    if not isinstance(limits, dict) or any(not isinstance(v, int) or v < 0 for v in limits.values()):
        raise PolicyError("max_allowed must map priorities to non-negative integers")
    return policy


def decide(policy: dict, findings: list[Finding], triage: TriageReport, controls: list[dict]) -> dict:
    counts = {priority: 0 for priority in ("P0", "P1", "P2", "P3")}
    for item in triage.items:
        counts[item.priority] = counts.get(item.priority, 0) + 1

    violations = []
    for priority, limit in policy["max_allowed"].items():
        if counts.get(priority, 0) > limit:
            violations.append(f"{counts[priority]} {priority} finding(s); policy allows {limit}")
    secrets = sum(1 for finding in findings if finding.category == "secret")
    if policy["block_on_any_secret"] and secrets:
        violations.append(f"{secrets} hard-coded secret(s); policy allows none")
    failed = sum(1 for control in controls if control["status"] == "FAIL")
    if failed > policy["max_failed_controls"]:
        violations.append(f"{failed} compliance control(s) failing; policy allows {policy['max_failed_controls']}")

    return {"passed": not violations, "violations": violations, "priority_counts": counts}
