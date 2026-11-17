"""Optional AWS integrations, used when the pipeline runs inside AWS CodeBuild.

inspector_sca        : ask Amazon Inspector which pinned dependencies have known vulnerabilities
export_to_security_hub : publish findings to AWS Security Hub as the compliance system of record

boto3 is imported lazily so the local demo runs without it. Every function that calls
AWS raises AwsUnavailable on failure; callers decide whether to fall back.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding, TriageReport, make_finding

PIN = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+!]+)\s*(?:#.*)?$")
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
ASFF_SCHEMA = "2018-10-08"
ASFF_BATCH_LIMIT = 100
MAX_ADVISORIES_SHOWN = 5


class AwsUnavailable(RuntimeError):
    """An AWS call could not be made or returned something unusable."""


# --------------------------------------------------------------------------- Inspector


def parse_requirements(text: str) -> list[tuple[str, str]]:
    """Return (name, version) for every exactly pinned line; other lines are ignored."""
    pins = []
    for line in text.splitlines():
        match = PIN.match(line)
        if match:
            pins.append((match.group(1).lower(), match.group(2)))
    return pins


def build_sbom(pins: list[tuple[str, str]]) -> dict:
    """A minimal CycloneDX 1.5 bill of materials for a list of PyPI pins."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {
                "bom-ref": f"comp-{index}",
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}@{version}",
            }
            for index, (name, version) in enumerate(pins, start=1)
        ],
    }


def _worst(severities: list[str]) -> str:
    known = [s for s in severities if s in SEVERITY_ORDER]
    return min(known, key=SEVERITY_ORDER.index) if known else "MEDIUM"


def findings_from_inspector(sbom: dict, requirements_file: str) -> list[Finding]:
    """Turn Inspector's CycloneDX answer into one Finding per vulnerable package."""
    components = {c.get("bom-ref"): c for c in sbom.get("components", [])}
    by_component: dict[str, list[dict]] = {}
    for vuln in sbom.get("vulnerabilities", []):
        for affected in vuln.get("affects", []):
            by_component.setdefault(affected.get("ref"), []).append(vuln)

    findings = []
    for ref, vulns in by_component.items():
        component = components.get(ref)
        if component is None:
            continue
        ids = sorted({v.get("id", "unknown") for v in vulns})
        severity = _worst([
            str(rating.get("severity", "")).upper()
            for v in vulns for rating in v.get("ratings", [])
        ])
        shown = ", ".join(ids[:MAX_ADVISORIES_SHOWN]) + (
            f" and {len(ids) - MAX_ADVISORIES_SHOWN} more" if len(ids) > MAX_ADVISORIES_SHOWN else ""
        )
        plural = "ies" if len(ids) > 1 else "y"
        name, version = component.get("name", "?"), component.get("version", "?")
        findings.append(
            make_finding(
                tool="amazon-inspector",
                category="sca",
                rule_id=f"SCA-{name}",
                title=f"{name} {version}: {len(ids)} known vulnerabilit{plural}",
                severity=severity,
                file=requirements_file,
                line=0,
                detail=f"Advisories: {shown}. Upgrade to a release that fixes all of them.",
                cwe="CWE-1395",
            )
        )
    return sorted(findings, key=lambda f: f.title)


def inspector_sca(requirements: Path, requirements_file: str) -> list[Finding]:
    pins = parse_requirements(requirements.read_text(encoding="utf-8"))
    if not pins:
        return []
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError as exc:
        raise AwsUnavailable(f"boto3 is not installed: {exc}") from exc
    try:
        response = boto3.client("inspector-scan").scan_sbom(
            sbom=build_sbom(pins), outputFormat="CYCLONE_DX_1_5"
        )
    except (BotoCoreError, ClientError) as exc:
        raise AwsUnavailable(f"Amazon Inspector scan failed: {exc}") from exc
    sbom = response.get("sbom")
    if not isinstance(sbom, dict):
        raise AwsUnavailable("Amazon Inspector returned no SBOM document")
    return findings_from_inspector(sbom, requirements_file)


# --------------------------------------------------------------------------- Security Hub

ASFF_TYPES = {
    "sca": "Software and Configuration Checks/Vulnerabilities/CVE",
    "sast": "Software and Configuration Checks/Vulnerabilities",
    "secret": "Sensitive Data Identifications/Passwords",
    "iac": "Software and Configuration Checks/Industry and Regulatory Standards",
}


def to_asff(finding: Finding, priority: str, fix: str, *, target: str, account: str,
            region: str, now: str) -> dict:
    """One finding in AWS Security Finding Format. Pure, so it can be unit tested."""
    severity = {"Label": finding.severity}
    types = [ASFF_TYPES[finding.category]]
    return {
        "SchemaVersion": ASFF_SCHEMA,
        "Id": f"shoplite-devsecops/{target}/{finding.id}",
        "ProductArn": f"arn:aws:securityhub:{region}:{account}:product/{account}/default",
        "GeneratorId": f"shoplite-devsecops/{finding.tool}/{finding.rule_id}",
        "AwsAccountId": account,
        "CreatedAt": now,
        "UpdatedAt": now,
        "Types": types,
        "Severity": severity,
        "FindingProviderFields": {"Severity": severity, "Types": types},
        "Title": f"[{priority}] {finding.title}"[:256],
        "Description": finding.detail[:1024],
        "Remediation": {"Recommendation": {"Text": fix[:512]}},
        "Resources": [{
            "Type": "Other",
            "Id": f"shoplite-devsecops/{target}/{finding.file}",
            "Partition": "aws",
            "Region": region,
        }],
        "UserDefinedFields": {"triagePriority": priority, "cwe": finding.cwe or "n/a"},
    }


def export_to_security_hub(findings: list[Finding], triage: TriageReport, target: str) -> int:
    """Import findings into Security Hub. Returns how many were accepted."""
    if not findings:
        return 0
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError as exc:
        raise AwsUnavailable(f"boto3 is not installed: {exc}") from exc
    items = {item.finding_id: item for item in triage.items}
    try:
        session = boto3.session.Session()
        region = session.region_name
        if not region:
            raise AwsUnavailable("no AWS region configured")
        account = session.client("sts").get_caller_identity()["Account"]
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        documents = [
            to_asff(f, items[f.id].priority, items[f.id].fix, target=target,
                    account=account, region=region, now=now)
            for f in findings
        ]
        client = session.client("securityhub")
        accepted = 0
        for start in range(0, len(documents), ASFF_BATCH_LIMIT):
            result = client.batch_import_findings(Findings=documents[start:start + ASFF_BATCH_LIMIT])
            accepted += result.get("SuccessCount", 0)
            if result.get("FailedCount"):
                first = result["FailedFindings"][0]
                raise AwsUnavailable(
                    f"Security Hub rejected {result['FailedCount']} finding(s): {first.get('ErrorMessage')}"
                )
    except (BotoCoreError, ClientError) as exc:
        raise AwsUnavailable(f"Security Hub import failed: {exc}") from exc
    return accepted
