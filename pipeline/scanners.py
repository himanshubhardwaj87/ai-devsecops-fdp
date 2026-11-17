"""Stage 1 - the scanners. Each returns normalised Finding objects.

secrets : regex rules over the source tree
sast    : Bandit (static analysis of the Python code)
sca     : pip-audit (known CVEs in pinned dependencies)
iac     : policy checks on the Dockerfile and Kubernetes manifest
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

from .models import Finding, make_finding

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
TEXT_SUFFIXES = {".py", ".txt", ".yaml", ".yml", ".env", ".json", ".cfg", ".ini", ""}
SCANNER_TIMEOUT_SECONDS = 180
MAX_ADVISORIES_SHOWN = 5


class ScannerError(RuntimeError):
    """A scanner could not produce a usable result."""


def _rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


# --------------------------------------------------------------------------- secrets

SECRET_RULES = (
    ("SEC001", "AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("SEC002", "Private key material", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "SEC003",
        "Hard-coded credential",
        re.compile(
            r"(?i)\b[\w\[\]\"']*(password|passwd|secret|api_key|apikey|token)[\w\[\]\"']*"
            r"\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']"
        ),
    ),
)


def redact(value: str) -> str:
    """Keep enough of a secret to recognise it, never enough to use it."""
    return value[:4] + "*" * max(len(value) - 4, 4)


def scan_secrets(target: Path) -> list[Finding]:
    findings = []
    for path in sorted(target.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(lines, start=1):
            for rule_id, title, pattern in SECRET_RULES:
                match = pattern.search(line)
                if match is None:
                    continue
                secret = match.group(match.lastindex or 0)
                findings.append(
                    make_finding(
                        tool="secret-scan",
                        category="secret",
                        rule_id=rule_id,
                        title=title,
                        severity="CRITICAL",
                        file=_rel(path),
                        line=number,
                        detail=f"Matched value {redact(secret)} (redacted)",
                        cwe="CWE-798",
                    )
                )
                break
    return findings


# --------------------------------------------------------------------------- SAST


def scan_sast(target: Path) -> list[Finding]:
    command = [sys.executable, "-m", "bandit", "-r", str(target), "-f", "json", "-q"]
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=SCANNER_TIMEOUT_SECONDS
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScannerError(f"bandit could not run: {exc}") from exc
    if proc.returncode not in (0, 1):
        raise ScannerError(f"bandit failed (exit {proc.returncode}): {proc.stderr.strip()}")
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ScannerError(f"bandit produced unreadable output: {exc}") from exc
    return [
        make_finding(
            tool="bandit",
            category="sast",
            rule_id=item["test_id"],
            title=item["issue_text"].split(". ")[0].rstrip("."),
            severity=item["issue_severity"].upper(),
            file=_rel(Path(item["filename"])),
            line=int(item["line_number"]),
            detail=f"{item['test_name']}: {item['issue_text']}",
            cwe=f"CWE-{item['issue_cwe']['id']}" if item.get("issue_cwe") else "",
        )
        for item in report.get("results", [])
    ]


# --------------------------------------------------------------------------- SCA


def _pip_audit_live(requirements: Path) -> dict:
    command = [
        sys.executable, "-m", "pip_audit",
        "-r", str(requirements),
        "--no-deps", "--disable-pip",
        "-f", "json", "--progress-spinner", "off",
    ]
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=SCANNER_TIMEOUT_SECONDS
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScannerError(f"pip-audit could not run: {exc}") from exc
    if proc.returncode not in (0, 1) or not proc.stdout.strip():
        raise ScannerError(f"pip-audit failed (exit {proc.returncode}): {proc.stderr.strip()[:300]}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ScannerError(f"pip-audit produced unreadable output: {exc}") from exc


def sca_snapshot_path(target: Path) -> Path:
    return SAMPLES / f"pip_audit_{target.name}.json"


def scan_sca(target: Path, offline: bool = False, engine: str = "pip-audit") -> tuple[list[Finding], str]:
    """Return (findings, note). The note says where the advisory data came from."""
    requirements = target / "requirements.txt"
    if not requirements.exists():
        return [], "no requirements.txt"
    if engine == "inspector" and not offline:
        from .aws_integrations import AwsUnavailable, inspector_sca

        try:
            return inspector_sca(requirements, _rel(requirements)), "Amazon Inspector vulnerability database"
        except AwsUnavailable as exc:
            findings, note = scan_sca(target, offline=False, engine="pip-audit")
            return findings, f"Amazon Inspector unavailable ({exc}); fell back to pip-audit, {note}"
    snapshot = sca_snapshot_path(target)
    note = "live advisory lookup"
    if offline:
        if not snapshot.exists():
            raise ScannerError(f"offline mode needs {snapshot.name}; run once online first")
        report = json.loads(snapshot.read_text(encoding="utf-8"))
        note = f"OFFLINE - cached advisory snapshot {snapshot.name}"
    else:
        try:
            report = _pip_audit_live(requirements)
        except ScannerError as exc:
            if not snapshot.exists():
                raise
            report = json.loads(snapshot.read_text(encoding="utf-8"))
            note = f"live lookup failed ({exc}); used cached snapshot {snapshot.name}"
        else:
            SAMPLES.mkdir(exist_ok=True)
            snapshot.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # One finding per package: the unit of work for a developer is "upgrade flask",
    # not forty separate advisory ids.
    findings = []
    for dep in report.get("dependencies", []):
        vulns = dep.get("vulns", [])
        if not vulns:
            continue
        ids = [
            next((a for a in vuln.get("aliases", []) if a.startswith("CVE-")), vuln["id"])
            for vuln in vulns
        ]
        shown = ", ".join(ids[:MAX_ADVISORIES_SHOWN]) + (
            f" and {len(ids) - MAX_ADVISORIES_SHOWN} more" if len(ids) > MAX_ADVISORIES_SHOWN else ""
        )
        plural = "ies" if len(ids) > 1 else "y"
        findings.append(
            make_finding(
                tool="pip-audit",
                category="sca",
                rule_id=f"SCA-{dep['name']}",
                title=f"{dep['name']} {dep['version']}: {len(ids)} known vulnerabilit{plural}",
                # pip-audit does not report severity; HIGH is this pipeline's default.
                severity="HIGH",
                file=_rel(requirements),
                line=0,
                detail=f"Advisories: {shown}. Upgrade to a release that fixes all of them.",
                cwe="CWE-1395",
            )
        )
    return findings, note


def deduplicate(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Drop a SAST hard-coded-password hit when the secret scanner flagged the same line."""
    secret_lines = {(f.file, f.line) for f in findings if f.category == "secret"}
    kept = [
        f for f in findings
        if not (f.category == "sast" and f.cwe == "CWE-259" and (f.file, f.line) in secret_lines)
    ]
    return kept, len(findings) - len(kept)


def mask_secrets(line: str) -> str:
    """Replace a line that matches any secret rule, so it can be shown or sent safely."""
    if any(pattern.search(line) for _, _, pattern in SECRET_RULES):
        return "<line withheld: contains a credential>"
    return line


# --------------------------------------------------------------------------- IaC


def _dockerfile_findings(path: Path) -> list[Finding]:
    lines = path.read_text(encoding="utf-8").splitlines()
    instructions = [(n, line.strip()) for n, line in enumerate(lines, start=1) if line.strip()]

    def issue(rule_id, title, severity, line, detail, cwe):
        return make_finding(
            tool="iac-policy", category="iac", rule_id=rule_id, title=title,
            severity=severity, file=_rel(path), line=line, detail=detail, cwe=cwe,
        )

    found = []
    for number, text in instructions:
        upper = text.upper()
        if upper.startswith("FROM ") and (":" not in text.split()[1] or text.split()[1].endswith(":latest")):
            found.append(issue("IAC001", "Base image is not pinned", "MEDIUM", number,
                               f"'{text}' pulls a moving tag; builds are not reproducible.", "CWE-1357"))
        if upper.startswith("ADD ") and re.search(r"https?://", text):
            found.append(issue("IAC002", "Remote file added without integrity check", "HIGH", number,
                               "ADD from a URL downloads unverified content into the image.", "CWE-494"))
    if not any(text.upper().startswith("USER ") for _, text in instructions):
        found.append(issue("IAC003", "Container runs as root", "HIGH", 0,
                           "No USER instruction; the process keeps root inside the container.", "CWE-250"))
    return found


def _manifest_findings(path: Path) -> list[Finding]:
    try:
        documents = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]
    except yaml.YAMLError as exc:
        raise ScannerError(f"{path.name} is not valid YAML: {exc}") from exc

    def issue(rule_id, title, severity, detail, cwe):
        return make_finding(
            tool="iac-policy", category="iac", rule_id=rule_id, title=title,
            severity=severity, file=_rel(path), line=0, detail=detail, cwe=cwe,
        )

    found = []
    for doc in documents:
        pod = doc.get("spec", {}).get("template", {}).get("spec", {})
        if pod.get("hostNetwork"):
            found.append(issue("IAC010", "Pod shares the host network", "HIGH",
                               "hostNetwork: true removes network isolation from the node.", "CWE-668"))
        for container in pod.get("containers", []):
            name = container.get("name", "?")
            context = container.get("securityContext", {})
            if context.get("privileged"):
                found.append(issue("IAC011", "Privileged container", "CRITICAL",
                                   f"Container '{name}' is privileged: a compromise is a node compromise.",
                                   "CWE-250"))
            if not context.get("runAsNonRoot"):
                found.append(issue("IAC012", "runAsNonRoot is not enforced", "MEDIUM",
                                   f"Container '{name}' may start as uid 0.", "CWE-250"))
            if not container.get("resources", {}).get("limits"):
                found.append(issue("IAC013", "No resource limits", "LOW",
                                   f"Container '{name}' can exhaust node CPU and memory.", "CWE-770"))
    return found


def scan_iac(target: Path) -> list[Finding]:
    findings = []
    dockerfile = target / "Dockerfile"
    if dockerfile.exists():
        findings.extend(_dockerfile_findings(dockerfile))
    for manifest in sorted(target.rglob("*.yaml")) + sorted(target.rglob("*.yml")):
        findings.extend(_manifest_findings(manifest))
    return findings
