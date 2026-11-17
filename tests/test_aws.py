"""Tests for the AWS integrations that need no AWS account: pure conversions and fallbacks."""
import importlib.util
import zipfile
from pathlib import Path

import pytest
import yaml

from pipeline import ai_triage, aws_integrations as aws, scanners
from pipeline.models import make_finding

ROOT = Path(__file__).resolve().parent.parent


def test_parse_requirements_keeps_only_exact_pins():
    text = "Flask==2.0.1\n# comment\nrequests>=2.0\npyyaml == 5.3.1  # old\n\n"
    assert aws.parse_requirements(text) == [("flask", "2.0.1"), ("pyyaml", "5.3.1")]


def test_sbom_has_a_purl_and_ref_per_component():
    sbom = aws.build_sbom([("flask", "2.0.1"), ("jinja2", "2.11.2")])
    assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.5"
    assert [c["purl"] for c in sbom["components"]] == ["pkg:pypi/flask@2.0.1", "pkg:pypi/jinja2@2.11.2"]
    assert len({c["bom-ref"] for c in sbom["components"]}) == 2


def test_inspector_answer_becomes_one_finding_per_package():
    answer = {
        "components": [
            {"bom-ref": "comp-1", "name": "flask", "version": "2.0.1"},
            {"bom-ref": "comp-2", "name": "jinja2", "version": "2.11.2"},
            {"bom-ref": "comp-3", "name": "clean", "version": "1.0"},
        ],
        "vulnerabilities": [
            {"id": "CVE-1", "ratings": [{"severity": "medium"}], "affects": [{"ref": "comp-1"}]},
            {"id": "CVE-2", "ratings": [{"severity": "critical"}], "affects": [{"ref": "comp-1"}]},
            {"id": "CVE-3", "ratings": [], "affects": [{"ref": "comp-2"}]},
            {"id": "CVE-4", "ratings": [{"severity": "high"}], "affects": [{"ref": "unknown-ref"}]},
        ],
    }
    found = aws.findings_from_inspector(answer, "app/requirements.txt")
    assert [f.title for f in found] == [
        "flask 2.0.1: 2 known vulnerabilities",
        "jinja2 2.11.2: 1 known vulnerability",
    ]
    assert found[0].severity == "CRITICAL"   # the worst rating wins
    assert found[1].severity == "MEDIUM"     # no rating supplied -> stated default
    assert all(f.category == "sca" and f.tool == "amazon-inspector" for f in found)


def test_asff_document_has_every_required_field():
    finding = make_finding(tool="bandit", category="sast", rule_id="B608", title="SQL injection",
                           severity="MEDIUM", file="app/app.py", line=36, detail="d" * 2000, cwe="CWE-89")
    doc = aws.to_asff(finding, "P0", "Use a parameterised query.", target="app",
                      account="111122223333", region="ap-south-1", now="2026-12-15T10:00:00Z")
    required = {"AwsAccountId", "CreatedAt", "Description", "GeneratorId", "Id", "ProductArn",
                "Resources", "SchemaVersion", "Severity", "Title", "Types", "UpdatedAt"}
    assert required <= doc.keys()
    assert doc["ProductArn"] == "arn:aws:securityhub:ap-south-1:111122223333:product/111122223333/default"
    assert doc["CreatedAt"] == doc["UpdatedAt"]
    assert doc["Severity"] == {"Label": "MEDIUM"} and doc["Title"].startswith("[P0]")
    assert len(doc["Description"]) <= 1024


def test_inspector_engine_falls_back_to_pip_audit_snapshot(monkeypatch):
    def unavailable(*_args, **_kwargs):
        raise aws.AwsUnavailable("no credentials")

    monkeypatch.setattr(aws, "inspector_sca", unavailable)
    monkeypatch.setattr(scanners, "_pip_audit_live",
                        lambda _req: (_ for _ in ()).throw(scanners.ScannerError("offline")))
    findings, note = scanners.scan_sca(ROOT / "app", engine="inspector")
    assert findings and "fell back to pip-audit" in note and "no credentials" in note


def test_bedrock_mode_without_region_falls_back_to_rules(monkeypatch, tmp_path):
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    finding = make_finding(tool="t", category="sast", rule_id="B608", title="x", severity="MEDIUM",
                           file="app/app.py", line=36, detail="d", cwe="CWE-89")
    report, note = ai_triage.triage(ROOT, [finding], "bedrock", tmp_path / "cache.json")
    assert report.source == "rules" and "AWS_REGION" in note
    assert not (tmp_path / "cache.json").exists()


def test_release_zip_uses_forward_slashes_and_names_the_target(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location("package", ROOT / "aws" / "package.py")
    package = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(package)
    assert package.main(["package.py", "nonsense"]) == 2
    assert package.main(["package.py", "app_secure"]) == 0
    with zipfile.ZipFile(ROOT / "aws" / "dist" / "release.zip") as bundle:
        names = bundle.namelist()
        assert bundle.read("TARGET").decode().strip() == "app_secure"
    assert "pipeline/run.py" in names and "app_secure/Dockerfile" in names and "policy.yaml" in names
    assert not any("\\" in n or ".venv" in n or n.startswith("out/") for n in names)


class _CfnLoader(yaml.SafeLoader):
    """Loads a CloudFormation template, treating !Ref / !Sub / !GetAtt tags as plain values."""


_CfnLoader.add_multi_constructor(
    "!", lambda loader, _suffix, node: (
        loader.construct_scalar(node) if isinstance(node, yaml.ScalarNode)
        else loader.construct_sequence(node) if isinstance(node, yaml.SequenceNode)
        else loader.construct_mapping(node)
    ),
)


@pytest.fixture(scope="module")
def template():
    return yaml.load((ROOT / "aws" / "devsecops.yaml").read_text(encoding="utf-8"), Loader=_CfnLoader)


def test_pipeline_puts_a_human_between_staging_and_production(template):
    stages = [s["Name"] for s in template["Resources"]["Pipeline"]["Properties"]["Stages"]]
    assert stages == ["Source", "SecurityGate", "Staging", "HumanApproval", "Production"]
    approval = template["Resources"]["Pipeline"]["Properties"]["Stages"][3]["Actions"][0]
    assert approval["ActionTypeId"]["Category"] == "Approval"


def test_embedded_buildspecs_are_valid_yaml(template):
    for name in ("ScanProject", "StagingProject", "PromoteProject"):
        spec = yaml.safe_load(template["Resources"][name]["Properties"]["Source"]["BuildSpec"])
        assert spec["version"] == 0.2 and "build" in spec["phases"]


def test_responder_lambda_formats_both_sample_events(template, monkeypatch):
    import json
    import sys
    import types

    sent = []
    fake_boto3 = types.SimpleNamespace(
        client=lambda _name: types.SimpleNamespace(publish=lambda **kwargs: sent.append(kwargs)))
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
    monkeypatch.setenv("TOPIC_ARN", "arn:aws:sns:ap-south-1:111122223333:t")
    monkeypatch.setenv("PIPELINE_NAME", "shoplite-devsecops")
    namespace: dict = {}
    exec(template["Resources"]["FindingResponder"]["Properties"]["Code"]["ZipFile"], namespace)  # noqa: S102

    for name in ("inspector-finding.json", "guardduty-finding.json"):
        event = json.loads((ROOT / "aws" / "sample-events" / name).read_text(encoding="utf-8"))
        assert namespace["handler"](event, None)["notified"] is True
    assert sent[0]["Subject"].startswith("New vulnerability") and "CRITICAL" in sent[0]["Message"]
    assert sent[1]["Subject"].startswith("Threat detected") and len(sent[1]["Subject"]) <= 100
    assert all("Nothing in production was changed automatically." in s["Message"] for s in sent)
