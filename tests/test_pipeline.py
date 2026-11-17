from pathlib import Path

import pytest

from pipeline import ai_triage, anomaly, compliance, gate, report, scanners
from pipeline.models import TriageItem, TriageReport, make_finding

ROOT = Path(__file__).resolve().parent.parent


def finding(category="sast", cwe="CWE-89", rule_id="B608", severity="MEDIUM", line=10):
    return make_finding(tool="t", category=category, rule_id=rule_id, title="x",
                        severity=severity, file="app/app.py", line=line, detail="d", cwe=cwe)


# ---- models

def test_finding_id_is_stable_and_validated():
    assert finding().id == finding().id
    assert finding(line=11).id != finding().id
    with pytest.raises(ValueError):
        finding(severity="URGENT")


# ---- scanners

def test_secret_scan_finds_and_redacts():
    found = scanners.scan_secrets(ROOT / "app")
    assert {f.rule_id for f in found} >= {"SEC001", "SEC003"}
    assert all("AKIAIOSFODNN7EXAMPLE" not in f.detail for f in found)


def test_secret_scan_is_clean_on_fixed_app():
    assert scanners.scan_secrets(ROOT / "app_secure") == []


def test_iac_flags_vulnerable_and_passes_fixed():
    bad = {f.rule_id for f in scanners.scan_iac(ROOT / "app")}
    assert {"IAC001", "IAC002", "IAC003", "IAC010", "IAC011"} <= bad
    assert scanners.scan_iac(ROOT / "app_secure") == []


def test_sca_offline_without_snapshot_fails_loudly(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n")
    with pytest.raises(scanners.ScannerError):
        scanners.scan_sca(tmp_path, offline=True)


# ---- triage

def test_rules_raise_sql_injection_above_scanner_severity():
    report_ = ai_triage.triage_with_rules([finding()])
    assert report_.items[0].priority == "P0"
    assert "no AI" in report_.executive_summary


def test_validate_report_drops_unknown_ids_and_fills_gaps():
    known, other = finding(), finding(cwe="CWE-78", rule_id="B602", line=20)
    model_output = TriageReport("claude", "s", (
        TriageItem(known.id, "P2", "e", "r", "f"),
        TriageItem("INVENTED-1", "P0", "e", "r", "f"),
        TriageItem(known.id, "P9", "e", "r", "f"),
    ))
    checked = ai_triage.validate_report(model_output, [known, other])
    assert [i.finding_id for i in checked.items] == [known.id, other.id]
    assert checked.items[0].priority == "P2"
    assert "omitted" in checked.items[1].rationale


def test_duplicate_password_hit_is_merged():
    secret = make_finding(tool="secret-scan", category="secret", rule_id="SEC003", title="s",
                          severity="CRITICAL", file="app/app.py", line=20, detail="d", cwe="CWE-798")
    same_line = finding(cwe="CWE-259", rule_id="B105", line=20)
    other = finding(cwe="CWE-259", rule_id="B105", line=99)
    kept, dropped = scanners.deduplicate([secret, same_line, other])
    assert kept == [secret, other] and dropped == 1


def test_prompt_never_contains_the_secret_line():
    # Excerpts around ANY finding near the credentials must be masked, not only secret findings.
    nearby = make_finding(tool="t", category="sast", rule_id="R", title="x", severity="LOW",
                          file="app/app.py", line=19, detail="d")
    prompt = ai_triage.build_prompt(ROOT, scanners.scan_secrets(ROOT / "app") + [nearby])
    assert "AKIAIOSFODNN7EXAMPLE" not in prompt
    assert "Sup3rS3cret" not in prompt


def test_auto_mode_without_credentials_uses_rules(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    result, note = ai_triage.triage(ROOT, [finding()], "auto", tmp_path / "none.json")
    assert result.source == "rules" and "rule table" in note


# ---- anomaly detection

def test_detects_all_injected_attackers_reproducibly():
    first = anomaly.detect(anomaly.generate_logs())
    second = anomaly.detect(anomaly.generate_logs())
    assert first == second
    assert first["attackers_caught"] == first["injected_attackers"] == 3


# ---- compliance and gate

def test_blocking_finding_fails_mapped_controls():
    f = finding()
    triage = ai_triage.triage_with_rules([f])
    controls = {c["control_id"]: c["status"] for c in compliance.evaluate([f], triage, True)}
    assert controls["A03"] == "FAIL" and controls["A.8.28"] == "FAIL"
    assert controls["A06"] == "PASS" and controls["A09"] == "PASS"


def test_gate_blocks_then_passes():
    f = finding()
    triage = ai_triage.triage_with_rules([f])
    controls = compliance.evaluate([f], triage, True)
    blocked = gate.decide(gate.DEFAULT_POLICY, [f], triage, controls)
    assert not blocked["passed"] and blocked["priority_counts"]["P0"] == 1

    empty = TriageReport("none", "", ())
    clean = gate.decide(gate.DEFAULT_POLICY, [], empty, compliance.evaluate([], empty, True))
    assert clean["passed"] and clean["violations"] == []


def test_policy_rejects_bad_limits(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("max_allowed:\n  P0: -1\n")
    with pytest.raises(gate.PolicyError):
        gate.load_policy(path)


# ---- report

def test_report_escapes_untrusted_text():
    f = make_finding(tool="t", category="sast", rule_id="R", title="<script>alert(1)</script>",
                     severity="LOW", file="a.py", line=1, detail="d")
    triage = ai_triage.triage_with_rules([f])
    controls = compliance.evaluate([f], triage, True)
    html = report.render({
        "target": "app", "generated_at": "now", "findings": [f.to_dict()],
        "triage": triage.to_dict(), "monitoring": anomaly.detect(anomaly.generate_logs()),
        "controls": controls, "gate": gate.decide(gate.DEFAULT_POLICY, [f], triage, controls),
        "notes": {"sca": "n", "triage": "n"},
    })
    assert "<script>alert(1)</script>" not in html
