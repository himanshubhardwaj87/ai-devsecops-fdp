"""Run the whole pipeline:  python -m pipeline.run --target app

Stages: scan -> AI triage -> runtime threat detection -> compliance -> gate -> report.
Exit code 0 means the release gate passed, 1 means it blocked, 2 means the pipeline broke.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from . import ai_triage, anomaly, compliance, gate, report, scanners
from .models import Finding

ROOT = Path(__file__).resolve().parent.parent
RED, GREEN, YELLOW, BOLD, DIM, RESET = "\033[91m", "\033[92m", "\033[93m", "\033[1m", "\033[2m", "\033[0m"
PRIORITY_COLOUR = {"P0": RED, "P1": RED, "P2": YELLOW, "P3": DIM}


def banner(number: int, title: str, step: bool) -> None:
    if step and number > 1:
        input(f"{DIM}  press Enter for the next stage...{RESET}")
    print(f"\n{BOLD}[{number}/6] {title}{RESET}")


def run_scanners(target: Path, offline: bool, sca_engine: str) -> tuple[list[Finding], str]:
    secrets = scanners.scan_secrets(target)
    print(f"  secret scan  : {len(secrets)} finding(s)")
    sast = scanners.scan_sast(target)
    print(f"  SAST (bandit): {len(sast)} finding(s)")
    sca, sca_note = scanners.scan_sca(target, offline=offline, engine=sca_engine)
    print(f"  SCA (dependencies): {len(sca)} finding(s)  {DIM}[{sca_note}]{RESET}")
    iac = scanners.scan_iac(target)
    print(f"  IaC policy   : {len(iac)} finding(s)")
    findings, dropped = scanners.deduplicate(secrets + sast + sca + iac)
    if dropped:
        print(f"  {DIM}correlation: {dropped} duplicate(s) reported by two tools merged{RESET}")
    return findings, sca_note


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default="app", help="folder to scan (app or app_secure)")
    parser.add_argument("--ai", default="auto", choices=("auto", "claude", "bedrock", "cached", "rules"),
                        help="triage source (default: auto; bedrock = Claude on Amazon Bedrock)")
    parser.add_argument("--sca", default="pip-audit", choices=("pip-audit", "inspector"),
                        help="dependency vulnerability source (inspector = Amazon Inspector)")
    parser.add_argument("--security-hub", action="store_true",
                        help="also publish findings to AWS Security Hub")
    parser.add_argument("--offline", action="store_true", help="use the cached dependency advisory snapshot")
    parser.add_argument("--step", action="store_true", help="pause between stages (for presenting)")
    args = parser.parse_args(argv)

    target = (ROOT / args.target).resolve()
    if not target.is_dir() or ROOT not in target.parents:
        print(f"{RED}target must be a folder inside the project: {args.target}{RESET}")
        return 2
    out_dir = ROOT / "out" / target.name
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        banner(1, f"Scan  ({target.name})", args.step)
        findings, sca_note = run_scanners(target, args.offline, args.sca)
        print(f"  {BOLD}{len(findings)} findings{RESET} to review")

        banner(2, "AI triage", args.step)
        cache_path = ROOT / "samples" / f"ai_triage_{target.name}.json"
        triage, triage_note = ai_triage.triage(ROOT, findings, args.ai, cache_path)
        print(f"  source: {triage.source}  {DIM}[{triage_note}]{RESET}")
        by_id = {finding.id: finding for finding in findings}
        for item in sorted(triage.items, key=lambda i: i.priority):
            finding = by_id[item.finding_id]
            where = f"{finding.file}:{finding.line}" if finding.line else finding.file
            print(f"  {PRIORITY_COLOUR[item.priority]}{item.priority}{RESET}  {finding.title[:52]:<52} {DIM}{where}{RESET}")
        print(f"\n  {triage.executive_summary}")

        banner(3, "Runtime threat detection", args.step)
        monitoring = anomaly.detect(anomaly.generate_logs())
        print(f"  {monitoring['log_lines']} log lines, {monitoring['clients']} clients -> {monitoring['flagged']} flagged")
        for entry in monitoring["anomalies"]:
            colour = RED if entry["is_injected_attack"] else YELLOW
            print(f"  {colour}{entry['ip']:<15}{RESET} score {entry['score']:.3f}  {entry['attack_type']}")
        print(f"  caught {monitoring['attackers_caught']}/{monitoring['injected_attackers']} injected attackers, "
              f"{monitoring['false_alarms']} false alarm(s)")

        banner(4, "Continuous compliance", args.step)
        controls = compliance.evaluate(findings, triage, monitoring_ran=True)
        for framework in dict.fromkeys(c["framework"] for c in controls):
            subset = [c for c in controls if c["framework"] == framework]
            passed = sum(1 for c in subset if c["status"] == "PASS")
            failed = [c["control_id"] for c in subset if c["status"] == "FAIL"]
            tail = f"  {RED}failing: {', '.join(failed)}{RESET}" if failed else ""
            print(f"  {framework:<20} {passed}/{len(subset)} passing{tail}")

        banner(5, "Release gate", args.step)
        verdict = gate.decide(gate.load_policy(ROOT / "policy.yaml"), findings, triage, controls)
        if verdict["passed"]:
            print(f"  {GREEN}{BOLD}PASSED{RESET} - policy.yaml is satisfied")
        else:
            print(f"  {RED}{BOLD}BLOCKED{RESET}")
            for violation in verdict["violations"]:
                print(f"   - {violation}")
    except (scanners.ScannerError, ai_triage.TriageUnavailable, gate.PolicyError) as exc:
        print(f"\n{RED}pipeline error: {exc}{RESET}")
        return 2

    banner(6, "Report", args.step)
    result = {
        "target": target.name,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "findings": [finding.to_dict() for finding in findings],
        "triage": triage.to_dict(),
        "monitoring": monitoring,
        "controls": controls,
        "gate": verdict,
        "notes": {"sca": sca_note, "triage": triage_note},
    }
    (out_dir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out_dir / "report.html").write_text(report.render(result), encoding="utf-8")
    print(f"  dashboard: {out_dir / 'report.html'}")
    if args.security_hub:
        from .aws_integrations import AwsUnavailable, export_to_security_hub

        try:
            sent = export_to_security_hub(findings, triage, target.name)
            print(f"  Security Hub: {sent} finding(s) imported")
        except AwsUnavailable as exc:
            # Evidence export failing must be visible, but it does not change the gate verdict.
            print(f"  {YELLOW}Security Hub export skipped: {exc}{RESET}")
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
