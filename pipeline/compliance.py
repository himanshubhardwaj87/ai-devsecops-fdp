"""Stage 4 - continuous compliance.

Each control is evaluated from pipeline evidence on every run, so the compliance
report is a by-product of delivery instead of a yearly spreadsheet exercise.

The mapping is ILLUSTRATIVE teaching material: a control marked PASS here means
"no contradicting evidence in this pipeline run", not "certified compliant".
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Finding, TriageReport

BLOCKING = ("P0", "P1")


@dataclass(frozen=True)
class Control:
    framework: str
    control_id: str
    name: str
    categories: tuple[str, ...] = ()
    cwes: tuple[str, ...] = ()
    needs_monitoring: bool = False


CONTROLS = (
    Control("OWASP Top 10:2021", "A03", "Injection", cwes=("CWE-89", "CWE-78")),
    Control("OWASP Top 10:2021", "A02", "Cryptographic Failures", cwes=("CWE-327", "CWE-328")),
    Control("OWASP Top 10:2021", "A05", "Security Misconfiguration", categories=("iac",), cwes=("CWE-94", "CWE-605")),
    Control("OWASP Top 10:2021", "A06", "Vulnerable and Outdated Components", categories=("sca",)),
    Control("OWASP Top 10:2021", "A07", "Identification and Authentication Failures", categories=("secret",)),
    Control("OWASP Top 10:2021", "A08", "Software and Data Integrity Failures", cwes=("CWE-502", "CWE-494")),
    Control("OWASP Top 10:2021", "A09", "Security Logging and Monitoring Failures", needs_monitoring=True),
    Control("NIST SSDF 1.1", "PW.4", "Reuse existing, well-secured software", categories=("sca",)),
    Control("NIST SSDF 1.1", "PW.7", "Review and analyse code to identify vulnerabilities", categories=("sast", "secret")),
    Control("NIST SSDF 1.1", "PW.9", "Configure software to have secure settings by default", categories=("iac",)),
    Control("NIST SSDF 1.1", "RV.1", "Identify and confirm vulnerabilities on an ongoing basis", categories=("sca", "sast")),
    Control("ISO/IEC 27001:2022", "A.5.17", "Authentication information", categories=("secret",)),
    Control("ISO/IEC 27001:2022", "A.8.8", "Management of technical vulnerabilities", categories=("sca",)),
    Control("ISO/IEC 27001:2022", "A.8.9", "Configuration management", categories=("iac",)),
    Control("ISO/IEC 27001:2022", "A.8.16", "Monitoring activities", needs_monitoring=True),
    Control("ISO/IEC 27001:2022", "A.8.24", "Use of cryptography", cwes=("CWE-327", "CWE-328")),
    Control("ISO/IEC 27001:2022", "A.8.28", "Secure coding", categories=("sast",)),
)


def evaluate(findings: list[Finding], triage: TriageReport, monitoring_ran: bool) -> list[dict]:
    priority = {item.finding_id: item.priority for item in triage.items}
    results = []
    for control in CONTROLS:
        if control.needs_monitoring:
            status = "PASS" if monitoring_ran else "FAIL"
            evidence = ("Anomaly detection ran on runtime logs in this pipeline run."
                        if monitoring_ran else "No runtime monitoring evidence in this run.")
        else:
            related = [
                f for f in findings
                if f.category in control.categories or (f.cwe and f.cwe in control.cwes)
            ]
            blocking = [f for f in related if priority.get(f.id) in BLOCKING]
            if blocking:
                status = "FAIL"
                evidence = f"{len(blocking)} blocking finding(s): " + ", ".join(f.id for f in blocking[:4])
            elif related:
                status = "WARN"
                evidence = f"{len(related)} lower-priority finding(s) accepted for now."
            else:
                status = "PASS"
                evidence = "No related findings in this run."
        results.append({
            "framework": control.framework,
            "control_id": control.control_id,
            "name": control.name,
            "status": status,
            "evidence": evidence,
        })
    return results
