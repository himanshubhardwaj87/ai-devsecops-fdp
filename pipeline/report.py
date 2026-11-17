"""Stage 6 - one self-contained HTML dashboard per run (no external assets)."""
from __future__ import annotations

from html import escape

STYLE = """
:root{--bg:#f6f7f9;--card:#ffffff;--ink:#16202c;--muted:#5b6777;--line:#dfe3e8;
--bad:#b3261e;--warn:#9a5b00;--good:#1b6e3c;--accent:#1f4e8c}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1180px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 10px}
.sub{color:var(--muted);margin:0 0 20px}
.verdict{padding:16px 20px;border-radius:10px;color:#fff;font-size:19px;font-weight:600}
.verdict.pass{background:var(--good)}.verdict.fail{background:var(--bad)}
.verdict ul{margin:8px 0 0;font-size:15px;font-weight:400}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:16px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.tile b{display:block;font-size:28px}.tile span{color:var(--muted);font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;white-space:nowrap}
.pill{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:700;color:#fff;white-space:nowrap}
.P0,.FAIL,.CRITICAL{background:var(--bad)}.P1,.HIGH{background:#c2410c}
.P2,.WARN,.MEDIUM{background:var(--warn)}.P3,.LOW{background:#5b6777}.PASS{background:var(--good)}
code{font:13px Consolas,monospace;background:#eef1f5;padding:1px 5px;border-radius:4px}
.note{color:var(--muted);font-size:13px;margin-top:8px}
"""


def _pill(value: str) -> str:
    return f'<span class="pill {escape(value)}">{escape(value)}</span>'


def _table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def render(result: dict) -> str:
    gate = result["gate"]
    triage = {item["finding_id"]: item for item in result["triage"]["items"]}
    counts = gate["priority_counts"]

    verdict_class = "pass" if gate["passed"] else "fail"
    verdict_text = "RELEASE GATE: PASSED" if gate["passed"] else "RELEASE GATE: BLOCKED"
    violations = "".join(f"<li>{escape(v)}</li>" for v in gate["violations"])

    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    findings = sorted(result["findings"], key=lambda f: order[triage[f["id"]]["priority"]])
    finding_rows = [
        [
            _pill(triage[f["id"]]["priority"]),
            _pill(f["severity"]),
            f"<b>{escape(f['title'])}</b><br><code>{escape(f['file'])}"
            + (f":{f['line']}" if f["line"] else "") + f"</code> &middot; {escape(f['tool'])}",
            escape(triage[f["id"]]["exploitability"]),
            escape(triage[f["id"]]["fix"]),
        ]
        for f in findings
    ]

    monitoring = result["monitoring"]
    anomaly_rows = [
        [
            f"<code>{escape(a['ip'])}</code>",
            f"{a['score']:.3f}",
            escape(a["attack_type"]),
            "<br>".join(escape(r) for r in a["reasons"]) or "no single dominant feature",
        ]
        for a in monitoring["anomalies"]
    ]

    control_rows = [
        [escape(c["framework"]), f"<b>{escape(c['control_id'])}</b> {escape(c['name'])}",
         _pill(c["status"]), escape(c["evidence"])]
        for c in result["controls"]
    ]
    passing = sum(1 for c in result["controls"] if c["status"] == "PASS")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DevSecOps run - {escape(result['target'])}</title><style>{STYLE}</style></head>
<body><main>
<h1>AI-driven DevSecOps pipeline</h1>
<p class="sub">Target <code>{escape(result['target'])}</code> &middot; run at {escape(result['generated_at'])}</p>

<div class="verdict {verdict_class}">{verdict_text}{f'<ul>{violations}</ul>' if violations else ''}</div>

<div class="tiles">
<div class="tile"><b>{len(findings)}</b><span>findings from 4 scanners</span></div>
<div class="tile"><b>{counts['P0']}</b><span>P0 - fix before release</span></div>
<div class="tile"><b>{counts['P1']}</b><span>P1 - fix this sprint</span></div>
<div class="tile"><b>{monitoring['attackers_caught']}/{monitoring['injected_attackers']}</b><span>injected attackers detected</span></div>
<div class="tile"><b>{passing}/{len(result['controls'])}</b><span>controls passing</span></div>
</div>

<h2>AI triage summary</h2>
<div class="card">{escape(result['triage']['executive_summary'])}
<div class="note">Triage source: {escape(result['triage']['source'])} &middot; {escape(result['notes']['triage'])}</div></div>

<h2>Findings, ordered by triage priority</h2>
<div class="card">{_table(['Priority', 'Scanner severity', 'Finding', 'Exploitability', 'Suggested fix'], finding_rows) if finding_rows else 'No findings.'}
<div class="note">Dependency advisories: {escape(result['notes']['sca'])}</div></div>

<h2>Runtime threat detection (Isolation Forest)</h2>
<div class="card">{_table(['Client', 'Anomaly score', 'Ground truth', 'Why it stands out'], anomaly_rows)}
<div class="note">{monitoring['log_lines']} synthetic log lines from {monitoring['clients']} clients;
{monitoring['flagged']} flagged, {monitoring['false_alarms']} false alarm(s). Ground truth is known because the attacks were injected.</div></div>

<h2>Continuous compliance</h2>
<div class="card">{_table(['Framework', 'Control', 'Status', 'Evidence from this run'], control_rows)}
<div class="note">Illustrative mapping for teaching. PASS means no contradicting evidence in this run, not a certification.</div></div>
</main></body></html>
"""
