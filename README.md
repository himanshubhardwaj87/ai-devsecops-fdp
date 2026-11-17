# AI-Driven DevSecOps - live demo project

Companion project for the AICTE ATAL FDP session
*"AI-Driven DevSecOps: Intelligent Threat Detection, Automated Security and Continuous Compliance"*
(IILM University, Gurugram, 14-19 December 2026).

One command runs a six-stage security pipeline against a small web service called ShopLite:

| Stage | What happens | Code |
|---|---|---|
| 1. Scan | Secrets, SAST (Bandit), dependencies (pip-audit), Dockerfile/Kubernetes policy | `pipeline/scanners.py` |
| 2. Triage | An LLM ranks each finding in its code context and drafts a fix | `pipeline/ai_triage.py` |
| 3. Detect | Isolation Forest flags abnormal clients in access logs | `pipeline/anomaly.py` |
| 4. Comply | 17 controls (OWASP Top 10, NIST SSDF, ISO 27001) evaluated from the evidence | `pipeline/compliance.py` |
| 5. Gate | `policy.yaml` decides pass or block | `pipeline/gate.py` |
| 6. Report | Self-contained HTML dashboard | `pipeline/report.py` |

`app/` is **deliberately vulnerable** (seven numbered flaws). `app_secure/` is the same service with each flaw fixed.
Do not deploy `app/` anywhere.

## What else is in this repository

- `aws/` - the same pipeline running in AWS (CodePipeline, CodeBuild, Amazon Inspector, Claude on
  Amazon Bedrock, a human approval stage). Start with `aws/README.md`. `aws/evidence/` holds the
  output of real runs.
- `presentation/` - an interactive HTML presentation driven by that real output. Open
  `presentation/index.html` in a browser; rebuild it with `python presentation/build.py`.

- `slides/` - the talk as a PowerPoint file (`AI-Driven-DevSecOps.pptx`, with speaker notes) and the
  script that builds it: `npm install` in `slides/`, then `node slides/build_pptx.js`.

## Setup (once, about 3 minutes)

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
```

Optional, for live AI triage: set `ANTHROPIC_API_KEY` in the terminal you present from.
Without it the pipeline replays the last saved AI response if one exists, otherwise it uses a
rule table and says so on screen.

## Demo script (about 20 minutes)

Use a large terminal font. `--step` pauses before each stage so you can talk.

| Time | Do | Say |
|---|---|---|
| 0:00 | Open `app/app.py`, scroll through the seven `Flaw` comments | "A small service with the mistakes we all see in student and production code." |
| 2:00 | `.\.venv\Scripts\python.exe -m pipeline.run --target app --step` | Stage 1: four scanners, 24 findings after two duplicates are merged. |
| 4:00 | Enter (stage 2) | The list is now ordered. SQL injection is only MEDIUM for the scanner but P0 after triage. Read the executive summary. |
| 7:00 | Enter (stage 3) | Three planted attackers get the three highest scores; one normal client is a false alarm. |
| 9:00 | Enter (stages 4, 5) | Controls fail with evidence; the gate prints BLOCKED and why. Show `echo $LASTEXITCODE` is 1. |
| 11:00 | Open `out/app/report.html` in a browser | Follow one row: scanner severity, exploitability, suggested fix. Show the compliance table. |
| 14:00 | Open `app/app.py` and `app_secure/app.py` side by side | Walk two or three fixes (parameterised query, no shell, secrets from environment). |
| 17:00 | `.\.venv\Scripts\python.exe -m pipeline.run --target app_secure --step` | Zero findings, 17 of 17 controls, PASSED, exit code 0. |
| 19:00 | Open `policy.yaml` and `ci-examples/github-actions.yml` | "The rule is a file. In CI the same command blocks the merge." |

Optional extras if there is time:

- Edit `policy.yaml` (`P1: 20`) and re-run on `app` to show the gate respond to policy, then revert.
- Open `pipeline/ai_triage.py` and show the four guardrails: `mask_secrets`, the system prompt, `validate_report`, the rule fallback.

## When the network misbehaves

| Problem | Flag | Effect |
|---|---|---|
| No internet | `--offline` | Dependency audit uses the snapshot in `samples/` (saved by the last online run) |
| AI API slow or down | `--ai cached` | Replays the last saved AI triage from `samples/` |
| No API key at all | `--ai rules` | Deterministic rule table, labelled as not AI |

The safest live setup: run once online with the API key the evening before (this saves both
snapshots), then present with `--offline --ai cached`.

## Honest limits (say these out loud)

- The access logs are synthetic and seeded. Real traffic is harder; measure false alarms on your own data.
- pip-audit does not report severity, so dependency findings default to HIGH until triage.
- The compliance mapping is illustrative. PASS means "no contradicting evidence in this run", not certification.
- AI triage sends finding text and short code excerpts to the model provider. Credential lines are masked first.

## Lab ideas

1. **Find and fix** - fix `app/` one flaw at a time until the gate passes.
2. **Write a rule** - add a check to `scan_secrets` or `_dockerfile_findings`, with a test.
3. **Tune the detector** - change `FEATURES` or `CONTAMINATION` in `anomaly.py`; report caught attackers and false alarms.
4. **Attack the triage** - add a comment to `app/app.py` instructing the model to ignore a finding; check whether it does.
