"""Build the interactive presentation: inject real pipeline output into template.html.

    python presentation/build.py          # results from the AWS runs (aws/evidence)
    python presentation/build.py out      # results from local laptop runs
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sklearn.ensemble import IsolationForest  # noqa: E402

from pipeline import anomaly  # noqa: E402

HERE = Path(__file__).resolve().parent
MARKER = "/*__DATA__*/"
BODY_START = '<div class="bar">'


def load_run(name: str, source: Path) -> dict:
    path = source / name / "result.json"
    if not path.exists():
        raise SystemExit(f"missing {path}; run the pipeline for '{name}' first, or pass another folder")
    return json.loads(path.read_text(encoding="utf-8"))


def client_scores() -> list[dict]:
    """Every client's features and anomaly score, using the same model settings as the pipeline."""
    ips, matrix = anomaly.featurise(anomaly.generate_logs())
    model = IsolationForest(n_estimators=200, contamination=anomaly.CONTAMINATION,
                            random_state=anomaly.SEED)
    model.fit(matrix)
    scores = -model.score_samples(matrix)
    return [
        {"ip": ip, "f": [round(float(v), 3) for v in row], "score": round(float(score), 4),
         "attack": anomaly.ATTACKERS.get(ip, "")}
        for ip, row, score in zip(ips, matrix, scores)
    ]


def main() -> None:
    # Default: evidence downloaded from the AWS runs. Pass "out" to use local laptop runs instead.
    source = ROOT / (sys.argv[1] if len(sys.argv) > 1 else "aws/evidence")
    runs = {name: load_run(name, source) for name in ("app", "app_secure")}
    print(f"using results from {source}")
    data = {
        "runs": runs,
        "clients": client_scores(),
        "features": list(anomaly.FEATURES),
        "modelFlagged": runs["app"]["monitoring"]["flagged"],
    }
    template = (HERE / "template.html").read_text(encoding="utf-8")
    if MARKER not in template:
        raise SystemExit("template.html is missing the data marker")
    payload = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    page = template.replace(MARKER, payload)
    if BODY_START not in page:
        raise SystemExit("template.html is missing the control bar that starts the body")
    head, body = page.split(BODY_START, 1)

    # page.html: the fragment a hosted page wrapper expects (no doctype/head/body of its own).
    (HERE / "page.html").write_text(page, encoding="utf-8")
    # index.html: a complete document you can double-click and present from, offline except for fonts.
    standalone = (
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"{head}</head>\n<body>\n{BODY_START}{body}</body>\n</html>\n"
    )
    (HERE / "index.html").write_text(standalone, encoding="utf-8")
    print(f"wrote index.html and page.html in {HERE} ({len(payload) // 1024} KB of data)")


if __name__ == "__main__":
    main()
