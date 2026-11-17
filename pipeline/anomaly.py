"""Stage 3 - intelligent threat detection on runtime logs.

An Isolation Forest learns what "normal" traffic per client looks like and flags
clients whose behaviour is easy to isolate. No attack signatures are written.

The logs are SYNTHETIC (seeded, reproducible): normal shoppers plus three injected
attackers. Because we know the ground truth, the stage can score itself honestly.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import IsolationForest

SEED = 42
NORMAL_CLIENTS = 120
CONTAMINATION = 0.03
FEATURES = (
    "requests",
    "error_rate",
    "distinct_paths",
    "failed_logins",
    "avg_response_kb",
    "night_share",
)
NORMAL_PATHS = ("/", "/products", "/cart", "/checkout", "/login", "/search")


@dataclass(frozen=True)
class LogLine:
    ip: str
    hour: int
    path: str
    status: int
    kilobytes: float


@dataclass(frozen=True)
class Anomaly:
    ip: str
    score: float
    is_injected_attack: bool
    attack_type: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "score": round(self.score, 3),
            "is_injected_attack": self.is_injected_attack,
            "attack_type": self.attack_type,
            "reasons": list(self.reasons),
        }


ATTACKERS = {
    "203.0.113.7": "credential stuffing",
    "198.51.100.23": "injection probing",
    "192.0.2.99": "data exfiltration",
}


def generate_logs(seed: int = SEED) -> list[LogLine]:
    rng = np.random.default_rng(seed)
    lines: list[LogLine] = []

    for client in range(NORMAL_CLIENTS):
        ip = f"10.0.{client // 250}.{client % 250 + 1}"
        for _ in range(int(rng.integers(8, 40))):
            path = str(rng.choice(NORMAL_PATHS))
            status = 200 if rng.random() > 0.04 else int(rng.choice((401, 404)))
            lines.append(LogLine(ip, int(rng.normal(14, 3)) % 24, path, status,
                                 float(abs(rng.normal(18, 6)))))

    # Credential stuffing: hundreds of failed logins at night.
    for _ in range(400):
        status = 401 if rng.random() > 0.01 else 200
        lines.append(LogLine("203.0.113.7", int(rng.integers(1, 4)), "/login", status, 0.4))

    # Injection probing: many distinct, odd paths that mostly error.
    for index in range(180):
        lines.append(LogLine("198.51.100.23", int(rng.integers(0, 24)),
                             f"/search?q=%27+OR+1%3D1--{index}", int(rng.choice((500, 404, 200))), 2.0))

    # Exfiltration: few requests, very large responses, off-hours.
    for _ in range(12):
        lines.append(LogLine("192.0.2.99", 3, "/export/customers", 200, float(rng.normal(9000, 800))))

    return lines


def featurise(lines: list[LogLine]) -> tuple[list[str], np.ndarray]:
    by_ip: dict[str, list[LogLine]] = {}
    for line in lines:
        by_ip.setdefault(line.ip, []).append(line)
    ips = sorted(by_ip)
    rows = []
    for ip in ips:
        entries = by_ip[ip]
        count = len(entries)
        rows.append([
            count,
            sum(1 for e in entries if e.status >= 400) / count,
            len({e.path for e in entries}),
            sum(1 for e in entries if e.path == "/login" and e.status == 401),
            sum(e.kilobytes for e in entries) / count,
            sum(1 for e in entries if e.hour < 6) / count,
        ])
    return ips, np.array(rows, dtype=float)


def _reasons(row: np.ndarray, median: np.ndarray, spread: np.ndarray) -> tuple[str, ...]:
    """Explain an anomaly: which features sit far from the typical client."""
    deviation = (row - median) / spread
    ranked = sorted(zip(FEATURES, row, median, deviation), key=lambda item: -abs(item[3]))
    return tuple(
        f"{name} = {value:.2f} (typical {typical:.2f})"
        for name, value, typical, dev in ranked[:3]
        if abs(dev) >= 3
    )


def detect(lines: list[LogLine], seed: int = SEED) -> dict:
    ips, matrix = featurise(lines)
    model = IsolationForest(n_estimators=200, contamination=CONTAMINATION, random_state=seed)
    labels = model.fit_predict(matrix)
    scores = -model.score_samples(matrix)

    median = np.median(matrix, axis=0)
    spread = np.maximum(np.median(np.abs(matrix - median), axis=0) * 1.4826, 1e-6)

    anomalies = sorted(
        (
            Anomaly(
                ip=ip,
                score=float(score),
                is_injected_attack=ip in ATTACKERS,
                attack_type=ATTACKERS.get(ip, "none (normal client)"),
                reasons=_reasons(row, median, spread),
            )
            for ip, row, label, score in zip(ips, matrix, labels, scores)
            if label == -1
        ),
        key=lambda anomaly: -anomaly.score,
    )
    caught = sum(1 for anomaly in anomalies if anomaly.is_injected_attack)
    return {
        "log_lines": len(lines),
        "clients": len(ips),
        "flagged": len(anomalies),
        "injected_attackers": len(ATTACKERS),
        "attackers_caught": caught,
        "false_alarms": len(anomalies) - caught,
        "anomalies": [anomaly.to_dict() for anomaly in anomalies],
    }
