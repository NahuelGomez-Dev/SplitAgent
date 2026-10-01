"""CVSS v3.1 base-score calculation.

Implements the official specification so findings recorded by the Red Agent
carry a defensible numeric score and severity label.
"""

from __future__ import annotations

import math
import re
from typing import Any

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

VECTOR_RE = re.compile(r"CVSS:3\.[01]/(.+)", re.IGNORECASE)


def _roundup(value: float) -> float:
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000.0) + 1) / 10.0


def parse_metrics(vector: str) -> dict[str, str]:
    match = VECTOR_RE.search(vector.strip())
    body = match.group(1) if match else vector.strip()
    metrics: dict[str, str] = {}
    for part in body.split("/"):
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key.strip().upper()] = value.strip().upper()
    return metrics


def parse_vector(vector: str) -> float | None:
    """Return the CVSS v3.1 base score for ``vector`` or ``None`` if invalid."""
    if not vector:
        return None
    metrics = parse_metrics(vector)
    try:
        scope = metrics["S"]
        av = AV[metrics["AV"]]
        ac = AC[metrics["AC"]]
        ui = UI[metrics["UI"]]
        pr = (PR_CHANGED if scope == "C" else PR_UNCHANGED)[metrics["PR"]]
        impact_conf = CIA[metrics["C"]]
        impact_int = CIA[metrics["I"]]
        impact_avail = CIA[metrics["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - impact_conf) * (1 - impact_int) * (1 - impact_avail))
    if scope == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    if scope == "C":
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)
    return _roundup(base)


def severity_from_score(score: float) -> str:
    if score <= 0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def describe(vector: str) -> dict[str, Any]:
    score = parse_vector(vector)
    return {
        "vector": vector,
        "score": score,
        "severity": severity_from_score(score) if score is not None else "unknown",
    }
