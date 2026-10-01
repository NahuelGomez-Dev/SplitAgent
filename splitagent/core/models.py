"""Data structures shared across the engine, the agents and the reports."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")

SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def normalize_severity(value: str | None, score: float | None = None) -> str:
    if value:
        value = value.strip().lower()
        if value in SEVERITY_ORDER:
            return value
    if score is not None:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
    return "info"


@dataclass
class Finding:
    """A vulnerability or weakness discovered by the Red Agent."""

    id: str = field(default_factory=lambda: new_id("F"))
    title: str = ""
    category: str = "general"
    description: str = ""
    severity: str = "info"
    cvss_vector: str = ""
    cvss_score: float = 0.0
    target: str = ""
    endpoint: str = ""
    evidence: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    confidence: str = "medium"
    discovered_by: str = "red"
    round: int = 0
    status: str = "open"  # open | mitigated | accepted | false-positive
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class Mitigation:
    """A defensive countermeasure produced by the Blue Agent."""

    id: str = field(default_factory=lambda: new_id("M"))
    finding_id: str = ""
    title: str = ""
    kind: str = "config"  # firewall | patch | config | detection | process
    description: str = ""
    content: str = ""
    rationale: str = ""
    status: str = "proposed"  # proposed | applied | verified | rejected
    verified: bool = False
    round: int = 0
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Mitigation:
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class Round:
    """A single Red -> Blue cycle."""

    index: int = 1
    red_summary: str = ""
    blue_summary: str = ""
    finding_ids: list[str] = field(default_factory=list)
    mitigation_ids: list[str] = field(default_factory=list)
    started_at: str = field(default_factory=_now)
    ended_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Round:
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class SessionState:
    """The complete, serialisable state of an audit session."""

    id: str = field(default_factory=lambda: new_id("S"))
    name: str = "splitagent"
    target: str = ""
    target_kind: str = "web"
    scope: list[str] = field(default_factory=list)
    model: str = ""
    provider: str = ""
    started_at: str = field(default_factory=_now)
    ended_at: str = ""
    rounds: list[Round] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    mitigations: list[Mitigation] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)
    checkpoints: list[dict[str, Any]] = field(default_factory=list)
    traces: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    todos: list[dict[str, str]] = field(default_factory=list)

    # -- convenience ------------------------------------------------------- #
    def add_finding(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        return finding

    def add_mitigation(self, mitigation: Mitigation) -> Mitigation:
        self.mitigations.append(mitigation)
        return mitigation

    def get_finding(self, finding_id: str) -> Finding | None:
        return next((f for f in self.findings if f.id == finding_id), None)

    def rounds_by_index(self) -> dict[int, Round]:
        return {r.index: r for r in self.rounds}

    def latest_round(self) -> Round | None:
        return self.rounds[-1] if self.rounds else None

    def severity_counts(self) -> dict[str, int]:
        counts = dict.fromkeys(SEVERITIES, 0)
        for finding in self.findings:
            counts[normalize_severity(finding.severity, finding.cvss_score)] += 1
        return counts

    def resilience_score(self) -> float:
        """0-100 score: how much of the discovered attack surface is mitigated."""
        if not self.findings:
            return 100.0
        weights = {
            "critical": 10.0,
            "high": 6.0,
            "medium": 3.0,
            "low": 1.0,
            "info": 0.25,
        }
        total = 0.0
        covered = 0.0
        for finding in self.findings:
            weight = weights.get(normalize_severity(finding.severity, finding.cvss_score), 0.25)
            total += weight
            if finding.status in ("mitigated", "accepted"):
                covered += weight
        if total <= 0:
            return 100.0
        return round((covered / total) * 100.0, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "target": self.target,
            "target_kind": self.target_kind,
            "scope": list(self.scope),
            "model": self.model,
            "provider": self.provider,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "rounds": [r.to_dict() for r in self.rounds],
            "findings": [f.to_dict() for f in self.findings],
            "mitigations": [m.to_dict() for m in self.mitigations],
            "notes": list(self.notes),
            "usage": dict(self.usage),
            "checkpoints": list(self.checkpoints),
            "traces": self.traces,
            "todos": list(self.todos),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionState:
        return cls(
            id=data.get("id", new_id("S")),
            name=data.get("name", "splitagent"),
            target=data.get("target", ""),
            target_kind=data.get("target_kind", "web"),
            scope=list(data.get("scope", [])),
            model=data.get("model", ""),
            provider=data.get("provider", ""),
            started_at=data.get("started_at", _now()),
            ended_at=data.get("ended_at", ""),
            rounds=[Round.from_dict(r) for r in data.get("rounds", [])],
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            mitigations=[Mitigation.from_dict(m) for m in data.get("mitigations", [])],
            notes=list(data.get("notes", [])),
            usage=dict(data.get("usage", {})),
            checkpoints=list(data.get("checkpoints", [])),
            traces=dict(data.get("traces", {})),
            todos=[dict(item) for item in data.get("todos", [])],
        )
