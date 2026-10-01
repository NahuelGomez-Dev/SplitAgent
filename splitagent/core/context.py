"""Encrypted shared context.

The context is the single source of truth the Red and Blue agents read from
and write to. It is serialised to JSON and encrypted at rest with a Fernet
key stored in the global config directory, so audited evidence and secrets
never touch disk in clear text.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from splitagent.config import ensure_home, global_key_path, sessions_dir
from splitagent.core.bus import Event, EventBus
from splitagent.core.context_manager import ContextPolicy
from splitagent.core.models import (
    Finding,
    Mitigation,
    Round,
    SessionState,
    normalize_severity,
)
from splitagent.errors import ConfigError


def _load_fernet() -> Any:
    try:
        from cryptography.fernet import Fernet
    except ImportError:  # pragma: no cover - dependency is declared
        return None
    return Fernet


def load_or_create_key(path: Path | None = None) -> bytes | None:
    """Return the Fernet key, creating it on first use. ``None`` if unavailable."""
    Fernet = _load_fernet()
    if Fernet is None:
        return None
    path = path or global_key_path()
    if path.exists():
        return path.read_bytes().strip()
    ensure_home()
    key = Fernet.generate_key()
    path.write_bytes(key)
    try:
        import os

        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover
        pass
    return key


class SharedContext:
    """Thread-safe-ish wrapper around :class:`SessionState` with persistence."""

    def __init__(
        self,
        state: SessionState,
        bus: EventBus | None = None,
        directory: Path | None = None,
    ) -> None:
        self.state = state
        self.bus = bus or EventBus()
        self.directory = directory or sessions_dir()
        self._fernet = _load_fernet()
        self._key: bytes | None = None
        # Context window policy shared by every agent in this session.
        self.policy = ContextPolicy()
        self.checkpoints: list[dict[str, Any]] = []
        # The agents' own working directory (set by the engine).
        self.workspace: Any = None

    # -- constructors ------------------------------------------------------ #
    @classmethod
    def create(
        cls,
        target: str,
        target_kind: str = "web",
        scope: list[str] | None = None,
        name: str = "splitagent",
        model: str = "",
        provider: str = "",
        bus: EventBus | None = None,
        directory: Path | None = None,
    ) -> SharedContext:
        state = SessionState(
            name=name,
            target=target,
            target_kind=target_kind,
            scope=list(scope or []),
            model=model,
            provider=provider,
        )
        return cls(state, bus=bus, directory=directory)

    # -- crypto ------------------------------------------------------------ #
    def _ensure_key(self) -> bytes | None:
        if self._fernet is None:
            return None
        if self._key is None:
            self._key = load_or_create_key()
        return self._key

    def encrypt(self, payload: bytes) -> bytes:
        key = self._ensure_key()
        if key is None or self._fernet is None:
            raise ConfigError(
                "cryptography is required to persist encrypted sessions. "
                "Install it with `pip install cryptography`."
            )
        return self._fernet(key).encrypt(payload)

    def decrypt(self, token: bytes) -> bytes:
        key = self._ensure_key()
        if key is None or self._fernet is None:
            raise ConfigError("cryptography is unavailable; cannot decrypt session.")
        return self._fernet(key).decrypt(token)

    # -- persistence ------------------------------------------------------- #
    def path_for(self, session_id: str | None = None) -> Path:
        return self.directory / f"{session_id or self.state.id}.session.enc"

    def save(self) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.state.to_dict(), ensure_ascii=False).encode("utf-8")
        token = self.encrypt(payload)
        path = self.path_for()
        path.write_bytes(token)
        return path

    @classmethod
    def load(
        cls, session_id: str, bus: EventBus | None = None, directory: Path | None = None
    ) -> SharedContext:
        directory = directory or sessions_dir()
        path = directory / f"{session_id}.session.enc"
        if not path.exists():
            raise ConfigError(f"Session '{session_id}' not found at {path}")
        ctx = cls(SessionState(), bus=bus, directory=directory)
        data = json.loads(ctx.decrypt(path.read_bytes()).decode("utf-8"))
        ctx.state = SessionState.from_dict(data)
        return ctx

    @classmethod
    def load_path(cls, path: Path, bus: EventBus | None = None) -> SharedContext:
        ctx = cls(SessionState(), bus=bus, directory=path.parent)
        data = json.loads(ctx.decrypt(path.read_bytes()).decode("utf-8"))
        ctx.state = SessionState.from_dict(data)
        return ctx

    def export_json(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.state.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return path

    # -- mutators ---------------------------------------------------------- #
    def find_duplicate(self, title: str, endpoint: str, category: str = "") -> Finding | None:
        """Return an existing finding that describes the same issue.

        The Red Agent re-tests the same surface every round, so without this
        the report fills with near-identical entries. Observed in a real run:
        phpinfo disclosure recorded three times, XSS twice, TRACE twice, all
        with different wording but the same endpoint and category.

        Two findings clash when they share an endpoint **and** either the same
        category or a strongly overlapping title. Different issues on the same
        URL (an XSS and a path traversal) keep their separate entries.
        """
        norm_ep = _normalise_endpoint(endpoint)
        key = _finding_key(title, endpoint)
        cat = (category or "").strip().lower()
        # "general" is the absence of a category, not a shared one: treating it
        # as a match would merge every uncategorised finding on the same URL.
        category_matches = bool(cat and cat != "general")
        for existing in self.state.findings:
            if _normalise_endpoint(existing.endpoint) != norm_ep:
                continue
            existing_cat = existing.category.strip().lower()
            if category_matches and existing_cat == cat:
                return existing
            if _finding_key(existing.title, existing.endpoint) == key:
                return existing
            if _titles_overlap(title, existing.title):
                return existing
        return None

    async def add_finding(self, data: dict[str, Any], agent: str = "red") -> Finding:
        score = _as_float(data.get("cvss_score"))
        severity = normalize_severity(data.get("severity"), score)
        title = str(data.get("title", "Untitled finding"))
        endpoint = str(data.get("endpoint", ""))
        category = str(data.get("category", "general"))
        duplicate = (
            self.find_duplicate(title, endpoint, category) if data.get("dedupe", True) else None
        )
        if duplicate is not None:
            # Keep the strongest score and freshest evidence, but do not add a
            # second entry to the report.
            if score is not None and score > duplicate.cvss_score:
                duplicate.cvss_score = score
                duplicate.cvss_vector = str(data.get("cvss_vector", duplicate.cvss_vector))
                duplicate.severity = normalize_severity(severity, score)
            evidence = str(data.get("evidence", ""))
            if evidence and evidence not in duplicate.evidence:
                duplicate.evidence = (duplicate.evidence + "\n\n" + evidence)[:8000]
            await self.bus.emit(
                Event(
                    type="finding.merged",
                    agent=agent,
                    data={"id": duplicate.id, "title": duplicate.title},
                )
            )
            return duplicate
        finding = Finding(
            title=title,
            category=category,
            description=str(data.get("description", "")),
            severity=severity,
            cvss_vector=str(data.get("cvss_vector", "")),
            cvss_score=score if score is not None else 0.0,
            target=str(data.get("target", self.state.target)),
            endpoint=endpoint,
            evidence=str(data.get("evidence", ""))[:8000],
            recommendation=str(data.get("recommendation", "")),
            references=list(data.get("references", []) or []),
            confidence=str(data.get("confidence", "medium")),
            discovered_by=agent,
            round=int(data.get("round", self._current_round_index())),
        )
        self.state.add_finding(finding)
        await self.bus.emit(
            Event(
                type="finding",
                agent=agent,
                data={"id": finding.id, "title": finding.title, "severity": severity},
            )
        )
        return finding

    async def add_mitigation(self, data: dict[str, Any], agent: str = "blue") -> Mitigation:
        finding_id = str(data.get("finding_id", ""))
        mitigation = Mitigation(
            finding_id=finding_id,
            title=str(data.get("title", "Mitigation")),
            kind=str(data.get("kind", "config")),
            description=str(data.get("description", "")),
            content=str(data.get("content", "")),
            rationale=str(data.get("rationale", "")),
            round=int(data.get("round", self._current_round_index())),
        )
        self.state.add_mitigation(mitigation)
        finding = self.state.get_finding(finding_id)
        if finding is not None:
            finding.status = "mitigated"
        await self.bus.emit(
            Event(
                type="mitigation",
                agent=agent,
                data={
                    "id": mitigation.id,
                    "finding_id": finding_id,
                    "title": mitigation.title,
                    "kind": mitigation.kind,
                },
            )
        )
        if finding is not None:
            await self.bus.emit(
                Event(
                    type="finding.updated",
                    agent=agent,
                    data={"id": finding.id, "status": finding.status},
                )
            )
        return mitigation

    async def add_note(self, note: str) -> None:
        self.state.notes.append(note)
        await self.bus.emit(Event(type="log", agent="core", data={"text": note}))

    async def add_checkpoint(self, agent: str, summary: str, removed: int, preserved: int) -> None:
        """Record a compaction checkpoint for audit and replay."""
        from datetime import datetime, timezone

        checkpoint = {
            "agent": agent,
            "round": self._current_round_index(),
            "removed_tokens": removed,
            "preserved_tokens": preserved,
            "summary": summary,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        self.checkpoints.append(checkpoint)
        self.state.checkpoints.append(checkpoint)
        await self.bus.emit(
            Event(
                type="checkpoint",
                agent=agent,
                data={
                    "removed": removed,
                    "preserved": preserved,
                    "summary": summary[:4000],
                },
            )
        )

    async def set_todos(self, todos: list[dict[str, Any]]) -> None:
        """Replace the session task list (OpenCode's ``todowrite`` pattern)."""
        cleaned: list[dict[str, str]] = []
        for item in todos or []:
            if not isinstance(item, dict):
                continue
            content = str(item.get("content", "")).strip()
            if not content:
                continue
            status = str(item.get("status", "pending")).lower()
            if status not in ("pending", "in_progress", "completed", "cancelled"):
                status = "pending"
            priority = str(item.get("priority", "medium")).lower()
            if priority not in ("high", "medium", "low"):
                priority = "medium"
            cleaned.append({"content": content, "status": status, "priority": priority})
        self.state.todos = cleaned
        await self.bus.emit(Event(type="todos", agent="core", data={"todos": cleaned}))

    def todo_summary(self) -> str:
        if not self.state.todos:
            return "(no task list yet)"
        return "\n".join(
            f"- [{item['status']}] {item['content']} ({item['priority']})"
            for item in self.state.todos
        )

    async def add_trace(self, agent: str, trace: list[dict[str, Any]]) -> None:
        """Persist a full reasoning/tool trace so the run can be replayed."""
        if not trace:
            return
        entries = self.state.traces.setdefault(agent, [])
        entries.append(
            {
                "round": self._current_round_index(),
                "entries": trace,
            }
        )
        # Bound the persisted trace so long engagements stay loadable.
        if len(entries) > 8:
            del entries[: len(entries) - 8]

    # -- rounds ------------------------------------------------------------ #
    def _current_round_index(self) -> int:
        latest = self.state.latest_round()
        return latest.index if latest else 1

    def begin_round(self, index: int) -> Round:
        round_ = Round(index=index)
        self.state.rounds.append(round_)
        return round_

    def end_round(self, index: int, red_summary: str, blue_summary: str) -> None:
        from datetime import datetime, timezone

        for round_ in self.state.rounds:
            if round_.index == index:
                round_.red_summary = red_summary
                round_.blue_summary = blue_summary
                round_.ended_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
                break

    # -- views for prompts ------------------------------------------------- #
    def findings_digest(self, limit: int = 40) -> str:
        if not self.state.findings:
            return "(no findings yet)"
        lines: list[str] = []
        for finding in self.state.findings[-limit:]:
            lines.append(
                f"- [{finding.id}] {finding.severity.upper()} "
                f"({finding.cvss_score:.1f}) {finding.title} @ "
                f"{finding.endpoint or finding.target} [{finding.status}]"
            )
        return "\n".join(lines)

    def mitigations_digest(self, limit: int = 40) -> str:
        if not self.state.mitigations:
            return "(no mitigations yet)"
        lines = [
            f"- [{m.id}] {m.kind}: {m.title} -> finding {m.finding_id or 'n/a'} ({m.status})"
            for m in self.state.mitigations[-limit:]
        ]
        return "\n".join(lines)

    def open_findings(self) -> list[Finding]:
        return [f for f in self.state.findings if f.status == "open"]

    def summary_dict(self) -> dict[str, Any]:
        return {
            "session": self.state.id,
            "target": self.state.target,
            "rounds": len(self.state.rounds),
            "findings": len(self.state.findings),
            "mitigations": len(self.state.mitigations),
            "severity": self.state.severity_counts(),
            "resilience": self.state.resilience_score(),
        }


_NOISE = (
    "blue",
    "red",
    "agent",
    "review",
    "confirmed",
    "re-check",
    "recheck",
    "round",
    "duplicate",
    "again",
    "still",
)

# Filler that carries no identifying meaning; ignored when comparing titles.
_FILLER = frozenset(
    [
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "been",
        "both",
        "by",
        "for",
        "from",
        "has",
        "have",
        "in",
        "into",
        "is",
        "it",
        "its",
        "of",
        "on",
        "or",
        "over",
        "the",
        "their",
        "there",
        "these",
        "this",
        "those",
        "to",
        "unauthenticated",
        "via",
        "was",
        "were",
        "with",
        "enabled",
        "exposed",
        "disclosed",
        "served",
        "mounted",
        "method",
        "methods",
        "stack",
        "stacks",
        "web",
        "root",
        "end-of-life",
        "outdated",
        "still",
        "missing",
    ]
)


def _normalise_endpoint(endpoint: str) -> str:
    """Collapse endpoint spellings that refer to the same surface.

    ``/`` keeps its identity (never collapse to empty), ``/a/`` becomes
    ``/a``, and the wording agents wrap around ports is stripped so
    ``/ and /dav/`` and ``/dav/`` agree.
    """
    import re

    value = (endpoint or "").strip().lower()
    value = value.split("?")[0]
    # Drop the "port 80" / "ports 32768 and 8080" prose agents add.
    value = re.sub(r"\bports?\s+[\d\s,and]*", "", value)
    value = value.replace(" and ", ", ")
    parts = []
    for chunk in value.split(","):
        chunk = chunk.strip().rstrip("/")
        if chunk:
            parts.append(chunk)
    if not parts:
        return "/"
    return ",".join(sorted(set(parts)))


def _finding_key(title: str, endpoint: str) -> tuple[str, str]:
    """Normalise a finding into a stable identity for duplicate detection."""
    import re

    words = re.findall(r"[a-z0-9]+", (title or "").lower())
    # Drop agent bookkeeping words so "XSS in page param — Blue review"
    # collapses onto "XSS in page param".
    kept = [w for w in words if w not in _NOISE]
    stem = " ".join(kept[:10])
    return stem, _normalise_endpoint(endpoint)


def _significant(title: str) -> tuple[set[str], set[str]]:
    """Split a title into (identifying tokens, acronyms/identifiers)."""
    import re

    words = [w for w in re.findall(r"[a-z0-9]+", (title or "").lower()) if w not in _NOISE]
    identity = {w for w in words if w not in _FILLER and len(w) > 2}
    # Decisive = product names and identifiers: a CVE id, a version, a file or
    # service name. Acronyms only count from four letters up, so the "xss"
    # inside "index" and "page" cannot masquerade as a shared identifier.
    decisive = {
        w
        for w in identity
        if any(ch.isdigit() for ch in w)
        or (
            len(w) >= 4 and w in {"webdav", "phpinfo", "trace", "server", "status", "dav", "vsftpd"}
        )
    }
    return identity, decisive


def _titles_overlap(a: str, b: str, threshold: float = 0.5) -> bool:
    """True when two titles describe the same issue in different words.

    The signal is the *shared identifying vocabulary*: two phrasings of the
    same phpinfo/TRACE/WebDAV/headers issue share distinctive words even when
    the surrounding prose differs. "Missing CSP header" vs "Missing HSTS
    header" share only the generic filler, so they stay separate.

    Decisive tokens (acronyms, versions, identifiers) break ties: a pair that
    agrees on one of those is a merge even if the rest is reworded.
    """
    left, left_dec = _significant(a)
    right, right_dec = _significant(b)
    if not left or not right:
        return False
    shared = left & right
    shared_dec = left_dec & right_dec
    # An acronym/identifier both sides name is decisive on its own.
    if shared_dec:
        return True
    if not shared:
        return False
    # Distinguishing words are those only one side has. If each side names its
    # own specific thing (CSP vs HSTS, xss vs disclosure), they are different
    # findings even though the surrounding wording matches.
    left_only = left - right
    right_only = right - left
    if left_only and right_only:
        # Shared vocabulary must clearly dominate for a merge.
        ratio = len(shared) / max(len(left), len(right))
        if ratio < 0.6:
            return False
    return len(shared) / max(1, min(len(left), len(right))) >= threshold


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
