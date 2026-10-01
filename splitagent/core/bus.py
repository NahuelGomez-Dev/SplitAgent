"""A tiny async event bus used to stream agent activity to the UI."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

Listener = Callable[["Event"], Any] | Callable[["Event"], Awaitable[Any]]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class Event:
    """A single unit of agent activity."""

    type: str
    # types: session.start | round.start | phase.start | agent.text |
    #        agent.tool_call | agent.tool_result | finding | mitigation |
    #        phase.end | round.end | session.end | log | error
    agent: str = "core"
    data: dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=_now)

    def summary(self) -> str:
        return self.data.get("text") or self.data.get("title") or self.type


class EventBus:
    """Dispatches events to any number of sync or async listeners."""

    def __init__(self) -> None:
        self._listeners: list[Listener] = []
        self._lock = asyncio.Lock()

    def subscribe(self, listener: Listener) -> Callable[[], None]:
        self._listeners.append(listener)

        def unsubscribe() -> None:
            if listener in self._listeners:
                self._listeners.remove(listener)

        return unsubscribe

    async def emit(self, event: Event) -> None:
        for listener in list(self._listeners):
            try:
                result = listener(event)
                if inspect.isawaitable(result):
                    await result
            except Exception:  # pragma: no cover - a broken UI must not stop the run
                continue

    async def emit_many(self, events: list[Event]) -> None:
        for event in events:
            await self.emit(event)
