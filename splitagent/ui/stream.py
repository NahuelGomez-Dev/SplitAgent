"""Live streaming renderer for the CLI (Rich).

Renders a two-column Red/Blue console with a status header and a findings
footer, updating as events arrive from the engine's event bus.
"""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from splitagent.core.bus import Event
from splitagent.ui import theme as t

MAX_LINES = 600


class StreamRenderer:
    """Subscribes to the bus and paints the audit in real time."""

    def __init__(self, console: Console | None = None, show_thinking: bool = True) -> None:
        self.console = console or Console()
        self.show_thinking = show_thinking
        self.buffers: dict[str, list[tuple[str, str]]] = {"red": [], "blue": []}
        self.findings: list[dict[str, Any]] = []
        self.mitigations: list[dict[str, Any]] = []
        self.logs: list[str] = []
        self.round = 0
        self.total_rounds = 0
        self.phase = "idle"
        self.target = ""
        self.model = ""
        self.provider = ""
        self.resilience = 0.0
        self._live: Live | None = None
        self._printed_logs = 0

    # -- wiring ------------------------------------------------------------ #
    def attach(self, bus) -> Any:
        return bus.subscribe(self.handle)

    # -- lifecycle --------------------------------------------------------- #
    def start(self) -> None:
        if self.console.is_terminal:
            self._live = Live(
                self.render(),
                console=self.console,
                refresh_per_second=12,
                screen=False,
                transient=False,
            )
            self._live.start()
        else:
            self.console.print(
                Text(t.BANNER, style=t.PRIMARY),
            )

    def stop(self) -> None:
        if self._live is not None:
            self._live.update(self.render())
            self._live.stop()
            self._live = None

    def _refresh(self) -> None:
        if self._live is not None:
            self._live.update(self.render())
        else:
            self._print_compact()

    def _print_compact(self) -> None:
        # Non-interactive output: emit each new log line exactly once.
        while self._printed_logs < len(self.logs):
            self.console.print(self.logs[self._printed_logs])
            self._printed_logs += 1

    # -- event handling ---------------------------------------------------- #
    def handle(self, event: Event) -> None:
        etype = event.type
        if etype == "session.start":
            self.target = event.data.get("target", "")
            self.model = event.data.get("model", "")
            self.provider = event.data.get("provider", "")
            self.total_rounds = event.data.get("rounds", 0)
            self.phase = "starting"
        elif etype == "round.start":
            self.round = event.data.get("round", self.round)
            self.phase = "round"
            for agent in ("red", "blue"):
                self._push(agent, "sep", f"-- Round {self.round}/{self.total_rounds} --")
        elif etype == "phase.start":
            self.phase = event.data.get("phase", self.phase)
            color = t.agent_color(event.agent)
            self._push(event.agent, "sep", f"> {event.agent.upper()} phase: {self.phase}")
            self.logs.append(f"[{color}]{event.agent}[/] {self.phase} (round {self.round})")
        elif etype == "agent.text":
            self._push(event.agent, "text", event.data.get("text", ""))
        elif etype == "agent.tool_call":
            tool = event.data.get("tool", "?")
            args = event.data.get("arguments", {})
            preview = json.dumps(args, ensure_ascii=False)
            if len(preview) > 160:
                preview = preview[:160] + "..."
            self._push(event.agent, "tool", f"\n* {tool}({preview})")
            self.logs.append(f"[{t.MUTED}]{event.agent} -> {tool}[/]")
        elif etype == "agent.tool_result":
            output = str(event.data.get("output", "")).replace("\n", " ")
            self._push(event.agent, "result", f"  ~ {output[:220]}")
        elif etype == "finding":
            self.findings.append(event.data)
            self.logs.append(
                f"[{t.severity_color(event.data.get('severity', 'info'))}]"
                f"finding {event.data.get('id')}: {event.data.get('title')}[/]"
            )
        elif etype == "mitigation":
            self.mitigations.append(event.data)
            self.logs.append(
                f"[{t.GREEN}]mitigation {event.data.get('id')} ({event.data.get('kind')})[/]"
            )
        elif etype == "round.end":
            self.resilience = float(event.data.get("resilience", self.resilience))
        elif etype == "log":
            self.logs.append(
                f"[{t.status_color(event.data.get('level', 'info'))}]"
                f"{event.data.get('text', '')}[/]"
            )
        elif etype == "error":
            self.logs.append(f"[{t.RED}]error: {event.data.get('text', '')}[/]")
        elif etype == "session.end":
            self.phase = "done"
            self.resilience = float(event.data.get("resilience", self.resilience))
            self.logs.append(f"[{t.GREEN}]session complete - resilience {self.resilience}/100[/]")
        self._refresh()

    def _push(self, agent: str, kind: str, text: str) -> None:
        buffer = self.buffers.setdefault(agent, [])
        buffer.append((kind, text))
        if len(buffer) > MAX_LINES:
            del buffer[: len(buffer) - MAX_LINES]

    # -- rendering --------------------------------------------------------- #
    def render(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=7),
        )
        layout["header"].update(self._header())
        body = Table.grid(expand=True)
        body.add_column(ratio=1)
        body.add_column(ratio=1)
        body.add_row(
            Panel(
                self._agent_text("red"),
                title=f"[{t.RED}]RED AGENT[/]",
                border_style=t.RED if self.phase == "offense" else t.BORDER,
                padding=(0, 1),
            ),
            Panel(
                self._agent_text("blue"),
                title=f"[{t.SECONDARY}]BLUE AGENT[/]",
                border_style=t.SECONDARY if self.phase == "defense" else t.BORDER,
                padding=(0, 1),
            ),
        )
        layout["body"].update(body)
        layout["footer"].update(self._footer())
        return layout

    def _header(self) -> Panel:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            counts[finding.get("severity", "info")] = (
                counts.get(finding.get("severity", "info"), 0) + 1
            )
        line = Text()
        line.append("SPLITAGENT ", style=f"bold {t.PRIMARY}")
        line.append("- ", style=t.MUTED)
        line.append(self.target or "no target", style=t.TEXT)
        line.append("  -  ", style=t.MUTED)
        line.append(self.provider or "?", style=t.SECONDARY)
        line.append("/", style=t.MUTED)
        line.append(self.model or "?", style=t.SECONDARY)
        line.append("  -  ", style=t.MUTED)
        line.append(f"round {self.round}/{self.total_rounds}", style=t.TEXT)
        line.append("  -  ", style=t.MUTED)
        line.append(f"phase {self.phase}", style=t.ACCENT)
        line.append("  -  ", style=t.MUTED)
        line.append(f"resilience {self.resilience}/100", style=t.GREEN)
        return Panel(line, border_style=t.BORDER, padding=(0, 1))

    def _agent_text(self, agent: str) -> Text:
        text = Text()
        for kind, payload in self.buffers.get(agent, [])[-MAX_LINES:]:
            if kind == "text":
                text.append(payload, style=t.TEXT)
            elif kind == "tool":
                text.append(payload + "\n", style=f"bold {t.CYAN}")
            elif kind == "result":
                text.append(payload + "\n", style=t.MUTED)
            elif kind == "sep":
                text.append("\n" + payload + "\n", style=f"bold {t.ACCENT}")
        if not text.plain:
            text.append("waiting...", style=t.MUTED)
        return text

    def _footer(self) -> Panel:
        table = Table.grid(expand=True)
        table.add_column(ratio=1)
        table.add_column(ratio=2)
        counts = Text()
        for name in ("critical", "high", "medium", "low", "info"):
            value = sum(1 for f in self.findings if f.get("severity") == name)
            counts.append(f"{name[:4].upper()} {value}  ", style=t.severity_color(name))
        counts.append(f"  mitigations {len(self.mitigations)}", style=t.GREEN)
        recent = Text()
        for line in self.logs[-5:]:
            recent.append(line + "\n")
        if not recent.plain:
            recent.append("waiting for events...", style=t.MUTED)
        table.add_row(counts, recent)
        return Panel(
            Group(counts, recent),
            title=f"[{t.MUTED}]STATUS[/]",
            border_style=t.BORDER,
            padding=(0, 1),
        )
