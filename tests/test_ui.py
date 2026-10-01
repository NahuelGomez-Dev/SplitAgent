from __future__ import annotations

from rich.console import Console

from splitagent.config import GlobalConfig, ProjectConfig
from splitagent.core.bus import Event
from splitagent.ui.stream import StreamRenderer


def test_stream_renderer_handles_events():
    console = Console(record=True, width=120)
    renderer = StreamRenderer(console=console, show_thinking=True)
    renderer.handle(
        Event(
            type="session.start", data={"target": "t", "model": "m", "provider": "p", "rounds": 2}
        )
    )
    renderer.handle(Event(type="round.start", data={"round": 1, "total": 2}))
    renderer.handle(Event(type="agent.text", agent="red", data={"text": "hello"}))
    renderer.handle(
        Event(
            type="agent.tool_call",
            agent="red",
            data={"tool": "port_scan", "arguments": {"host": "x"}},
        )
    )
    renderer.handle(Event(type="finding", data={"id": "F-1", "title": "X", "severity": "high"}))
    layout = renderer.render()
    assert layout is not None
    assert renderer.findings


async def test_tui_composes(tmp_path, monkeypatch):
    monkeypatch.setenv("SPLITAGENT_HOME", str(tmp_path / "home"))
    from splitagent.ui.app import SplitAgentApp

    app = SplitAgentApp(GlobalConfig(), ProjectConfig())
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.query_one("#findings-table") is not None
        assert app.query_one("#topbar-title") is not None
