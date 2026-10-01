from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from splitagent.config import (
    GlobalConfig,
    LLMSettings,
    ProjectConfig,
    RunConfig,
    TargetConfig,
)
from splitagent.core.bus import EventBus
from splitagent.core.context import SharedContext
from splitagent.core.engine import Engine
from splitagent.tools.base import ToolContext


class _TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "nginx")
        self.end_headers()
        self.wfile.write(b"<html><title>Target</title><body>ok</body></html>")

    def log_message(self, *args):
        pass


class _MockLLMHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        messages = body.get("messages", [])
        already_used_tool = any(m.get("role") == "tool" for m in messages)
        if already_used_tool:
            payload = _text_stream("Analysis complete: no confirmed exploitable issues.")
        else:
            payload = _tool_stream("read_shared_context", "{}")
        data = payload.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def _tool_stream(name: str, arguments: str) -> str:
    chunk = {
        "choices": [
            {
                "delta": {
                    "tool_calls": [
                        {
                            "index": 0,
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": name, "arguments": arguments},
                        }
                    ]
                }
            }
        ]
    }
    return f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n"


def _text_stream(text: str) -> str:
    chunk = {"choices": [{"delta": {"content": text}}]}
    return f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n"


@pytest.fixture()
def servers():
    target = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
    llm = ThreadingHTTPServer(("127.0.0.1", 0), _MockLLMHandler)
    for server in (target, llm):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    yield (
        f"http://127.0.0.1:{target.server_port}",
        f"http://127.0.0.1:{llm.server_port}/v1",
    )
    target.shutdown()
    llm.shutdown()


async def test_nested_usage_counters_are_flattened(tmp_path):
    """Providers nest cache/reasoning counters; the totals must include them."""
    from splitagent.agents.base import BaseAgent
    from splitagent.config import LLMSettings
    from splitagent.llm.client import LLMClient
    from splitagent.tools.registry import ToolRegistry

    class Probe(BaseAgent):
        name = "red"

    ctx = SharedContext.create(target="http://t", directory=tmp_path)
    agent = Probe(
        client=LLMClient(LLMSettings(api_key="k", model="m")),
        context=ctx,
        tool_context=ToolContext(target=TargetConfig(url="http://t"), run=RunConfig(), context=ctx),
        registry=ToolRegistry(),
        bus=EventBus(),
        system_prompt="x",
    )
    agent._accumulate_usage(
        {
            "prompt_tokens": 1000,
            "completion_tokens": 50,
            "total_tokens": 1050,
            "prompt_tokens_details": {"cached_tokens": 900},
            "completion_tokens_details": {"reasoning_tokens": 20},
        }
    )
    agent._accumulate_usage({"prompt_tokens_details": {"cached_tokens": 100}})
    assert agent.usage_total["prompt_tokens"] == 1000
    assert agent.usage_total["cached_tokens"] == 1000  # 900 + 100
    assert agent.usage_total["reasoning_tokens"] == 20


async def test_engine_runs_a_round(servers, tmp_path, monkeypatch):
    target_url, llm_url = servers
    monkeypatch.setenv("SPLITAGENT_HOME", str(tmp_path / "home"))

    global_config = GlobalConfig(
        llm=LLMSettings(
            provider="custom",
            protocol="openai",
            base_url=llm_url,
            api_key="test-key",
            model="mock-model",
            stream=True,
        )
    )
    project = ProjectConfig(name="test-project")
    project.target.url = target_url
    project.target.scope = ["127.0.0.1"]
    project.run.rounds = 1
    project.run.max_steps = 4
    project.run.sandbox.enabled = False

    bus = EventBus()
    events: list[str] = []
    bus.subscribe(lambda event: events.append(event.type))

    engine = Engine(global_config, project, bus=bus)
    context = await engine.run()

    assert len(context.state.rounds) == 1
    assert context.state.rounds[0].red_summary
    assert context.state.rounds[0].blue_summary
    assert "session.start" in events
    assert "round.start" in events
    assert "agent.tool_call" in events
    assert "round.end" in events
    assert context.path_for().exists()
