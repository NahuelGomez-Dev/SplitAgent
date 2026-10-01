"""Tests for the Anthropic wire protocol.

The framework promises any OpenAI-compatible *or* Anthropic endpoint, so the
Anthropic path is exercised against a server that speaks the real event
sequence (``content_block_start`` / ``content_block_delta`` / ``message_delta``)
rather than a mock.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from splitagent.config import LLMSettings
from splitagent.llm.client import LLMClient
from splitagent.llm.types import ChatMessage, ToolCall, ToolSpec

CAPTURED: list[dict] = []


def _sse(events: list[dict]) -> bytes:
    body = "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events)
    return body.encode()


def _text_stream(text: str, usage_in: int = 10, usage_out: int = 5) -> bytes:
    return _sse(
        [
            {"type": "message_start", "message": {"usage": {"input_tokens": usage_in}}},
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": text},
            },
            {"type": "content_block_stop", "index": 0},
            {"type": "message_delta", "usage": {"output_tokens": usage_out}},
            {"type": "message_stop"},
        ]
    )


def _tool_stream(name: str, arguments: str, tool_id: str = "toolu_1") -> bytes:
    return _sse(
        [
            {"type": "message_start", "message": {"usage": {"input_tokens": 20}}},
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "tool_use", "id": tool_id, "name": name},
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": arguments},
            },
            {"type": "content_block_stop", "index": 0},
            {"type": "message_delta", "usage": {"output_tokens": 8}},
            {"type": "message_stop"},
        ]
    )


class AnthropicServer(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    payload = b""
    status = 200

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        raw = self.rfile.read(length)
        try:
            CAPTURED.append(
                {
                    "body": json.loads(raw),
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                }
            )
        except json.JSONDecodeError:
            CAPTURED.append({"body": {}, "headers": {}})

        data = type(self).payload
        self.send_response(type(self).status)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.fixture()
def anthropic_server():
    CAPTURED.clear()

    def _start(payload: bytes, status: int = 200) -> str:
        AnthropicServer.payload = payload
        AnthropicServer.status = status
        server = ThreadingHTTPServer(("127.0.0.1", 0), AnthropicServer)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        server._splitagent_url = f"http://127.0.0.1:{server.server_port}"  # type: ignore[attr-defined]
        return server._splitagent_url  # type: ignore[attr-defined]

    yield _start


def _settings(base_url: str, **kwargs) -> LLMSettings:
    defaults: dict = {
        "provider": "anthropic",
        "protocol": "anthropic",
        "base_url": base_url,
        "api_key": "test-key",
        "model": "claude-3-5-sonnet-latest",
        "stream": True,
        "max_retries": 0,
    }
    defaults.update(kwargs)
    return LLMSettings(**defaults)


# --------------------------------------------------------------------------- #
# request shape
# --------------------------------------------------------------------------- #
async def test_endpoint_is_messages(anthropic_server):
    url = anthropic_server(_text_stream("hi"))
    async with LLMClient(_settings(url)) as client:
        assert client._endpoint() == f"{url}/messages"


async def test_auth_headers_are_anthropic_style(anthropic_server):
    url = anthropic_server(_text_stream("hi"))
    async with LLMClient(_settings(url)) as client:
        headers = client._headers()
    assert headers["x-api-key"] == "test-key"
    assert headers["anthropic-version"] == "2023-06-01"
    # Anthropic uses x-api-key, not a bearer token.
    assert "Authorization" not in headers


async def test_system_prompt_is_sent_as_blocks(anthropic_server):
    url = anthropic_server(_text_stream("hi"))
    messages = [
        ChatMessage(role="system", content="You are a tester."),
        ChatMessage(role="user", content="go"),
    ]
    async with LLMClient(_settings(url)) as client:
        await client.complete(messages)

    body = CAPTURED[-1]["body"]
    assert isinstance(body["system"], list)
    assert body["system"][0]["text"] == "You are a tester."
    # The system prompt must not also appear in the messages array.
    assert all(m["role"] != "system" for m in body["messages"])


async def test_system_block_carries_the_cache_marker(anthropic_server):
    url = anthropic_server(_text_stream("hi"))
    messages = [
        ChatMessage(role="system", content="stable"),
        ChatMessage(role="user", content="go"),
    ]
    async with LLMClient(_settings(url, prompt_cache=True)) as client:
        await client.complete(messages)
    assert CAPTURED[-1]["body"]["system"][0]["cache_control"] == {"type": "ephemeral"}


async def test_cache_can_be_disabled(anthropic_server):
    url = anthropic_server(_text_stream("hi"))
    messages = [
        ChatMessage(role="system", content="stable"),
        ChatMessage(role="user", content="go"),
    ]
    async with LLMClient(_settings(url, prompt_cache=False)) as client:
        await client.complete(messages)
    assert "cache_control" not in CAPTURED[-1]["body"]["system"][0]


async def test_tools_use_input_schema(anthropic_server):
    url = anthropic_server(_text_stream("done"))
    tools = [
        ToolSpec(
            name="port_scan",
            description="Scan ports",
            parameters={"type": "object", "properties": {"host": {"type": "string"}}},
        )
    ]
    async with LLMClient(_settings(url)) as client:
        await client.complete([ChatMessage(role="user", content="scan")], tools)

    sent = CAPTURED[-1]["body"]["tools"][0]
    # Anthropic expects `input_schema`, not `parameters`.
    assert sent["name"] == "port_scan"
    assert "input_schema" in sent
    assert "parameters" not in sent


# --------------------------------------------------------------------------- #
# streaming
# --------------------------------------------------------------------------- #
async def test_text_streaming(anthropic_server):
    url = anthropic_server(_text_stream("Hello from Claude"))
    async with LLMClient(_settings(url)) as client:
        message, usage = await client.complete([ChatMessage(role="user", content="hi")])
    assert message.content == "Hello from Claude"
    assert message.role == "assistant"
    assert usage["input_tokens"] == 10
    assert usage["output_tokens"] == 5


async def test_incremental_text_events(anthropic_server):
    url = anthropic_server(_text_stream("chunked"))
    chunks: list[str] = []
    async with LLMClient(_settings(url)) as client:
        async for event in client.stream([ChatMessage(role="user", content="hi")]):
            if event.type == "text":
                chunks.append(event.text)
    assert "".join(chunks) == "chunked"
    assert len(chunks) >= 1


async def test_tool_use_streaming(anthropic_server):
    url = anthropic_server(_tool_stream("http_request", '{"url":"http://x"}'))
    async with LLMClient(_settings(url)) as client:
        message, _ = await client.complete([ChatMessage(role="user", content="scan")])
    assert len(message.tool_calls) == 1
    call = message.tool_calls[0]
    assert call.name == "http_request"
    assert call.id == "toolu_1"
    assert call.parsed_arguments() == {"url": "http://x"}


async def test_tool_arguments_are_reassembled_from_partial_json(anthropic_server):
    """Anthropic streams the JSON input in fragments that must be joined."""
    payload = _sse(
        [
            {"type": "message_start", "message": {"usage": {"input_tokens": 5}}},
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "tool_use", "id": "t1", "name": "x"},
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": '{"a"'},
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": ": 1, "},
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": '"b": 2}'},
            },
            {"type": "content_block_stop", "index": 0},
            {"type": "message_stop"},
        ]
    )
    url = anthropic_server(payload)
    async with LLMClient(_settings(url)) as client:
        message, _ = await client.complete([ChatMessage(role="user", content="x")])
    assert message.tool_calls[0].parsed_arguments() == {"a": 1, "b": 2}


async def test_text_and_content_blocks_are_not_confused(anthropic_server):
    """A text block followed by a tool block must yield both."""
    payload = _sse(
        [
            {"type": "message_start", "message": {"usage": {"input_tokens": 5}}},
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "thinking... "},
            },
            {"type": "content_block_stop", "index": 0},
            {
                "type": "content_block_start",
                "index": 1,
                "content_block": {"type": "tool_use", "id": "t9", "name": "nmap"},
            },
            {
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "input_json_delta", "partial_json": "{}"},
            },
            {"type": "content_block_stop", "index": 1},
            {"type": "message_stop"},
        ]
    )
    url = anthropic_server(payload)
    async with LLMClient(_settings(url)) as client:
        message, _ = await client.complete([ChatMessage(role="user", content="x")])
    assert message.content == "thinking... "
    assert message.tool_calls[0].name == "nmap"


# --------------------------------------------------------------------------- #
# errors
# --------------------------------------------------------------------------- #
async def test_http_error_is_surfaced(anthropic_server):
    from splitagent.errors import LLMError

    url = anthropic_server(b'{"error":{"message":"invalid api key"}}', status=401)
    async with LLMClient(_settings(url)) as client:
        with pytest.raises(LLMError) as exc:
            await client.complete([ChatMessage(role="user", content="hi")])
    assert "401" in str(exc.value)


async def test_stream_error_event_is_reported(anthropic_server):
    payload = _sse(
        [{"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}]
    )
    url = anthropic_server(payload)
    errors: list[str] = []
    async with LLMClient(_settings(url)) as client:
        async for event in client.stream([ChatMessage(role="user", content="hi")]):
            if event.type == "error":
                errors.append(event.error or "")
    assert errors and "Overloaded" in errors[0]


async def test_connection_error_is_clean():
    """An unreachable host must raise a clear LLMError, not a raw socket error."""
    from splitagent.errors import LLMError

    settings = _settings("http://127.0.0.1:1", timeout=2, max_retries=0)
    async with LLMClient(settings) as client:
        with pytest.raises(LLMError):
            await client.complete([ChatMessage(role="user", content="hi")])


# --------------------------------------------------------------------------- #
# conversion helpers
# --------------------------------------------------------------------------- #
def test_tool_result_converts_to_a_user_block():
    message = ChatMessage(role="tool", content="output", tool_call_id="toolu_1")
    payload = message.to_anthropic()
    assert payload["role"] == "user"
    block = payload["content"][0]
    assert block["type"] == "tool_result"
    assert block["tool_use_id"] == "toolu_1"
    assert block["content"] == "output"


def test_assistant_tool_call_converts_to_a_tool_use_block():
    message = ChatMessage(
        role="assistant",
        content="",
        tool_calls=[ToolCall(id="t1", name="nmap", arguments='{"host":"x"}')],
    )
    payload = message.to_anthropic()
    block = payload["content"][0]
    assert block["type"] == "tool_use"
    assert block["input"] == {"host": "x"}


def test_openai_and_anthropic_shapes_differ():
    message = ChatMessage(role="user", content="hi")
    assert message.to_openai()["content"] == "hi"
    # Anthropic accepts a plain string for a simple user turn.
    assert message.to_anthropic() == {"role": "user", "content": "hi"}
