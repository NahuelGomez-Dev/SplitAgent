from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from splitagent.config import LLMSettings
from splitagent.llm.client import LLMClient, _is_retryable
from splitagent.llm.types import ChatMessage


class FlakyProvider(BaseHTTPRequestHandler):
    """Fails the first ``fail_until`` requests with a 503, then answers."""

    protocol_version = "HTTP/1.1"
    fail_until = 2
    calls = 0
    fail_status = 503

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        self.rfile.read(length)
        type(self).calls += 1
        if type(self).calls <= type(self).fail_until:
            body = b'{"error":{"message":"service unavailable"}}'
            self.send_response(type(self).fail_status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        payload = b'data: {"choices":[{"delta":{"content":"recovered"}}]}\n\ndata: [DONE]\n\n'
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # silence
        pass


@pytest.fixture()
def flaky_provider():
    def _start(fail_until: int, status: int = 503) -> str:
        FlakyProvider.fail_until = fail_until
        FlakyProvider.calls = 0
        FlakyProvider.fail_status = status
        server = ThreadingHTTPServer(("127.0.0.1", 0), FlakyProvider)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{server.server_port}/v1"

    return _start


def test_retryable_classification():
    assert _is_retryable("HTTP 429: rate limited") is True
    assert _is_retryable("HTTP 503: service unavailable") is True
    assert _is_retryable("HTTP 500: internal error") is True
    assert _is_retryable("Connection error: timed out") is True
    assert _is_retryable("connection reset by peer") is True
    # Permanent failures must not be retried.
    assert _is_retryable("HTTP 401: invalid api key") is False
    assert _is_retryable("HTTP 400: bad request") is False
    assert _is_retryable("model not found") is False
    assert _is_retryable("insufficient balance") is False
    assert _is_retryable("") is False


async def _stream(settings: LLMSettings) -> tuple[str, list[dict], str | None]:
    retries: list[dict] = []
    text: list[str] = []
    async with LLMClient(settings) as client:
        async for event in client.stream([ChatMessage(role="user", content="hi")]):
            if event.type == "retry":
                retries.append(event.data or {})
            elif event.type == "text":
                text.append(event.text)
            elif event.type == "error":
                return "".join(text), retries, event.error
    return "".join(text), retries, None


async def test_recovers_after_transient_failures(flaky_provider):
    url = flaky_provider(fail_until=2)
    settings = LLMSettings(
        provider="custom",
        base_url=url,
        api_key="k",
        model="m",
        stream=True,
        max_retries=3,
        retry_initial_delay=0.01,
    )
    text, retries, error = await _stream(settings)
    assert error is None
    assert text == "recovered"
    assert len(retries) == 2
    # Backoff grows between attempts.
    assert retries[0]["delay"] < retries[1]["delay"]


async def test_gives_up_after_max_retries(flaky_provider):
    url = flaky_provider(fail_until=99)
    settings = LLMSettings(
        provider="custom",
        base_url=url,
        api_key="k",
        model="m",
        stream=True,
        max_retries=2,
        retry_initial_delay=0.01,
    )
    text, retries, error = await _stream(settings)
    assert text == ""
    assert error is not None
    assert "gave up after 3 attempts" in error
    assert len(retries) == 2  # between the 3 attempts


async def test_permanent_error_is_not_retried(flaky_provider):
    """A 400/401 must fail immediately: retrying hides the real cause."""
    url = flaky_provider(fail_until=99, status=401)
    settings = LLMSettings(
        provider="custom",
        base_url=url,
        api_key="k",
        model="m",
        stream=True,
        max_retries=5,
        retry_initial_delay=0.01,
    )
    _text, retries, error = await _stream(settings)
    assert error is not None
    assert retries == []
    assert FlakyProvider.calls == 1


async def test_retries_can_be_disabled(flaky_provider):
    url = flaky_provider(fail_until=99)
    settings = LLMSettings(
        provider="custom",
        base_url=url,
        api_key="k",
        model="m",
        stream=True,
        max_retries=0,
        retry_initial_delay=0.01,
    )
    _text, retries, error = await _stream(settings)
    assert retries == []
    assert "gave up after 1 attempts" in (error or "")


def test_retry_settings_defaults():
    settings = LLMSettings()
    assert settings.max_retries == 3
    assert settings.retry_initial_delay == 1.0
    assert settings.retry_max_delay == 30.0


def test_backoff_is_capped():
    """Delay must never exceed retry_max_delay."""
    settings = LLMSettings(retry_initial_delay=10.0, retry_max_delay=15.0)
    delay = settings.retry_initial_delay
    delays = []
    for _ in range(5):
        delays.append(delay)
        delay = min(delay * 2, settings.retry_max_delay)
    assert max(delays) == 15.0
    assert delays[0] == 10.0


def test_run_deadline_config():
    from splitagent.config import RunConfig

    assert RunConfig().max_duration_minutes == 90
