"""Async LLM client supporting OpenAI-compatible and Anthropic APIs.

The framework never assumes a local model: every provider is reached over
HTTP using credentials stored in the global configuration. A single client
therefore works with OpenAI, OpenRouter, Groq, DeepSeek, Together, Mistral,
xAI, vLLM, LM Studio, Ollama (OpenAI compatibility mode), Anthropic and any
other OpenAI-compatible endpoint.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import AsyncIterator
from typing import Any

import httpx

from splitagent.config import LLMSettings
from splitagent.errors import LLMError
from splitagent.llm.types import ChatMessage, LLMEvent, ToolCall, ToolSpec

# Status codes and message shapes worth a second attempt. Everything else
# (auth, bad request, model not found) fails fast so the operator sees the
# real cause instead of a slow retry loop.
_RETRYABLE_STATUS = (408, 409, 425, 429, 500, 502, 503, 504, 522, 524)
_RETRYABLE_HINTS = (
    "rate limit",
    "rate_limit",
    "too many requests",
    "overloaded",
    "temporarily",
    "timeout",
    "timed out",
    "connection reset",
    "connection aborted",
    "connection error",
    "server error",
    "bad gateway",
    "service unavailable",
    "gateway timeout",
    "internal error",
    "try again",
)


def _is_retryable(message: str) -> bool:
    """Decide whether an error is transient."""
    if not message:
        return False
    lowered = message.lower()
    status = re.search(r"\bhttp\s+(\d{3})", lowered)
    if status:
        return int(status.group(1)) in _RETRYABLE_STATUS
    return any(hint in lowered for hint in _RETRYABLE_HINTS)


class LLMClient:
    """Thin async wrapper around the two supported wire protocols."""

    def __init__(self, settings: LLMSettings):
        self.settings = settings
        self._client: httpx.AsyncClient | None = None
        # Populated when a retry happens, so the UI can explain a pause.
        self.last_retry: dict[str, Any] | None = None

    # -- lifecycle -------------------------------------------------------- #
    async def __aenter__(self) -> LLMClient:
        self._client = httpx.AsyncClient(timeout=self.settings.timeout)
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.settings.timeout)
        return self._client

    # -- headers ---------------------------------------------------------- #
    def _headers(self) -> dict[str, str]:
        from splitagent import __version__

        headers = {
            "Content-Type": "application/json",
            # Identify the client, as requested by gateway providers (e.g. OpenCode Go).
            "User-Agent": self.settings.user_agent or f"SplitAgent/{__version__}",
        }
        key = self.settings.resolved_api_key()
        if self.settings.protocol == "anthropic":
            if key:
                headers["x-api-key"] = key
            headers["anthropic-version"] = "2023-06-01"
        else:
            if key:
                headers["Authorization"] = f"Bearer {key}"
        # Stable per-conversation id for routing and prompt caching.
        if self.settings.session_id:
            headers["x-opencode-session"] = self.settings.session_id
        headers.update(self.settings.extra_headers or {})
        return headers

    def _endpoint(self) -> str:
        base = (self.settings.base_url or "").rstrip("/")
        if self.settings.protocol == "anthropic":
            if base.endswith("/messages"):
                return base
            return f"{base}/messages"
        if base.endswith("/chat/completions"):
            return base
        return f"{base}/chat/completions"

    # -- public API ------------------------------------------------------- #
    def _with_cache_points(self, messages: list[ChatMessage]) -> list[ChatMessage]:
        """Mark cache breakpoints the way OpenCode does.

        The system prompt plus the last exchanged messages are the stable
        prefix a provider can reuse. This is a no-op when ``prompt_cache`` is
        disabled or the provider has no explicit marker.
        """
        if not self.settings.prompt_cache:
            return messages
        system = [m for m in messages if m.role == "system"][: self.settings.cache_system_messages]
        tail = [m for m in messages if m.role != "system"][-self.settings.cache_tail_messages :]
        for message in {id(m): m for m in [*system, *tail]}.values():
            message.cache = True
        return messages

    async def stream(
        self, messages: list[ChatMessage], tools: list[ToolSpec] | None = None
    ) -> AsyncIterator[LLMEvent]:
        """Yield incremental events for a completion request.

        Transient provider failures are retried with exponential backoff. A
        streaming response that fails *after* emitting content is not retried
        blindly - only failures seen before any text arrives are, so a long
        answer is never duplicated.
        """
        messages = self._with_cache_points(messages)
        attempts = max(1, self.settings.max_retries + 1)
        delay = self.settings.retry_initial_delay

        for attempt in range(1, attempts + 1):
            emitted = False
            retryable = ""
            try:
                stream = (
                    self._stream_anthropic(messages, tools or [])
                    if self.settings.protocol == "anthropic"
                    else self._stream_openai(messages, tools or [])
                )
                async for event in stream:
                    if event.type in ("text", "tool_call", "reasoning"):
                        emitted = True
                    if event.type == "error":
                        if not emitted and _is_retryable(event.error or ""):
                            retryable = event.error or ""
                            break
                        yield event
                        return
                    yield event
                if not retryable:
                    return
            except httpx.HTTPError as exc:
                if emitted or not _is_retryable(str(exc)):
                    yield LLMEvent(type="error", error=f"Connection error: {exc}")
                    return
                retryable = str(exc)

            if not retryable or attempt == attempts:
                yield LLMEvent(
                    type="error",
                    error=(
                        f"{retryable} (gave up after {attempts} attempts)"
                        if retryable
                        else "Unknown LLM error"
                    ),
                )
                return

            yield self._emit_retry(attempt, attempts, delay, retryable)
            await asyncio.sleep(delay)
            delay = min(delay * 2, self.settings.retry_max_delay)

    def _emit_retry(self, attempt: int, attempts: int, delay: float, reason: str) -> LLMEvent:
        """Surface the retry so the UI can show it instead of seeming stuck."""
        self.last_retry = {
            "attempt": attempt,
            "of": attempts,
            "delay": delay,
            "reason": reason[:300],
        }
        return LLMEvent(type="retry", data=dict(self.last_retry))

    async def complete(
        self, messages: list[ChatMessage], tools: list[ToolSpec] | None = None
    ) -> tuple[ChatMessage, dict[str, Any]]:
        """Run a full completion, gathering the streamed events."""
        content_parts: list[str] = []
        reasoning_parts: list[str] = []
        calls: dict[str, ToolCall] = {}
        usage: dict[str, Any] = {}

        async for event in self.stream(messages, tools):
            if event.type == "text":
                content_parts.append(event.text)
            elif event.type == "reasoning":
                reasoning_parts.append(event.text)
            elif event.type == "tool_call" and event.tool_call is not None:
                calls[event.tool_call.id] = event.tool_call
            elif event.type == "usage" and event.usage:
                usage.update(event.usage)
            elif event.type == "error":
                raise LLMError(event.error or "Unknown LLM error")

        message = ChatMessage(
            role="assistant",
            content="".join(content_parts),
            reasoning="".join(reasoning_parts),
            tool_calls=list(calls.values()),
        )
        return message, usage

    # -- OpenAI-compatible ------------------------------------------------- #
    async def _stream_openai(
        self, messages: list[ChatMessage], tools: list[ToolSpec]
    ) -> AsyncIterator[LLMEvent]:
        body: dict[str, Any] = {
            "model": self.settings.model,
            "messages": [m.to_openai(cache=m.cache) for m in messages],
            "temperature": self.settings.temperature,
            "max_tokens": self.settings.max_tokens,
            "stream": bool(self.settings.stream),
        }
        if tools:
            body["tools"] = [t.to_openai() for t in tools]
            body["tool_choice"] = "auto"
        if self.settings.stream:
            body["stream_options"] = {"include_usage": True}

        if not self.settings.stream:
            message, usage = await self._openai_nonstream(body)
            if message.content:
                yield LLMEvent(type="text", text=message.content)
            for call in message.tool_calls:
                yield LLMEvent(type="tool_call", tool_call=call)
            yield LLMEvent(type="usage", usage=usage)
            yield LLMEvent(type="done")
            return

        partial_calls: dict[int, dict[str, str]] = {}
        usage: dict[str, Any] = {}
        try:
            async with self._http().stream(
                "POST", self._endpoint(), json=body, headers=self._headers()
            ) as response:
                if response.status_code >= 400:
                    detail = (await response.aread()).decode("utf-8", "replace")
                    yield LLMEvent(
                        type="error",
                        error=f"HTTP {response.status_code}: {detail[:800]}",
                    )
                    return
                async for line in response.aiter_lines():
                    if not line or not line.startswith("data:"):
                        continue
                    payload = line[5:].strip()
                    if payload == "[DONE]":
                        break
                    try:
                        chunk = json.loads(payload)
                    except json.JSONDecodeError:
                        continue
                    if chunk.get("usage"):
                        usage.update(chunk["usage"])
                    choices = chunk.get("choices") or []
                    if not choices:
                        continue
                    delta = choices[0].get("delta") or {}
                    text = delta.get("content")
                    if text:
                        yield LLMEvent(type="text", text=text)
                    reasoning = delta.get("reasoning_content") or delta.get("reasoning")
                    if isinstance(reasoning, str) and reasoning:
                        yield LLMEvent(type="reasoning", text=reasoning)
                    for tc in delta.get("tool_calls") or []:
                        index = tc.get("index", 0)
                        slot = partial_calls.setdefault(
                            index, {"id": "", "name": "", "arguments": ""}
                        )
                        if tc.get("id"):
                            slot["id"] = tc["id"]
                        fn = tc.get("function") or {}
                        if fn.get("name"):
                            slot["name"] = fn["name"]
                        if fn.get("arguments"):
                            slot["arguments"] += fn["arguments"]
        except httpx.HTTPError as exc:
            yield LLMEvent(type="error", error=f"Connection error: {exc}")
            return

        for index in sorted(partial_calls):
            slot = partial_calls[index]
            call = ToolCall(
                id=slot["id"] or f"call_{index}",
                name=slot["name"],
                arguments=slot["arguments"] or "{}",
            )
            if call.name:
                yield LLMEvent(type="tool_call", tool_call=call)
        if usage:
            yield LLMEvent(type="usage", usage=usage)
        yield LLMEvent(type="done")

    async def _openai_nonstream(self, body: dict[str, Any]) -> tuple[ChatMessage, dict[str, Any]]:
        body = {**body, "stream": False}
        try:
            response = await self._http().post(self._endpoint(), json=body, headers=self._headers())
        except httpx.HTTPError as exc:
            raise LLMError(f"Connection error: {exc}") from exc
        if response.status_code >= 400:
            raise LLMError(f"HTTP {response.status_code}: {response.text[:800]}")
        data = response.json()
        usage = data.get("usage") or {}
        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        calls = [
            ToolCall(
                id=call.get("id", f"call_{i}"),
                name=(call.get("function") or {}).get("name", ""),
                arguments=(call.get("function") or {}).get("arguments", "{}"),
            )
            for i, call in enumerate(message.get("tool_calls") or [])
        ]
        return (
            ChatMessage(
                role="assistant",
                content=message.get("content") or "",
                reasoning=message.get("reasoning_content") or message.get("reasoning") or "",
                tool_calls=calls,
            ),
            usage,
        )

    # -- Anthropic --------------------------------------------------------- #
    async def _stream_anthropic(
        self, messages: list[ChatMessage], tools: list[ToolSpec]
    ) -> AsyncIterator[LLMEvent]:
        system_parts = [m.content for m in messages if m.role == "system"]
        conversation = [m for m in messages if m.role != "system"]
        body: dict[str, Any] = {
            "model": self.settings.model,
            "messages": [m.to_anthropic(cache=m.cache) for m in conversation],
            "max_tokens": self.settings.max_tokens,
            "temperature": self.settings.temperature,
            "stream": True,
        }
        if system_parts:
            # Anthropic caches the system block explicitly; this is the largest
            # and most stable part of the prefix.
            block: dict[str, Any] = {"type": "text", "text": "\n\n".join(system_parts)}
            if self.settings.prompt_cache:
                block["cache_control"] = {"type": "ephemeral"}
            body["system"] = [block]
        if tools:
            body["tools"] = [t.to_anthropic() for t in tools]

        current_tool: dict[str, Any] | None = None
        usage: dict[str, Any] = {}
        try:
            async with self._http().stream(
                "POST", self._endpoint(), json=body, headers=self._headers()
            ) as response:
                if response.status_code >= 400:
                    detail = (await response.aread()).decode("utf-8", "replace")
                    yield LLMEvent(
                        type="error",
                        error=f"HTTP {response.status_code}: {detail[:800]}",
                    )
                    return
                async for line in response.aiter_lines():
                    if not line or not line.startswith("data:"):
                        continue
                    payload = line[5:].strip()
                    if not payload:
                        continue
                    try:
                        event = json.loads(payload)
                    except json.JSONDecodeError:
                        continue
                    etype = event.get("type")
                    if etype == "content_block_start":
                        block = event.get("content_block") or {}
                        if block.get("type") == "tool_use":
                            current_tool = {
                                "id": block.get("id", ""),
                                "name": block.get("name", ""),
                                "arguments": "",
                            }
                    elif etype == "content_block_delta":
                        delta = event.get("delta") or {}
                        if delta.get("type") == "text_delta":
                            yield LLMEvent(type="text", text=delta.get("text", ""))
                        elif delta.get("type") == "input_json_delta" and current_tool:
                            current_tool["arguments"] += delta.get("partial_json", "")
                    elif etype == "content_block_stop":
                        if current_tool:
                            call = ToolCall(
                                id=current_tool["id"] or "call_0",
                                name=current_tool["name"],
                                arguments=current_tool["arguments"] or "{}",
                            )
                            if call.name:
                                yield LLMEvent(type="tool_call", tool_call=call)
                            current_tool = None
                    elif etype == "message_delta":
                        if event.get("usage"):
                            usage.update(event["usage"])
                    elif etype == "error":
                        error = event.get("error") or {}
                        yield LLMEvent(
                            type="error",
                            error=str(error.get("message") or error),
                        )
                        return
        except httpx.HTTPError as exc:
            yield LLMEvent(type="error", error=f"Connection error: {exc}")
            return

        if usage:
            yield LLMEvent(type="usage", usage=usage)
        yield LLMEvent(type="done")

    # -- utility ----------------------------------------------------------- #
    async def list_models(self) -> list[dict[str, str]]:
        """Fetch the model catalogue from an OpenAI-compatible ``/models``."""
        base = (self.settings.base_url or "").rstrip("/")
        url = f"{base}/models"
        headers = self._headers()
        headers.pop("Content-Type", None)
        try:
            async with httpx.AsyncClient(timeout=25.0) as client:
                response = await client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            raise LLMError(f"Connection error: {exc}") from exc
        if response.status_code >= 400:
            raise LLMError(f"HTTP {response.status_code}: {response.text[:300]}")
        data = response.json()
        items = data.get("data") if isinstance(data, dict) else None
        if items is None and isinstance(data, dict):
            items = data.get("models")
        if not isinstance(items, list):
            return []
        models: list[dict[str, str]] = []
        for item in items:
            if isinstance(item, str):
                models.append({"id": item, "name": item})
                continue
            if not isinstance(item, dict):
                continue
            model_id = item.get("id") or item.get("name") or ""
            if not model_id:
                continue
            models.append({"id": str(model_id), "name": str(item.get("name") or model_id)})
        return models

    async def test_connection(self) -> tuple[bool, str]:
        """Cheap round-trip used by the setup wizard to validate credentials."""
        if not self.settings.session_id:
            self.settings.session_id = "splitagent-connectivity"
        try:
            message, _ = await self.complete(
                [ChatMessage(role="user", content="Reply with the single word: ok")]
            )
        except LLMError as exc:
            return False, str(exc)
        except Exception as exc:  # pragma: no cover - defensive
            return False, f"{type(exc).__name__}: {exc}"
        return True, (message.content or "").strip()[:200]
