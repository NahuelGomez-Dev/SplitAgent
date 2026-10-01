"""Message and event types shared by the LLM clients and the agents."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolSpec:
    """A tool exposed to the model, in JSON-Schema form."""

    name: str
    description: str
    parameters: dict[str, Any]

    def to_openai(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def to_anthropic(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters,
        }


def estimate_tokens(text: str) -> int:
    """Character-based token estimate (OpenCode uses 4 chars per token)."""
    return max(0, round(len(text or "") / 4))


@dataclass
class ToolCall:
    """A tool invocation requested by the model."""

    id: str
    name: str
    arguments: str = "{}"

    def parsed_arguments(self) -> dict[str, Any]:
        if not self.arguments or not self.arguments.strip():
            return {}
        try:
            value = json.loads(self.arguments)
        except json.JSONDecodeError:
            # Some models stream partial or unwrapped JSON; try to salvage it.
            try:
                value = json.loads(self.arguments.strip().strip("`"))
            except json.JSONDecodeError:
                return {"_raw": self.arguments}
        if isinstance(value, dict):
            return value
        return {"_value": value}


@dataclass
class ChatMessage:
    """A single conversation turn, provider agnostic."""

    role: str  # system | user | assistant | tool
    content: str = ""
    reasoning: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None
    compacted: bool = False
    pinned: bool = False
    # Mark this message as a prompt-cache checkpoint (prefix up to and
    # including it can be reused by the provider).
    cache: bool = False

    def token_estimate(self) -> int:
        total = estimate_tokens(self.content) + estimate_tokens(self.reasoning)
        for call in self.tool_calls:
            total += estimate_tokens(call.name) + estimate_tokens(call.arguments)
        return total

    def serialize(self) -> str:
        parts: list[str] = []
        if self.content:
            parts.append(f"{self.role}: {self.content}")
        if self.reasoning:
            parts.append(f"{self.role} reasoning: {self.reasoning}")
        for call in self.tool_calls:
            parts.append(f"tool_call {call.name}({call.arguments})")
        return "\n".join(parts)

    def to_openai(self, cache: bool = False) -> dict[str, Any]:
        if self.role == "tool":
            return {
                "role": "tool",
                "tool_call_id": self.tool_call_id or "",
                "content": self.content,
            }
        message: dict[str, Any] = {"role": self.role, "content": self.content}
        # OpenAI-compatible providers do not take an explicit marker for plain
        # string content; caching is automatic on a stable prefix. When the
        # content is a block list (Anthropic-style) we can mark it though.
        if cache and isinstance(message.get("content"), list):
            for block in message["content"]:
                if block.get("type") == "text":
                    block["cache_control"] = {"type": "ephemeral"}
        # DeepSeek-style reasoning models require the reasoning echoed back.
        if self.reasoning:
            message["reasoning_content"] = self.reasoning
        if self.tool_calls:
            message["tool_calls"] = [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {"name": call.name, "arguments": call.arguments},
                }
                for call in self.tool_calls
            ]
            if not self.content:
                message["content"] = None
        return message

    def to_anthropic(self, cache: bool = False) -> dict[str, Any]:
        marker = {"cache_control": {"type": "ephemeral"}} if cache else {}
        if self.role == "tool":
            block: dict[str, Any] = {
                "type": "tool_result",
                "tool_use_id": self.tool_call_id or "",
                "content": self.content,
            }
            block.update(marker)
            return {"role": "user", "content": [block]}
        if self.role == "assistant" and self.tool_calls:
            blocks: list[dict[str, Any]] = []
            if self.content:
                blocks.append({"type": "text", "text": self.content})
            for call in self.tool_calls:
                blocks.append(
                    {
                        "type": "tool_use",
                        "id": call.id,
                        "name": call.name,
                        "input": call.parsed_arguments(),
                    }
                )
            # A cache checkpoint goes on the last block of the message.
            if marker and blocks:
                blocks[-1] = {**blocks[-1], **marker}
            return {"role": "assistant", "content": blocks}
        if isinstance(self.content, str) and marker:
            return {
                "role": self.role,
                "content": [{"type": "text", "text": self.content, **marker}],
            }
        return {"role": self.role, "content": self.content}


@dataclass
class LLMEvent:
    """An incremental event produced while streaming a completion."""

    type: str  # text | reasoning | tool_call | done | usage | retry | error
    text: str = ""
    tool_call: ToolCall | None = None
    usage: dict[str, Any] | None = None
    error: str | None = None
    data: dict[str, Any] | None = None
