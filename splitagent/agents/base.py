"""Shared agent runtime: a streaming tool-calling loop."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from splitagent.core.bus import Event, EventBus
from splitagent.core.context import SharedContext
from splitagent.core.context_manager import (
    ContextPolicy,
    compact,
    context_report,
    is_overflow,
    optimize,
    prune_tool_output,
)
from splitagent.errors import LLMError
from splitagent.llm.client import LLMClient
from splitagent.llm.types import ChatMessage
from splitagent.tools.base import ToolContext
from splitagent.tools.registry import ToolRegistry


@dataclass
class AgentResult:
    text: str = ""
    steps: int = 0
    usage: dict[str, Any] = field(default_factory=dict)
    tool_calls: int = 0
    transcript: list[ChatMessage] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)
    pruned: int = 0
    saved: int = 0
    compactions: int = 0
    wrapped_up: bool = False
    hit_step_limit: bool = False


# Injected when the agent is about to run out of steps. The goal is to make it
# persist what it already knows and write a usable summary instead of silently
# dying with no output - which is exactly what happened in production runs.
WRAP_UP_PROMPT = """You are almost out of steps ({remaining} left of {total}).

STOP exploring. Do this now, in this order:
1. Persist every weakness you have already confirmed with `record_finding`, \
including the evidence you gathered and a CVSS v3.1 vector. If you have no \
evidence for something, do not record it.
2. Save your working state with `workspace_write` to `notes/<scope>-state.md` \
so the next round can continue: what you tested, what you found, what is left.
3. Reply with a concise markdown summary of what you tested, what you found, \
and what remains untested.

Do not start new scans. Answer in plain text with no further tool calls after \
the writes."""


class BaseAgent:
    """A model-driven agent that can call tools until it produces an answer."""

    name = "agent"
    role = "assistant"
    color = "white"

    def __init__(
        self,
        client: LLMClient,
        context: SharedContext,
        tool_context: ToolContext,
        registry: ToolRegistry,
        bus: EventBus,
        system_prompt: str,
        max_steps: int = 12,
        temperature: float | None = None,
        history_limit: int = 16,
        policy: ContextPolicy | None = None,
        wrap_up_at: int = 3,
        volatile_builder: Any = None,
        tool_concurrency: int = 4,
    ) -> None:
        self.client = client
        self.context = context
        self.tool_context = tool_context
        self.registry = registry
        self.bus = bus
        self.system_prompt = system_prompt
        self.max_steps = max_steps
        self.temperature = temperature
        self.history_limit = history_limit
        self.history: list[ChatMessage] = []
        self.usage_total: dict[str, int] = {}
        self.policy = policy or context.policy
        # Steps reserved for persisting findings and summarising. 0 disables.
        self.wrap_up_at = max(0, min(wrap_up_at, max_steps - 1))
        # Produces the per-turn context that must stay out of the cached
        # system prefix (findings, task list, round counter, notes).
        self.volatile_builder = volatile_builder
        # Bounded parallelism for independent tools in the same step.
        self.tool_concurrency = max(1, tool_concurrency)
        self.trace: list[dict[str, Any]] = []
        self.compactions = 0
        self.pruned_tokens = 0
        self.saved_tokens = 0
        self.wrapped_up = False
        self.last_usage: dict[str, Any] = {}

    # -- trace ------------------------------------------------------------- #
    def _trace(self, kind: str, **data: Any) -> None:
        import time

        entry = {"t": round(time.time(), 3), "kind": kind, **data}
        self.trace.append(entry)

    async def _maintain_context(self, messages: list[ChatMessage]) -> list[ChatMessage]:
        """Optimise, then compact, before sending the next request."""
        # Cheap, per-request projection first: reasoning of settled steps,
        # superseded snapshots and old tool output. This is what keeps the
        # billed prompt small even on models with a huge window.
        _, stats = optimize(messages, self.policy)
        saved = stats["reasoning"] + stats["stateful"] + stats["pruned"]
        if saved:
            self.saved_tokens += saved
            self._trace("optimize", **stats)
            await self._emit("context.optimize", **stats, saved=saved)

        before = context_report(messages, self.policy, self.last_usage)
        overflow = is_overflow(self.policy, self.last_usage)
        if overflow or before["percent"] >= 100:
            messages, result = compact(messages, self.policy)
            if result.compacted:
                self.compactions += 1
                self._trace(
                    "compaction",
                    removed=result.removed,
                    preserved=result.preserved,
                )
                await self._emit(
                    "context.compaction",
                    removed=result.removed,
                    preserved=result.preserved,
                    summary=result.summary[:4000],
                    overflow=overflow,
                )
                await self.context.add_checkpoint(
                    self.name, result.summary, result.removed, result.preserved
                )
                # Rewrite history so future turns use the compacted view.
                self.history = [m for m in messages if m.role != "system"]

        report = context_report(messages, self.policy, self.last_usage)
        self._trace("context", **report)
        await self._emit("context.usage", **report)
        return messages

    # -- helpers ----------------------------------------------------------- #
    def _build_messages(self, task: str) -> list[ChatMessage]:
        """System prompt (stable, cacheable) + history + current task.

        The volatile context is regenerated every turn and merged into the
        task message, so the system prefix stays byte-identical and the
        provider's prompt cache keeps hitting.
        """
        messages = [ChatMessage(role="system", content=self.system_prompt)]
        messages.extend(self.history[-self.history_limit :])
        message = ChatMessage(role="user", content=self._task_with_context(task))
        message._task_base = task  # type: ignore[attr-defined]
        messages.append(message)
        return messages

    def _task_with_context(self, task: str) -> str:
        if not self.volatile_builder:
            return task
        try:
            extra = self.volatile_builder()
        except Exception:
            return task
        if not extra.strip():
            return task
        return f"{task}\n\n=== CURRENT STATE ===\n{extra}"

    def _refresh_context_message(self, messages: list[ChatMessage]) -> None:
        """Rewrite the newest user turn with fresh volatile context.

        Called each step so findings recorded moments ago are visible without
        touching the cached prefix.
        """
        if not self.volatile_builder or not messages:
            return
        for message in reversed(messages):
            if message.role != "user":
                continue
            base = getattr(message, "_task_base", None)
            if base is None:
                return
            message.content = self._task_with_context(base)
            return

    def _accumulate_usage(self, usage: dict[str, Any]) -> None:
        """Sum token counters, including the ones providers nest.

        OpenAI-compatible APIs report cache hits as
        ``prompt_tokens_details.cached_tokens`` and reasoning as
        ``completion_tokens_details.reasoning_tokens``. Flattening them here
        means the session totals and the UI report the truth instead of zero.
        """
        for key, value in usage.items():
            if isinstance(value, int):
                self.usage_total[key] = self.usage_total.get(key, 0) + value
                continue
            if not isinstance(value, dict):
                continue
            for nested_key, nested_value in value.items():
                if not isinstance(nested_value, int):
                    continue
                # ``cached_tokens`` -> ``cached_tokens``; keep a flat alias so
                # existing readers (report, UI) pick it up without changes.
                flat = "cached_tokens" if nested_key == "cached_tokens" else nested_key
                self.usage_total[flat] = self.usage_total.get(flat, 0) + nested_value

    async def _emit(self, type_: str, **data: Any) -> None:
        await self.bus.emit(Event(type=type_, agent=self.name, data=data))

    async def _execute_tools(self, tool_calls: list[Any]) -> list[tuple[Any, str, str]]:
        """Run the step's tool calls, in parallel when it is safe.

        Independent probes (a port scan and a headers audit, or several
        injection tests on different parameters) used to run one after the
        other, so a step cost the sum of every timeout. Read-only tools now run
        concurrently; anything that mutates state, installs or shells out keeps
        the sequential path and stays ordered.

        Results are always reassembled in the model's original call order, so
        the conversation stays deterministic.
        """
        for call in tool_calls:
            await self._emit(
                "agent.tool_call",
                tool=call.name,
                arguments=call.parsed_arguments(),
                call_id=call.id,
            )

        tools = [self.registry.get(call.name) for call in tool_calls]
        parallel = [i for i, tool in enumerate(tools) if tool is not None and tool.parallel_safe]
        sequential = [i for i, tool in enumerate(tools) if tool is None or not tool.parallel_safe]
        outputs: list[str] = ["" for _ in tool_calls]

        async def invoke(index: int) -> None:
            call = tool_calls[index]
            tool = tools[index]
            try:
                if tool is None:
                    outputs[index] = f"error: unknown tool '{call.name}'"
                else:
                    outputs[index] = await tool.run(call.parsed_arguments())
            except Exception as exc:
                outputs[index] = f"error: {type(exc).__name__}: {exc}"

        if parallel:
            # A single hard tool cannot block the whole step: cap concurrency
            # so we stay polite to the target and avoid tripping rate limits.
            guard = asyncio.Semaphore(self.tool_concurrency)

            async def guarded(index: int) -> None:
                async with guard:
                    await invoke(index)

            await asyncio.gather(*(guarded(i) for i in parallel))
        for index in sequential:
            await invoke(index)

        assembled: list[tuple[Any, str, str]] = []
        for index, call in enumerate(tool_calls):
            output = outputs[index]
            await self._emit(
                "agent.tool_result",
                tool=call.name,
                call_id=call.id,
                output=output[:2000],
            )
            bounded = prune_tool_output(output)
            self._trace(
                "tool_result",
                tool=call.name,
                call_id=call.id,
                full_chars=len(output),
                sent_chars=len(bounded),
                parallel=index in parallel,
            )
            assembled.append((call, output, bounded))
        return assembled

    # -- main loop --------------------------------------------------------- #
    async def run(self, task: str) -> AgentResult:
        messages = self._build_messages(task)
        result = AgentResult()
        final_text = ""

        if self.temperature is not None:
            self.client.settings.temperature = self.temperature
        # Stable per-conversation id (required by gateway providers such as
        # OpenCode Go for routing and prompt caching).
        self.client.settings.session_id = f"{self.context.state.id}-{self.name}"

        for step in range(1, self.max_steps + 1):
            result.steps = step
            await self._emit("agent.step", step=step, max_steps=self.max_steps)

            messages = await self._maintain_context(messages)
            self._refresh_context_message(messages)

            # Reserve the last steps for persisting and summarising. Without
            # this the agent burns its budget exploring and returns nothing.
            remaining = self.max_steps - step
            if self.wrap_up_at and not self.wrapped_up and remaining <= self.wrap_up_at:
                self.wrapped_up = True
                result.wrapped_up = True
                await self._emit(
                    "agent.wrap_up",
                    remaining=remaining,
                    total=self.max_steps,
                )
                messages.append(
                    ChatMessage(
                        role="user",
                        pinned=True,
                        content=WRAP_UP_PROMPT.format(remaining=remaining, total=self.max_steps),
                    )
                )
                self._trace("wrap_up", step=step, remaining=remaining)

            await self._emit("agent.working", step=step, max_steps=self.max_steps)

            text_parts: list[str] = []
            reasoning_parts: list[str] = []
            tool_calls = []
            try:
                async for event in self.client.stream(messages, self.registry.specs()):
                    if event.type == "text":
                        text_parts.append(event.text)
                        await self._emit("agent.text", text=event.text, step=step)
                    elif event.type == "reasoning":
                        reasoning_parts.append(event.text)
                    elif event.type == "tool_call" and event.tool_call is not None:
                        tool_calls.append(event.tool_call)
                    elif event.type == "usage" and event.usage:
                        self._accumulate_usage(event.usage)
                        self.last_usage = dict(event.usage)
                        result.usage = dict(self.usage_total)
                        self._trace("usage", **event.usage)
                        await self._emit("usage", **event.usage)
                    elif event.type == "retry":
                        self._trace("retry", **event.data)
                        await self._emit("agent.retry", **(event.data or {}))
                    elif event.type == "error":
                        await self._emit("error", text=event.error or "LLM error")
                        raise LLMError(event.error or "LLM error")
            except LLMError as exc:
                await self._emit("error", text=str(exc))
                result.text = final_text or f"[{self.name}] LLM error: {exc}"
                return result

            assistant_text = "".join(text_parts)
            reasoning_text = "".join(reasoning_parts)
            if reasoning_text:
                await self._emit("agent.thinking", text=reasoning_text[:4000], step=step)
            assistant_message = ChatMessage(
                role="assistant",
                content=assistant_text,
                reasoning=reasoning_text,
                tool_calls=tool_calls,
            )
            messages.append(assistant_message)
            self.history.append(assistant_message)

            if not tool_calls:
                final_text = assistant_text
                break

            outputs = await self._execute_tools(tool_calls)
            result.tool_calls += len(tool_calls)
            for call, _output, bounded in outputs:
                # The full output is kept out of band so it can still be
                # audited; only a bounded slice enters the conversation.
                tool_message = ChatMessage(
                    role="tool",
                    content=bounded,
                    tool_call_id=call.id,
                    name=call.name,
                )
                messages.append(tool_message)
                self.history.append(tool_message)

        if not final_text:
            result.hit_step_limit = True
            final_text = self._fallback_summary()
        result.text = final_text
        result.transcript = messages
        result.trace = self.trace
        result.pruned = self.pruned_tokens
        result.saved = self.saved_tokens
        result.compactions = self.compactions
        await self._emit(
            "agent.done",
            text=final_text[:4000],
            steps=result.steps,
            pruned=self.pruned_tokens,
            saved=self.saved_tokens,
            compactions=self.compactions,
            hit_step_limit=result.hit_step_limit,
        )
        return result

    def _fallback_summary(self) -> str:
        """Last resort when even the wrap-up turn produced no text.

        Anything persisted still stands, so the summary reports the real state
        instead of a bare "[agent] reached the step limit".
        """
        findings = self.context.state.findings
        mine = [f for f in findings if f.discovered_by == self.name]
        lines = [
            f"## {self.name.capitalize()} agent - automatic summary",
            "",
            f"Ran out of steps ({self.max_steps}) after {len(self.trace)} recorded "
            f"events. The wrap-up turn produced no text, so this summary is built "
            f"from persisted state.",
            "",
            f"- Tool calls executed: {sum(1 for t in self.trace if t['kind'] == 'tool_result')}",
            f"- Findings persisted: {len(mine)}",
        ]
        for finding in mine:
            lines.append(
                f"  - [{finding.severity}] {finding.title} "
                f"({finding.cvss_score:.1f}) @ {finding.endpoint or finding.target}"
            )
        notes = self.context.todo_summary()
        if self.context.state.todos:
            lines += ["", "Task list left behind:", notes]
        lines += [
            "",
            "Untested surface remains - increase `run.max_steps` or continue in the next round.",
        ]
        return "\n".join(lines)
