"""Context window management: usable budget, pruning and compaction.

Ported from OpenCode's session model (``session/overflow.ts`` and
``session/compaction.ts``):

* **usable()** - how many prompt tokens fit, reserving room for the reply.
* **is_overflow()** - whether the last turn exceeded that budget.
* **prune()** - walk backwards protecting the most recent
  ``PRUNE_PROTECT`` tokens of tool output, then blank the output of older
  tool results, which frees context without losing conversation.
* **compact()** - keep a tail of recent turns within a token budget and
  summarise everything before it into a single checkpoint message.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from splitagent.llm.types import ChatMessage, estimate_tokens

# --- OpenCode constants ------------------------------------------------- #
COMPACTION_BUFFER = 20_000
PRUNE_MINIMUM = 20_000
PRUNE_PROTECT = 40_000
MIN_PRESERVE_RECENT_TOKENS = 2_000
MAX_PRESERVE_RECENT_TOKENS = 15_000
TOOL_OUTPUT_MAX_CHARS = 2_000
PRUNE_PROTECTED_TOOLS = ("skill",)

# --- Efficiency defaults (ported from OpenCode's per-step handling) -------- #
# Reasoning is thought, not context: OpenCode drops the reasoning of every
# step that already produced a tool result and keeps it only on the final
# answer. Replaying it every turn is the single biggest source of waste.
KEEP_REASONING_STEPS = 1
# Results from these tools are state snapshots; only the newest one matters.
STATEFUL_TOOLS = (
    "workspace_info",
    "read_shared_context",
    "list_findings",
    "todowrite",
    "check_tool",
)
# Output of these tools is already bounded by the tool itself.
COMPACT_TOOLS = ("todowrite", "record_finding", "record_mitigation")


@dataclass
class ContextPolicy:
    """Tunable knobs, mapped 1:1 onto OpenCode's ``compaction`` config."""

    auto: bool = True
    prune: bool = True
    reserved: int | None = None
    preserve_recent_tokens: int | None = None
    tail_turns: int | None = None
    context_limit: int = 128_000
    input_limit: int = 0
    output_token_max: int = 32_000
    # Aggressive per-request reductions (default on).
    optimize: bool = True
    keep_reasoning_steps: int = KEEP_REASONING_STEPS


@dataclass
class CompactionResult:
    compacted: bool = False
    removed: int = 0
    preserved: int = 0
    summary: str = ""
    reason: str = ""


@dataclass
class PruneResult:
    pruned: int = 0
    protected: int = 0
    parts: int = 0


def max_output_tokens(policy: ContextPolicy) -> int:
    return max(0, policy.output_token_max)


def usable(policy: ContextPolicy) -> int:
    """Prompt budget: context window minus the room reserved for the reply."""
    if policy.context_limit <= 0:
        return 0
    if policy.input_limit:
        reserved = policy.reserved
        if reserved is None:
            reserved = min(COMPACTION_BUFFER, max_output_tokens(policy))
        return max(0, policy.input_limit - reserved)
    # Without an explicit reserved budget, leave room for the longest reply
    # the model can produce (OpenCode caps that reservation with a buffer).
    reserved = policy.reserved
    if reserved is None:
        reserved = max_output_tokens(policy)
    return max(0, policy.context_limit - reserved)


def is_overflow(policy: ContextPolicy, usage: dict[str, Any]) -> bool:
    """True when the last turn consumed more than the usable budget."""
    if not policy.auto or policy.context_limit <= 0:
        return False
    total = usage.get("total_tokens")
    if not total:
        total = int(usage.get("prompt_tokens") or 0) + int(usage.get("completion_tokens") or 0)
    return int(total) >= usable(policy)


def messages_tokens(messages: list[ChatMessage]) -> int:
    return sum(message.token_estimate() for message in messages)


# --------------------------------------------------------------------------- #
# Per-request projection: what actually gets sent to the model
# --------------------------------------------------------------------------- #
def strip_reasoning(messages: list[ChatMessage], keep_last: int = KEEP_REASONING_STEPS) -> int:
    """Drop reasoning from all but the most recent assistant turns.

    Reasoning is scaffolding: once a step has produced tool calls the model has
    already acted on it, so replaying it wastes the whole context window.
    Returns the number of tokens saved.
    """
    saved = 0
    indices = [
        index
        for index, message in enumerate(messages)
        if message.role == "assistant" and message.reasoning
    ]
    keep = set(indices[-keep_last:]) if keep_last > 0 else set()
    for index in indices:
        if index in keep:
            continue
        saved += estimate_tokens(messages[index].reasoning)
        messages[index].reasoning = ""
    return saved


def supersede_stateful_results(messages: list[ChatMessage]) -> int:
    """Blank older snapshots from tools whose newest result supersedes them.

    ``workspace_info``, ``read_shared_context`` or ``list_findings`` return the
    full current state; only the latest call is meaningful. Earlier copies are
    replaced by a marker so the conversation stays coherent.
    """
    latest: dict[str, int] = {}
    for index, message in enumerate(messages):
        if message.role == "tool" and message.name in STATEFUL_TOOLS:
            latest[message.name] = index
    saved = 0
    for index, message in enumerate(messages):
        if message.role != "tool" or message.name not in STATEFUL_TOOLS:
            continue
        if message.compacted or latest.get(message.name) == index:
            continue
        saved += estimate_tokens(message.content)
        message.content = f"[superseded by a newer {message.name} call]"
        message.compacted = True
    return saved


def dedupe_tool_calls(messages: list[ChatMessage]) -> int:
    """Collapse consecutive identical tool calls from separate steps."""
    saved = 0
    seen: set[tuple[str, str]] = set()
    for message in messages:
        for call in message.tool_calls:
            signature = (call.name, call.arguments or "{}")
            if signature in seen:
                saved += estimate_tokens(call.arguments) + estimate_tokens(call.name)
            else:
                seen.add(signature)
    return saved


def optimize(
    messages: list[ChatMessage], policy: ContextPolicy
) -> tuple[list[ChatMessage], dict[str, int]]:
    """Apply the cheap, lossless-ish reductions before every request.

    Order matters: reasoning first (largest win, no information loss for
    decisions already taken), then superseded snapshots, then pruning of old
    tool output. Never touches the system prompt or the latest turn.
    """
    if not policy.optimize:
        return messages, {"reasoning": 0, "stateful": 0, "pruned": 0}
    stats = {"reasoning": 0, "stateful": 0, "pruned": 0}
    stats["reasoning"] = strip_reasoning(messages, policy.keep_reasoning_steps)
    stats["stateful"] = supersede_stateful_results(messages)
    prune_result = prune(messages, policy)
    stats["pruned"] = prune_result.pruned
    return messages, stats


def protect_budget(policy: ContextPolicy) -> int:
    if policy.preserve_recent_tokens is not None:
        return policy.preserve_recent_tokens
    return min(
        MAX_PRESERVE_RECENT_TOKENS,
        max(MIN_PRESERVE_RECENT_TOKENS, int(usable(policy) * 0.25)),
    )


def prune(messages: list[ChatMessage], policy: ContextPolicy) -> PruneResult:
    """Erase the output of old tool results, protecting recent ones.

    Walks backwards accumulating tool-output tokens; once more than
    ``PRUNE_PROTECT`` tokens have been seen, every older tool result is
    blanked (it stays in the transcript for auditing).
    """
    if not policy.prune:
        return PruneResult()
    pruned = 0
    protected: list[tuple[ChatMessage, int]] = []
    cleared: list[tuple[ChatMessage, str, int]] = []
    for message in reversed(messages):
        if message.role != "tool" or message.compacted:
            continue
        if message.pinned:
            continue
        size = estimate_tokens(message.content)
        if not protected:
            # Always keep the most recent tool result, exactly like OpenCode.
            protected.append((message, size))
            continue
        protected_tokens = sum(item[1] for item in protected)
        if protected_tokens + size <= PRUNE_PROTECT:
            protected.append((message, size))
            continue
        cleared.append((message, message.content, size))
        pruned += size
    protected_tokens = sum(item[1] for item in protected)
    if pruned <= PRUNE_MINIMUM:
        # Not worth mutating the transcript: leave every message untouched.
        return PruneResult(pruned=0, protected=protected_tokens, parts=0)
    for message, _, _ in cleared:
        message.compacted = True
        message.content = "[Old tool result content cleared to save context]"
    return PruneResult(pruned=pruned, protected=protected_tokens, parts=len(cleared))


def _turn_starts(messages: list[ChatMessage]) -> list[int]:
    """Indexes of user turns, used as turn boundaries."""
    return [i for i, message in enumerate(messages) if message.role == "user"]


def _summarize(messages: list[ChatMessage], max_chars: int = 12_000) -> str:
    """Build a terse, structured checkpoint from the head of the transcript."""
    lines: list[str] = []
    for message in messages:
        if message.role == "tool" or message.compacted:
            continue
        if message.role == "assistant" and message.tool_calls:
            calls = ", ".join(call.name for call in message.tool_calls)
            if calls:
                lines.append(f"- red/blue tool calls: {calls}")
        text = (message.content or "").strip()
        if not text:
            continue
        label = {
            "system": "system",
            "user": "task",
            "assistant": "agent",
        }.get(message.role, message.role)
        snippet = " ".join(text.split())[:400]
        lines.append(f"- {label}: {snippet}")
    summary = "\n".join(lines)
    if len(summary) > max_chars:
        summary = summary[:max_chars] + "\n- ...(older history omitted)"
    return summary


def compact(
    messages: list[ChatMessage], policy: ContextPolicy
) -> tuple[list[ChatMessage], CompactionResult]:
    """Return a compacted copy of ``messages``.

    The head is replaced by a single checkpoint message; the tail (recent
    turns) is kept verbatim within ``protect_budget``. The system message is
    always preserved.
    """
    if not policy.auto:
        return messages, CompactionResult(reason="auto compaction disabled")

    system = [m for m in messages if m.role == "system"]
    body = [m for m in messages if m.role != "system"]
    if len(body) <= 2:
        return messages, CompactionResult(reason="nothing to compact")

    budget = protect_budget(policy)
    starts = _turn_starts(body)
    if not starts:
        return messages, CompactionResult(reason="no user turns")

    # Anchor the tail at a user-turn boundary within the budget.
    tail_start = starts[-1]
    total = 0
    for index in range(len(starts) - 1, -1, -1):
        start = starts[index]
        end = starts[index + 1] if index + 1 < len(starts) else len(body)
        size = messages_tokens(body[start:end])
        if total + size <= budget or index == len(starts) - 1:
            total += size
            tail_start = start
            continue
        break

    head = body[:tail_start]
    if not head:
        return messages, CompactionResult(reason="tail already fits the budget")

    summary = _summarize(head)
    checkpoint = ChatMessage(
        role="user",
        pinned=True,
        content=(
            "[Context checkpoint] Earlier work in this engagement was summarised "
            "to stay within the model context window. Details omitted here are "
            "still available in the full transcript and the session file.\n\n"
            f"{summary}"
        ),
    )
    removed = messages_tokens(head)
    compacted_messages = [*system, checkpoint, *body[tail_start:]]
    return compacted_messages, CompactionResult(
        compacted=True,
        removed=removed,
        preserved=messages_tokens(body[tail_start:]),
        summary=summary,
        reason="context exceeded the usable budget",
    )


def prune_tool_output(text: str, max_chars: int = TOOL_OUTPUT_MAX_CHARS) -> str:
    """Bound a tool result before storing it in the transcript."""
    if len(text) <= max_chars:
        return text
    return f"{text[:max_chars]}\n[tool output truncated for context: {len(text) - max_chars} chars omitted]"


def context_report(
    messages: list[ChatMessage], policy: ContextPolicy, usage: dict[str, Any] | None = None
) -> dict[str, Any]:
    budget = usable(policy)
    used = messages_tokens(messages)
    # Effective size after the per-request projection, which is what the
    # provider actually bills for.
    projected = used
    if policy.optimize:
        scratch = [
            ChatMessage(
                role=m.role,
                content=m.content,
                reasoning=m.reasoning,
                tool_calls=m.tool_calls,
                name=m.name,
                compacted=m.compacted,
                pinned=m.pinned,
            )
            for m in messages
        ]
        strip_reasoning(scratch, policy.keep_reasoning_steps)
        supersede_stateful_results(scratch)
        projected = messages_tokens(scratch)
    return {
        "context_limit": policy.context_limit,
        "usable": budget,
        "estimated": used,
        "projected": projected,
        "saved": max(0, used - projected),
        "saving_percent": round((1 - projected / used) * 100, 1) if used else 0.0,
        "percent": round((projected / budget) * 100, 1) if budget else 0.0,
        "overflow": is_overflow(policy, usage or {}),
        "prune": policy.prune,
        "auto_compact": policy.auto,
        "optimize": policy.optimize,
        "protect_budget": protect_budget(policy),
        "messages": len(messages),
    }
