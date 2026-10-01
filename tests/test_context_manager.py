from __future__ import annotations

from splitagent.core.context_manager import (
    COMPACTION_BUFFER,
    PRUNE_PROTECT,
    ContextPolicy,
    compact,
    context_report,
    is_overflow,
    protect_budget,
    prune,
    prune_tool_output,
    usable,
)
from splitagent.llm.types import ChatMessage, estimate_tokens


def _policy(**kwargs) -> ContextPolicy:
    defaults = {
        "context_limit": 10_000,
        "output_token_max": 2_000,
        "reserved": 1_000,
    }
    defaults.update(kwargs)
    return ContextPolicy(**defaults)


def test_estimate_tokens():
    assert estimate_tokens("") == 0
    assert estimate_tokens("abcd") == 1
    assert estimate_tokens("a" * 400) == 100


def test_usable_reserves_output_room():
    policy = _policy(context_limit=10_000, output_token_max=2_000, reserved=None)
    assert usable(policy) == 10_000 - min(COMPACTION_BUFFER, 2_000)


def test_usable_honours_explicit_reserved():
    policy = _policy(context_limit=4_000, output_token_max=8_000, reserved=1_500)
    assert usable(policy) == 2_500


def test_usable_with_input_limit():
    policy = ContextPolicy(context_limit=200_000, input_limit=100_000, reserved=1_000)
    assert usable(policy) == 99_000


def test_is_overflow():
    policy = _policy(context_limit=10_000, output_token_max=2_000, reserved=None)
    assert usable(policy) == 8_000
    assert is_overflow(policy, {"total_tokens": 8_500}) is True
    assert is_overflow(policy, {"prompt_tokens": 5_000, "completion_tokens": 500}) is False


def test_is_overflow_disabled():
    policy = _policy(auto=False)
    assert is_overflow(policy, {"total_tokens": 10_000_000}) is False


def test_prune_protects_recent_tool_output():
    policy = _policy(prune=True)
    recent = "y" * (PRUNE_PROTECT * 4)
    messages = [
        ChatMessage(role="system", content="sys"),
        ChatMessage(role="tool", content="x" * (PRUNE_PROTECT * 6) + " old"),
        ChatMessage(role="tool", content=recent + " recent"),
    ]
    result = prune(messages, policy)
    assert result.parts == 1
    assert "cleared" in messages[1].content
    assert messages[2].content.startswith("y" * 100)  # most recent survives


def test_prune_below_minimum_restores_output():
    """Small savings are not worth mutating the transcript (PRUNE_MINIMUM)."""
    policy = _policy(prune=True)
    # Savings stay under PRUNE_MINIMUM (20k tokens) so nothing is cleared.
    old = "a" * 4_000
    newest = "b" * (PRUNE_PROTECT * 5)
    messages = [
        ChatMessage(role="tool", content=old),
        ChatMessage(role="tool", content=newest),
    ]
    result = prune(messages, policy)
    assert result.pruned == 0
    assert result.parts == 0
    assert messages[0].content.startswith("a" * 100)


def test_prune_respects_pinned_and_disabled():
    policy = _policy(prune=True)
    messages = [
        ChatMessage(role="tool", content="x" * (PRUNE_PROTECT * 6), pinned=True),
        ChatMessage(role="tool", content="y" * (PRUNE_PROTECT * 6)),
    ]
    prune(messages, policy)
    assert "x" * 50 in messages[0].content  # pinned tool output is never cleared

    untouched = [ChatMessage(role="tool", content="z" * 10_000)]
    prune(untouched, _policy(prune=False))
    assert untouched[0].content == "z" * 10_000


def test_compact_keeps_system_and_tail():
    policy = _policy(preserve_recent_tokens=500)
    messages = [ChatMessage(role="system", content="SYSTEM PROMPT")]
    for index in range(6):
        messages.append(ChatMessage(role="user", content=f"task {index} " + "a" * 800))
        messages.append(ChatMessage(role="assistant", content=f"answer {index} " + "b" * 800))
    compacted, result = compact(messages, policy)
    assert result.compacted is True
    assert result.removed > 0
    assert compacted[0].content == "SYSTEM PROMPT"
    assert compacted[1].role == "user"
    assert "Context checkpoint" in compacted[1].content
    # The newest turn is preserved verbatim.
    assert "task 5" in compacted[-2].content


def test_compact_disabled_and_small():
    policy = _policy(auto=False)
    messages = [ChatMessage(role="user", content="hi")]
    compacted, result = compact(messages, policy)
    assert result.compacted is False
    assert compacted == messages


def test_protect_budget_bounds():
    small = _policy(context_limit=4_000, output_token_max=0, reserved=0)
    assert protect_budget(small) == 2_000  # MIN_PRESERVE_RECENT_TOKENS
    large = _policy(context_limit=1_000_000, output_token_max=0, reserved=0)
    assert protect_budget(large) == 15_000  # MAX_PRESERVE_RECENT_TOKENS


def test_prune_tool_output_bounds_length():
    long_text = "a" * 5_000
    bounded = prune_tool_output(long_text)
    assert len(bounded) < len(long_text)
    assert "truncated for context" in bounded
    assert prune_tool_output("short") == "short"


def test_strip_reasoning_keeps_only_the_last_turn():
    from splitagent.core.context_manager import strip_reasoning

    messages = [
        ChatMessage(role="system", content="sys"),
        ChatMessage(role="assistant", content="a", reasoning="r" * 4000),
        ChatMessage(role="tool", content="out"),
        ChatMessage(role="assistant", content="b", reasoning="s" * 4000),
    ]
    saved = strip_reasoning(messages, keep_last=1)
    assert saved > 900  # the first reasoning block was dropped
    assert messages[1].reasoning == ""
    assert messages[3].reasoning == "s" * 4000  # newest survives


def test_strip_reasoning_can_disable_keeping():
    from splitagent.core.context_manager import strip_reasoning

    messages = [ChatMessage(role="assistant", content="a", reasoning="r" * 400)]
    strip_reasoning(messages, keep_last=0)
    assert messages[0].reasoning == ""


def test_supersede_stateful_results():
    from splitagent.core.context_manager import supersede_stateful_results

    messages = [
        ChatMessage(role="tool", name="workspace_info", content="x" * 4000),
        ChatMessage(role="tool", name="http_request", content="keep me"),
        ChatMessage(role="tool", name="workspace_info", content="newest snapshot"),
    ]
    saved = supersede_stateful_results(messages)
    assert saved > 900
    assert messages[0].compacted is True
    assert "superseded" in messages[0].content
    assert messages[1].content == "keep me"  # unrelated tool untouched
    assert messages[2].content == "newest snapshot"  # newest kept


def test_optimize_reports_savings():
    from splitagent.core.context_manager import optimize

    policy = _policy(optimize=True)
    messages = [
        ChatMessage(role="system", content="sys"),
        ChatMessage(role="assistant", content="a", reasoning="r" * 8000),
        ChatMessage(role="tool", name="read_shared_context", content="s" * 8000),
        ChatMessage(role="tool", name="read_shared_context", content="new"),
        ChatMessage(role="assistant", content="b", reasoning="z" * 100),
    ]
    _, stats = optimize(messages, policy)
    assert stats["reasoning"] > 0
    assert stats["stateful"] > 0
    total = stats["reasoning"] + stats["stateful"] + stats["pruned"]
    assert total > 1500


def test_optimize_disabled_is_a_noop():
    from splitagent.core.context_manager import optimize

    policy = _policy(optimize=False)
    messages = [ChatMessage(role="assistant", content="a", reasoning="r" * 400)]
    _, stats = optimize(messages, policy)
    assert stats == {"reasoning": 0, "stateful": 0, "pruned": 0}
    assert messages[0].reasoning == "r" * 400


def test_report_exposes_projection():
    policy = _policy()
    messages = [
        ChatMessage(role="system", content="sys"),
        ChatMessage(role="assistant", content="a", reasoning="r" * 8000),
        ChatMessage(role="assistant", content="b", reasoning="z" * 100),
    ]
    report = context_report(messages, policy)
    assert report["projected"] < report["estimated"]
    assert report["saved"] > 0
    assert report["saving_percent"] > 0
    assert report["optimize"] is True


def test_context_report():
    policy = _policy()
    report = context_report(
        [ChatMessage(role="user", content="a" * 400)], policy, {"total_tokens": 10}
    )
    assert report["estimated"] == 100
    assert report["usable"] == usable(policy)
    assert report["messages"] == 1
    assert report["prune"] is True
