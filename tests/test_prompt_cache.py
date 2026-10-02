from __future__ import annotations

from splitagent.agents.prompts import (
    build_chat_prompt,
    build_red_prompt,
    volatile_context,
)
from splitagent.config import LLMSettings, ProjectConfig
from splitagent.core.context import SharedContext
from splitagent.core.workspace import workspace_for
from splitagent.llm.client import LLMClient
from splitagent.llm.types import ChatMessage


def _context(tmp_path) -> SharedContext:
    ctx = SharedContext.create(target="http://127.0.0.1:8080", directory=tmp_path)
    project = ProjectConfig()
    ctx.workspace = workspace_for(project, base=tmp_path)
    ctx.workspace.ensure()
    return ctx


def test_system_prompt_is_stable_across_rounds(tmp_path):
    """The cached prefix must not change between rounds."""
    ctx = _context(tmp_path)
    project = ProjectConfig()
    first = build_red_prompt(project, ctx, 1, 3)
    second = build_red_prompt(project, ctx, 2, 3)
    third = build_red_prompt(project, ctx, 3, 3)
    assert first == second == third


def test_system_prompt_is_stable_after_findings_change(tmp_path):
    """Recording findings must not invalidate the cached prefix."""
    import asyncio

    ctx = _context(tmp_path)
    project = ProjectConfig()
    before = build_red_prompt(project, ctx, 1, 3)
    asyncio.run(ctx.add_finding({"title": "XSS", "severity": "high"}))
    after = build_red_prompt(project, ctx, 1, 3)
    assert before == after


def test_volatile_context_carries_the_changes(tmp_path):
    import asyncio

    ctx = _context(tmp_path)
    project = ProjectConfig()
    before = volatile_context(project, ctx, 1, 3)
    asyncio.run(ctx.add_finding({"title": "SQLi found", "severity": "critical"}))
    after = volatile_context(project, ctx, 1, 3)
    assert before != after
    assert "SQLi found" in after
    assert "SQLi found" not in before


def test_blue_volatile_mentions_mitigations(tmp_path):
    ctx = _context(tmp_path)
    project = ProjectConfig()
    text = volatile_context(project, ctx, 1, 1, role="blue")
    assert "FINDINGS TO MITIGATE" in text
    assert "EXISTING MITIGATIONS" in text


def test_chat_prompt_stable(tmp_path):
    ctx = _context(tmp_path)
    project = ProjectConfig()
    assert build_chat_prompt(project, ctx) == build_chat_prompt(project, ctx)


def test_no_volatile_data_leaks_into_system_prompt(tmp_path):
    import asyncio

    ctx = _context(tmp_path)
    project = ProjectConfig()
    asyncio.run(
        ctx.set_todos([{"content": "UNIQUE_TODO_MARKER", "status": "pending", "priority": "high"}])
    )
    asyncio.run(ctx.add_finding({"title": "UNIQUE_FINDING_MARKER", "severity": "low"}))
    prompt = build_red_prompt(project, ctx, 1, 3)
    assert "UNIQUE_TODO_MARKER" not in prompt
    assert "UNIQUE_FINDING_MARKER" not in prompt
    volatile = volatile_context(project, ctx, 1, 3)
    assert "UNIQUE_TODO_MARKER" in volatile
    assert "UNIQUE_FINDING_MARKER" in volatile


def _bare_agent(tmp_path):
    from splitagent.agents.base import BaseAgent
    from splitagent.agents.red import RedAgent
    from splitagent.config import ProjectConfig
    from splitagent.core.bus import EventBus
    from splitagent.tools.base import ToolContext
    from splitagent.tools.registry import build_registry

    project = ProjectConfig()

    class _Stub:
        pass

    agent = RedAgent.__new__(RedAgent)
    ctx = SharedContext.create(target="http://x", directory=tmp_path)
    tool_context = ToolContext(
        target=project.target, run=project.run, context=ctx, round=1, agent="red", settings={}
    )
    BaseAgent.__init__(
        agent,
        client=_Stub(),
        context=ctx,
        tool_context=tool_context,
        registry=build_registry(tool_context, "red"),
        bus=EventBus(),
        system_prompt="SYS",
        max_steps=3,
        volatile_builder=lambda: "STATE",
    )
    return agent


def test_task_message_is_not_carried_into_history(tmp_path):
    """Continuous conversation: the injected current-state block never replays."""
    agent = _bare_agent(tmp_path)
    messages = agent._build_messages("do the thing")
    cleaned = agent._clean_history(messages)
    assert all(m.role != "system" for m in cleaned)
    assert cleaned[0].role == "user"
    assert cleaned[0].content == "do the thing"
    assert "STATE" not in cleaned[0].content


def test_clean_history_keeps_real_turns(tmp_path):
    agent = _bare_agent(tmp_path)
    messages = agent._build_messages("hello")
    messages.append(ChatMessage(role="assistant", content="hi there"))
    cleaned = agent._clean_history(messages)
    roles = [m.role for m in cleaned]
    assert roles == ["user", "assistant"]
    assert cleaned[1].content == "hi there"


def test_openai_message_keeps_content_when_unmarked():
    message = ChatMessage(role="user", content="hello")
    payload = message.to_openai(cache=False)
    assert payload == {"role": "user", "content": "hello"}


def test_anthropic_markers_system_and_tail():
    settings_probe = ChatMessage(role="user", content="tail")
    assert settings_probe.to_anthropic(cache=True)["content"][0]["cache_control"] == {
        "type": "ephemeral"
    }


def test_anthropic_without_cache_has_no_marker():
    payload = ChatMessage(role="user", content="x").to_anthropic(cache=False)
    assert payload == {"role": "user", "content": "x"}


def test_with_cache_points_marks_prefix_and_tail():
    settings = LLMSettings(prompt_cache=True, cache_system_messages=1, cache_tail_messages=2)
    client = LLMClient(settings)
    messages = [
        ChatMessage(role="system", content="sys"),
        ChatMessage(role="user", content="a"),
        ChatMessage(role="assistant", content="b"),
        ChatMessage(role="user", content="c"),
    ]
    marked = client._with_cache_points(messages)
    assert marked[0].cache is True  # system
    assert marked[-1].cache is True  # newest
    assert marked[-2].cache is True  # second newest
    assert marked[1].cache is False


def test_cache_points_disabled():
    settings = LLMSettings(prompt_cache=False)
    client = LLMClient(settings)
    messages = [ChatMessage(role="system", content="sys"), ChatMessage(role="user", content="a")]
    client._with_cache_points(messages)
    assert all(m.cache is False for m in messages)
