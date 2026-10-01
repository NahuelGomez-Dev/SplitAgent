from __future__ import annotations

import asyncio
import time

import pytest

from splitagent.config import ProjectConfig, RunConfig, TargetConfig
from splitagent.core.bus import EventBus
from splitagent.core.context import SharedContext
from splitagent.tools.base import Tool, ToolContext
from splitagent.tools.http_pool import aclose_all, get_client
from splitagent.tools.registry import ToolRegistry


@pytest.fixture(autouse=True)
def _close_pool():
    yield
    asyncio.get_event_loop_policy().new_event_loop().run_until_complete(aclose_all())


async def test_pool_reuses_the_same_client():
    first = await get_client(follow=True, verify=False, timeout=5)
    second = await get_client(follow=True, verify=False, timeout=5)
    assert first is second  # same policy -> same pooled client
    await aclose_all()


async def test_pool_separates_by_transport_policy():
    a = await get_client(follow=True, verify=False, timeout=5)
    b = await get_client(follow=False, verify=False, timeout=5)
    assert a is not b
    await aclose_all()


async def test_pool_separates_authenticated_traffic():
    """Different credentials must never share a connection pool."""
    anon = await get_client(timeout=5)
    auth = await get_client(timeout=5, headers={"Authorization": "Bearer x"})
    assert anon is not auth
    await aclose_all()


async def test_pool_recreates_after_close():
    first = await get_client(timeout=5)
    await aclose_all()
    second = await get_client(timeout=5)
    assert first is not second
    await aclose_all()


def test_tools_declare_parallel_safety():
    ctx = ToolContext(
        target=TargetConfig(url="http://localhost"),
        run=RunConfig(),
        context=SharedContext.create(target="http://localhost"),
    )
    from splitagent.tools.registry import build_registry

    registry = build_registry(ctx, "red")
    # Read-only probes are parallel-safe.
    for name in ("audit_security_headers", "test_cors", "test_http_methods", "dns_lookup"):
        tool = registry.get(name)
        assert tool is not None and tool.parallel_safe is True, name
    # State-mutating / shelling tools are not.
    for name in ("install_tool", "run_tool"):
        tool = registry.get(name)
        assert tool is not None and tool.parallel_safe is False, name


async def test_parallel_execution_is_faster_and_ordered():
    """Independent tools must overlap, and results must keep call order."""
    from splitagent.agents.base import BaseAgent
    from splitagent.config import LLMSettings
    from splitagent.llm.client import LLMClient
    from splitagent.llm.types import ToolCall

    order: list[str] = []

    async def slow(name: str, delay: float) -> str:
        await asyncio.sleep(delay)
        order.append(f"{name}-done")
        return f"result-{name}"

    registry = ToolRegistry(
        [
            Tool(
                name=f"t{i}",
                description="",
                parameters={"type": "object", "properties": {}},
                func=(lambda n=f"t{i}": asyncio.sleep(0) or f"r{n}"),
                parallel_safe=True,
            )
            for i in range(3)
        ]
    )
    # Replace with genuinely slow async tools.
    for index in range(3):
        name = f"t{index}"
        registry.get(name).func = (  # type: ignore[union-attr]
            lambda n=name: slow(n, 0.4)
        )

    class Probe(BaseAgent):
        name = "red"

    ctx = SharedContext.create(target="http://localhost")
    tool_ctx = ToolContext(
        target=TargetConfig(url="http://localhost"), run=RunConfig(), context=ctx
    )
    client = LLMClient(LLMSettings(api_key="k", model="m"))
    agent = Probe(
        client=client,
        context=ctx,
        tool_context=tool_ctx,
        registry=registry,
        bus=EventBus(),
        system_prompt="x",
        tool_concurrency=4,
    )

    calls = [ToolCall(id=f"c{i}", name=f"t{i}", arguments="{}") for i in range(3)]
    start = time.perf_counter()
    results = await agent._execute_tools(calls)
    elapsed = time.perf_counter() - start

    # Sequential would be ~1.2s; parallel should be well under.
    assert elapsed < 0.9, f"tools did not overlap ({elapsed:.2f}s)"
    # Order is preserved even though completion order varies.
    assert [r[0].name for r in results] == ["t0", "t1", "t2"]
    assert [r[2] for r in results] == ["result-t0", "result-t1", "result-t2"]


async def test_sequential_tools_do_not_run_in_parallel():
    """Non-parallel-safe tools must keep the ordered, serialized path."""
    from splitagent.agents.base import BaseAgent
    from splitagent.config import LLMSettings
    from splitagent.llm.client import LLMClient
    from splitagent.llm.types import ToolCall

    registry = ToolRegistry(
        [
            Tool(
                name="mutate",
                description="",
                parameters={"type": "object", "properties": {}},
                func=lambda: "ok",
                parallel_safe=False,
            )
            for _ in range(2)
        ]
    )

    class Probe(BaseAgent):
        name = "red"

    ctx = SharedContext.create(target="http://localhost")
    tool_ctx = ToolContext(
        target=TargetConfig(url="http://localhost"), run=RunConfig(), context=ctx
    )
    agent = Probe(
        client=LLMClient(LLMSettings(api_key="k", model="m")),
        context=ctx,
        tool_context=tool_ctx,
        registry=registry,
        bus=EventBus(),
        system_prompt="x",
    )
    calls = [ToolCall(id="a", name="mutate", arguments="{}")]
    results = await agent._execute_tools(calls)
    assert len(results) == 1
    assert results[0][2] == "ok"


def test_tool_concurrency_configuration():
    project = ProjectConfig()
    assert project.run.tool_concurrency == 4
    project.run.tool_concurrency = 8
    assert project.run.tool_concurrency == 8
