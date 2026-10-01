"""The Blue Agent: telemetry triage, mitigation and verification."""

from __future__ import annotations

from typing import Any

from splitagent.agents.base import BaseAgent
from splitagent.agents.prompts import build_blue_prompt, volatile_context
from splitagent.agents.red import build_policy
from splitagent.config import ProjectConfig
from splitagent.core.bus import EventBus
from splitagent.core.context import SharedContext
from splitagent.llm.client import LLMClient
from splitagent.tools.base import ToolContext
from splitagent.tools.registry import build_registry


class BlueAgent(BaseAgent):
    name = "blue"
    color = "blue"

    def __init__(
        self,
        client: LLMClient,
        context: SharedContext,
        project: ProjectConfig,
        bus: EventBus,
        round_index: int = 1,
        total_rounds: int = 1,
        settings: dict[str, Any] | None = None,
    ) -> None:
        tool_context = ToolContext(
            target=project.target,
            run=project.run,
            context=context,
            round=round_index,
            agent="blue",
            settings=settings or {},
        )
        registry = build_registry(tool_context, "blue")
        prompt = build_blue_prompt(project, context, round_index, total_rounds)
        super().__init__(
            client=client,
            context=context,
            tool_context=tool_context,
            registry=registry,
            bus=bus,
            system_prompt=prompt,
            max_steps=project.run.max_steps,
            temperature=project.agents.blue.temperature,
            policy=build_policy(project, client.settings),
            wrap_up_at=project.agents.blue.wrap_up_at,
            volatile_builder=lambda: volatile_context(
                project, context, round_index, total_rounds, role="blue"
            ),
            tool_concurrency=project.run.tool_concurrency,
        )
