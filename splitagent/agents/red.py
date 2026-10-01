"""The Red Agent: offensive reconnaissance and controlled exploitation."""

from __future__ import annotations

from typing import Any

from splitagent.agents.base import BaseAgent
from splitagent.agents.prompts import build_red_prompt, volatile_context
from splitagent.config import LLMSettings, ProjectConfig, model_spec
from splitagent.core.bus import EventBus
from splitagent.core.context import SharedContext
from splitagent.core.context_manager import ContextPolicy
from splitagent.llm.client import LLMClient
from splitagent.tools.base import ToolContext
from splitagent.tools.registry import build_registry


def build_policy(project: ProjectConfig, llm: LLMSettings) -> ContextPolicy:
    """Context policy derived from the active model and project settings."""
    spec = model_spec(llm.model)
    compaction = project.run.compaction
    return ContextPolicy(
        auto=compaction.auto,
        prune=compaction.prune,
        optimize=compaction.optimize,
        keep_reasoning_steps=compaction.keep_reasoning_steps,
        reserved=compaction.reserved,
        preserve_recent_tokens=compaction.preserve_recent_tokens,
        tail_turns=compaction.tail_turns,
        context_limit=spec.context,
        input_limit=0,
        output_token_max=min(llm.max_tokens, spec.output) or spec.output,
    )


class RedAgent(BaseAgent):
    name = "red"
    color = "red"

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
            agent="red",
            settings=settings or {},
        )
        registry = build_registry(tool_context, "red")
        prompt = build_red_prompt(project, context, round_index, total_rounds)
        super().__init__(
            client=client,
            context=context,
            tool_context=tool_context,
            registry=registry,
            bus=bus,
            system_prompt=prompt,
            max_steps=project.run.max_steps,
            temperature=project.agents.red.temperature,
            policy=build_policy(project, client.settings),
            wrap_up_at=project.agents.red.wrap_up_at,
            volatile_builder=lambda: volatile_context(
                project, context, round_index, total_rounds, role="red"
            ),
            tool_concurrency=project.run.tool_concurrency,
        )
