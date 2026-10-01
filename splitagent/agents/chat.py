"""The copilot: an interactive pentest assistant with the full toolset."""

from __future__ import annotations

from typing import Any

from splitagent.agents.base import BaseAgent
from splitagent.agents.prompts import build_chat_prompt, volatile_context
from splitagent.agents.red import build_policy
from splitagent.config import ProjectConfig
from splitagent.core.bus import EventBus
from splitagent.core.context import SharedContext
from splitagent.llm.client import LLMClient
from splitagent.llm.types import ChatMessage
from splitagent.tools.base import ToolContext
from splitagent.tools.registry import build_registry


class ChatAgent(BaseAgent):
    """Free-form assistant that can inspect the target and advise the operator."""

    name = "assistant"
    color = "accent"

    def __init__(
        self,
        client: LLMClient,
        context: SharedContext,
        project: ProjectConfig,
        bus: EventBus,
        settings: dict[str, Any] | None = None,
        history: list[ChatMessage] | None = None,
    ) -> None:
        tool_context = ToolContext(
            target=project.target,
            run=project.run,
            context=context,
            round=0,
            agent="chat",
            settings=settings or {},
        )
        registry = build_registry(tool_context, "chat")
        prompt = build_chat_prompt(project, context)
        super().__init__(
            client=client,
            context=context,
            tool_context=tool_context,
            registry=registry,
            bus=bus,
            system_prompt=prompt,
            max_steps=project.run.max_steps,
            temperature=project.agents.red.temperature,
            history_limit=40,
            policy=build_policy(project, client.settings),
            wrap_up_at=0,  # the copilot is interactive, never wrap it up
            volatile_builder=lambda: volatile_context(project, context, role="red"),
            tool_concurrency=project.run.tool_concurrency,
        )
        if history:
            self.history = list(history)
