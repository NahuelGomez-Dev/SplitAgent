"""Tool registry assembling the correct toolset per agent."""

from __future__ import annotations

from splitagent.llm.types import ToolSpec
from splitagent.tools.base import Tool, ToolContext
from splitagent.tools.defense import blue_tools
from splitagent.tools.exploit import red_exploit_tools
from splitagent.tools.knowledge import knowledge_tools
from splitagent.tools.recon import red_recon_tools
from splitagent.tools.validate import exploitation_tools
from splitagent.tools.web import red_web_tools
from splitagent.tools.workspace_tools import workspace_tools


class ToolRegistry:
    def __init__(self, tools: list[Tool] | None = None) -> None:
        self._tools: dict[str, Tool] = {}
        if tools:
            self.add_many(tools)

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def add_many(self, tools: list[Tool]) -> None:
        for tool in tools:
            self.register(tool)

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def specs(self) -> list[ToolSpec]:
        return [tool.spec() for tool in self._tools.values()]

    def subset(self, scope: str) -> ToolRegistry:
        registry = ToolRegistry()
        for tool in self._tools.values():
            if tool.scope in ("shared", scope):
                registry.register(tool)
        return registry


def build_registry(ctx: ToolContext, agent: str) -> ToolRegistry:
    """Build the toolset for ``agent`` (``red`` or ``blue``)."""
    registry = ToolRegistry(knowledge_tools(ctx))
    registry.add_many(workspace_tools(ctx))
    if agent == "red":
        registry.add_many(red_recon_tools(ctx))
        registry.add_many(red_web_tools(ctx))
        registry.add_many(red_exploit_tools(ctx))
        registry.add_many(exploitation_tools(ctx))
    elif agent == "blue":
        registry.add_many(blue_tools(ctx))
    else:
        registry.add_many(red_recon_tools(ctx))
        registry.add_many(red_web_tools(ctx))
        registry.add_many(red_exploit_tools(ctx))
        registry.add_many(blue_tools(ctx))
    return registry
