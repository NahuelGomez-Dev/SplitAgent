"""Red and Blue agents."""

from __future__ import annotations

from splitagent.agents.base import AgentResult, BaseAgent
from splitagent.agents.blue import BlueAgent
from splitagent.agents.chat import ChatAgent
from splitagent.agents.red import RedAgent

__all__ = ["AgentResult", "BaseAgent", "BlueAgent", "ChatAgent", "RedAgent"]
