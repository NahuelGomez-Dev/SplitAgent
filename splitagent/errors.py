"""Custom exception hierarchy for SplitAgent."""

from __future__ import annotations


class SplitAgentError(Exception):
    """Base error for every SplitAgent failure."""


class ConfigError(SplitAgentError):
    """Raised when configuration is missing or invalid."""


class LLMError(SplitAgentError):
    """Raised when the LLM provider call fails."""


class ToolError(SplitAgentError):
    """Raised when a tool cannot complete its operation."""


class SandboxError(SplitAgentError):
    """Raised when the Docker sandbox cannot be managed."""


class ScopeError(SplitAgentError):
    """Raised when an action would fall outside the authorised target scope."""
