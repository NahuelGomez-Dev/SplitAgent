"""Base classes for the agent toolset."""

from __future__ import annotations

import dataclasses
import ipaddress
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from splitagent.config import RunConfig, TargetConfig
from splitagent.core.context import SharedContext
from splitagent.errors import ScopeError
from splitagent.llm.types import ToolSpec


@dataclass
class ToolContext:
    """Everything a tool needs to do its job."""

    target: TargetConfig
    run: RunConfig
    context: SharedContext
    round: int = 1
    agent: str = "red"
    settings: dict[str, Any] = field(default_factory=dict)

    @property
    def safe_mode(self) -> bool:
        return bool(self.run.safe_mode)

    def auth_headers(self) -> dict[str, str]:
        """Default headers for authenticated testing, if any were provided."""
        value = self.settings.get("auth_headers")
        return dict(value) if isinstance(value, dict) else {}

    def allowed_hosts(self) -> set[str]:
        hosts = set(self.target.effective_hosts())
        hosts.update(self.target.scope or [])
        excluded = {h.lower() for h in (self.target.out_of_scope or []) if h}
        return {h.lower() for h in hosts if h and h.lower() not in excluded}

    def check_scope(self, host_or_url: str) -> None:
        """Refuse targets outside the authorised scope when enforcement is on."""
        if host_or_url.startswith(("http://", "https://")):
            host = urlparse(host_or_url).hostname or ""
        else:
            host = host_or_url
        host = host.split(":")[0].lower()
        if not host:
            return
        # An explicit exclusion always wins, even in allow_network mode.
        if host in {h.lower() for h in (self.target.out_of_scope or []) if h}:
            raise ScopeError(f"'{host}' is explicitly out of scope (target.out_of_scope).")
        if self.run.allow_network:
            return
        allowed = self.allowed_hosts()
        if not allowed:
            return
        if host in allowed:
            return
        # allow loopback aliases for localhost targets
        loopback = {"localhost", "127.0.0.1", "::1"}
        if host in loopback and allowed & loopback:
            return
        try:
            if ipaddress.ip_address(host).is_loopback and any(
                _is_loopback_name(a) for a in allowed
            ):
                return
        except ValueError:
            pass
        raise ScopeError(
            f"'{host}' is outside the authorised scope {sorted(allowed)}. "
            "Extend target.scope or set run.allow_network=true for lab use."
        )


ToolFunc = Callable[..., Any]


@dataclass
class Tool:
    """A callable exposed to the model."""

    name: str
    description: str
    parameters: dict[str, Any]
    func: ToolFunc
    scope: str = "shared"  # red | blue | shared
    dangerous: bool = False
    # Safe to run concurrently with other tools in the same step. Read-only
    # probes qualify; anything that mutates state or shells out does not.
    parallel_safe: bool = True

    def spec(self) -> ToolSpec:
        return ToolSpec(name=self.name, description=self.description, parameters=self.parameters)

    async def run(self, arguments: dict[str, Any]) -> str:
        try:
            result = self.func(**(arguments or {}))
            if hasattr(result, "__await__"):
                result = await result
        except ScopeError as exc:
            return _pack({"error": "out_of_scope", "message": str(exc)})
        except TypeError as exc:
            return _pack({"error": "bad_arguments", "message": str(exc)})
        except Exception as exc:
            return _pack({"error": type(exc).__name__, "message": str(exc)[:600]})
        return _pack(result)


def _pack(result: Any) -> str:
    if isinstance(result, str):
        return result
    try:
        return json.dumps(_serialise(result), ensure_ascii=False, indent=2, default=str)
    except (TypeError, ValueError):
        return str(result)


def _serialise(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    if isinstance(value, dict):
        return {k: _serialise(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_serialise(v) for v in value]
    return value


def _is_loopback_name(name: str) -> bool:
    return name.lower() in {"localhost", "127.0.0.1", "::1"}
