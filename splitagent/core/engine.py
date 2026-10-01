"""The central orchestrator: coordinates the Red/Blue rounds."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from splitagent.config import GlobalConfig, ProjectConfig
from splitagent.core.bus import Event, EventBus
from splitagent.core.context import SharedContext
from splitagent.core.sandbox import DockerSandbox, SandboxStatus
from splitagent.errors import ConfigError
from splitagent.llm.client import LLMClient


class Engine:
    """Drives a full purple-team audit session."""

    def __init__(
        self,
        global_config: GlobalConfig,
        project: ProjectConfig,
        bus: EventBus | None = None,
        context: SharedContext | None = None,
    ) -> None:
        self.global_config = global_config
        self.project = project
        self.bus = bus or EventBus()
        self.sandbox = DockerSandbox(project.run.sandbox, session_id="run")
        self._sandbox_status: SandboxStatus | None = None
        self.workspace: Any = None
        self.toolbox: Any = None
        self.toolbox_status: Any = None
        self._toolbox_error = ""
        target = project.target.url or ", ".join(project.target.effective_hosts())
        self.context = context or SharedContext.create(
            target=target or "unspecified",
            target_kind=project.target.kind,
            scope=project.target.scope or project.target.effective_hosts(),
            name=project.name,
            model=global_config.llm.model,
            provider=global_config.llm.provider,
            bus=self.bus,
        )

    # -- helpers ----------------------------------------------------------- #
    def _require_llm(self) -> None:
        if (
            not self.global_config.llm.resolved_api_key()
            and self.global_config.llm.provider
            not in (
                "ollama",
                "lmstudio",
                "vllm",
                "custom",
            )
        ):
            raise ConfigError(
                "No API key configured. Run `splitagent config setup` to choose a "
                "provider and model, or set the provider API key environment variable."
            )
        if not self.global_config.llm.model or not self.global_config.llm.base_url:
            raise ConfigError("LLM model/base_url missing. Run `splitagent config setup`.")

    def _configure_context(self) -> None:
        """Point the shared context at the active model and the workspace."""
        from splitagent.agents.red import build_policy
        from splitagent.core.workspace import workspace_for

        self.context.policy = build_policy(self.project, self.global_config.llm)
        workspace = workspace_for(self.project, base=Path.cwd())
        workspace.ensure()
        self.workspace = workspace
        self.context.workspace = workspace

    def _start_toolbox(self) -> None:
        """Bring up the isolated toolbox when the mode calls for it."""
        from splitagent.core.toolbox import Toolbox, resolve_mode

        config = self.project.run.execution
        toolbox = Toolbox(config, self.workspace.root if self.workspace else None)
        status = toolbox.detect()
        self.toolbox_status = status
        effective = resolve_mode(config, status)
        if effective != "toolbox":
            if config.mode == "toolbox":
                raise ConfigError(
                    "Toolbox mode is enabled but Docker is not available. Install "
                    "Docker or switch run.execution.mode to 'auto'."
                )
            self.toolbox = None
            return
        if not status.running:
            result = toolbox.up()
            if not result.get("ok"):
                self.toolbox = None
                self._toolbox_error = result.get("error", "unknown error")
                if config.mode == "toolbox":
                    raise ConfigError(f"Could not start the toolbox: {result.get('error')}")
                return
        self.toolbox = toolbox

    def _target_is_external(self) -> bool:
        """True when the engagement points at a real, non-local server.

        The sandbox exists to *provide* a disposable target. When the operator
        has already given one - a domain, a public IP, a reachable host - the
        sandbox would substitute the wrong thing: it would spin up Juice Shop
        and audit that instead of the server they asked about.
        """
        host = (self.project.target.effective_hosts() or [""])[0].lower()
        if not host:
            return False
        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return False
        try:
            import ipaddress

            address = ipaddress.ip_address(host)
            return not (address.is_loopback or address.is_private or address.is_link_local)
        except ValueError:
            pass
        # A hostname that is not a loopback alias is an external target.
        return not host.endswith(".local")

    async def _start_sandbox(self) -> None:
        if not self.project.run.sandbox.enabled:
            await self.bus.emit(Event(type="log", agent="core", data={"text": "Sandbox disabled."}))
            return
        if self._target_is_external():
            # Auditing a real server: never start the lab container.
            self._sandbox_status = None
            await self.bus.emit(
                Event(
                    type="log",
                    agent="core",
                    data={
                        "text": (
                            f"Target {self.project.target.effective_hosts()[0]} is a real "
                            "server, so no sandbox is started. Disable run.sandbox to "
                            "silence this."
                        ),
                        "level": "info",
                    },
                )
            )
            return
        status = await self.sandbox.up()
        self._sandbox_status = status
        if status.running and status.url and not self.project.target.url:
            self.project.target.url = status.url
        await self.bus.emit(
            Event(
                type="log",
                agent="core",
                data={
                    "text": f"Sandbox: {status.message}"
                    + (f" -> {status.url}" if status.url else ""),
                    "level": "info" if status.available else "warning",
                },
            )
        )

    async def _stop_sandbox(self) -> None:
        if self._sandbox_status and self._sandbox_status.running:
            await self.sandbox.down()
            await self.bus.emit(Event(type="log", agent="core", data={"text": "Sandbox removed."}))

    def _agent_settings(self) -> dict[str, Any]:
        return {
            "sandbox": self.sandbox if self.project.run.sandbox.enabled else None,
            "auth_headers": self.project.auth.as_headers(),
            "workspace": self.context.workspace,
            "project": self.project,
            "toolbox": self.toolbox,
        }

    # -- main entry point -------------------------------------------------- #
    async def run(self) -> SharedContext:
        self._require_llm()
        self._configure_context()
        await self.bus.emit(
            Event(
                type="workspace",
                agent="core",
                data={
                    "root": str(self.workspace.root),
                    "installers": __import__(
                        "splitagent.core.workspace", fromlist=["available_installers"]
                    ).available_installers(),
                    "allow_install": self.project.workspace.allow_install,
                    "allow_external_tools": self.project.workspace.allow_external_tools,
                    "file_counts": self.workspace.stats(),
                },
            )
        )
        await self.bus.emit(
            Event(
                type="context.policy",
                agent="core",
                data={
                    "context_limit": self.context.policy.context_limit,
                    "output_token_max": self.context.policy.output_token_max,
                    "usable": __import__(
                        "splitagent.core.context_manager", fromlist=["usable"]
                    ).usable(self.context.policy),
                    "prune": self.context.policy.prune,
                    "auto_compact": self.context.policy.auto,
                },
            )
        )
        await self.bus.emit(
            Event(
                type="session.start",
                agent="core",
                data={
                    "session": self.context.state.id,
                    "target": self.context.state.target,
                    "model": self.global_config.llm.model,
                    "provider": self.global_config.llm.provider,
                    "rounds": self.project.run.rounds,
                },
            )
        )

        try:
            self._start_toolbox()
            await self.bus.emit(
                Event(
                    type="toolbox",
                    agent="core",
                    data={
                        "mode": self.project.run.execution.mode,
                        "edition": self.project.run.execution.edition,
                        "active": self.toolbox is not None,
                        "error": self._toolbox_error,
                        "status": self.toolbox_status.to_dict() if self.toolbox_status else {},
                    },
                )
            )
            await self._start_sandbox()
            async with LLMClient(self.global_config.llm) as client:
                await self._run_with_deadline(client)
        finally:
            from splitagent.tools.http_pool import aclose_all

            await aclose_all()
            await self._stop_sandbox()
            self.context.save()
            await self.bus.emit(
                Event(
                    type="session.end",
                    agent="core",
                    data=self.context.summary_dict(),
                )
            )
        return self.context

    async def _run_with_deadline(self, client: LLMClient) -> None:
        """Run the rounds under a wall-clock ceiling.

        An open-ended engagement can hang for hours on a slow target or a
        provider that never answers. Hitting the deadline stops cleanly with
        everything already persisted, instead of being killed by the operator.
        """
        minutes = max(0, int(self.project.run.max_duration_minutes))
        if minutes <= 0:
            await self._run_rounds(client)
            return
        try:
            await asyncio.wait_for(self._run_rounds(client), timeout=minutes * 60)
        except asyncio.TimeoutError:
            await self.bus.emit(
                Event(
                    type="error",
                    agent="core",
                    data={
                        "text": (
                            f"Run stopped: the {minutes}-minute limit was reached. "
                            "Everything confirmed so far is saved - raise "
                            "run.max_duration_minutes to go further."
                        )
                    },
                )
            )
            self.context.state.notes.append(f"Stopped at the {minutes}-minute deadline.")

    async def _run_rounds(self, client: LLMClient) -> None:
        total = max(1, self.project.run.rounds)
        previous_blue_summary = ""
        for index in range(1, total + 1):
            round_ = self.context.begin_round(index)
            await self.bus.emit(
                Event(type="round.start", agent="core", data={"round": index, "total": total})
            )

            if self.project.agents.red.enabled:
                red_summary = await self._run_red(client, index, total, previous_blue_summary)
                round_.red_summary = red_summary
                round_.finding_ids = [f.id for f in self.context.state.findings if f.round == index]
            else:
                red_summary = "(red agent disabled)"

            if self.project.agents.blue.enabled:
                blue_summary = await self._run_blue(client, index, total, red_summary)
                round_.blue_summary = blue_summary
                round_.mitigation_ids = [
                    m.id for m in self.context.state.mitigations if m.round == index
                ]
            else:
                blue_summary = "(blue agent disabled)"

            previous_blue_summary = blue_summary
            self.context.end_round(index, red_summary, blue_summary)
            self.context.save()
            await self.bus.emit(
                Event(
                    type="round.end",
                    agent="core",
                    data={
                        "round": index,
                        "findings": len(self.context.state.findings),
                        "mitigations": len(self.context.state.mitigations),
                        "resilience": self.context.state.resilience_score(),
                    },
                )
            )

        self.context.state.ended_at = _now()

    async def _run_red(self, client: LLMClient, index: int, total: int, previous_blue: str) -> str:
        from splitagent.agents.red import RedAgent

        agent = RedAgent(
            client=client,
            context=self.context,
            project=self.project,
            bus=self.bus,
            round_index=index,
            total_rounds=total,
            settings=self._agent_settings(),
        )
        await self.bus.emit(
            Event(type="phase.start", agent="red", data={"round": index, "phase": "offense"})
        )
        task = (
            f"Round {index}/{total}. Perform reconnaissance and controlled "
            "exploitation against the target, then persist every confirmed "
            "finding with evidence."
        )
        if previous_blue:
            task += (
                "\n\nDefences applied by the Blue Agent in the previous round "
                "(test whether they hold):\n" + previous_blue
            )
        result = await agent.run(task)
        self._accumulate_usage(result.usage)
        await self.context.add_trace("red", result.trace)
        await self.bus.emit(
            Event(
                type="phase.end",
                agent="red",
                data={
                    "round": index,
                    "phase": "offense",
                    "summary": result.text,
                    "tool_calls": result.tool_calls,
                    "pruned": result.pruned,
                    "compactions": result.compactions,
                },
            )
        )
        return result.text

    async def _run_blue(self, client: LLMClient, index: int, total: int, red_summary: str) -> str:
        from splitagent.agents.blue import BlueAgent

        agent = BlueAgent(
            client=client,
            context=self.context,
            project=self.project,
            bus=self.bus,
            round_index=index,
            total_rounds=total,
            settings=self._agent_settings(),
        )
        await self.bus.emit(
            Event(type="phase.start", agent="blue", data={"round": index, "phase": "defense"})
        )
        task = (
            f"Round {index}/{total}. The Red Agent just reported:\n\n"
            f"{red_summary}\n\n"
            "Triage telemetry, produce countermeasures for the open findings and "
            "verify them where possible."
        )
        result = await agent.run(task)
        self._accumulate_usage(result.usage)
        await self.context.add_trace("blue", result.trace)
        await self.bus.emit(
            Event(
                type="phase.end",
                agent="blue",
                data={
                    "round": index,
                    "phase": "defense",
                    "summary": result.text,
                    "tool_calls": result.tool_calls,
                    "pruned": result.pruned,
                    "compactions": result.compactions,
                },
            )
        )
        return result.text

    def _accumulate_usage(self, usage: dict[str, Any]) -> None:
        for key, value in usage.items():
            if isinstance(value, int):
                self.context.state.usage[key] = self.context.state.usage.get(key, 0) + value


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")
