"""Native desktop shell: a frameless pywebview window backed by the engine."""

from __future__ import annotations

import asyncio
import copy
import json
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from splitagent.agents.chat import ChatAgent
from splitagent.config import (
    PROVIDER_PRESETS,
    GlobalConfig,
    LLMSettings,
    ProjectConfig,
    ProviderConfig,
    config_home,
    ensure_provider,
    project_config_path,
    save_global_config,
    save_project_config,
    sessions_dir,
    settings_for_provider,
)
from splitagent.core.bus import Event, EventBus
from splitagent.core.context import SharedContext
from splitagent.core.engine import Engine
from splitagent.core.toolbox import (
    Toolbox,
    build_command,
    estimated_size,
    resolve_mode,
)
from splitagent.core.workspace import workspace_for
from splitagent.desktop.api import JsApi
from splitagent.llm.client import LLMClient
from splitagent.llm.types import ChatMessage

WEB_DIR = Path(__file__).parent / "web"
FLUSH_INTERVAL = 0.06
# The planner is one short call; past this we use the deterministic fallback.
PLANNER_TIMEOUT_SECONDS = 15.0


def _extract_json_object(text: str) -> dict[str, Any]:
    """Pull the first JSON object out of a model reply.

    Providers without a JSON mode sometimes wrap the object in prose or a
    fenced code block; we tolerate all of that and fail soft (empty dict).
    """
    if not text:
        return {}
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidate = fenced.group(1) if fenced else None
    if candidate is None:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end <= start:
            return {}
        candidate = text[start : end + 1]
    try:
        parsed = json.loads(candidate)
    except (ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _compose_brief_instructions(brief: dict[str, Any]) -> str:
    """Turn the audit brief into operator instructions for the agents.

    This is what makes the brief actually reach the Red/Blue agents instead of
    being lost as a project name.
    """
    if not isinstance(brief, dict):
        return ""
    lines: list[str] = []
    label = {
        "objective": "Objective",
        "crown_jewels": "What matters most",
        "authorization": "Authorization",
        "goal": "Engagement goal",
        "exclude_areas": "Areas/endpoints to exclude",
        "window": "Window / rate constraints",
        "noise": "Noise profile",
        "notes": "Additional notes",
    }
    for key, title in label.items():
        value = brief.get(key)
        if value is None:
            continue
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value if str(v).strip())
        value = str(value).strip()
        if value:
            lines.append(f"- {title}: {value}")
    scope_doc = str(brief.get("scope_document") or "").strip()
    if scope_doc:
        lines.append("- Operator scope document:")
        lines.append(scope_doc)
    if not lines:
        return ""
    return "=== ENGAGEMENT BRIEF ===\n" + "\n".join(lines)


async def _fetch_models_async(settings: LLMSettings) -> list[dict[str, str]]:
    async with LLMClient(settings) as client:
        return await client.list_models()


def _event_dict(event: Event) -> dict[str, Any]:
    return {
        "type": event.type,
        "agent": event.agent,
        "data": event.data,
        "ts": event.ts,
    }


class DesktopApp:
    """Owns the webview window, the JS bridge and the audit worker."""

    def __init__(self, global_config: GlobalConfig, project: ProjectConfig) -> None:
        self.global_config = global_config
        self.project = project
        self.window: Any = None
        self.api = JsApi(self)
        self.session: SharedContext | None = None
        self.report_paths: list[str] = []
        self._audit_thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._task: asyncio.Task[Any] | None = None
        self._queue: list[dict[str, Any]] = []
        self._last_flush = 0.0
        self._stop = threading.Event()
        self._maximized = False
        # copilot chat state
        self._chat_context: SharedContext | None = None
        self.workspace: Any = None
        self._chat_history: list[ChatMessage] = []
        self._chat_thread: threading.Thread | None = None
        self._chat_loop: asyncio.AbstractEventLoop | None = None
        self._chat_task: asyncio.Task[Any] | None = None
        self._chat_events: list[dict[str, Any]] = []
        self._chat_done = False
        self._toolbox_thread: threading.Thread | None = None
        self._queue_lock = threading.Lock()

    # -- lifecycle --------------------------------------------------------- #
    def run(self) -> None:
        import webview

        index = (WEB_DIR / "index.html").as_uri()
        self.window = webview.create_window(
            "SplitAgent",
            url=index,
            js_api=self.api,
            width=1460,
            height=940,
            min_size=(760, 540),
            frameless=True,
            easy_drag=False,
            background_color="#161616",
            text_select=True,
            confirm_close=False,
        )
        self.window.events.closed += self._on_closed
        storage = config_home() / "webview"
        storage.mkdir(parents=True, exist_ok=True)
        webview.start(
            self._keepalive,
            gui="edgechromium",
            debug=False,
            private_mode=False,
            storage_path=str(storage),
        )

    def _keepalive(self) -> None:
        # Runs in a background thread for the lifetime of the window.
        while not self._stop.is_set():
            time.sleep(0.25)

    def _on_closed(self) -> None:
        self._stop.set()

    def is_running(self) -> bool:
        return self._audit_thread is not None and self._audit_thread.is_alive()

    # -- JS bridge helpers ------------------------------------------------- #
    # Threads that feed the bridge: the audit worker, the chat worker and the
    # toolbox worker all push into the same queue. Every read/modify is done
    # under a lock so a batch can never be duplicated or dropped mid-flush.
    def _emit(self, batch: list[dict[str, Any]]) -> None:
        if not batch or self.window is None:
            return
        payload = json.dumps(batch, ensure_ascii=False, default=str)
        script = f"window.SplitAgent && window.SplitAgent.emit({payload});"
        try:
            self.window.evaluate_js(script)
        except Exception:  # pragma: no cover - window may be closing
            pass

    def _emit_chat(self, batch: list[dict[str, Any]]) -> None:
        """Chat events go only to the polled buffer, never the live bridge.

        Delivering them both ways duplicated every event (the bridge pushed it
        and the poll replayed it). The front-end polls ``chat_state`` for chat,
        so this is the single channel.
        """
        if batch:
            with self._queue_lock:
                self._chat_events.extend(batch)

    def _push(self, event: dict[str, Any]) -> None:
        with self._queue_lock:
            self._queue.append(event)

    def _flush(self, force: bool = False) -> None:
        now = time.monotonic()
        with self._queue_lock:
            if not self._queue:
                return
            if not force and (now - self._last_flush) < FLUSH_INTERVAL:
                return
            self._last_flush = now
            batch = self._queue[:]
            del self._queue[:]
        self._emit(batch)

    # -- audit ------------------------------------------------------------- #
    def start_audit(self, options: dict[str, Any]) -> dict[str, Any]:
        if self.is_running():
            return {"ok": False, "error": "An audit is already running."}
        self.report_paths = []
        self.session = None
        self._audit_thread = threading.Thread(
            target=self._audit_entry, args=(options,), daemon=True
        )
        self._audit_thread.start()
        return {"ok": True}

    def stop_audit(self) -> dict[str, Any]:
        if self._loop is not None and self._task is not None:
            try:
                self._loop.call_soon_threadsafe(self._task.cancel)
            except RuntimeError:
                pass
            return {"ok": True}
        return {"ok": False, "error": "No audit running."}

    def _audit_entry(self, options: dict[str, Any]) -> None:
        try:
            asyncio.run(self._audit_async(options))
        except asyncio.CancelledError:
            self._push({"type": "error", "agent": "core", "data": {"text": "Audit cancelled."}})
            self._flush(force=True)
            self._emit([{"type": "audit.end", "data": {"ok": False, "error": "cancelled"}}])
        except Exception as exc:
            self._push(
                {
                    "type": "error",
                    "agent": "core",
                    "data": {"text": f"{type(exc).__name__}: {exc}"},
                }
            )
            self._flush(force=True)
            self._emit(
                [
                    {
                        "type": "audit.end",
                        "data": {"ok": False, "error": str(exc)},
                    }
                ]
            )

    async def _audit_async(self, options: dict[str, Any]) -> None:
        project = self._build_project(options)
        self.project = project

        bus = EventBus()
        bus.subscribe(lambda event: self._push(_event_dict(event)))
        engine = Engine(self.global_config, project, bus=bus)

        self._loop = asyncio.get_running_loop()
        self._emit(
            [
                {
                    "type": "audit.start",
                    "data": {
                        "target": project.target.url,
                        "model": self.global_config.llm.model,
                        "provider": self.global_config.llm.provider,
                        "rounds": project.run.rounds,
                    },
                }
            ]
        )
        self._task = asyncio.ensure_future(engine.run())
        while not self._task.done():
            await asyncio.sleep(0.04)
            self._flush()
        context = self._task.result()
        self.session = context
        self._flush(force=True)

        report_paths: list[str] = []
        try:
            from splitagent.report.generator import write_reports

            paths = write_reports(context.state, project.report, Path(project.report.output_dir))
            report_paths = [str(p.resolve()) for p in paths]
        except Exception as exc:
            self._push({"type": "error", "agent": "core", "data": {"text": f"report: {exc}"}})
        self.report_paths = report_paths
        # Counting completed audits feeds the dashboard header.
        self.global_config.ui.audits_completed += 1
        save_global_config(self.global_config)
        self._emit(
            [
                {
                    "type": "audit.end",
                    "data": {
                        "ok": True,
                        "session": context.state.id,
                        "reports": report_paths,
                        "summary": context.summary_dict(),
                    },
                }
            ]
        )

    # -- engagement planner (audit brief) ---------------------------------- #
    def build_audit_plan(self, brief: dict[str, Any] | None = None) -> dict[str, Any]:
        """Turn an operator brief into a plan, with the model doing the adapting.

        The AI writes the plan (phases, techniques, cautions) because a fixed
        template cannot fit every environment. Hard facts — scope and
        out_of_scope — come from the brief and are enforced afterwards: the
        plan is sanitised so a hallucinated host can never enter scope. If the
        model fails or is slow, a deterministic fallback plan is returned so the
        audit always has something to approve.
        """
        brief = brief or {}
        fallback = self._fallback_plan(brief)
        try:
            plan = asyncio.run(self._plan_async(brief))
        except Exception as exc:
            fallback["source"] = "fallback"
            fallback["note"] = f"planner unavailable: {type(exc).__name__}"
            return fallback
        if not plan:
            fallback["source"] = "fallback"
            fallback["note"] = "planner returned no usable plan"
            return fallback
        return self._sanitise_plan(plan, brief)

    async def _plan_async(self, brief: dict[str, Any]) -> dict[str, Any]:
        from splitagent.agents.prompts import build_audit_brief_prompt

        project = self.project
        context = SharedContext.create(
            target=project.target.url
            or ", ".join(project.target.effective_hosts())
            or "unspecified",
            target_kind=project.target.kind,
            scope=project.target.scope or project.target.effective_hosts(),
            name="planner",
            model=self.global_config.llm.model,
            provider=self.global_config.llm.provider,
        )
        system = build_audit_brief_prompt(project, context)
        user = "=== BRIEF ===\n" + json.dumps(brief, ensure_ascii=False, indent=2)
        async with LLMClient(self.global_config.llm) as client:
            message, _usage = await asyncio.wait_for(
                client.complete(
                    [
                        ChatMessage(role="system", content=system),
                        ChatMessage(role="user", content=user),
                    ]
                ),
                timeout=PLANNER_TIMEOUT_SECONDS,
            )
        return _extract_json_object(message.content)

    def _sanitise_plan(self, plan: dict[str, Any], brief: dict[str, Any]) -> dict[str, Any]:
        """Keep the AI's judgement but enforce the operator's hard facts."""

        def _as_list(value: Any) -> list[str]:
            if isinstance(value, list):
                return [str(v).strip() for v in value if str(v).strip()]
            if isinstance(value, str):
                return [p.strip() for p in value.split(",") if p.strip()]
            return []

        out_of_scope = {h.lower() for h in _as_list(brief.get("out_of_scope"))}
        scope = _as_list(brief.get("scope")) or _as_list(plan.get("scope"))
        # A host can never be both in scope and explicitly excluded.
        scope = [h for h in scope if h.lower() not in out_of_scope]
        noise = str(plan.get("noise") or brief.get("noise") or "normal").lower()
        if noise not in ("stealth", "normal", "aggressive"):
            noise = "normal"
        return {
            "objective": str(plan.get("objective") or brief.get("objective") or "Security audit"),
            "scope": scope,
            "out_of_scope": _as_list(brief.get("out_of_scope"))
            or _as_list(plan.get("out_of_scope")),
            "phases": _as_list(plan.get("phases")),
            "techniques": _as_list(plan.get("techniques")),
            "cautions": _as_list(plan.get("cautions")),
            "noise": noise,
            "source": "ai",
            "awaiting_approval": True,
        }

    def _fallback_plan(self, brief: dict[str, Any]) -> dict[str, Any]:
        """A deterministic plan used when the model is unavailable."""
        kind = str(brief.get("kind") or self.project.target.kind or "web")
        goal = str(brief.get("goal") or "full audit")
        common = ["reconnaissance", "enumeration", "targeted validation", "report"]
        by_kind = {
            "web": [
                "map the web surface (crawl, routes, forms)",
                "audit authentication and session handling",
                "test input-handling endpoints (injection, XSS)",
            ],
            "api": [
                "enumerate API endpoints and schemas",
                "audit object-level authorisation (IDOR)",
                "test authentication, rate limiting and input validation",
            ],
            "network": [
                "service/version discovery",
                "sweep all ports for exposed services",
                "validate known CVEs on discovered versions",
            ],
            "repo": [
                "inventory the repository and dependencies",
                "review auth, secrets and injection sinks",
                "check dependency vulnerabilities",
            ],
        }
        return {
            "objective": str(brief.get("objective") or f"{goal} of the {kind} target"),
            "scope": [str(s).strip() for s in brief.get("scope", []) if str(s).strip()],
            "out_of_scope": [
                str(s).strip() for s in brief.get("out_of_scope", []) if str(s).strip()
            ],
            "phases": by_kind.get(kind, common),
            "techniques": [],
            "cautions": [
                "Stay strictly within the authorised scope.",
                "Non-destructive testing only.",
            ]
            + ([str(brief["window"])] if brief.get("window") else []),
            "noise": str(brief.get("noise") or "normal"),
            "source": "fallback",
            "awaiting_approval": True,
        }

    def brief_chat(self, payload: dict[str, Any]) -> dict[str, Any]:
        """A bounded scoping assistant for the audit brief.

        It answers questions and can suggest brief adjustments, but it has no
        tools and never starts an audit — the audit begins only when the
        operator approves a plan.
        """
        message = str((payload or {}).get("message") or "").strip()
        brief = (payload or {}).get("brief") or {}
        if not message:
            return {"ok": False, "error": "empty message"}
        try:
            text = asyncio.run(self._brief_chat_async(message, brief))
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        return {"ok": True, "text": text}

    async def _brief_chat_async(self, message: str, brief: dict[str, Any]) -> str:
        from splitagent.agents.prompts import build_planner_chat_prompt

        project = self.project
        context = SharedContext.create(
            target=project.target.url or "unspecified",
            target_kind=project.target.kind,
            scope=project.target.scope or project.target.effective_hosts(),
            name="planner",
            model=self.global_config.llm.model,
            provider=self.global_config.llm.provider,
        )
        # The *chat* prompt: conversational, not the JSON-only plan prompt.
        system = build_planner_chat_prompt(project, context)
        user = (
            "=== CURRENT BRIEF ===\n"
            + json.dumps(brief, ensure_ascii=False, indent=2)
            + "\n\n=== OPERATOR ===\n"
            + message
            + "\n\nAnswer briefly in the operator's language. If the brief should "
            "change, list concrete adjustments. You run no tools and start nothing."
        )
        async with LLMClient(self.global_config.llm) as client:
            result, _usage = await asyncio.wait_for(
                client.complete(
                    [
                        ChatMessage(role="system", content=system),
                        ChatMessage(role="user", content=user),
                    ]
                ),
                timeout=PLANNER_TIMEOUT_SECONDS,
            )
        return result.content or "(no answer)"

    def _build_project(self, options: dict[str, Any]) -> ProjectConfig:
        project = copy.deepcopy(self.project)
        target = options.get("target") or {}
        if target.get("url"):
            project.target.url = str(target["url"])
        if target.get("kind"):
            project.target.kind = str(target["kind"])
        if target.get("scope"):
            project.target.scope = [s.strip() for s in str(target["scope"]).split(",") if s.strip()]
        run = options.get("run") or {}
        if run.get("rounds") is not None:
            try:
                project.run.rounds = max(1, int(run["rounds"]))
            except (TypeError, ValueError):
                pass
        if run.get("max_steps") is not None:
            try:
                project.run.max_steps = max(1, int(run["max_steps"]))
            except (TypeError, ValueError):
                pass
        if run.get("allow_network") is not None:
            project.run.allow_network = bool(run["allow_network"])
        if run.get("sandbox") is not None:
            project.run.sandbox.enabled = bool(run["sandbox"])
        workspace = options.get("workspace")
        if isinstance(workspace, dict):
            if "path" in workspace:
                project.workspace.path = str(workspace.get("path") or "")
            for key in ("allow_install", "allow_external_tools"):
                if workspace.get(key) is not None:
                    setattr(project.workspace, key, bool(workspace[key]))
            if workspace.get("max_install_seconds") is not None:
                try:
                    project.workspace.max_install_seconds = max(
                        30, int(workspace["max_install_seconds"])
                    )
                except (TypeError, ValueError):
                    pass
            if "instructions" in workspace:
                project.workspace.instructions = str(workspace.get("instructions") or "")
        compaction = options.get("compaction")
        if isinstance(compaction, dict):
            for key in ("auto", "prune"):
                if compaction.get(key) is not None:
                    setattr(project.run.compaction, key, bool(compaction[key]))
            for key in ("reserved", "preserve_recent_tokens", "tail_turns"):
                if compaction.get(key) is not None:
                    try:
                        setattr(project.run.compaction, key, int(compaction[key]))
                    except (TypeError, ValueError):
                        pass
        auth = options.get("auth") or {}
        if auth:
            if "username" in auth:
                project.auth.username = str(auth.get("username") or "")
            if "password" in auth:
                project.auth.password = str(auth.get("password") or "")
            if "token" in auth:
                project.auth.token = str(auth.get("token") or "")
            if "cookies" in auth:
                project.auth.cookies = str(auth.get("cookies") or "")
            if isinstance(auth.get("headers"), dict):
                project.auth.headers = {str(k): str(v) for k, v in auth["headers"].items() if k}
        brief = options.get("brief")
        if isinstance(brief, dict):
            instructions = _compose_brief_instructions(brief)
            if instructions:
                project.workspace.instructions = (
                    (project.workspace.instructions + "\n\n" + instructions).strip()
                    if project.workspace.instructions
                    else instructions
                )
            noise = str(brief.get("noise") or "").lower()
            if noise == "stealth":
                project.run.tool_concurrency = 1
                project.run.max_duration_minutes = max(project.run.max_duration_minutes, 120)
            elif noise == "aggressive":
                project.run.tool_concurrency = max(project.run.tool_concurrency, 8)
        if options.get("objective"):
            project.name = str(options["objective"])[:60] or project.name
        return project

    # -- copilot chat ------------------------------------------------------ #
    def is_chatting(self) -> bool:
        return self._chat_thread is not None and self._chat_thread.is_alive()

    def chat_reset(self) -> dict[str, Any]:
        self._chat_history = []
        self._chat_context = None
        self._emit([{"type": "chat.reset", "data": {}}])
        return {"ok": True}

    def chat_stop(self) -> dict[str, Any]:
        if self._chat_loop is not None and self._chat_task is not None:
            try:
                self._chat_loop.call_soon_threadsafe(self._chat_task.cancel)
            except RuntimeError:
                pass
            return {"ok": True}
        return {"ok": False, "error": "No chat running."}

    def chat_send(self, message: str) -> dict[str, Any]:
        text = (message or "").strip()
        if not text:
            return {"ok": False, "error": "empty message"}
        if self.is_chatting():
            return {"ok": False, "error": "The copilot is still answering."}
        self._chat_events = []
        self._chat_done = False
        self._chat_thread = threading.Thread(target=self._chat_entry, args=(text,), daemon=True)
        self._chat_thread.start()
        return {"ok": True}

    def chat_state(self, since: int = 0) -> dict[str, Any]:
        """Events since an index, for the UI to poll without gaps.

        Pushes over the bridge are best-effort; this lets the front-end replay
        whatever it missed, so a reply can never be lost mid-stream.
        """
        with self._queue_lock:
            events = list(self._chat_events)
        return {
            "ok": True,
            "running": self.is_chatting(),
            "pending": not self._chat_done,
            "events": events[since:],
            "next": len(events),
        }

    def _chat_entry(self, message: str) -> None:
        try:
            asyncio.run(self._chat_message(message))
        except asyncio.CancelledError:
            self._emit_chat([{"type": "chat.end", "data": {"ok": False, "error": "cancelled"}}])
            self._chat_done = True
        except Exception as exc:
            self._emit_chat(
                [
                    {
                        "type": "error",
                        "agent": "assistant",
                        "data": {"text": f"{type(exc).__name__}: {exc}"},
                    },
                    {"type": "chat.end", "data": {"ok": False, "error": str(exc)}},
                ]
            )
            self._chat_done = True

    async def _chat_message(self, message: str) -> None:
        return await self._chat_async(message)

    async def _chat_async(self, message: str) -> None:
        if self._chat_context is None:
            target = self.project.target.url or ", ".join(self.project.target.effective_hosts())
            self._chat_context = SharedContext.create(
                target=target or "unspecified",
                target_kind=self.project.target.kind,
                scope=self.project.target.scope or self.project.target.effective_hosts(),
                name="copilot",
                model=self.global_config.llm.model,
                provider=self.global_config.llm.provider,
            )
        bus = EventBus()
        # Chat events feed only the polled buffer (single channel, no bridge).
        bus.subscribe(lambda event: self._emit_chat([_event_dict(event)]))
        self._emit_chat([{"type": "chat.start", "data": {"text": message}}])

        self._chat_loop = asyncio.get_running_loop()
        async with LLMClient(self.global_config.llm) as client:
            agent = ChatAgent(
                client=client,
                context=self._chat_context,
                project=self.project,
                bus=bus,
                settings={
                    "sandbox": None,
                    "auth_headers": self.project.auth.as_headers(),
                },
                history=self._chat_history,
            )
            self._chat_task = asyncio.ensure_future(agent.run(message))
            while not self._chat_task.done():
                await asyncio.sleep(0.04)
            result = self._chat_task.result()
            self._chat_history = list(agent.history)
        self._emit_chat([{"type": "chat.end", "data": {"ok": True, "text": result.text}}])
        self._chat_done = True

    # -- toolbox ----------------------------------------------------------- #
    def _toolbox(self) -> Toolbox:
        workspace = workspace_for(self.project, base=Path.cwd())
        return Toolbox(self.project.run.execution, workspace.root)

    def toolbox_status(self, probe: bool = False) -> dict[str, Any]:
        toolbox = self._toolbox()
        status = toolbox.detect(probe=probe)
        effective = resolve_mode(self.project.run.execution, status)
        data = status.to_dict()
        data["effective_mode"] = effective
        data["installed"] = self.project.run.execution.installed
        data["build_command"] = " ".join(build_command(self.project.run.execution.edition))
        data["estimated_size"] = estimated_size(self.project.run.execution.edition)
        data["workspace"] = str(toolbox.workspace_root)
        return {"ok": True, "status": data}

    def is_toolbox_busy(self) -> bool:
        return self._toolbox_thread is not None and self._toolbox_thread.is_alive()

    def toolbox_setup(self, edition: str = "", build: bool = True) -> dict[str, Any]:
        """Kick off the one-time setup in the background.

        A Docker build takes minutes, so this must never block the UI thread:
        the webview would freeze and the progress events would never flush.
        Progress and the final result arrive through the event bus.
        """
        if self.is_toolbox_busy():
            return {"ok": False, "error": "setup already running", "async": True}
        config = self.project.run.execution
        if edition in ("standard", "kali"):
            config.edition = edition
            path = project_config_path()
            if path.exists():
                save_project_config(self.project, path)
        self._toolbox_thread = threading.Thread(
            target=self._toolbox_setup_worker, args=(build,), daemon=True
        )
        self._toolbox_thread.start()
        return {"ok": True, "async": True, "status": self.toolbox_status()["status"]}

    def toolbox_probe(self) -> dict[str, Any]:
        """Slow path: ask the container which tools it has (used sparingly)."""
        return self.toolbox_status(probe=True)

    def _toolbox_setup_worker(self, build: bool) -> None:
        config = self.project.run.execution
        toolbox = self._toolbox()

        def progress(stage: str, text: str) -> None:
            self._emit([{"type": "toolbox.progress", "data": {"stage": stage, "text": text}}])
            self._flush(force=True)

        try:
            status = toolbox.detect()
            if not status.docker_cli:
                self._toolbox_fail("Docker is not installed. Install Docker Desktop and retry.")
                return

            if not status.daemon:
                if not config.auto_start:
                    self._toolbox_fail("Docker is not running.")
                    return
                progress("daemon", "Starting Docker…")
                started, message = toolbox.start_daemon()
                if not started:
                    self._toolbox_fail(message)
                    return

            if build and not toolbox.detect().image:
                progress(
                    "build",
                    f"Building the {config.edition} toolbox image ({estimated_size(config.edition)})…",
                )
                built = toolbox.build()
                if not built["ok"]:
                    self._toolbox_fail(
                        built.get("error", "build failed"),
                        output=built.get("output", ""),
                    )
                    return

            progress("start", "Starting the toolbox…")
            result = toolbox.up(build_if_missing=False)
            if not result.get("ok"):
                self._toolbox_fail(result.get("error", "could not start the toolbox"))
                return

            config.installed = True
            # ``config`` lives on the project, so persist the project too.
            save_global_config(self.global_config)
            save_project_config(self.project, project_config_path())
            status = self.toolbox_status()["status"]
            self._emit([{"type": "toolbox.ready", "data": status}])
            self._flush(force=True)
        except Exception as exc:
            self._toolbox_fail(f"{type(exc).__name__}: {exc}")

    def _toolbox_fail(self, error: str, output: str = "") -> None:
        self.project.run.execution.installed = False
        self._emit(
            [
                {
                    "type": "toolbox.failed",
                    "data": {"error": error, "output": output[-4000:]},
                }
            ]
        )
        self._flush(force=True)

    def _toolbox_action_worker(self, action: str) -> None:
        toolbox = self._toolbox()
        try:
            if action == "start":
                result = toolbox.up()
            elif action == "reset":
                result = toolbox.reset()
            elif action == "rebuild":
                toolbox.remove_image()
                result = toolbox.up()
            else:
                result = {"ok": False, "error": f"unknown action '{action}'"}
            if not result.get("ok"):
                self._toolbox_fail(result.get("error", f"{action} failed"))
                return
            self._emit([{"type": "toolbox.ready", "data": self.toolbox_status()["status"]}])
            self._flush(force=True)
        except Exception as exc:
            self._toolbox_fail(f"{type(exc).__name__}: {exc}")

    def toolbox_action(self, action: str, edition: str = "") -> dict[str, Any]:
        toolbox = self._toolbox()
        # Anything that can take more than a moment runs in the background so
        # the window never freezes and no console windows pile up.
        if action in ("start", "reset", "rebuild"):
            if self.is_toolbox_busy():
                return {"ok": False, "error": "another toolbox task is running", "async": True}
            self._toolbox_thread = threading.Thread(
                target=self._toolbox_action_worker, args=(action,), daemon=True
            )
            self._toolbox_thread.start()
            return {"ok": True, "async": True}
        if action == "stop":
            toolbox.down()
            return {"ok": True}
        if action == "setup":
            return self.toolbox_setup(edition=edition)
        if action == "set_edition":
            if edition in ("standard", "kali"):
                self.project.run.execution.edition = edition
                path = project_config_path()
                if path.exists():
                    save_project_config(self.project, path)
            return {"ok": True, "edition": self.project.run.execution.edition}
        if action == "status":
            return self.toolbox_status()
        return {"ok": False, "error": f"unknown action '{action}'"}

    def toolbox_install(self, manager: str, package: str) -> dict[str, Any]:
        toolbox = self._toolbox()
        status = toolbox.detect()
        if not status.running:
            return {"ok": False, "error": "the toolbox is not running"}
        return toolbox.install(manager, package)

    # -- models & providers ------------------------------------------------ #
    def list_models(self) -> dict[str, Any]:
        """Aggregate the catalogues of every connected provider."""
        config = self.global_config
        entries: list[dict[str, Any]] = []
        for provider_id, provider in config.providers.items():
            catalogue = dict(provider.models)
            if not catalogue:
                preset = PROVIDER_PRESETS.get(provider_id, {})
                default = preset.get("model", config.llm.model)
                if default:
                    catalogue = {default: default}
            for model_id, name in catalogue.items():
                entries.append(
                    {
                        "provider": provider_id,
                        "provider_name": provider_id,
                        "id": model_id,
                        "name": name or model_id,
                        "source": "connected",
                        "visible": provider.visible(model_id),
                        "free": model_id.endswith("-free"),
                    }
                )
        return {
            "ok": True,
            "models": entries,
            "current": {"provider": config.llm.provider, "model": config.llm.model},
            "connected": list(config.providers),
        }

    def list_providers(self) -> dict[str, Any]:
        config = self.global_config
        connected = []
        for provider_id, provider in config.providers.items():
            connected.append(
                {
                    "id": provider_id,
                    "name": provider_id,
                    "base_url": provider.base_url,
                    "protocol": provider.protocol,
                    "enabled": provider.enabled,
                    "models": len(provider.models),
                    "hidden": len(provider.hidden),
                    "has_key": bool(provider.api_key),
                    "active": provider_id == config.llm.provider,
                }
            )
        connected.sort(key=lambda item: (not item["active"], item["id"]))
        popular = [
            {
                "id": name,
                "name": name,
                "base_url": preset["base_url"],
                "protocol": preset.get("protocol", "openai"),
                "default_model": preset["model"],
            }
            for name, preset in PROVIDER_PRESETS.items()
            if name not in config.providers
        ]
        return {"ok": True, "connected": connected, "popular": popular}

    def _provider_settings(
        self, provider_id: str, base_url: str, protocol: str, api_key: str, model: str
    ) -> LLMSettings:
        settings = LLMSettings(**vars(self.global_config.llm))
        settings.provider = provider_id
        settings.base_url = base_url or settings.base_url
        settings.protocol = protocol or "openai"
        settings.api_key = api_key
        if model:
            settings.model = model
        return settings

    def connect_provider(self, payload: dict[str, Any]) -> dict[str, Any]:
        config = self.global_config
        provider_id = str(payload.get("provider") or "").strip()
        if not provider_id:
            return {"ok": False, "error": "provider is required"}
        preset = PROVIDER_PRESETS.get(provider_id, {})
        base_url = str(payload.get("base_url") or preset.get("base_url") or "").strip()
        protocol = str(payload.get("protocol") or preset.get("protocol") or "openai")
        api_key = str(payload.get("api_key") or "").strip()
        if not base_url:
            return {"ok": False, "error": "base URL is required"}

        provider = config.providers.get(provider_id) or ProviderConfig(id=provider_id)
        provider.base_url = base_url
        provider.protocol = protocol
        if api_key:
            provider.api_key = api_key
        provider.enabled = True

        warning = ""
        fetched: list[dict[str, str]] = []
        settings = self._provider_settings(
            provider_id, base_url, protocol, provider.api_key, preset.get("model", "")
        )
        try:
            fetched = asyncio.run(_fetch_models_async(settings))
        except Exception as exc:
            warning = f"could not list models: {exc}"

        for model in fetched:
            provider.models.setdefault(model["id"], model["name"])
        if not provider.models:
            default = preset.get("model") or config.llm.model
            if default:
                provider.models[default] = default

        config.providers[provider_id] = provider
        if payload.get("activate") or not config.llm.model or provider_id == config.llm.provider:
            self.activate_model(
                provider_id, config.llm.model if provider_id == config.llm.provider else ""
            )
        save_global_config(config)
        return {
            "ok": True,
            "provider": provider_id,
            "models": len(provider.models),
            "warning": warning,
        }

    def _fetch_models(self, settings: LLMSettings) -> list[dict[str, str]]:
        return asyncio.run(_fetch_models_async(settings))

    def refresh_provider(self, provider_id: str) -> dict[str, Any]:
        config = self.global_config
        provider = config.providers.get(provider_id)
        if provider is None:
            return {"ok": False, "error": f"provider '{provider_id}' is not connected"}
        settings = self._provider_settings(
            provider_id, provider.base_url, provider.protocol, provider.api_key, ""
        )
        try:
            fetched = self._fetch_models(settings)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        for model in fetched:
            provider.models.setdefault(model["id"], model["name"])
        save_global_config(config)
        return {"ok": True, "models": len(provider.models)}

    def disconnect_provider(self, provider_id: str) -> dict[str, Any]:
        config = self.global_config
        config.providers.pop(provider_id, None)
        if config.llm.provider == provider_id:
            remaining = next(iter(config.providers), None)
            if remaining:
                self.activate_model(remaining, "")
            else:
                config.llm.api_key = ""
        save_global_config(config)
        return {"ok": True}

    def activate_model(self, provider_id: str, model: str = "") -> dict[str, Any]:
        config = self.global_config
        provider = config.providers.get(provider_id)
        chosen = model
        if not chosen and provider is not None:
            chosen = next(iter(provider.models), "")
        if not chosen:
            preset = PROVIDER_PRESETS.get(provider_id, {})
            chosen = preset.get("model", config.llm.model)
        settings = settings_for_provider(config, provider_id, chosen)
        config.llm.provider = settings.provider
        config.llm.base_url = settings.base_url
        config.llm.protocol = settings.protocol
        config.llm.model = settings.model
        if settings.api_key:
            config.llm.api_key = settings.api_key
        save_global_config(config)
        return {"ok": True, "provider": provider_id, "model": config.llm.model}

    def set_model_visibility(self, provider_id: str, model: str, visible: bool) -> dict[str, Any]:
        config = self.global_config
        provider = config.providers.get(provider_id)
        if provider is None:
            return {"ok": False, "error": "provider not connected"}
        if visible:
            provider.hidden = [m for m in provider.hidden if m != model]
        elif model not in provider.hidden:
            provider.hidden.append(model)
        save_global_config(config)
        return {"ok": True}

    def set_provider_visibility(self, provider_id: str, visible: bool) -> dict[str, Any]:
        config = self.global_config
        provider = config.providers.get(provider_id)
        if provider is None:
            return {"ok": False, "error": "provider not connected"}
        provider.enabled = visible
        save_global_config(config)
        return {"ok": True}

    def add_custom_model(self, provider_id: str, model: str, name: str = "") -> dict[str, Any]:
        config = self.global_config
        model = (model or "").strip()
        if not model:
            return {"ok": False, "error": "model id is required"}
        provider = ensure_provider(config, provider_id)
        provider.models[model] = (name or model).strip()
        provider.hidden = [m for m in provider.hidden if m != model]
        save_global_config(config)
        return {"ok": True, "provider": provider_id, "model": model}

    def remove_model(self, provider_id: str, model: str) -> dict[str, Any]:
        config = self.global_config
        provider = config.providers.get(provider_id)
        if provider is None:
            return {"ok": False, "error": "provider not connected"}
        provider.models.pop(model, None)
        provider.hidden = [m for m in provider.hidden if m != model]
        save_global_config(config)
        return {"ok": True}

    # -- sessions / reports ------------------------------------------------ #
    def list_sessions(self) -> list[dict[str, Any]]:
        directory = sessions_dir()
        if not directory.exists():
            return []
        entries: list[dict[str, Any]] = []
        for path in directory.glob("*.session.enc"):
            stat = path.stat()
            entries.append(
                {
                    "id": path.name.replace(".session.enc", ""),
                    "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(
                        timespec="seconds"
                    ),
                    "size": stat.st_size,
                }
            )
        entries.sort(key=lambda item: item["modified"], reverse=True)
        return entries[:40]

    def load_session(self, session_id: str) -> dict[str, Any]:
        try:
            context = SharedContext.load(session_id)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        self.session = context
        return {
            "ok": True,
            "state": context.state.to_dict(),
            "summary": context.summary_dict(),
        }

    def export_report(self, formats: list[str] | None = None) -> dict[str, Any]:
        if self.session is None:
            return {"ok": False, "error": "No session to export."}
        from splitagent.report.generator import write_reports

        report_settings = self.project.report
        if formats:
            report_settings.formats = list(formats)
        try:
            paths = write_reports(
                self.session.state, report_settings, Path(report_settings.output_dir)
            )
        except (OSError, ValueError) as exc:
            return {"ok": False, "error": f"could not write report: {exc}"}
        self.report_paths = [str(p.resolve()) for p in paths]
        return {"ok": True, "reports": self.report_paths}
