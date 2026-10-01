"""Python <-> JavaScript bridge for the desktop app.

Every method here is callable from the front-end as
``window.pywebview.api.<method>(...)`` and must return JSON-serialisable data.
"""

from __future__ import annotations

import asyncio
import dataclasses
import os
from pathlib import Path
from typing import Any

from splitagent import __version__
from splitagent.config import (
    PROVIDER_PRESETS,
    LLMSettings,
    ensure_provider,
    global_config_path,
    load_project_config,
    project_config_path,
    save_global_config,
    save_project_config,
)
from splitagent.core.sandbox import TARGET_PRESETS


class JsApi:
    """Exposed to the WebView as ``window.pywebview.api``."""

    def __init__(self, app: Any) -> None:
        self._app = app

    # -- bootstrap --------------------------------------------------------- #
    def bootstrap(self) -> dict[str, Any]:
        config = self._app.global_config
        project = self._app.project
        return {
            "version": __version__,
            "configured": config.configured,
            "config": {
                "provider": config.llm.provider,
                "protocol": config.llm.protocol,
                "base_url": config.llm.base_url,
                "model": config.llm.model,
                "temperature": config.llm.temperature,
                "max_tokens": config.llm.max_tokens,
                "api_key_set": bool(config.llm.resolved_api_key()),
            },
            "config_path": str(global_config_path()),
            "providers": PROVIDER_PRESETS,
            "project": dataclasses.asdict(project),
            "project_path": str(project_config_path()),
            "target_presets": {
                name: {"image": preset["image"], "url": preset["url"]}
                for name, preset in TARGET_PRESETS.items()
            },
            "running": self._app.is_running(),
            "chatting": self._app.is_chatting(),
            "sessions": self._app.list_sessions(),
            "execution": dataclasses.asdict(project.run.execution),
            "ui": {
                "experience": config.ui.experience,
                "developer_mode": config.ui.developer_mode,
                "experience_chosen": config.ui.experience_chosen,
                "audits_completed": config.ui.audits_completed,
                "show_thinking": config.ui.show_thinking,
            },
        }

    # -- configuration ----------------------------------------------------- #
    def save_llm_config(self, payload: dict[str, Any]) -> dict[str, Any]:
        config = self._app.global_config
        provider = str(payload.get("provider") or config.llm.provider)
        preset = PROVIDER_PRESETS.get(provider, {})
        provider_cfg = ensure_provider(config, provider)

        if payload.get("base_url"):
            provider_cfg.base_url = str(payload["base_url"]).strip()
        elif preset.get("base_url"):
            provider_cfg.base_url = preset["base_url"]
        provider_cfg.protocol = preset.get("protocol", provider_cfg.protocol or "openai")
        key = str(payload.get("api_key") or "").strip()
        if key:
            provider_cfg.api_key = key
        provider_cfg.enabled = True

        if payload.get("temperature") is not None:
            try:
                config.llm.temperature = float(payload["temperature"])
            except (TypeError, ValueError):
                pass
        if payload.get("max_tokens"):
            try:
                config.llm.max_tokens = int(payload["max_tokens"])
            except (TypeError, ValueError):
                pass

        model = str(payload.get("model") or "").strip()
        if model:
            provider_cfg.models.setdefault(model, model)
        self._app.activate_model(provider, model)

        config.authorized = True
        path = save_global_config(config)
        return {"ok": True, "path": str(path), "configured": config.configured}

    # -- providers & model visibility -------------------------------------- #
    # -- interface preferences --------------------------------------------- #
    def set_experience(self, value: str) -> dict[str, Any]:
        """Switch between the guided and developer interfaces.

        ``guided`` is for someone who is not a security engineer: plain
        language, one obvious action at a time. ``developer`` is the full
        cockpit. Choosing either marks the preference as explicit so the
        automatic first-run heuristic stops overriding it.
        """
        value = str(value or "").strip().lower()
        if value not in ("auto", "guided", "developer"):
            return {"ok": False, "error": f"unknown experience '{value}'"}
        config = self._app.global_config
        config.ui.experience = value
        config.ui.experience_chosen = value != "auto"
        save_global_config(config)
        return {
            "ok": True,
            "experience": config.ui.experience,
            "developer_mode": config.ui.developer_mode,
        }

    def set_ui_preference(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Persist a single UI preference (currently ``show_thinking``)."""
        config = self._app.global_config
        if "show_thinking" in (payload or {}):
            config.ui.show_thinking = bool(payload["show_thinking"])
        save_global_config(config)
        return {"ok": True, "ui": dataclasses.asdict(config.ui)}

    # -- toolbox ----------------------------------------------------------- #
    def toolbox_status(self) -> dict[str, Any]:
        return self._app.toolbox_status()

    def toolbox_setup(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = payload or {}
        return self._app.toolbox_setup(
            edition=str(payload.get("edition") or ""),
            build=payload.get("build", True),
        )

    def toolbox_action(self, action: str, edition: str = "") -> dict[str, Any]:
        return self._app.toolbox_action(action, edition)

    def toolbox_install(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._app.toolbox_install(
            str(payload.get("manager") or "apt"), str(payload.get("package") or "")
        )

    # -- workspace --------------------------------------------------------- #
    def workspace_info(self) -> dict[str, Any]:
        from splitagent.core.workspace import available_installers, workspace_for

        workspace = workspace_for(self._app.project, base=Path.cwd())
        workspace.ensure()
        return {
            "ok": True,
            "root": str(workspace.root),
            "installers": available_installers(),
            "allow_install": self._app.project.workspace.allow_install,
            "allow_external_tools": self._app.project.workspace.allow_external_tools,
            "stats": workspace.stats(),
            "inventory": workspace.inventory()[:80],
            "instructions": workspace.instructions(self._app.project)[:8000],
        }

    def workspace_open(self) -> dict[str, Any]:
        info = self.workspace_info()
        return self.open_path(info["root"])

    def list_providers(self) -> dict[str, Any]:
        return self._app.list_providers()

    def connect_provider(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._app.connect_provider(payload or {})

    def disconnect_provider(self, provider_id: str) -> dict[str, Any]:
        return self._app.disconnect_provider(provider_id)

    def refresh_provider(self, provider_id: str) -> dict[str, Any]:
        return self._app.refresh_provider(provider_id)

    def activate_model(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._app.activate_model(
            str(payload.get("provider") or ""), str(payload.get("model") or "")
        )

    def set_model_visibility(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._app.set_model_visibility(
            str(payload.get("provider") or ""),
            str(payload.get("model") or ""),
            bool(payload.get("visible")),
        )

    def set_provider_visibility(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._app.set_provider_visibility(
            str(payload.get("provider") or ""), bool(payload.get("visible"))
        )

    def add_custom_model(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._app.add_custom_model(
            str(payload.get("provider") or ""),
            str(payload.get("model") or ""),
            str(payload.get("name") or ""),
        )

    def remove_model(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._app.remove_model(
            str(payload.get("provider") or ""), str(payload.get("model") or "")
        )

    def test_connection(self, payload: dict[str, Any]) -> dict[str, Any]:
        from splitagent.llm.client import LLMClient

        settings = LLMSettings(**vars(self._app.global_config.llm))
        if payload:
            settings.provider = str(payload.get("provider") or settings.provider)
            settings.protocol = PROVIDER_PRESETS.get(settings.provider, {}).get(
                "protocol", settings.protocol
            )
            if payload.get("base_url"):
                settings.base_url = str(payload["base_url"]).strip()
            if payload.get("model"):
                settings.model = str(payload["model"]).strip()
            if payload.get("api_key"):
                settings.api_key = str(payload["api_key"]).strip()

        async def _probe() -> tuple[bool, str]:
            async with LLMClient(settings) as client:
                return await client.test_connection()

        try:
            ok, message = asyncio.run(_probe())
        except Exception as exc:
            return {"ok": False, "message": f"{type(exc).__name__}: {exc}"}
        return {"ok": ok, "message": message}

    # -- project ----------------------------------------------------------- #
    def save_project(self, payload: dict[str, Any]) -> dict[str, Any]:
        project = self._app.project
        target = payload.get("target") or {}
        run = payload.get("run") or {}
        if target.get("kind"):
            project.target.kind = str(target["kind"])
        if "url" in target:
            project.target.url = str(target.get("url") or "")
        if "hosts" in target:
            project.target.hosts = _as_list(target["hosts"])
        if "ports" in target:
            project.target.ports = _as_int_list(target["ports"])
        if "scope" in target:
            project.target.scope = _as_list(target["scope"])
        if "out_of_scope" in target:
            project.target.out_of_scope = _as_list(target["out_of_scope"])
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
        if run.get("safe_mode") is not None:
            project.run.safe_mode = bool(run["safe_mode"])
        if run.get("allow_network") is not None:
            project.run.allow_network = bool(run["allow_network"])
        sandbox = run.get("sandbox") or {}
        if sandbox:
            if "enabled" in sandbox:
                project.run.sandbox.enabled = bool(sandbox["enabled"])
            if sandbox.get("image"):
                project.run.sandbox.image = str(sandbox["image"])
            if sandbox.get("port_map"):
                project.run.sandbox.port_map = {
                    str(k): int(v) for k, v in sandbox["port_map"].items()
                }
        workspace = payload.get("workspace") or {}
        if workspace:
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
        auth = payload.get("auth") or {}
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
        if payload.get("name"):
            project.name = str(payload["name"])

        path = project_config_path()
        if payload.get("path"):
            path = Path(str(payload["path"]))
        save_project_config(project, path)
        return {"ok": True, "path": str(path), "project": dataclasses.asdict(project)}

    def load_project(self, path: str = "") -> dict[str, Any]:
        candidate = Path(path) if path else project_config_path()
        if not candidate.exists():
            return {"ok": False, "error": f"not found: {candidate}"}
        project = load_project_config(candidate)
        self._app.project = project
        return {"ok": True, "path": str(candidate), "project": dataclasses.asdict(project)}

    def choose_project_file(self) -> dict[str, Any]:
        import webview

        result = self._app.window.create_file_dialog(
            webview.FileDialog.OPEN,
            allow_multiple=False,
            file_types=("SplitAgent config (*.yaml;*.yml)", "All files (*.*)"),
        )
        if not result:
            return {"ok": False}
        return self.load_project(str(result[0]))

    def apply_target_preset(self, name: str) -> dict[str, Any]:
        preset = TARGET_PRESETS.get(name)
        if not preset:
            return {"ok": False, "error": f"unknown preset '{name}'"}
        project = self._app.project
        project.target.url = preset["url"]
        project.target.ports = [int(p) for p in preset["port_map"]]
        project.run.sandbox.image = preset["image"]
        project.run.sandbox.port_map = preset["port_map"]
        return {"ok": True, "project": dataclasses.asdict(project)}

    # -- audit ------------------------------------------------------------- #
    def start_audit(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._app.start_audit(payload or {})

    def stop_audit(self) -> dict[str, Any]:
        return self._app.stop_audit()

    # -- copilot ----------------------------------------------------------- #
    def chat_send(self, message: str) -> dict[str, Any]:
        return self._app.chat_send(message)

    def chat_reset(self) -> dict[str, Any]:
        return self._app.chat_reset()

    def chat_stop(self) -> dict[str, Any]:
        return self._app.chat_stop()

    def list_models(self) -> dict[str, Any]:
        return self._app.list_models()

    def list_sessions(self) -> list[dict[str, Any]]:
        return self._app.list_sessions()

    def load_session(self, session_id: str) -> dict[str, Any]:
        return self._app.load_session(session_id)

    def export_report(self, formats: list[str] | None = None) -> dict[str, Any]:
        return self._app.export_report(formats)

    def save_trace(self, payload: str) -> dict[str, Any]:
        """Persist the full client-side replay trace next to the sessions."""
        from datetime import datetime

        from splitagent.config import config_home

        try:
            directory = config_home() / "traces"
            directory.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            path = directory / f"trace-{stamp}.json"
            path.write_text(str(payload), encoding="utf-8")
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "path": str(path)}

    # -- diagnostics ------------------------------------------------------- #
    def log_js_error(self, message: str) -> dict[str, Any]:
        from datetime import datetime

        from splitagent.config import config_home

        try:
            home = config_home()
            home.mkdir(parents=True, exist_ok=True)
            with (home / "desktop-js.log").open("a", encoding="utf-8") as handle:
                handle.write(f"{datetime.now().isoformat(timespec='seconds')} {message}\n")
        except Exception:  # pragma: no cover - best effort
            pass
        return {"ok": True}

    # -- shell ------------------------------------------------------------- #
    def window_action(self, action: str) -> dict[str, Any]:
        window = self._app.window
        try:
            if action == "minimize":
                window.minimize()
            elif action == "maximize":
                if getattr(self._app, "_maximized", False):
                    window.restore()
                    self._app._maximized = False
                else:
                    window.maximize()
                    self._app._maximized = True
            elif action == "close":
                window.destroy()
            elif action == "fullscreen":
                window.toggle_fullscreen()
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True}

    def open_path(self, path: str) -> dict[str, Any]:
        target = Path(path)
        if not target.exists():
            return {"ok": False, "error": "path not found"}
        try:
            os.startfile(str(target))  # type: ignore[attr-defined]
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True}

    def reveal(self, path: str) -> dict[str, Any]:
        target = Path(path)
        try:
            os.startfile(str(target.parent if target.is_file() else target))  # type: ignore[attr-defined]
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True}

    def get_session_state(self) -> dict[str, Any]:
        context = self._app.session
        if context is None:
            return {"ok": False}
        return {"ok": True, "state": context.state.to_dict()}


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return []


def _as_int_list(value: Any) -> list[int]:
    result: list[int] = []
    for item in _as_list(value):
        try:
            result.append(int(item))
        except ValueError:
            continue
    return result
