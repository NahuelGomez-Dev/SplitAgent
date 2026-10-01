"""Tests for the JS bridge (``window.pywebview.api``).

Every method is called the way the front-end calls it, and the return value
must be JSON-serialisable. These are the contract the whole UI depends on.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from splitagent.config import (
    GlobalConfig,
    ProjectConfig,
    ProviderConfig,
    load_global_config,
    load_project_config,
)
from splitagent.desktop import DesktopApp


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("SPLITAGENT_HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)
    return DesktopApp(GlobalConfig(), ProjectConfig())


@pytest.fixture()
def api(app):
    return app.api


def _jsonable(value) -> bool:
    """Assert the front-end could actually receive this value."""
    json.dumps(value)
    return True


# --------------------------------------------------------------------------- #
# bootstrap
# --------------------------------------------------------------------------- #
def test_bootstrap_is_json_serialisable(api):
    data = api.bootstrap()
    assert _jsonable(data)
    for key in (
        "version",
        "configured",
        "config",
        "providers",
        "project",
        "project_path",
        "target_presets",
        "running",
        "chatting",
        "sessions",
        "execution",
    ):
        assert key in data, key


def test_bootstrap_reports_the_provider_catalogue(api):
    data = api.bootstrap()
    assert "openai" in data["providers"]
    assert "opencode-go" in data["providers"]
    assert "juice-shop" in data["target_presets"]


def test_bootstrap_never_leaks_the_api_key(api, app):
    app.global_config.llm.api_key = "super-secret"
    data = api.bootstrap()
    assert "super-secret" not in json.dumps(data)
    assert data["config"]["api_key_set"] is True


# --------------------------------------------------------------------------- #
# models / providers
# --------------------------------------------------------------------------- #
def test_list_models_after_connecting_a_provider(app, api):
    app.global_config.providers["local"] = ProviderConfig(
        id="local",
        base_url="http://localhost/v1",
        models={"m1": "Model One", "m2": "m2"},
    )
    result = api.list_models()
    assert result["ok"] is True
    ids = {m["id"] for m in result["models"]}
    assert {"m1", "m2"} <= ids
    assert all(m["visible"] for m in result["models"])


def test_list_providers_separates_connected_and_popular(app, api):
    app.global_config.providers["mine"] = ProviderConfig(id="mine", models={"a": "a"})
    result = api.list_providers()
    assert result["ok"] is True
    assert any(p["id"] == "mine" for p in result["connected"])
    assert any(p["id"] == "openai" for p in result["popular"])


def test_activate_model_switches_the_active_provider(app, api):
    app.global_config.providers["p"] = ProviderConfig(
        id="p", base_url="http://p/v1", models={"m": "m"}
    )
    result = api.activate_model({"provider": "p", "model": "m"})
    assert result["ok"] is True
    assert app.global_config.llm.provider == "p"
    assert app.global_config.llm.model == "m"
    assert load_global_config().llm.provider == "p"  # persisted


def test_model_visibility_toggles(app, api):
    app.global_config.providers["p"] = ProviderConfig(id="p", models={"m": "m", "n": "n"})
    assert api.set_model_visibility({"provider": "p", "model": "m", "visible": False})["ok"]
    listed = api.list_models()["models"]
    assert next(x for x in listed if x["id"] == "m")["visible"] is False

    api.set_model_visibility({"provider": "p", "model": "m", "visible": True})
    listed = api.list_models()["models"]
    assert next(x for x in listed if x["id"] == "m")["visible"] is True


def test_provider_visibility_disables_all_its_models(app, api):
    app.global_config.providers["p"] = ProviderConfig(id="p", models={"m": "m"})
    api.set_provider_visibility({"provider": "p", "visible": False})
    listed = api.list_models()["models"]
    assert all(not x["visible"] for x in listed if x["provider"] == "p")


def test_visibility_on_an_unknown_provider_is_rejected(api):
    assert (
        api.set_model_visibility({"provider": "nope", "model": "x", "visible": True})["ok"] is False
    )


def test_add_and_remove_custom_model(app, api):
    app.global_config.providers["p"] = ProviderConfig(id="p", models={})
    assert api.add_custom_model({"provider": "p", "model": "custom-1"})["ok"]
    assert any(m["id"] == "custom-1" for m in api.list_models()["models"])

    assert api.remove_model({"provider": "p", "model": "custom-1"})["ok"]
    assert not any(m["id"] == "custom-1" for m in api.list_models()["models"])


def test_add_custom_model_requires_an_id(api):
    assert api.add_custom_model({"provider": "p", "model": "  "})["ok"] is False


def test_disconnect_provider_removes_it(app, api):
    app.global_config.providers["p"] = ProviderConfig(id="p", models={"m": "m"})
    app.global_config.llm.provider = "p"
    app.global_config.providers["q"] = ProviderConfig(id="q", models={"n": "n"})

    assert api.disconnect_provider("p")["ok"]
    assert "p" not in app.global_config.providers
    # The active provider fell back to another connected one.
    assert app.global_config.llm.provider in ("q", "")


def test_refresh_provider_rejects_unknown(api):
    result = api.refresh_provider("does-not-exist")
    assert result["ok"] is False
    assert "not connected" in result["error"]


def test_connect_provider_falls_back_to_the_preset_url(api):
    """A known provider has a default endpoint, so an empty URL is fine."""
    result = api.connect_provider({"provider": "openai", "base_url": ""})
    assert result["ok"] is True


def test_connect_provider_requires_a_base_url_without_a_preset(api):
    """A provider with no known preset must supply its own endpoint."""
    result = api.connect_provider({"provider": "self-hosted-llm", "base_url": ""})
    assert result["ok"] is False
    assert "base URL" in result["error"]


def test_connect_provider_requires_a_provider(api):
    result = api.connect_provider({"base_url": "http://x/v1"})
    assert result["ok"] is False
    assert "provider" in result["error"].lower()


# --------------------------------------------------------------------------- #
# interface experience
# --------------------------------------------------------------------------- #
def test_bootstrap_exposes_the_experience(app, api):
    data = api.bootstrap()
    assert "ui" in data
    # A first run defaults to the simple interface.
    assert data["ui"]["developer_mode"] is False
    assert data["ui"]["experience"] == "auto"


def test_set_experience_developer(app, api):
    result = api.set_experience("developer")
    assert result["ok"] is True
    assert result["developer_mode"] is True
    assert app.global_config.ui.experience_chosen is True
    # Persisted, so the next launch keeps it.
    assert load_global_config().ui.experience == "developer"


def test_set_experience_guided(app, api):
    result = api.set_experience("guided")
    assert result["ok"] is True
    assert result["developer_mode"] is False
    assert load_global_config().ui.developer_mode is False


def test_set_experience_auto_clears_the_explicit_choice(app, api):
    api.set_experience("developer")
    result = api.set_experience("auto")
    assert result["ok"] is True
    assert app.global_config.ui.experience_chosen is False


def test_set_experience_rejects_an_unknown_value(api):
    result = api.set_experience("fancy")
    assert result["ok"] is False
    assert "unknown" in result["error"]


def test_set_ui_preference_toggles_thinking(app, api):
    api.set_ui_preference({"show_thinking": False})
    assert app.global_config.ui.show_thinking is False
    assert load_global_config().ui.show_thinking is False
    api.set_ui_preference({"show_thinking": True})
    assert load_global_config().ui.show_thinking is True


def test_experience_promotes_after_a_completed_audit(app):
    from splitagent.config import save_global_config

    app.global_config.ui.audits_completed = 1
    save_global_config(app.global_config)
    assert app.api.bootstrap()["ui"]["developer_mode"] is True


# --------------------------------------------------------------------------- #
# project
# --------------------------------------------------------------------------- #
def test_save_project_persists_every_field(app, api):
    result = api.save_project(
        {
            "name": "engagement",
            "target": {
                "kind": "api",
                "url": "http://127.0.0.1:8080",
                "scope": "127.0.0.1, localhost",
                "out_of_scope": "prod.example",
                "hosts": ["a.local"],
                "ports": ["80", "443", "not-a-port"],
            },
            "run": {
                "rounds": 4,
                "max_steps": 9,
                "allow_network": True,
                "sandbox": {"enabled": False},
            },
            "auth": {"username": "admin", "token": "t0ken"},
        }
    )
    assert result["ok"] is True
    project = app.project
    assert project.name == "engagement"
    assert project.target.kind == "api"
    assert project.target.scope == ["127.0.0.1", "localhost"]
    assert project.target.ports == [80, 443]  # the bad entry is dropped
    assert project.run.rounds == 4
    assert project.run.allow_network is True
    assert project.run.sandbox.enabled is False
    assert project.auth.username == "admin"

    # And it round-tripped to disk.
    assert load_project_config().target.url == "http://127.0.0.1:8080"


def test_save_project_rejects_bad_rounds(app, api):
    result = api.save_project({"run": {"rounds": 0, "max_steps": "abc"}})
    assert result["ok"] is True  # tolerated, clamped/ignored
    assert app.project.run.rounds >= 1


def test_load_project_from_a_file(app, api, tmp_path):
    from splitagent.config import save_project_config

    path = tmp_path / "other.yaml"
    project = ProjectConfig(name="loaded")
    project.target.url = "http://loaded.example"
    save_project_config(project, path)

    result = api.load_project(str(path))
    assert result["ok"] is True
    assert app.project.name == "loaded"


def test_load_project_missing_file(api, tmp_path):
    result = api.load_project(str(tmp_path / "nope.yaml"))
    assert result["ok"] is False
    assert "not found" in result["error"]


def test_apply_target_preset(app, api):
    result = api.apply_target_preset("juice-shop")
    assert result["ok"] is True
    assert app.project.target.url.endswith(":3000")
    assert app.project.run.sandbox.image.endswith("juice-shop:latest")


def test_apply_unknown_preset(api):
    result = api.apply_target_preset("nope")
    assert result["ok"] is False


# --------------------------------------------------------------------------- #
# audit lifecycle
# --------------------------------------------------------------------------- #
def test_start_audit_refuses_a_second_run(app, api, monkeypatch):
    app._audit_thread = _FakeThread(alive=True)
    result = api.start_audit({})
    assert result["ok"] is False
    assert "already running" in result["error"]


def test_stop_audit_without_a_run(api):
    result = api.stop_audit()
    assert result["ok"] is False


def test_start_audit_launches_a_worker(app, api, monkeypatch):
    launched: dict[str, bool] = {}

    class Recorder:
        def __init__(self, *a, **k):
            launched["yes"] = True

        def start(self):
            launched["started"] = True

        def is_alive(self):
            return True  # the caller stores it and treats the run as active

        def join(self, timeout=None):
            pass

    monkeypatch.setattr("threading.Thread", Recorder)
    result = api.start_audit({"objective": "test"})
    assert result["ok"] is True
    assert launched.get("yes") and launched.get("started")


# --------------------------------------------------------------------------- #
# workspace / toolbox
# --------------------------------------------------------------------------- #
def test_workspace_info_creates_the_directory(api, tmp_path):
    result = api.workspace_info()
    assert result["ok"] is True
    root = Path(result["root"])
    assert root.is_dir()
    assert (root / "notes").is_dir()
    assert _jsonable(result)


def test_save_and_read_a_trace(app, api):
    payload = json.dumps({"trace": [{"kind": "tool_call"}]})
    result = api.save_trace(payload)
    assert result["ok"] is True
    written = Path(result["path"])
    assert written.is_file()
    assert "tool_call" in written.read_text(encoding="utf-8")


def test_toolbox_status_shape(api):
    result = api.toolbox_status()
    assert result["ok"] is True
    status = result["status"]
    for key in ("docker_cli", "daemon", "image", "running", "effective_mode"):
        assert key in status, key
    assert _jsonable(result)


def test_toolbox_action_status_delegates(api):
    result = api.toolbox_action("status")
    assert result["ok"] is True


def test_toolbox_install_is_guarded_by_container_state(api):
    """With no running container it must refuse cleanly, never crash.

    The result depends on whether Docker happens to be up on the machine
    running the suite, so both outcomes are acceptable - a traceback is not.
    """
    result = api.toolbox_install({"manager": "apt", "package": "nmap"})
    assert isinstance(result, dict)
    if result["ok"] is False:
        assert "error" in result


# --------------------------------------------------------------------------- #
# sessions / reports
# --------------------------------------------------------------------------- #
def test_list_sessions_is_a_list(api):
    assert isinstance(api.list_sessions(), list)


def test_load_session_unknown(api):
    result = api.load_session("S-does-not-exist")
    assert result["ok"] is False


def test_export_without_a_session(api):
    result = api.export_report(None)
    assert result["ok"] is False
    assert "session" in result["error"].lower()


def test_get_session_state_without_a_session(api):
    assert api.get_session_state()["ok"] is False


def test_chat_controls(api):
    assert api.chat_reset()["ok"] is True
    assert api.chat_stop()["ok"] is False  # nothing running


def test_chat_send_rejects_an_empty_message(api):
    result = api.chat_send("   ")
    assert result["ok"] is False
    assert "empty" in result["error"]


# --------------------------------------------------------------------------- #
# diagnostics and shell
# --------------------------------------------------------------------------- #
def test_log_js_error_writes_a_file(app, api, tmp_path):
    result = api.log_js_error("TypeError: x is undefined")
    assert result["ok"] is True
    log = (
        Path(
            app.global_config.__class__.__module__
            and __import__("splitagent.config", fromlist=["config_home"]).config_home()
        )
        / "desktop-js.log"
    )
    assert log.is_file()
    assert "TypeError" in log.read_text(encoding="utf-8")


def test_open_path_missing(api, tmp_path):
    result = api.open_path(str(tmp_path / "nope.txt"))
    assert result["ok"] is False
    assert "not found" in result["error"]


def test_window_action_without_a_window(api):
    """Must report an error rather than raising when no window is bound."""
    result = api.window_action("minimize")
    assert "ok" in result  # either branch is acceptable, but it must not raise


class _FakeThread:
    def __init__(self, alive: bool = False):
        self._alive = alive

    def is_alive(self) -> bool:
        return self._alive

    def start(self) -> None:
        pass

    def join(self, timeout=None) -> None:
        pass
