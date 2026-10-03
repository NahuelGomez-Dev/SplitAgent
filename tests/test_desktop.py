from __future__ import annotations

from pathlib import Path

from splitagent.config import GlobalConfig, ProjectConfig
from splitagent.desktop import DesktopApp
from splitagent.desktop.app import WEB_DIR


def _app(tmp_path, monkeypatch) -> DesktopApp:
    monkeypatch.setenv("SPLITAGENT_HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)
    return DesktopApp(GlobalConfig(), ProjectConfig())


def test_web_assets_present():
    assert (WEB_DIR / "index.html").exists()
    assert (WEB_DIR / "styles.css").exists()
    assert (WEB_DIR / "app.js").exists()
    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    assert "app.js" in html and "styles.css" in html
    assert "pywebview-drag-region" in html


def test_bundled_fonts_present():
    """The UI ships its own fonts so it never falls back to a system face."""
    fonts = WEB_DIR / "assets"
    assert (fonts / "Inter.ttf").is_file()
    assert (fonts / "JetBrainsMonoNerdFontMono-Regular.woff2").is_file()
    css = (WEB_DIR / "styles.css").read_text(encoding="utf-8")
    assert "@font-face" in css
    assert "assets/Inter.ttf" in css
    assert "JetBrainsMonoNerdFontMono-Regular.woff2" in css


def test_palette_tokens_defined():
    """Every colour the app references must resolve to a token."""
    css = (WEB_DIR / "styles.css").read_text(encoding="utf-8")
    for token in (
        "--bg-deep",
        "--bg-base",
        "--layer-01",
        "--text",
        "--text-muted",
        "--accent",
        "--accent-soft",
        "--border",
        "--radius-lg",
        "--ease",
        "--shadow-2",
    ):
        assert token in css, token


def test_layout_cannot_overflow_horizontally():
    """The shell must clip, and the tab strip must scroll rather than push."""
    css = (WEB_DIR / "styles.css").read_text(encoding="utf-8")
    assert "overflow: hidden;" in css
    # The review tab strip is the one strip that can exceed its column.
    assert ".review-tabs::-webkit-scrollbar { display: none; }" in css
    assert "flex: none; white-space: nowrap;" in css


def test_bootstrap_shape(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    data = app.api.bootstrap()
    assert data["version"]
    assert "config" in data and "providers" in data
    assert "target_presets" in data
    assert data["configured"] is False


def test_save_llm_config(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    res = app.api.save_llm_config(
        {
            "provider": "groq",
            "base_url": "https://api.groq.com/openai/v1",
            "model": "llama-3.3-70b-versatile",
            "api_key": "test-key",
            "temperature": 0.1,
            "apply_preset": True,
        }
    )
    assert res["ok"] is True
    data = app.api.bootstrap()
    assert data["config"]["provider"] == "groq"
    assert data["config"]["api_key_set"] is True
    assert data["configured"] is True


def test_save_project_and_preset(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    res = app.api.save_project(
        {
            "target": {"kind": "api", "url": "http://127.0.0.1:8080", "scope": "127.0.0.1"},
            "run": {"rounds": 2, "sandbox": {"enabled": False}},
        }
    )
    assert res["ok"] is True
    assert app.project.target.url == "http://127.0.0.1:8080"
    assert app.project.run.rounds == 2
    assert app.project.run.sandbox.enabled is False

    preset = app.api.apply_target_preset("juice-shop")
    assert preset["ok"] is True
    assert app.project.target.url.endswith(":3000")


def test_export_without_session(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    res = app.api.export_report(None)
    assert res["ok"] is False


def test_list_sessions_empty(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    assert app.api.list_sessions() == []


def test_window_asset_uri():
    index = (WEB_DIR / "index.html").resolve()
    assert Path(index).as_uri().startswith("file://")


def test_list_models_has_presets(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    app.global_config.llm.base_url = "http://127.0.0.1:1/v1"  # unreachable
    app.global_config.llm.api_key = "x"
    app.api.save_llm_config({"provider": "openai", "apply_preset": True})
    result = app.api.list_models()
    assert result["ok"] is True
    providers = {m["provider"] for m in result["models"]}
    assert "openai" in providers
    assert result["connected"]


def test_connect_provider_fetches_catalogue(tmp_path, monkeypatch, llm_servers):
    """Connect must populate the provider catalogue from /models."""
    _target_url, llm_url = llm_servers
    app = _app(tmp_path, monkeypatch)
    res = app.api.connect_provider(
        {
            "provider": "custom-live",
            "base_url": llm_url,
            "api_key": "test-key",
            "activate": True,
        }
    )
    assert res["ok"] is True
    assert res["warning"] == ""
    assert res["models"] >= 1
    provider = app.global_config.providers["custom-live"]
    assert "mock-model" in provider.models

    listed = app.api.list_models()["models"]
    assert any(m["provider"] == "custom-live" and m["id"] == "mock-model" for m in listed)

    refreshed = app.api.refresh_provider("custom-live")
    assert refreshed["ok"] is True

    activated = app.api.activate_model({"provider": "custom-live", "model": "mock-model"})
    assert activated["ok"] is True
    assert app.global_config.llm.provider == "custom-live"
    assert app.global_config.llm.base_url == llm_url


def test_provider_lifecycle(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    app.global_config.llm.base_url = "http://127.0.0.1:1/v1"
    providers = app.api.list_providers()
    assert providers["ok"] is True
    popular = {p["id"] for p in providers["popular"]}
    assert "openai" in popular

    app.api.connect_provider(
        {
            "provider": "groq",
            "base_url": "http://127.0.0.1:1/v1",
            "api_key": "k",
            "activate": True,
        }
    )
    providers = app.api.list_providers()
    connected = {p["id"]: p for p in providers["connected"]}
    assert "groq" in connected
    assert connected["groq"]["has_key"] is True

    app.api.add_custom_model({"provider": "groq", "model": "my-model"})
    listed = app.api.list_models()["models"]
    assert any(m["id"] == "my-model" for m in listed)

    app.api.set_model_visibility({"provider": "groq", "model": "my-model", "visible": False})
    listed = app.api.list_models()["models"]
    hidden = next(m for m in listed if m["id"] == "my-model")
    assert hidden["visible"] is False

    app.api.set_provider_visibility({"provider": "groq", "visible": False})
    listed = app.api.list_models()["models"]
    assert all(m["visible"] is False for m in listed if m["provider"] == "groq")

    app.api.disconnect_provider("groq")
    assert "groq" not in {p["id"] for p in app.api.list_providers()["connected"]}


def test_chat_pipeline(llm_servers, tmp_path, monkeypatch):
    target_url, llm_url = llm_servers
    app = _app(tmp_path, monkeypatch)
    app.global_config.llm.provider = "custom"
    app.global_config.llm.base_url = llm_url
    app.global_config.llm.api_key = "test-key"
    app.global_config.llm.model = "mock-model"
    app.global_config.llm.stream = True
    app.project.target.url = target_url
    app.project.target.scope = ["127.0.0.1"]
    app.project.run.max_steps = 3

    collected: list[dict] = []
    app._emit_chat = lambda batch: collected.extend(batch)  # type: ignore[assignment]

    app._chat_entry("How should I test this target?")

    types = [event["type"] for event in collected]
    assert "chat.start" in types
    assert "agent.tool_call" in types
    assert "chat.end" in types
    assert app._chat_history  # conversation persisted for the next turn

    app.api.chat_reset()
    assert app._chat_history == []


def _configured_app(tmp_path, monkeypatch, llm_url):
    app = _app(tmp_path, monkeypatch)
    app.global_config.llm.provider = "custom"
    app.global_config.llm.base_url = llm_url
    app.global_config.llm.api_key = "test-key"
    app.global_config.llm.model = "mock-model"
    app.global_config.llm.stream = True
    return app


def test_build_audit_plan_uses_the_model(llm_servers, tmp_path, monkeypatch):
    _target_url, llm_url = llm_servers
    app = _configured_app(tmp_path, monkeypatch, llm_url)
    plan = app.build_audit_plan(
        {
            "objective": "Audit the login",
            "scope": ["localhost"],
            "out_of_scope": ["admin.localhost"],
            "noise": "stealth",
        }
    )
    assert plan["source"] == "ai"
    assert plan["awaiting_approval"] is True
    assert plan["objective"]
    assert "admin.localhost" not in plan["scope"]


def test_build_audit_plan_sanitises_scope(llm_servers, tmp_path, monkeypatch):
    """A host the model puts in scope but the brief excludes must be dropped."""
    _target_url, llm_url = llm_servers
    app = _configured_app(tmp_path, monkeypatch, llm_url)
    plan = app.build_audit_plan({"scope": ["localhost"], "out_of_scope": ["localhost"]})
    assert plan["scope"] == []


def test_fallback_plan_without_a_model(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)  # no model configured
    plan = app.build_audit_plan({"objective": "Audit x", "scope": ["a.com"], "kind": "api"})
    assert plan["source"] == "fallback"
    assert plan["phases"]
    assert plan["awaiting_approval"] is True


def test_brief_chat_answers_without_starting_an_audit(llm_servers, tmp_path, monkeypatch):
    _target_url, llm_url = llm_servers
    app = _configured_app(tmp_path, monkeypatch, llm_url)
    res = app.brief_chat({"message": "it is a healthcare app", "brief": {}})
    assert res["ok"] is True
    assert res["text"]
    assert app.is_running() is False  # the planner never starts an audit


def test_planner_chat_prompt_is_conversational_not_json(tmp_path):
    from splitagent.agents.prompts import PLANNER_CHAT_SYSTEM

    # The chat must not demand a JSON answer; the plan prompt does.
    assert "never answer with JSON" in PLANNER_CHAT_SYSTEM
    assert "Return **only** a JSON" not in PLANNER_CHAT_SYSTEM


def test_build_project_maps_brief_to_instructions(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    project = app._build_project(
        {
            "brief": {
                "objective": "Audit auth",
                "crown_jewels": "SSO login",
                "noise": "stealth",
                "notes": "staging only",
            }
        }
    )
    assert "ENGAGEMENT BRIEF" in project.workspace.instructions
    assert "SSO login" in project.workspace.instructions
    assert project.run.tool_concurrency == 1  # stealth


def test_save_project_persists_hosts_and_tuning(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    res = app.api.save_project(
        {
            "target": {"hosts": ["10.0.0.5"]},
            "run": {"tool_concurrency": 6, "max_duration_minutes": 30},
            "workspace": {"instruction_files": ["scope.md"]},
        }
    )
    assert res["ok"] is True
    assert app.project.target.hosts == ["10.0.0.5"]
    assert app.project.run.tool_concurrency == 6
    assert app.project.run.max_duration_minutes == 30
    assert app.project.workspace.instruction_files == ["scope.md"]


def test_pick_scope_document_reads_text(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    doc = tmp_path / "scope.md"
    doc.write_text("In scope: app.example.com\nOut: admin.example.com", encoding="utf-8")

    class FakeWindow:
        def create_file_dialog(self, *a, **k):
            return [str(doc)]

    app.window = FakeWindow()
    res = app.api.pick_scope_document()
    assert res["ok"] is True
    assert res["name"] == "scope.md"
    assert "app.example.com" in res["content"]


def test_pick_scope_document_cancelled(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)

    class FakeWindow:
        def create_file_dialog(self, *a, **k):
            return None

    app.window = FakeWindow()
    assert app.api.pick_scope_document()["ok"] is False


def test_scope_document_reaches_the_instructions(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    project = app._build_project(
        {"brief": {"scope_document": "In scope: app.example.com", "noise": "normal"}}
    )
    assert "Operator scope document:" in project.workspace.instructions
    assert "app.example.com" in project.workspace.instructions


def test_save_project_with_auth(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    res = app.api.save_project(
        {
            "target": {"url": "http://127.0.0.1:8080"},
            "auth": {"username": "admin", "password": "secret", "token": "abc"},
        }
    )
    assert res["ok"] is True
    assert app.project.auth.username == "admin"
    assert app.project.auth.as_headers()["Authorization"] == "Bearer abc"


def test_desktop_audit_pipeline(llm_servers, tmp_path, monkeypatch):
    target_url, llm_url = llm_servers
    app = _app(tmp_path, monkeypatch)
    app.global_config.llm.provider = "custom"
    app.global_config.llm.base_url = llm_url
    app.global_config.llm.api_key = "test-key"
    app.global_config.llm.model = "mock-model"
    app.global_config.llm.stream = True
    app.project.target.url = target_url
    app.project.target.scope = ["127.0.0.1"]
    app.project.run.rounds = 1
    app.project.run.max_steps = 3
    app.project.run.sandbox.enabled = False

    collected: list[dict] = []
    app._emit = lambda batch: collected.extend(batch)  # type: ignore[assignment]

    app._audit_entry({"run": {"rounds": 1, "sandbox": False}})

    types = [event["type"] for event in collected]
    assert "audit.start" in types
    assert "agent.tool_call" in types
    assert "audit.end" in types
    end = next(event for event in collected if event["type"] == "audit.end")
    assert end["data"]["ok"] is True
    assert app.report_paths
