"""End-to-end tests for the command line interface.

The CLI is the first thing a new user touches, so every subcommand is driven
through ``main()`` with a real argument vector, asserting on the exit code and
the file side effects rather than on internal calls.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from splitagent import __version__
from splitagent.cli import build_parser, main
from splitagent.config import (
    GlobalConfig,
    LLMSettings,
    ProjectConfig,
    load_global_config,
    load_project_config,
    save_global_config,
    save_project_config,
)


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    """Keep every test off the real home and out of the real cwd."""
    home = tmp_path / "home"
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setenv("SPLITAGENT_HOME", str(home))
    monkeypatch.chdir(work)
    return work


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
def test_parser_has_all_subcommands():
    parser = build_parser()
    actions = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
    assert actions, "no subparsers registered"
    names = set(actions[0].choices)
    for expected in (
        "init",
        "config",
        "run",
        "tui",
        "desktop",
        "report",
        "sandbox",
        "toolbox",
        "version",
    ):
        assert expected in names, expected


def test_parser_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_main_without_command_prints_help(capsys):
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "usage" in out.lower()


# --------------------------------------------------------------------------- #
# init
# --------------------------------------------------------------------------- #
def test_init_writes_a_project_file(isolated_env):
    target = isolated_env / "splitagent.yaml"
    code = main(["init", "--url", "http://localhost:3000", "--kind", "web", "-y"])
    assert code == 0
    assert target.exists()

    project = load_project_config(target)
    assert project.target.url == "http://localhost:3000"
    assert project.target.kind == "web"
    # Scope is derived from the target when not given explicitly.
    assert "localhost" in project.target.scope


def test_init_with_a_lab_preset(isolated_env):
    code = main(["init", "--preset", "juice-shop", "-y"])
    assert code == 0
    project = load_project_config(isolated_env / "splitagent.yaml")
    assert project.target.url.endswith(":3000")
    assert project.run.sandbox.image.endswith("juice-shop:latest")
    assert 3000 in project.target.ports


def test_init_rejects_an_unknown_preset(isolated_env, capsys):
    # argparse validates --preset against TARGET_PRESETS and exits 2.
    with pytest.raises(SystemExit) as exc:
        main(["init", "--preset", "not-a-preset", "-y"])
    assert exc.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_init_refuses_to_overwrite_without_force(isolated_env):
    assert main(["init", "--url", "http://a", "-y"]) == 0
    assert main(["init", "--url", "http://b", "-y"]) == 1
    # The original file survived.
    assert load_project_config().target.url == "http://a"


def test_init_force_overwrites(isolated_env):
    main(["init", "--url", "http://a", "-y"])
    assert main(["init", "--url", "http://b", "-y", "--force"]) == 0
    assert load_project_config().target.url == "http://b"


def test_init_honours_rounds_and_hosts(isolated_env):
    code = main(
        [
            "init",
            "--url",
            "http://x",
            "--hosts",
            "a.example",
            "b.example",
            "--rounds",
            "5",
            "-y",
        ]
    )
    assert code == 0
    project = load_project_config()
    assert project.run.rounds == 5
    assert project.target.hosts == ["a.example", "b.example"]


def test_init_custom_path(isolated_env):
    custom = isolated_env / "nested" / "custom.yaml"
    custom.parent.mkdir()
    assert main(["init", "--url", "http://x", "--path", str(custom), "-y"]) == 0
    assert custom.exists()


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #
def test_config_path_prints_location(capsys):
    assert main(["config", "path"]) == 0
    assert "config.yaml" in capsys.readouterr().out


def test_config_show_redacts_the_key(capsys):
    config = GlobalConfig(llm=LLMSettings(api_key="super-secret-value"))
    save_global_config(config)
    assert main(["config", "show"]) == 0
    out = capsys.readouterr().out
    assert "super-secret-value" not in out
    assert "***" in out


def test_config_set_updates_a_value():
    assert main(["config", "set", "model", "my-model"]) == 0
    assert load_global_config().llm.model == "my-model"


def test_config_set_coerces_types():
    assert main(["config", "set", "temperature", "0.7"]) == 0
    assert main(["config", "set", "max_tokens", "1234"]) == 0
    assert main(["config", "set", "stream", "false"]) == 0
    llm = load_global_config().llm
    assert llm.temperature == 0.7
    assert llm.max_tokens == 1234
    assert llm.stream is False


def test_config_set_rejects_unknown_key(capsys):
    assert main(["config", "set", "nonsense", "x"]) == 1
    assert "Unknown key" in capsys.readouterr().out


def test_config_preset_applies_a_provider():
    assert main(["config", "preset", "deepseek"]) == 0
    llm = load_global_config().llm
    assert llm.provider == "deepseek"
    assert "deepseek.com" in llm.base_url


def test_config_preset_rejects_unknown(capsys):
    assert main(["config", "preset", "does-not-exist"]) == 1
    assert "Unknown provider" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# version
# --------------------------------------------------------------------------- #
def test_version_command(capsys):
    assert main(["version"]) == 0
    out = capsys.readouterr().out
    assert __version__ in out
    assert "config" in out


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #
def _write_session(tmp_path: Path) -> Path:
    """Create a real encrypted session with one finding to report on."""
    import asyncio

    from splitagent.core.context import SharedContext

    directory = tmp_path / "sessions"
    ctx = SharedContext.create(target="http://target", directory=directory)
    asyncio.run(
        ctx.add_finding(
            {
                "title": "Missing CSP",
                "severity": "medium",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "cvss_score": 6.1,
                "evidence": "no CSP header",
            }
        )
    )
    asyncio.run(ctx.add_mitigation({"finding_id": ctx.state.findings[0].id, "title": "Add CSP"}))
    return ctx.save()


def test_report_from_an_encrypted_session(isolated_env, tmp_path):
    session_file = _write_session(tmp_path)
    out_dir = isolated_env / "reports"
    code = main(
        [
            "report",
            "--input",
            str(session_file),
            "--formats",
            "markdown",
            "json",
            "--output",
            str(out_dir),
        ]
    )
    assert code == 0
    produced = sorted(p.name for p in out_dir.iterdir())
    assert any(name.endswith(".md") for name in produced)
    assert any(name.endswith(".json") for name in produced)


def test_report_missing_file_fails(isolated_env, capsys):
    code = main(["report", "--input", str(isolated_env / "nope.enc")])
    assert code == 1
    assert "not found" in capsys.readouterr().out.lower()


def test_report_requires_a_source(isolated_env, capsys):
    assert main(["report"]) == 1
    assert "session" in capsys.readouterr().out.lower()


# --------------------------------------------------------------------------- #
# run / _load_project_or_fail
# --------------------------------------------------------------------------- #
def test_run_without_a_project_file_fails(isolated_env, capsys):
    assert main(["run"]) == 1
    assert "init" in capsys.readouterr().out.lower()


def test_run_prompts_setup_when_no_model_is_configured(isolated_env, monkeypatch, capsys):
    """An unconfigured run offers the wizard instead of failing blindly."""
    save_project_config(ProjectConfig(), isolated_env / "splitagent.yaml")

    # Answer the wizard: provider, base URL, model, key, temperature.
    answers = iter(["openai", "", "", "test-key", "0.2"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(answers))
    monkeypatch.setattr("getpass.getpass", lambda *a, **k: "test-key")
    # Skip the live connectivity probe.
    monkeypatch.setattr("splitagent.cli.run_setup_wizard", lambda *a, **k: load_global_config())

    # The engine will fail to reach a provider; we only assert the wizard ran.
    try:
        main(["run", "--no-sandbox", "--no-report"])
    except Exception:
        pass
    out = capsys.readouterr().out
    assert "setup" in out.lower() or "configure the model" in out.lower()


def test_run_with_a_configured_model_reaches_the_engine(isolated_env, monkeypatch, capsys):
    """With credentials present the CLI builds an engine and runs it."""
    save_project_config(ProjectConfig(), isolated_env / "splitagent.yaml")
    save_global_config(
        GlobalConfig(
            llm=LLMSettings(
                provider="custom",
                base_url="http://127.0.0.1:1/v1",
                api_key="k",
                model="m",
            )
        )
    )

    called: dict[str, bool] = {}

    class FakeEngine:
        def __init__(self, *a, **k):
            called["built"] = True

        async def run(self):
            from splitagent.core.context import SharedContext

            ctx = SharedContext.create(target="http://x")
            called["ran"] = True
            return ctx

    monkeypatch.setattr("splitagent.cli.Engine", FakeEngine)
    code = main(["run", "--no-sandbox", "--no-report"])
    assert code == 0
    assert called.get("built") and called.get("ran")


# --------------------------------------------------------------------------- #
# sandbox / toolbox (CLI surface only; Docker is tested separately)
# --------------------------------------------------------------------------- #
def test_sandbox_status_runs_without_docker(isolated_env):
    """Must degrade gracefully, never raise."""
    code = main(["sandbox", "status"])
    assert code in (0, 1)


def test_sandbox_rejects_unknown_preset(isolated_env, capsys):
    # argparse validates the choice list before the handler is reached.
    with pytest.raises(SystemExit) as exc:
        main(["sandbox", "up", "--preset", "nope"])
    assert exc.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_toolbox_status_reports_state(isolated_env, capsys):
    code = main(["toolbox", "status"])
    assert code == 0
    out = capsys.readouterr().out
    assert "docker cli" in out
    assert "edition" in out


def test_toolbox_shell_prints_the_command(isolated_env, capsys):
    assert main(["toolbox", "shell"]) == 0
    assert "docker exec" in capsys.readouterr().out


def test_toolbox_accepts_edition_and_mode_flags(isolated_env, capsys):
    assert main(["toolbox", "status", "--edition", "kali", "--mode", "local"]) == 0
    assert "kali" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# error handling
# --------------------------------------------------------------------------- #
def test_main_returns_one_on_config_error(monkeypatch, capsys):
    """A SplitAgentError must become a clean message, not a traceback."""
    from splitagent import cli
    from splitagent.errors import ConfigError

    def boom(args):
        raise ConfigError("something went wrong")

    monkeypatch.setattr(cli, "cmd_version", boom)
    assert cli.main(["version"]) == 1
    assert "something went wrong" in capsys.readouterr().out


def test_main_handles_keyboard_interrupt(monkeypatch, capsys):
    from splitagent import cli

    def interrupt(args):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "cmd_version", interrupt)
    assert cli.main(["version"]) == 130


def test_force_utf8_is_safe():
    from splitagent.cli import _force_utf8

    _force_utf8()  # must not raise under pytest's captured streams


# --------------------------------------------------------------------------- #
# interactive helpers
# --------------------------------------------------------------------------- #
def test_prompt_returns_the_default_on_eof(monkeypatch):
    from splitagent.cli import _prompt

    monkeypatch.setattr("builtins.input", lambda *a, **k: (_ for _ in ()).throw(EOFError))
    assert _prompt("Target", "fallback") == "fallback"


def test_prompt_returns_the_default_on_interrupt(monkeypatch):
    from splitagent.cli import _prompt

    monkeypatch.setattr("builtins.input", lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt))
    assert _prompt("Target", "fallback") == "fallback"


def test_prompt_uses_typed_value(monkeypatch):
    from splitagent.cli import _prompt

    monkeypatch.setattr("builtins.input", lambda *a, **k: "  typed  ")
    assert _prompt("Target", "default") == "typed"


def test_prompt_blank_input_keeps_the_default(monkeypatch):
    from splitagent.cli import _prompt

    monkeypatch.setattr("builtins.input", lambda *a, **k: "   ")
    assert _prompt("Target", "default") == "default"


def test_prompt_secret_uses_getpass(monkeypatch):
    from splitagent.cli import _prompt

    monkeypatch.setattr("getpass.getpass", lambda *a, **k: "s3cret")
    assert _prompt("API key", secret=True) == "s3cret"


def test_setup_wizard_saves_a_provider(monkeypatch, capsys):
    """The wizard must persist whatever the operator types."""
    from splitagent.cli import run_setup_wizard

    # Order: provider, base URL, model, temperature. The key uses getpass.
    answers = iter(["1", "https://api.openai.com/v1", "gpt-4o-mini", "0.3"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(answers))
    monkeypatch.setattr("getpass.getpass", lambda *a, **k: "sk-test")

    config = run_setup_wizard(test=False)
    assert config.llm.provider == "openai"
    assert config.llm.model == "gpt-4o-mini"
    assert config.llm.api_key == "sk-test"
    assert config.llm.temperature == 0.3
    assert config.authorized is True

    # It was written to disk.
    assert load_global_config().llm.api_key == "sk-test"


def test_setup_wizard_accepts_a_provider_name(monkeypatch):
    from splitagent.cli import run_setup_wizard

    answers = iter(["deepseek", "https://api.deepseek.com/v1", "deepseek-chat", "0.2"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(answers))
    monkeypatch.setattr("getpass.getpass", lambda *a, **k: "")

    config = run_setup_wizard(test=False)
    assert config.llm.provider == "deepseek"
    assert "deepseek.com" in config.llm.base_url


def test_setup_wizard_falls_back_to_custom(monkeypatch):
    from splitagent.cli import run_setup_wizard

    answers = iter(["totally-made-up", "http://localhost:9999/v1", "m", "0.2"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(answers))
    monkeypatch.setattr("getpass.getpass", lambda *a, **k: "")

    config = run_setup_wizard(test=False)
    assert config.llm.provider == "custom"
    assert config.llm.base_url == "http://localhost:9999/v1"


def test_init_interactive_flow(isolated_env, monkeypatch):
    """With no flags, init asks the operator for the target details."""
    answers = iter(["api", "http://api.example", "extra.example", "2"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(answers))
    assert main(["init"]) == 0

    project = load_project_config()
    assert project.target.kind == "api"
    assert project.target.url == "http://api.example"
    assert project.target.hosts == ["extra.example"]
    assert project.run.rounds == 2


# --------------------------------------------------------------------------- #
# dispatch
# --------------------------------------------------------------------------- #
def test_run_desktop_flag_dispatches_to_desktop(isolated_env, monkeypatch):
    from splitagent import cli

    called: dict[str, bool] = {}

    def fake(args):
        called["desktop"] = True
        return 0

    monkeypatch.setattr(cli, "cmd_desktop", fake)

    assert cli.main(["run", "--desktop"]) == 0
    assert called.get("desktop")


def test_run_tui_flag_dispatches_to_tui(isolated_env, monkeypatch):
    from splitagent import cli

    called: dict[str, bool] = {}

    def fake(args):
        called["tui"] = True
        return 0

    monkeypatch.setattr(cli, "cmd_tui", fake)

    assert cli.main(["run", "--tui"]) == 0
    assert called.get("tui")


def test_toolbox_action_dispatch(monkeypatch):
    """down/reset must reach the toolbox object and report success."""
    from splitagent.core.toolbox import Toolbox

    calls: list[str] = []
    monkeypatch.setattr(Toolbox, "detect", lambda self, probe=False: _status())
    monkeypatch.setattr(Toolbox, "down", lambda self: calls.append("down"))
    monkeypatch.setattr(Toolbox, "reset", lambda self: calls.append("reset") or {"ok": True})

    assert main(["toolbox", "down"]) == 0
    assert main(["toolbox", "reset"]) == 0
    assert calls == ["down", "reset"]


def test_load_project_or_fail_raises_for_missing_file(tmp_path):
    from splitagent.cli import _load_project_or_fail
    from splitagent.errors import SplitAgentError

    args = argparse.Namespace(config=str(tmp_path / "missing.yaml"))
    with pytest.raises(SplitAgentError):
        _load_project_or_fail(args)


def test_load_project_or_fail_applies_overrides(isolated_env):
    from splitagent.cli import _load_project_or_fail

    save_project_config(ProjectConfig(), isolated_env / "splitagent.yaml")
    args = argparse.Namespace(
        config=None,
        rounds=7,
        url="http://override",
        max_steps=3,
        no_sandbox=True,
        allow_network=True,
    )
    project = _load_project_or_fail(args)
    assert project.run.rounds == 7
    assert project.target.url == "http://override"
    assert project.run.max_steps == 3
    assert project.run.sandbox.enabled is False
    assert project.run.allow_network is True


def _status():
    from splitagent.core.toolbox import ToolboxStatus

    return ToolboxStatus(docker_cli=True, daemon=True, image=True, running=True)
