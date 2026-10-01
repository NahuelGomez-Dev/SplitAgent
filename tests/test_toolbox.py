from __future__ import annotations

import shutil

import pytest

from splitagent.config import ExecutionConfig, ProjectConfig
from splitagent.core.toolbox import (
    DOCKERFILE,
    Toolbox,
    ToolboxStatus,
    build_command,
    docker_available,
    estimated_size,
    resolve_mode,
)


def _config(**kwargs) -> ExecutionConfig:
    defaults = {"mode": "auto", "auto_start": False}
    defaults.update(kwargs)
    return ExecutionConfig(**defaults)


def test_dockerfile_exists_and_has_both_editions():
    assert DOCKERFILE.is_file()
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "ARG EDITION=standard" in text
    assert "FROM debian:bookworm-slim AS standard" in text
    assert "FROM kalilinux/kali-rolling AS kali" in text
    assert "FROM ${EDITION} AS runtime" in text
    # tools we promise
    for tool in ("nmap", "masscan", "dirb", "nuclei", "ffuf", "sqlmap"):
        assert tool in text


def test_resolve_mode_local():
    config = _config(mode="local")
    status = ToolboxStatus(docker_cli=True, daemon=True, image=True)
    assert resolve_mode(config, status) == "local"


def test_resolve_mode_toolbox_forced():
    config = _config(mode="toolbox")
    status = ToolboxStatus(docker_cli=True, daemon=True, image=True)
    assert resolve_mode(config, status) == "toolbox"


def test_resolve_mode_auto_without_docker():
    config = _config(mode="auto")
    assert resolve_mode(config, ToolboxStatus(docker_cli=False)) == "local"


def test_resolve_mode_auto_with_docker_and_image():
    config = _config(mode="auto")
    status = ToolboxStatus(docker_cli=True, daemon=True, image=True)
    assert resolve_mode(config, status) == "toolbox"


def test_resolve_mode_auto_running_container():
    config = _config(mode="auto")
    status = ToolboxStatus(docker_cli=True, daemon=True, running=True)
    assert resolve_mode(config, status) == "toolbox"


def test_status_usable_and_serialisable():
    status = ToolboxStatus(docker_cli=True, daemon=True)
    assert status.usable is True
    data = status.to_dict()
    assert data["usable"] is True
    assert "container" in data and "edition" in data

    offline = ToolboxStatus(docker_cli=True, daemon=False)
    assert offline.usable is False


def test_build_command_and_sizes():
    command = build_command("standard")
    assert command[:2] == ["docker", "build"]
    assert "EDITION=standard" in command
    assert "splitagent-toolbox:latest" in command

    kali = build_command("kali")
    assert "EDITION=kali" in kali

    assert "450" in estimated_size("standard")
    assert "2.5" in estimated_size("kali")


def test_detect_without_docker(monkeypatch, tmp_path):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    toolbox = Toolbox(_config(), tmp_path)
    status = toolbox.detect()
    assert status.docker_cli is False
    assert status.usable is False
    assert "not installed" in status.message


def test_install_rejects_unknown_manager(tmp_path, monkeypatch):
    toolbox = Toolbox(_config(), tmp_path)
    monkeypatch.setattr(toolbox, "exec_shell", lambda *a, **k: {"ok": True, "output": ""})
    result = toolbox.install("nonsense", "x")
    assert result["ok"] is False
    assert "not supported" in result["error"]
    assert "apt" in result["supported"]


def test_install_disabled(tmp_path, monkeypatch):
    toolbox = Toolbox(_config(allow_install=False), tmp_path)
    result = toolbox.install("apt", "nmap")
    assert result["ok"] is False
    assert "disabled" in result["error"]


def test_install_builds_expected_scripts(tmp_path, monkeypatch):
    captured: list[str] = []
    toolbox = Toolbox(_config(), tmp_path)
    monkeypatch.setattr(
        toolbox,
        "exec_shell",
        lambda script, timeout=600: captured.append(script) or {"ok": True, "output": ""},
    )

    toolbox.install("apt", "smbclient")
    assert "apt-get install" in captured[-1] and "smbclient" in captured[-1]

    toolbox.install("pip", "impacket")
    assert "pip install" in captured[-1] and "impacket" in captured[-1]

    toolbox.install("go", "github.com/x/y@latest")
    assert "GOBIN=/workspace/tools/bin" in captured[-1]

    toolbox.install("git", "https://github.com/a/b.git")
    assert "git clone" in captured[-1] and "/workspace/tools/b" in captured[-1]


def test_up_without_docker_returns_error(monkeypatch, tmp_path):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    toolbox = Toolbox(_config(), tmp_path)
    result = toolbox.up()
    assert result["ok"] is False
    assert "not installed" in result["error"]


def test_up_without_daemon_and_no_autostart(monkeypatch, tmp_path):
    toolbox = Toolbox(_config(auto_start=False), tmp_path)
    monkeypatch.setattr(
        toolbox,
        "detect",
        lambda: ToolboxStatus(docker_cli=True, daemon=False),
    )
    result = toolbox.up()
    assert result["ok"] is False
    assert "not running" in result["error"]


def test_default_config_is_auto():
    project = ProjectConfig()
    assert project.run.execution.mode == "auto"
    assert project.run.execution.edition == "standard"
    assert project.run.execution.installed is False
    assert project.run.execution.auto_start is True


def test_docker_available_returns_bool():
    assert isinstance(docker_available(), bool)


def test_detect_skips_tool_probe_by_default(tmp_path, monkeypatch):
    """detect() must be fast: it is called on every UI refresh."""
    toolbox = Toolbox(_config(), tmp_path)
    calls: list[int] = []
    monkeypatch.setattr(toolbox, "probe_tools", lambda: calls.append(1) or {})
    monkeypatch.setattr(
        toolbox,
        "_run",
        lambda *a, **k: (0, "splitagent-toolbox\n", ""),
    )
    status = toolbox.detect()
    assert status.running is True
    assert calls == []  # no probing unless asked
    assert status.tools == {}

    toolbox.detect(probe=True)
    assert calls == [1]  # explicit probe does run


def test_setup_is_async_and_never_blocks(tmp_path, monkeypatch):
    """Building takes minutes; setup must return immediately."""
    import time

    from splitagent.config import GlobalConfig
    from splitagent.desktop import DesktopApp

    monkeypatch.setenv("SPLITAGENT_HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)
    app = DesktopApp(GlobalConfig(), ProjectConfig())
    app._emit = lambda batch: None  # type: ignore[assignment]

    # A deliberately slow worker: if setup blocked, this would hang the call.
    def slow_worker(build: bool) -> None:
        time.sleep(1.5)

    monkeypatch.setattr(app, "_toolbox_setup_worker", slow_worker)

    start = time.monotonic()
    result = app.toolbox_setup(edition="standard", build=True)
    elapsed = time.monotonic() - start

    assert result["async"] is True
    assert elapsed < 0.9, f"setup blocked for {elapsed:.2f}s"
    assert app.is_toolbox_busy() is True

    # A second request while busy is rejected rather than queued.
    again = app.toolbox_setup()
    assert again["ok"] is False
    assert "already running" in again["error"]

    app._toolbox_thread.join(timeout=5)  # type: ignore[union-attr]
    assert app.is_toolbox_busy() is False


def test_toolbox_failure_clears_installed(tmp_path, monkeypatch):
    from splitagent.config import GlobalConfig
    from splitagent.desktop import DesktopApp

    monkeypatch.setenv("SPLITAGENT_HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)
    app = DesktopApp(GlobalConfig(), ProjectConfig())
    events: list[dict] = []
    app._emit = lambda batch: events.extend(batch)  # type: ignore[assignment]

    app.project.run.execution.installed = True
    app._toolbox_fail("boom")

    assert app.project.run.execution.installed is False
    assert any(e["type"] == "toolbox.failed" for e in events)
    failed = next(e for e in events if e["type"] == "toolbox.failed")
    assert failed["data"]["error"] == "boom"


@pytest.mark.skipif(not docker_available(), reason="docker CLI not installed")
def test_exec_requires_running_container(tmp_path):
    """Without a running container, exec reports a clean error, not a crash."""
    toolbox = Toolbox(_config(auto_start=False), tmp_path)
    status = toolbox.detect()
    if not status.running:
        result = toolbox.exec(["echo", "hi"])
        assert result["ok"] is False
