"""Auditing a real server must never be replaced by the lab sandbox.

The sandbox exists to *provide* a disposable target. When the operator points
the engagement at a domain or a public IP, starting Juice Shop instead would
audit the wrong thing entirely. These tests pin that down.
"""

from __future__ import annotations

import pytest

from splitagent.config import GlobalConfig, LLMSettings, ProjectConfig
from splitagent.core.bus import EventBus
from splitagent.core.engine import Engine


def _engine(target: str, sandbox_enabled: bool = True) -> Engine:
    project = ProjectConfig()
    project.target.url = f"http://{target}" if "://" not in target else target
    project.target.scope = [target]
    project.run.sandbox.enabled = sandbox_enabled
    config = GlobalConfig(
        llm=LLMSettings(provider="custom", base_url="http://127.0.0.1:1/v1", api_key="k", model="m")
    )
    return Engine(config, project, bus=EventBus())


@pytest.mark.parametrize(
    "target",
    [
        "scanme.nmap.org",
        "example.com",
        "https://api.example.com",
        "93.184.216.34",
        "8.8.8.8",
        "subdomain.example.co.uk",
    ],
)
def test_external_targets_are_detected(target):
    assert _engine(target)._target_is_external() is True


@pytest.mark.parametrize(
    "target",
    [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "192.168.1.50",
        "10.0.0.5",
        "172.16.4.2",
        "169.254.1.1",
        "myapp.local",
    ],
)
def test_lab_targets_are_not_external(target):
    assert _engine(target)._target_is_external() is False


def test_no_target_is_not_external():
    project = ProjectConfig()
    engine = Engine(GlobalConfig(), project)
    assert engine._target_is_external() is False


async def test_external_target_does_not_start_the_sandbox(monkeypatch):
    engine = _engine("scanme.nmap.org", sandbox_enabled=True)

    started = {"up": False}

    async def fake_up():
        started["up"] = True
        raise AssertionError("the sandbox must not start for a real server")

    monkeypatch.setattr(engine.sandbox, "up", fake_up)
    await engine._start_sandbox()

    assert started["up"] is False
    assert engine._sandbox_status is None


async def test_external_target_explains_itself(monkeypatch):
    engine = _engine("example.com")
    events: list[str] = []
    engine.bus.subscribe(
        lambda e: events.append(e.data.get("text", "")) if e.type == "log" else None
    )

    async def fake_up():
        raise AssertionError("must not start")

    monkeypatch.setattr(engine.sandbox, "up", fake_up)
    await engine._start_sandbox()

    assert any("real server" in text for text in events)


async def test_local_target_still_starts_the_sandbox(monkeypatch):
    engine = _engine("127.0.0.1", sandbox_enabled=True)
    started = {"up": False}

    async def fake_up():
        from splitagent.core.sandbox import SandboxStatus

        started["up"] = True
        return SandboxStatus(available=True, running=False, message="disabled in test")

    monkeypatch.setattr(engine.sandbox, "up", fake_up)
    await engine._start_sandbox()
    assert started["up"] is True


async def test_disabled_sandbox_is_a_no_op(monkeypatch):
    engine = _engine("127.0.0.1", sandbox_enabled=False)

    async def fake_up():
        raise AssertionError("sandbox is disabled")

    monkeypatch.setattr(engine.sandbox, "up", fake_up)
    await engine._start_sandbox()  # must return before touching docker


# --------------------------------------------------------------------------- #
# init configures a real target correctly
# --------------------------------------------------------------------------- #
def test_init_disables_the_sandbox_for_a_real_target(tmp_path, monkeypatch):
    from splitagent.cli import main
    from splitagent.config import load_project_config

    monkeypatch.setenv("SPLITAGENT_HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)

    assert main(["init", "--url", "https://real.example.com", "-y"]) == 0
    project = load_project_config(tmp_path / "splitagent.yaml")
    assert project.run.sandbox.enabled is False
    assert project.run.allow_network is True


def test_init_keeps_the_sandbox_for_a_lab_preset(tmp_path, monkeypatch):
    from splitagent.cli import main
    from splitagent.config import load_project_config

    monkeypatch.setenv("SPLITAGENT_HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)

    assert main(["init", "--preset", "juice-shop", "-y"]) == 0
    project = load_project_config(tmp_path / "splitagent.yaml")
    assert project.run.sandbox.enabled is True
    assert project.run.allow_network is False


def test_init_keeps_the_sandbox_for_localhost(tmp_path, monkeypatch):
    from splitagent.cli import main
    from splitagent.config import load_project_config

    monkeypatch.setenv("SPLITAGENT_HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)

    assert main(["init", "--url", "http://localhost:8080", "-y"]) == 0
    project = load_project_config(tmp_path / "splitagent.yaml")
    assert project.run.sandbox.enabled is True


def test_is_external_target_helper():
    from splitagent.cli import _is_external_target
    from splitagent.config import TargetConfig

    assert _is_external_target(TargetConfig(url="https://a.example.com")) is True
    assert _is_external_target(TargetConfig(url="http://localhost")) is False
    assert _is_external_target(TargetConfig(hosts=["192.168.0.1"])) is False
    assert _is_external_target(TargetConfig()) is False
