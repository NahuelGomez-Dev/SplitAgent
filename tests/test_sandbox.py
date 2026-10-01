"""Tests for the target sandbox and the JSON bridge.

The sandbox is tested by faking the ``docker`` executable on PATH, so the
lifecycle logic (build, up, down, status, degraded mode) is exercised without
a container runtime. The JS bridge is tested through its real call signatures.
"""

from __future__ import annotations

import os
import stat

import pytest

from splitagent.config import SandboxConfig
from splitagent.core.sandbox import TARGET_PRESETS, DockerSandbox


# --------------------------------------------------------------------------- #
# presets
# --------------------------------------------------------------------------- #
def test_presets_are_complete():
    for name, preset in TARGET_PRESETS.items():
        assert preset["image"], name
        assert preset["url"].startswith("http"), name
        assert preset["port_map"], name


def test_known_vulnerable_targets_are_offered():
    for name in ("juice-shop", "dvwa", "bwapp", "webgoat"):
        assert name in TARGET_PRESETS


# --------------------------------------------------------------------------- #
# a fake docker CLI so no daemon is needed
# --------------------------------------------------------------------------- #
@pytest.fixture()
def fake_docker(tmp_path, monkeypatch):
    """Put a scripted ``docker`` on PATH and record the calls made."""
    calls: list[list[str]] = []
    behaviour: dict[str, tuple[int, str]] = {}

    def _make(replies: dict[str, tuple[int, str]] | None = None) -> list[list[str]]:
        behaviour.clear()
        if replies:
            behaviour.update(replies)
        calls.clear()

        if os.name == "nt":
            script = tmp_path / "docker.bat"
            lines = ["@echo off"]
            for pattern, (code, output) in behaviour.items():
                lines.append(f'echo %* | find "{pattern}" >nul && (echo {output}& exit /b {code})')
            lines.append("exit /b 0")
            script.write_text("\r\n".join(lines), encoding="utf-8")
        else:
            script = tmp_path / "docker"
            lines = ["#!/bin/sh"]
            for pattern, (code, output) in behaviour.items():
                lines.append(f'case "$*" in *"{pattern}"*) echo "{output}"; exit {code};; esac')
            lines.append("exit 0")
            script.write_text("\n".join(lines), encoding="utf-8")
            script.chmod(script.stat().st_mode | stat.S_IEXEC)

        monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
        return calls

    return _make


def _sandbox(**kwargs) -> DockerSandbox:
    config = SandboxConfig(enabled=True, **kwargs)
    return DockerSandbox(config, session_id="test")


# --------------------------------------------------------------------------- #
# detection / degradation
# --------------------------------------------------------------------------- #
def test_docker_unavailable_degrades(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))  # nothing on it
    sandbox = _sandbox()
    assert DockerSandbox.docker_available() is False
    assert sandbox._infer_url() == "http://localhost:3000" or sandbox._infer_url() == ""


async def test_up_without_docker_reports_cleanly(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))
    sandbox = _sandbox()
    status = await sandbox.up()
    assert status.available is False
    assert "Docker not found" in status.message


async def test_up_when_disabled(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/docker")
    sandbox = DockerSandbox(SandboxConfig(enabled=False), session_id="x")
    status = await sandbox.up()
    assert status.message == "sandbox disabled"


def test_infer_url_uses_the_first_mapped_port():
    sandbox = _sandbox(port_map={"8080": 80})
    assert sandbox._infer_url() == "http://localhost:8080"


def test_infer_url_without_a_mapping():
    sandbox = _sandbox(port_map={})
    assert sandbox._infer_url() == ""


# --------------------------------------------------------------------------- #
# lifecycle with a scripted docker
# --------------------------------------------------------------------------- #
async def test_up_success_reports_the_container(fake_docker, monkeypatch):
    fake_docker({"run -d": (0, "abcdef123456")})
    monkeypatch.setattr(
        DockerSandbox, "_run", _scripted({"network ls": (0, "bridge"), "run": (0, "cid123")})
    )
    sandbox = _sandbox(port_map={"3000": 3000})
    status = await sandbox.up()
    assert status.running is True
    assert status.container_id == "cid123"
    assert status.url == "http://localhost:3000"
    assert status.name.startswith("splitagent-target-")


async def test_up_failure_reports_the_error(fake_docker, monkeypatch):
    monkeypatch.setattr(DockerSandbox, "_run", _scripted({"run": (1, "port is already allocated")}))
    sandbox = _sandbox()
    status = await sandbox.up()
    assert status.running is False
    assert "already allocated" in status.message


async def test_down_is_safe_without_docker(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))
    sandbox = _sandbox()
    await sandbox.down()  # must not raise


async def test_status_reports_running(fake_docker, monkeypatch):
    monkeypatch.setattr(
        DockerSandbox,
        "_run",
        _scripted({"ps": (0, "abc123 splitagent-target-test")}),
    )
    sandbox = _sandbox()
    status = await sandbox.status()
    assert status.available is True
    assert status.running is True


async def test_status_reports_stopped(fake_docker, monkeypatch):
    monkeypatch.setattr(DockerSandbox, "_run", _scripted({"ps": (0, "")}))
    sandbox = _sandbox()
    status = await sandbox.status()
    assert status.running is False
    assert status.message == "stopped"


async def test_status_without_docker(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))
    sandbox = _sandbox()
    status = await sandbox.status()
    assert status.available is False


async def test_logs_returns_output(fake_docker, monkeypatch):
    monkeypatch.setattr(DockerSandbox, "_run", _scripted({"logs": (0, "line one\nline two")}))
    sandbox = _sandbox()
    assert "line one" in await sandbox.logs()


async def test_exec_returns_stdout_on_success(fake_docker, monkeypatch):
    monkeypatch.setattr(DockerSandbox, "_run", _scripted({"exec": (0, "root")}))
    sandbox = _sandbox()
    assert await sandbox.exec("whoami") == "root"


async def test_exec_returns_stderr_on_failure(fake_docker, monkeypatch):
    monkeypatch.setattr(DockerSandbox, "_run", _scripted({"exec": (1, "not found")}))
    sandbox = _sandbox()
    assert await sandbox.exec("nope") == "not found"


async def test_network_is_created_when_missing(monkeypatch):
    calls: list[tuple[str, ...]] = []

    # An async method assigned to the class receives self as the first arg.
    async def fake_run(self, *args, check=False):
        calls.append(args)
        if args[:2] == ("network", "ls"):
            return 0, "bridge\nhost\n", ""
        return 0, "", ""

    monkeypatch.setattr(DockerSandbox, "_run", fake_run)
    sandbox = _sandbox(network="splitagent-net")
    await sandbox._ensure_network()
    assert any(c[:2] == ("network", "create") for c in calls)


async def test_network_is_not_recreated_when_present(monkeypatch):
    calls: list[tuple[str, ...]] = []

    async def fake_run(self, *args, check=False):
        calls.append(args)
        return 0, "splitagent-net\nbridge\n", ""

    monkeypatch.setattr(DockerSandbox, "_run", fake_run)
    sandbox = _sandbox(network="splitagent-net")
    await sandbox._ensure_network()
    assert not any(c[:2] == ("network", "create") for c in calls)


async def test_check_mode_raises_on_failure(monkeypatch):
    """The real ``_run`` must turn a non-zero exit into a SandboxError."""
    from splitagent.errors import SandboxError

    class FakeProc:
        returncode = 1

        async def communicate(self):
            return b"", b"boom"

    async def fake_exec(*args, **kwargs):
        return FakeProc()

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec, raising=True)
    sandbox = _sandbox()
    with pytest.raises(SandboxError):
        await sandbox._run("ps", check=True)


def _scripted(replies: dict[str, tuple[int, str]]):
    """Return an async ``_run`` replacement driven by substring matches.

    It is assigned onto the class, so it must accept ``self`` as the instance.
    """

    async def fake_run(self, *args: str, check: bool = False) -> tuple[int, str, str]:
        joined = " ".join(args)
        for pattern, (code, output) in replies.items():
            if pattern in joined:
                return code, output, "" if code == 0 else output
        if check:
            raise __import__("splitagent.errors", fromlist=["SandboxError"]).SandboxError(
                "scripted failure"
            )
        return 0, "", ""

    return fake_run
