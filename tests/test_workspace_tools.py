"""Tests for the workspace tools, in both local and toolbox mode.

The two backends share a contract: whatever the mode, ``install_tool``,
``run_tool`` and ``check_tool`` must return the same shape and report which
backend served the request.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from splitagent.config import ExecutionConfig, ProjectConfig, RunConfig, TargetConfig
from splitagent.core.context import SharedContext
from splitagent.core.workspace import workspace_for
from splitagent.tools.base import ToolContext
from splitagent.tools.workspace_tools import (
    _check_tool,
    _install_tool,
    _list_dir,
    _read_file,
    _run_command,
    _workspace_info,
    _write_file,
    workspace_tools,
)


def _ctx(tmp_path: Path, *, toolbox=None, workspace=None) -> ToolContext:
    project = ProjectConfig()
    ws = workspace or workspace_for(project, base=tmp_path)
    ws.ensure()
    settings: dict = {"workspace": ws, "project": project}
    if toolbox is not None:
        settings["toolbox"] = toolbox
    return ToolContext(
        target=TargetConfig(),
        run=RunConfig(),
        context=SharedContext.create(target="http://x", directory=tmp_path),
        settings=settings,
    )


class FakeToolbox:
    """Records what the tools asked the container to do."""

    def __init__(self, *, which: str | None = "/usr/bin/nmap", install_ok: bool = True):
        self.calls: list[tuple] = []
        self._which = which
        self._install_ok = install_ok
        # workspace_info reports these, so the fake needs them too.
        self.config = ExecutionConfig(container="fake-toolbox", image="fake:latest")

    def install(self, manager, package, timeout=900):
        self.calls.append(("install", manager, package))
        return {"ok": self._install_ok, "output": "installed" if self._install_ok else "boom"}

    def exec(self, argv, cwd="/workspace/tools", timeout=300, env=None):
        self.calls.append(("exec", tuple(argv), cwd))
        missing = "not found" if argv and argv[0] == "ghost" else ""
        return {
            "ok": not missing,
            "output": missing or "ran",
            "exit_code": 0 if not missing else 127,
        }

    def which(self, name):
        self.calls.append(("which", name))
        return self._which


# --------------------------------------------------------------------------- #
# no workspace configured
# --------------------------------------------------------------------------- #
def test_tools_refuse_without_a_workspace(tmp_path):
    ctx = ToolContext(
        target=TargetConfig(),
        run=RunConfig(),
        context=SharedContext.create(target="http://x", directory=tmp_path),
        settings={},
    )
    for fn, args in (
        (_write_file, ("a.txt", "x")),
        (_read_file, ("a.txt",)),
        (_list_dir, ()),
        (_workspace_info, ()),
        (_install_tool, ("pip", "x")),
        (_run_command, (["ls"],)),
    ):
        assert "error" in fn(ctx, *args)


# --------------------------------------------------------------------------- #
# files
# --------------------------------------------------------------------------- #
def test_write_read_and_list(tmp_path):
    ctx = _ctx(tmp_path)
    assert _write_file(ctx, "recon/scan.json", '{"open":[]}')["ok"] is True
    assert "open" in _read_file(ctx, "recon/scan.json")["content"]

    entries = _list_dir(ctx, "recon")["entries"]
    assert [e["name"] for e in entries] == ["scan.json"]


def test_write_creates_nested_directories(tmp_path):
    ctx = _ctx(tmp_path)
    assert _write_file(ctx, "notes/deep/plan.md", "x")["ok"] is True
    assert _read_file(ctx, "notes/deep/plan.md")["content"] == "x"


def test_read_truncates_large_files(tmp_path):
    ctx = _ctx(tmp_path)
    _write_file(ctx, "big.txt", "x" * 5000)
    result = _read_file(ctx, "big.txt", max_bytes=100)
    assert result["truncated"] is True
    assert len(result["content"]) == 100


def test_read_missing_file(tmp_path):
    ctx = _ctx(tmp_path)
    assert "error" in _read_file(ctx, "nope.txt")


def test_list_missing_directory(tmp_path):
    ctx = _ctx(tmp_path)
    assert "error" in _list_dir(ctx, "nope")


def test_paths_cannot_escape_the_workspace(tmp_path):
    ctx = _ctx(tmp_path)
    assert "error" in _write_file(ctx, "../escape.txt", "x")
    assert "error" in _read_file(ctx, "../../../etc/passwd")


# --------------------------------------------------------------------------- #
# workspace_info
# --------------------------------------------------------------------------- #
def test_workspace_info_local(tmp_path):
    ctx = _ctx(tmp_path)
    info = _workspace_info(ctx)
    assert info["backend"] == "local"
    assert info["container_path"] is None
    assert "installers" in info
    assert "security_tools" in info
    assert "file_counts" in info


def test_workspace_info_toolbox(tmp_path):
    ctx = _ctx(tmp_path, toolbox=FakeToolbox())
    info = _workspace_info(ctx)
    assert info["backend"] == "toolbox"
    assert info["container_path"] == "/workspace"
    assert info["toolbox"]["isolated"] is True
    # The toolbox supports apt, which local mode on Windows does not.
    assert "apt" in info["installers"]


# --------------------------------------------------------------------------- #
# install_tool
# --------------------------------------------------------------------------- #
def test_install_respects_the_operator_flag(tmp_path):
    project = ProjectConfig()
    project.workspace.allow_install = False
    ws = workspace_for(project, base=tmp_path)
    ws.ensure()
    ctx = _ctx(tmp_path, workspace=ws)
    result = _install_tool(ctx, "pip", "requests")
    assert "error" in result
    assert "disabled" in result["error"]


def test_install_via_toolbox(tmp_path):
    fake = FakeToolbox()
    ctx = _ctx(tmp_path, toolbox=fake)
    result = _install_tool(ctx, "apt", "nmap")
    assert result["backend"] == "toolbox"
    assert result["ok"] is True
    assert ("install", "apt", "nmap") in fake.calls
    assert "apt" in result["supported_managers"]


def test_install_local_reports_the_backend(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(
        "splitagent.tools.workspace_tools.run_install",
        lambda ws, m, p, timeout=900: {"ok": True, "manager": m, "package": p},
    )
    result = _install_tool(ctx, "pip", "requests")
    assert result["backend"] == "local"
    assert "available_installers" in result


# --------------------------------------------------------------------------- #
# run_tool
# --------------------------------------------------------------------------- #
def test_run_respects_the_operator_flag(tmp_path):
    project = ProjectConfig()
    project.workspace.allow_external_tools = False
    ws = workspace_for(project, base=tmp_path)
    ws.ensure()
    ctx = _ctx(tmp_path, workspace=ws)
    result = _run_command(ctx, ["nmap"])
    assert "error" in result
    assert "disabled" in result["error"]


def test_run_via_toolbox_maps_the_workdir(tmp_path):
    fake = FakeToolbox()
    ctx = _ctx(tmp_path, toolbox=fake)
    result = _run_command(ctx, ["nmap", "-sV"], cwd="recon")
    assert result["backend"] == "toolbox"
    assert ("exec", ("nmap", "-sV"), "/workspace/recon") in fake.calls


def test_run_via_toolbox_root_workdir(tmp_path):
    fake = FakeToolbox()
    ctx = _ctx(tmp_path, toolbox=fake)
    _run_command(ctx, ["ls"], cwd="root")
    assert ("exec", ("ls",), "/workspace") in fake.calls


def test_run_via_toolbox_suggests_an_install_when_missing(tmp_path):
    fake = FakeToolbox()
    ctx = _ctx(tmp_path, toolbox=fake)
    result = _run_command(ctx, ["ghost"])
    assert result["ok"] is False
    assert "suggestions" in result


def test_run_local_resolves_the_binary(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(
        "splitagent.tools.workspace_tools.run_workspace_command",
        lambda ws, cmd, timeout=300, cwd_kind="tools": {
            "ok": True,
            "command": " ".join(cmd),
        },
    )
    result = _run_command(ctx, ["echo", "hi"])
    assert result["backend"] == "local"


# --------------------------------------------------------------------------- #
# check_tool
# --------------------------------------------------------------------------- #
def test_check_tool_local_for_a_missing_binary(tmp_path):
    result = _check_tool(_ctx(tmp_path), "definitely-not-a-real-binary-xyz")
    assert result["available"] is False
    assert result["backend"] == "local"


def test_check_tool_toolbox(tmp_path):
    fake = FakeToolbox(which="/usr/bin/nmap")
    result = _check_tool(_ctx(tmp_path, toolbox=fake), "nmap")
    assert result["available"] is True
    assert result["path"] == "/usr/bin/nmap"
    assert result["backend"] == "toolbox"


def test_check_tool_toolbox_when_absent(tmp_path):
    fake = FakeToolbox(which=None)
    result = _check_tool(_ctx(tmp_path, toolbox=fake), "nmap")
    assert result["available"] is False
    assert result["path"] == ""


def test_check_tool_offers_install_suggestions(tmp_path):
    result = _check_tool(_ctx(tmp_path), "nmap")
    assert isinstance(result["install_suggestions"], list)


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #
def test_all_workspace_tools_are_registered(tmp_path):
    ctx = _ctx(tmp_path)
    names = {t.name for t in workspace_tools(ctx)}
    for expected in (
        "workspace_info",
        "workspace_write",
        "workspace_read",
        "workspace_list",
        "install_tool",
        "run_tool",
        "check_tool",
    ):
        assert expected in names, expected


def test_dangerous_workspace_tools_are_not_parallel_safe(tmp_path):
    ctx = _ctx(tmp_path)
    tools = {t.name: t for t in workspace_tools(ctx)}
    assert tools["install_tool"].parallel_safe is False
    assert tools["run_tool"].parallel_safe is False
    # Read-only ones may run concurrently.
    assert tools["workspace_read"].parallel_safe is True


# --------------------------------------------------------------------------- #
# scope enforcement (run_tool / install_tool must obey target.scope)
# --------------------------------------------------------------------------- #
def _scoped_ctx(tmp_path: Path, scope: list[str]) -> ToolContext:
    project = ProjectConfig()
    ws = workspace_for(project, base=tmp_path)
    ws.ensure()
    return ToolContext(
        target=TargetConfig(url="http://localhost", scope=scope),
        run=RunConfig(allow_network=False),
        context=SharedContext.create(target="http://localhost", directory=tmp_path),
        settings={"workspace": ws, "project": project},
    )


def test_run_command_refuses_an_out_of_scope_host(tmp_path):
    from splitagent.errors import ScopeError

    ctx = _scoped_ctx(tmp_path, ["localhost"])
    with pytest.raises(ScopeError):
        _run_command(ctx, ["nmap", "-sV", "scanme.nmap.org"])
    with pytest.raises(ScopeError):
        _run_command(ctx, ["curl", "http://evil.example.com/x"])


def test_run_command_allows_an_in_scope_host(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "splitagent.tools.workspace_tools.run_workspace_command",
        lambda ws, cmd, timeout=300, cwd_kind="tools": {"ok": True, "command": " ".join(cmd)},
    )
    ctx = _scoped_ctx(tmp_path, ["localhost"])
    result = _run_command(ctx, ["nmap", "-sV", "localhost"])
    assert result["backend"] == "local"


def test_install_tool_refuses_an_out_of_scope_remote(tmp_path):
    from splitagent.errors import ScopeError

    ctx = _scoped_ctx(tmp_path, ["localhost"])
    with pytest.raises(ScopeError):
        _install_tool(ctx, "git", "https://github.com/evil/repo")


def test_scope_hosts_extraction(tmp_path):
    from splitagent.tools.workspace_tools import _scope_hosts_from_argv

    found = _scope_hosts_from_argv(
        [
            "nmap",
            "-sV",
            "10.0.0.5",
            "http://target.example.com/x",
            "git@github.com:o/r.git",
            "-p",
            "80",
        ]
    )
    assert "10.0.0.5" in found
    assert "http://target.example.com/x" in found
    assert "github.com" in found
    # Flags and bare numbers are not hosts.
    assert "80" not in found
    assert "-p" not in found
