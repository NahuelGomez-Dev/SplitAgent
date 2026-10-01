from __future__ import annotations

import pytest

from splitagent.config import ProjectConfig
from splitagent.core.workspace import (
    available_installers,
    install_command,
    run_workspace_command,
    workspace_for,
)


def test_workspace_structure(tmp_path):
    project = ProjectConfig()
    workspace = workspace_for(project, base=tmp_path)
    root = workspace.ensure()
    assert root == tmp_path / "splitagent-workspace"
    for name in ("tools", "recon", "loot", "notes", "sessions", "cache"):
        assert (root / name).is_dir()
    assert (root / "README.md").is_file()
    assert (root / "AGENTS.md").is_file()


def test_workspace_custom_path(tmp_path):
    project = ProjectConfig()
    project.workspace.path = str(tmp_path / "custom-ws")
    workspace = workspace_for(project, base=tmp_path)
    assert workspace.root == tmp_path / "custom-ws"
    workspace.ensure()
    assert workspace.root.is_dir()


def test_env_and_stats(tmp_path):
    project = ProjectConfig()
    workspace = workspace_for(project, base=tmp_path)
    workspace.ensure()
    env = workspace.env
    assert env["SPLITAGENT_WORKSPACE"] == str(workspace.root)
    assert env["SPLITAGENT_RECON"] == str(workspace.root / "recon")

    (workspace.path_for("recon") / "scan.json").write_text("{}", encoding="utf-8")
    (workspace.path_for("notes") / "n.md").write_text("hello", encoding="utf-8")
    stats = workspace.stats()
    assert stats["recon"] == 1
    assert stats["notes"] == 1


def test_instructions_loaded(tmp_path):
    project = ProjectConfig()
    project.workspace.instructions = "Always prefer passive recon."
    workspace = workspace_for(project, base=tmp_path)
    workspace.ensure()
    text = workspace.instructions(project)
    assert "Always prefer passive recon." in text
    assert "AGENTS.md" in text  # the workspace template is attached too

    # A custom instruction file is honoured.
    custom = tmp_path / "rules.md"
    custom.write_text("No noisy scanners.", encoding="utf-8")
    project.workspace.instruction_files = [str(custom)]
    text = workspace.instructions(project)
    assert "No noisy scanners." in text


def test_notes_digest(tmp_path):
    project = ProjectConfig()
    workspace = workspace_for(project, base=tmp_path)
    workspace.ensure()
    assert workspace.notes_digest() == "(no notes yet)"
    (workspace.path_for("notes") / "plan.md").write_text("# Plan\nmap the app", encoding="utf-8")
    digest = workspace.notes_digest()
    assert "plan.md" in digest and "map the app" in digest


def test_install_command_shapes(tmp_path):
    project = ProjectConfig()
    workspace = workspace_for(project, base=tmp_path)
    workspace.ensure()

    pip_cmd = install_command("pip", "requests", workspace)
    assert "pip" in pip_cmd and "install" in pip_cmd and "requests" in pip_cmd
    assert str(workspace.path_for("tools")) in pip_cmd[0]

    git_cmd = install_command("git", "https://github.com/x/y.git", workspace)
    assert git_cmd[0] == "git" and git_cmd[1] == "clone"
    assert git_cmd[-1].endswith("y")

    # The {package} placeholder is substituted, not duplicated.
    winget = install_command("winget", "Insecure.Nmap", workspace)
    assert winget.count("Insecure.Nmap") == 1
    assert "{package}" not in " ".join(winget)

    with pytest.raises(ValueError):
        install_command("nonsense", "x", workspace)


def test_install_suggestions():
    from splitagent.core.workspace import install_suggestions

    suggestions = install_suggestions("nmap")
    assert suggestions
    assert all("manager" in s and "package" in s for s in suggestions)
    assert install_suggestions("not-a-real-tool") == []


def test_which_tool_resolves_python(tmp_path):
    from splitagent.core.workspace import which_tool

    workspace = workspace_for(ProjectConfig(), base=tmp_path)
    workspace.ensure()
    assert which_tool("definitely-not-real-binary-xyz", workspace) is None
    # Write a fake binary into the workspace bin and confirm resolution.
    bin_dir = workspace.path_for("tools") / "bin"
    fake = bin_dir / "mytool"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")
    resolved = which_tool("mytool", workspace)
    assert resolved is not None and "mytool" in resolved


def test_tool_environment_puts_workspace_on_path(tmp_path):
    from splitagent.core.workspace import tool_environment

    workspace = workspace_for(ProjectConfig(), base=tmp_path)
    workspace.ensure()
    env = tool_environment(workspace)
    assert str(workspace.path_for("tools") / "bin") in env["PATH"]


def test_available_installers_is_list():
    installers = available_installers()
    assert isinstance(installers, list)
    assert all(isinstance(name, str) for name in installers)


def test_run_workspace_command(tmp_path):
    workspace = workspace_for(ProjectConfig(), base=tmp_path)
    workspace.ensure()
    result = run_workspace_command(workspace, ["python", "-c", "print('workspace-ok')"], timeout=60)
    assert result["ok"] is True
    assert "workspace-ok" in result["output"]

    missing = run_workspace_command(workspace, ["definitely-not-a-real-binary"])
    assert missing["ok"] is False
    assert "not found" in missing["error"]
