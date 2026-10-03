"""Workspace tools: the agents' own directory, tooling and notes."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from splitagent.core.workspace import (
    available_installers,
    install_suggestions,
    run_install,
    run_workspace_command,
    toolbox_installers,
    which_tool,
    workspace_for,
)
from splitagent.tools.base import Tool, ToolContext

# A token that looks like a host, URL or IP inside a shell command.
_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_HOST_HINT_RE = re.compile(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_SCP_RE = re.compile(r"^[^@/]+@([A-Za-z0-9.-]+):")


def _scope_hosts_from_argv(argv: list[str]) -> list[str]:
    """Best-effort extraction of network destinations from a command line.

    run_tool/install_tool shell out, so a tool can reach hosts the higher-level
    probes already validate. We pull out anything URL-, host- or IP-shaped and
    let ``check_scope`` decide. A token that is clearly a local flag or file is
    skipped so ordinary invocations are not blocked.
    """
    found: list[str] = []
    for raw in argv:
        token = str(raw).strip().strip("\"'")
        if not token or token.startswith("-"):
            continue
        if _URL_RE.match(token):
            found.append(token)
            continue
        # git remotes: git@host:path or user@host:path
        scp = _SCP_RE.match(token)
        if scp:
            found.append(scp.group(1))
            continue
        if "/" in token or "\\" in token or token.startswith("."):
            continue
        try:
            ipaddress.ip_address(token)
            found.append(token)
            continue
        except ValueError:
            pass
        if _HOST_HINT_RE.fullmatch(token):
            found.append(token)
    return found


def _enforce_scope(ctx: ToolContext, argv: list[str]) -> None:
    """Raise ScopeError if the command targets a host outside the scope."""
    for host in _scope_hosts_from_argv(argv):
        ctx.check_scope(host)


def _workspace(ctx: ToolContext):
    workspace = ctx.settings.get("workspace")
    if workspace is not None:
        return workspace
    project = ctx.settings.get("project")
    return workspace_for(project) if project is not None else None


def _toolbox(ctx: ToolContext):
    """The active toolbox, if the engine set one up for this session."""
    return ctx.settings.get("toolbox")


def _backend(ctx: ToolContext) -> str:
    return "toolbox" if _toolbox(ctx) is not None else "local"


def _write_file(ctx: ToolContext, path: str, content: str) -> dict[str, Any]:
    workspace = _workspace(ctx)
    if workspace is None:
        return {"error": "workspace is not configured"}
    workspace.ensure()
    target = (workspace.root / path).resolve()
    if not str(target).startswith(str(workspace.root.resolve())):
        return {"error": "path escapes the workspace"}
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return {"ok": True, "path": str(target), "bytes": len(content)}


def _read_file(ctx: ToolContext, path: str, max_bytes: int = 20000) -> dict[str, Any]:
    workspace = _workspace(ctx)
    if workspace is None:
        return {"error": "workspace is not configured"}
    target = (workspace.root / path).resolve()
    if not str(target).startswith(str(workspace.root.resolve())):
        return {"error": "path escapes the workspace"}
    if not target.is_file():
        return {"error": f"not a file: {path}"}
    text = target.read_text(encoding="utf-8", errors="replace")
    return {
        "path": str(target),
        "bytes": target.stat().st_size,
        "content": text[:max_bytes],
        "truncated": len(text) > max_bytes,
    }


def _list_dir(ctx: ToolContext, path: str = ".") -> dict[str, Any]:
    workspace = _workspace(ctx)
    if workspace is None:
        return {"error": "workspace is not configured"}
    workspace.ensure()
    target = (workspace.root / path).resolve()
    if not str(target).startswith(str(workspace.root.resolve())):
        return {"error": "path escapes the workspace"}
    if not target.exists():
        return {"error": f"not found: {path}"}
    entries = []
    for item in sorted(target.iterdir()):
        entries.append(
            {
                "name": item.name,
                "kind": "dir" if item.is_dir() else "file",
                "size": item.stat().st_size if item.is_file() else None,
            }
        )
    return {"path": str(target), "entries": entries[:200]}


def _install_tool(ctx: ToolContext, manager: str, package: str) -> dict[str, Any]:
    workspace = _workspace(ctx)
    if workspace is None:
        return {"error": "workspace is not configured"}
    if not workspace.config.allow_install:
        return {"error": "tool installation is disabled by the operator"}
    # Installing from a remote can reach a host outside the authorized scope.
    _enforce_scope(ctx, str(package).split())

    toolbox = _toolbox(ctx)
    if toolbox is not None:
        result = toolbox.install(manager, package)
        result["backend"] = "toolbox"
        result["supported_managers"] = toolbox_installers()
        return result

    timeout = max(30, int(workspace.config.max_install_seconds))
    result = run_install(workspace, manager, package, timeout=timeout)
    result["backend"] = "local"
    result["available_installers"] = available_installers()
    return result


def _run_command(
    ctx: ToolContext, argv: list[str], cwd: str = "tools", timeout: int = 300
) -> dict[str, Any]:
    workspace = _workspace(ctx)
    if workspace is None:
        return {"error": "workspace is not configured"}
    if not workspace.config.allow_external_tools:
        return {"error": "running external tools is disabled by the operator"}
    command = [str(a) for a in argv]
    # run_tool shells out, so enforce the same scope every network probe obeys.
    _enforce_scope(ctx, command)

    toolbox = _toolbox(ctx)
    if toolbox is not None:
        # Inside the toolbox everything runs against /workspace.
        workdir = "/workspace" if cwd == "root" else f"/workspace/{cwd}"
        result = toolbox.exec(command, cwd=workdir, timeout=timeout)
        result["backend"] = "toolbox"
        if not result.get("ok") and "not found" in str(result.get("output", "")):
            result["suggestions"] = install_suggestions(command[0])
        return result

    # Resolve the binary across PATH, the workspace bin and Go's bin.
    resolved = which_tool(command[0], workspace)
    if resolved:
        command[0] = resolved
    result = run_workspace_command(workspace, command, timeout=timeout, cwd_kind=cwd)
    result["backend"] = "local"
    return result


def _check_tool(ctx: ToolContext, name: str) -> dict[str, Any]:
    toolbox = _toolbox(ctx)
    if toolbox is not None:
        path = toolbox.which(name)
        return {
            "tool": name,
            "available": path is not None,
            "path": path or "",
            "backend": "toolbox",
            "install_suggestions": install_suggestions(name),
        }
    workspace = _workspace(ctx)
    resolved = which_tool(name, workspace)
    return {
        "tool": name,
        "available": resolved is not None,
        "path": resolved or "",
        "backend": "local",
        "install_suggestions": install_suggestions(name),
    }


def _workspace_info(ctx: ToolContext) -> dict[str, Any]:
    workspace = _workspace(ctx)
    if workspace is None:
        return {"error": "workspace is not configured"}
    workspace.ensure()
    toolbox = _toolbox(ctx)
    backend = "toolbox" if toolbox is not None else "local"
    info = {
        "root": str(workspace.root),
        "backend": backend,
        "container_path": "/workspace" if toolbox is not None else None,
        "structure": {
            "tools": str(workspace.path_for("tools")),
            "recon": str(workspace.path_for("recon")),
            "loot": str(workspace.path_for("loot")),
            "notes": str(workspace.path_for("notes")),
            "sessions": str(workspace.path_for("sessions")),
        },
        "installers": (toolbox_installers() if toolbox is not None else available_installers()),
        "security_tools": {
            name: _check_tool(ctx, name)["available"]
            for name in (
                "nmap",
                "nuclei",
                "ffuf",
                "gobuster",
                "sqlmap",
                "nikto",
                "subfinder",
                "httpx",
                "masscan",
                "whatweb",
            )
        },
        "allow_install": workspace.config.allow_install,
        "allow_external_tools": workspace.config.allow_external_tools,
        "inventory": workspace.inventory()[:60],
        "file_counts": workspace.stats(),
        "notes": workspace.notes_digest(),
    }
    if toolbox is not None:
        info["toolbox"] = {
            "container": toolbox.config.container,
            "image": toolbox.config.image,
            "edition": toolbox.config.edition,
            "isolated": True,
            "note": (
                "You are running inside an isolated container. The host is never "
                "touched: install and run anything here freely."
            ),
        }
    return info


def workspace_tools(ctx: ToolContext) -> list[Tool]:
    return [
        Tool(
            name="workspace_info",
            description=(
                "Inspect your persistent working directory: structure, installed "
                "tooling, available package managers and your own notes. Call "
                "this before planning so you know what you already have."
            ),
            parameters={"type": "object", "properties": {}},
            func=lambda: _workspace_info(ctx),
            scope="shared",
        ),
        Tool(
            name="workspace_write",
            description=(
                "Write a file inside your workspace (notes, recon output, "
                "scripts). Use it to keep structured context for yourself: "
                "`notes/<topic>.md` for plans, `recon/<target>.json` for data."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path, e.g. notes/plan.md",
                    },
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
            func=lambda path, content: _write_file(ctx, path, content),
            scope="shared",
        ),
        Tool(
            name="workspace_read",
            description="Read a file from your workspace.",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            func=lambda path: _read_file(ctx, path),
            scope="shared",
        ),
        Tool(
            name="workspace_list",
            description="List a directory inside your workspace.",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string", "default": "."}},
            },
            func=lambda path=".": _list_dir(ctx, path),
            scope="shared",
        ),
        Tool(
            name="install_tool",
            description=(
                "Install a tool for the engagement. In toolbox mode this runs "
                "inside the isolated container (apt/pip/pipx/go/npm/cargo/git), "
                "so it never touches the host. In local mode pip goes into an "
                "isolated virtualenv and npm/go/cargo/apt/brew/winget use the "
                "system manager. Check `workspace_info` first for what exists."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "manager": {
                        "type": "string",
                        "enum": [
                            "apt",
                            "pip",
                            "pipx",
                            "go",
                            "npm",
                            "cargo",
                            "git",
                            "brew",
                            "winget",
                        ],
                    },
                    "package": {
                        "type": "string",
                        "description": "Package name, or a git URL for `git`.",
                    },
                },
                "required": ["manager", "package"],
            },
            func=lambda manager, package: _install_tool(ctx, manager, package),
            scope="shared",
            dangerous=True,
            parallel_safe=False,
        ),
        Tool(
            name="check_tool",
            description=(
                "Check whether a tool is available (PATH, your workspace bin or "
                "Go's bin) and get install suggestions if it is missing. Call "
                "this for nmap, nuclei, ffuf, sqlmap, nikto, etc. before "
                "installing anything."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Executable name, e.g. nmap",
                    }
                },
                "required": ["name"],
            },
            func=lambda name: _check_tool(ctx, name),
            scope="shared",
        ),
        Tool(
            name="run_tool",
            description=(
                "Run a command from your workspace (cwd defaults to tools/). "
                "The binary is resolved from PATH, your tools/bin and Go's bin, "
                "so installed scanners like nmap, nuclei or ffuf work directly. "
                "Redirect heavy output to recon/ and prefer non-invasive flags "
                "plus rate limits to avoid tripping firewalls or IDS."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "argv": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": 'Command and arguments, e.g. ["nmap","-sV","127.0.0.1"]',
                    },
                    "cwd": {
                        "type": "string",
                        "enum": ["tools", "recon", "notes", "loot", "root"],
                        "default": "tools",
                    },
                    "timeout": {"type": "integer", "default": 300},
                },
                "required": ["argv"],
            },
            func=lambda argv, cwd="tools", timeout=300: _run_command(ctx, argv, cwd, timeout),
            scope="shared",
            dangerous=True,
            parallel_safe=False,
        ),
    ]
