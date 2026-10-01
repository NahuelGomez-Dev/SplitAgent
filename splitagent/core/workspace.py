"""Workspace: the agent's own directory for tools, notes and recon data.

Mirrors how OpenCode roots an agent in a working directory and reads
``AGENTS.md`` instructions from it: the agents get a persistent, structured
place to install tooling, keep reconnaissance output, write notes and build
their own context between runs.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from splitagent.config import ProjectConfig, WorkspaceConfig
from splitagent.core import proc

INSTRUCTION_FILES = ("AGENTS.md", "CONTEXT.md", "SPLITAGENT.md")

README_TEMPLATE = """# SplitAgent workspace

This directory belongs to the agents. It persists across runs.

```
tools/            installed tooling (virtualenvs, binaries, scripts)
recon/            raw reconnaissance output (scans, crawls, screenshots)
loot/             downloaded artefacts and evidence
notes/            agent notes and structured context
sessions/         per-run logs and traces
cache/            package and request caches
```

Everything here is ignored by git. Put operator instructions in `AGENTS.md`.
"""

AGENTS_TEMPLATE = """# AGENTS.md

Operator instructions for the SplitAgent agents. Rules here are loaded into the
system prompt of the Red Agent, the Blue Agent and the copilot, and take
precedence over their defaults.

## Scope and rules of engagement
- Only test hosts listed in the engagement scope.
- Non-destructive probes only; never delete data or cause outages.

## Preferred approach
- Plan before acting: pick the smallest set of techniques that answers the
  question, and prefer passive recon before active scanning.
- Be resilient: rotate user agents, add delays, and avoid signature patterns
  that a WAF would block.

## Installed tooling
<!-- Describe the tools you installed under tools/ and how to invoke them. -->

## Notes
<!-- Durable context the agents should remember across runs. -->
"""


@dataclass
class Workspace:
    root: Path
    config: WorkspaceConfig

    # -- structure --------------------------------------------------------- #
    def ensure(self) -> Path:
        for name in (
            "tools",
            "recon",
            "loot",
            "notes",
            "sessions",
            "cache",
            "tools/bin",
        ):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        readme = self.root / "README.md"
        if not readme.exists():
            readme.write_text(README_TEMPLATE, encoding="utf-8")
        agents = self.root / "AGENTS.md"
        if not agents.exists():
            agents.write_text(AGENTS_TEMPLATE, encoding="utf-8")
        return self.root

    @property
    def env(self) -> dict[str, str]:
        return {
            "SPLITAGENT_WORKSPACE": str(self.root),
            "SPLITAGENT_TOOLS": str(self.root / "tools"),
            "SPLITAGENT_RECON": str(self.root / "recon"),
            "SPLITAGENT_NOTES": str(self.root / "notes"),
        }

    def path_for(self, kind: str) -> Path:
        mapping = {
            "tools": self.root / "tools",
            "recon": self.root / "recon",
            "loot": self.root / "loot",
            "notes": self.root / "notes",
            "sessions": self.root / "sessions",
            "cache": self.root / "cache",
        }
        target = mapping.get(kind, self.root)
        target.mkdir(parents=True, exist_ok=True)
        return target

    # -- instructions ------------------------------------------------------ #
    def instructions(self, project: ProjectConfig) -> str:
        """Operator guidance loaded into the agents' system prompt."""
        blocks: list[str] = []
        if project.workspace.instructions.strip():
            blocks.append(project.workspace.instructions.strip())
        for name in project.workspace.instruction_files:
            candidate = Path(name).expanduser()
            if not candidate.is_absolute():
                candidate = self.root / name
            if candidate.is_file():
                blocks.append(
                    f"Instructions from: {candidate}\n"
                    f"{candidate.read_text(encoding='utf-8', errors='replace')}"
                )
        agents = self.root / "AGENTS.md"
        if agents.is_file() and "AGENTS.md" not in project.workspace.instruction_files:
            blocks.append(
                f"Instructions from: {agents}\n"
                f"{agents.read_text(encoding='utf-8', errors='replace')}"
            )
        return "\n\n".join(blocks)

    def notes_digest(self, limit: int = 8) -> str:
        """A structured digest of the agent's own notes, oldest first."""
        files = sorted(
            (self.root / "notes").glob("*"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[:limit]
        if not files:
            return "(no notes yet)"
        lines: list[str] = []
        for path in reversed(files):
            try:
                text = path.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                continue
            snippet = " ".join(text.split())[:300]
            lines.append(f"- {path.name}: {snippet}")
        return "\n".join(lines) or "(no notes yet)"

    def inventory(self) -> list[dict[str, Any]]:
        tools = self.path_for("tools")
        entries: list[dict[str, Any]] = []
        for path in sorted(tools.iterdir()):
            if path.name == "bin":
                continue
            entries.append(
                {
                    "name": path.name,
                    "kind": "dir" if path.is_dir() else "file",
                }
            )
        for path in sorted((tools / "bin").iterdir() if (tools / "bin").exists() else []):
            entries.append({"name": f"bin/{path.name}", "kind": "binary"})
        return entries

    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for kind in ("tools", "recon", "loot", "notes", "sessions"):
            directory = self.path_for(kind)
            counts[kind] = sum(1 for _ in directory.rglob("*") if _.is_file())
        return counts


def workspace_for(project: ProjectConfig, base: Path | None = None) -> Workspace:
    configured = project.workspace.path.strip()
    if configured:
        root = Path(configured).expanduser()
        if not root.is_absolute():
            root = (base or Path.cwd()) / root
    else:
        root = (base or Path.cwd()) / "splitagent-workspace"
    return Workspace(root=root, config=project.workspace)


# --------------------------------------------------------------------------- #
# Tool installation
# --------------------------------------------------------------------------- #
INSTALLERS = {
    "pip": [sys.executable, "-m", "pip", "install", "--disable-pip-version-check"],
    "pipx": ["pipx", "install"],
    "npm": ["npm", "install", "--no-audit", "--no-fund", "-g"],
    "go": ["go", "install"],
    "cargo": ["cargo", "install"],
    "apt": ["apt-get", "install", "-y"],
    "brew": ["brew", "install"],
    "winget": [
        "winget",
        "install",
        "--id",
        "{package}",
        "--accept-source-agreements",
        "--accept-package-agreements",
        "--disable-interactivity",
    ],
    "binary": None,  # handled as a download
}

# Tools worth trying before a full install, and how to get them per platform.
TOOL_INSTALL_HINTS: dict[str, list[tuple[str, str]]] = {
    "nmap": [("winget", "Insecure.Nmap"), ("apt", "nmap"), ("brew", "nmap")],
    "masscan": [("winget", "Robertof.Masscan"), ("apt", "masscan"), ("brew", "masscan")],
    "nikto": [("apt", "nikto"), ("brew", "nikto")],
    "sqlmap": [("pip", "sqlmap"), ("apt", "sqlmap"), ("brew", "sqlmap")],
    "ffuf": [("go", "github.com/ffuf/ffuf/v2@latest"), ("brew", "ffuf")],
    "gobuster": [("go", "github.com/OJ/gobuster/v3@latest"), ("apt", "gobuster")],
    "nuclei": [("go", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")],
    "subfinder": [("go", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")],
    "httpx": [("go", "github.com/projectdiscovery/httpx/cmd/httpx@latest")],
    "whatweb": [("apt", "whatweb"), ("brew", "whatweb")],
    "dnsx": [("go", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest")],
}

# Location of tools installed through Go, which land in GOBIN/GOPATH/bin.
GO_BIN_DIRS = ("gopath_bin", "gobin")


def go_bin_dir() -> Path | None:
    for env in ("GOBIN", "GOPATH"):
        value = os.environ.get(env)
        if not value:
            continue
        path = Path(value)
        return path if env == "GOBIN" else path / "bin"
    home = Path.home()
    candidate = home / "go" / "bin"
    return candidate if candidate.exists() else None


def available_installers() -> list[str]:
    known = ("pip", "pipx", "npm", "go", "cargo", "apt", "brew", "winget", "git")
    return [name for name in known if shutil.which(name)]


# Managers that only exist inside the toolbox container.
TOOLBOX_INSTALLERS = ("apt", "pip", "pipx", "go", "npm", "cargo", "git")


def toolbox_installers() -> list[str]:
    return list(TOOLBOX_INSTALLERS)


def install_suggestions(tool: str) -> list[dict[str, str]]:
    """Preferred (manager, package) pairs for a well-known security tool."""
    hints = TOOL_INSTALL_HINTS.get(tool.lower())
    if not hints:
        return []
    available = set(available_installers())
    return [
        {"manager": manager, "package": package}
        for manager, package in hints
        if manager in available
    ]


def which_tool(name: str, workspace: Workspace | None = None) -> str | None:
    """Resolve a tool: PATH first, then the workspace bin, then Go's bin dir."""
    found = shutil.which(name)
    if found:
        return found
    if workspace is not None:
        candidate = workspace.path_for("tools") / "bin" / name
        for suffix in ("", ".exe", ".cmd", ".bat"):
            if Path(str(candidate) + suffix).is_file():
                return str(candidate) + suffix
    go_dir = go_bin_dir()
    if go_dir is not None:
        for suffix in ("", ".exe"):
            candidate = go_dir / f"{name}{suffix}"
            if candidate.is_file():
                return str(candidate)
    return None


def install_command(manager: str, package: str, workspace: Workspace) -> list[str]:
    if manager == "pip":
        venv = workspace.path_for("tools") / "venv"
        python = _venv_python(venv)
        return [str(python), "-m", "pip", "install", "--disable-pip-version-check", package]
    if manager == "git":
        target = workspace.path_for("tools") / package.rstrip("/").split("/")[-1].replace(
            ".git", ""
        )
        return ["git", "clone", "--depth", "1", package, str(target)]
    template = INSTALLERS.get(manager)
    if template is None:
        raise ValueError(f"unknown installer '{manager}'")
    # Templates may already carry a {package} placeholder (winget); otherwise
    # the package name is appended.
    if any("{package}" in part for part in template):
        return [part.replace("{package}", package) for part in template]
    return [*template, package]


def _venv_python(venv: Path) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def ensure_venv(workspace: Workspace) -> Path:
    """A dedicated virtualenv inside the workspace so installs stay contained."""
    venv = workspace.path_for("tools") / "venv"
    python = _venv_python(venv)
    if python.exists():
        return python
    import venv as venv_module

    venv_module.create(venv, with_pip=True, clear=False)
    return _venv_python(venv)


def run_install(
    workspace: Workspace,
    manager: str,
    package: str,
    timeout: int = 900,
) -> dict[str, Any]:
    workspace.ensure()
    if manager == "pip":
        ensure_venv(workspace)
    if shutil.which(manager) is None and manager not in ("pip", "pipx"):
        hints = install_suggestions(str(package).split("@")[0])
        return {
            "ok": False,
            "error": f"'{manager}' is not installed on this machine",
            "alternatives": hints,
            "available_installers": available_installers(),
        }
    command = install_command(manager, package, workspace)
    env = {**os.environ, **workspace.env}
    if manager == "go":
        # Keep Go binaries reachable by run_tool and the agents.
        target = workspace.path_for("tools") / "bin"
        env["GOBIN"] = str(target)
        env["PATH"] = str(target) + os.pathsep + env.get("PATH", "")
    try:
        completed = proc.run(command, cwd=str(workspace.root), timeout=timeout, env=env)
    except FileNotFoundError as exc:
        return {"ok": False, "error": f"{command[0]} not found: {exc}"}
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": f"installation timed out after {timeout}s",
            "command": " ".join(command),
        }
    result = completed
    stdout = (result.stdout or b"").decode("utf-8", "replace")
    stderr = (result.stderr or b"").decode("utf-8", "replace")
    output = stdout + stderr
    return {
        "ok": result.returncode == 0,
        "manager": manager,
        "package": package,
        "command": " ".join(command),
        "exit_code": result.returncode,
        "output": output[-4000:],
    }


def tool_environment(workspace: Workspace) -> dict[str, str]:
    """Environment with the workspace bin and Go bin on PATH."""
    env = {**os.environ, **workspace.env}
    extra: list[str] = [str(workspace.path_for("tools") / "bin")]
    go_dir = go_bin_dir()
    if go_dir is not None:
        extra.append(str(go_dir))
    venv_bin = workspace.path_for("tools") / "venv" / ("Scripts" if os.name == "nt" else "bin")
    if venv_bin.exists():
        extra.append(str(venv_bin))
    env["PATH"] = os.pathsep.join(extra) + os.pathsep + env.get("PATH", "")
    return env


def run_workspace_command(
    workspace: Workspace,
    argv: list[str],
    timeout: int = 300,
    cwd_kind: str = "tools",
) -> dict[str, Any]:
    """Run a tool from inside the workspace in a controlled way."""
    workspace.ensure()
    if not argv:
        return {"ok": False, "error": "empty command"}
    cwd = workspace.path_for(cwd_kind)
    env = tool_environment(workspace)
    try:
        completed = proc.run(argv, cwd=str(cwd), timeout=timeout, env=env)
    except FileNotFoundError:
        resolution = which_tool(argv[0], workspace)
        return {
            "ok": False,
            "error": f"command not found: {argv[0]}"
            + (f" (found at {resolution})" if resolution else ""),
            "suggestions": install_suggestions(argv[0]),
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timed out after {timeout}s"}
    result = completed
    stdout = (result.stdout or b"").decode("utf-8", "replace")
    stderr = (result.stderr or b"").decode("utf-8", "replace")
    output = stdout + stderr
    return {
        "ok": result.returncode == 0,
        "command": " ".join(argv),
        "exit_code": result.returncode,
        "output": output[-8000:],
    }
