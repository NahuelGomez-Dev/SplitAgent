"""The isolated toolbox: a disposable container the agents work inside.

Unlike :mod:`splitagent.core.sandbox` (which is the *target* under test), the
toolbox is the *attacker's machine*. Every tool the agents install or run goes
here, so the host is never modified. The workspace is bind-mounted at
``/workspace`` so tooling and reconnaissance data survive container rebuilds.

Lifecycle:

* ``detect()``      - is the docker CLI present and is the daemon answering?
* ``start_daemon()``- launch Docker Desktop and wait for the engine
* ``build()``       - build the image from ``docker/toolbox.Dockerfile``
* ``up()``          - create and start the container (builds first if needed)
* ``exec()``        - run a command inside the running container
* ``down()``        - stop the container (the image and workspace remain)

Everything degrades gracefully: with no Docker the callers fall back to local
execution, which is why ``mode="auto"`` is the default.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from splitagent.config import ExecutionConfig
from splitagent.core import proc

DOCKERFILE = Path(__file__).resolve().parents[2] / "docker" / "toolbox.Dockerfile"

# Windows/macOS Desktop install locations, used by start_daemon().
DESKTOP_CANDIDATES = (
    r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
    "/Applications/Docker.app",
    "/Applications/Docker.app/Contents/MacOS/Docker",
)

# Tools the toolbox ships with, used for status reporting.
KNOWN_TOOLS = (
    "nmap",
    "masscan",
    "nikto",
    "sqlmap",
    "whatweb",
    "wafw00f",
    "gobuster",
    "ffuf",
    "dirb",
    "nuclei",
    "subfinder",
    "httpx",
    "dnsx",
    "curl",
    "git",
    "python3",
    "pip3",
)

DAEMON_WAIT_SECONDS = 120


@dataclass
class ToolboxStatus:
    docker_cli: bool = False
    daemon: bool = False
    image: bool = False
    running: bool = False
    container: str = ""
    image_name: str = ""
    edition: str = "standard"
    mode: str = "auto"
    message: str = ""
    tools: dict[str, bool] = field(default_factory=dict)

    @property
    def usable(self) -> bool:
        return self.docker_cli and self.daemon

    def to_dict(self) -> dict[str, Any]:
        return {
            "docker_cli": self.docker_cli,
            "daemon": self.daemon,
            "image": self.image,
            "running": self.running,
            "container": self.container,
            "image_name": self.image_name,
            "edition": self.edition,
            "mode": self.mode,
            "message": self.message,
            "usable": self.usable,
            "tools": self.tools,
        }


def docker_available() -> bool:
    return shutil.which("docker") is not None


class Toolbox:
    """Manage the agent execution container."""

    def __init__(self, config: ExecutionConfig, workspace_root: Path | None = None) -> None:
        self.config = config
        self.workspace_root = workspace_root
        self._last_build_output = ""

    # -- low level --------------------------------------------------------- #
    def _run(
        self,
        *args: str,
        timeout: int = 120,
        check: bool = False,
    ) -> tuple[int, str, str]:
        if not docker_available():
            raise RuntimeError("docker was not found on PATH")
        try:
            completed = proc.run(["docker", *args], timeout=timeout)
        except FileNotFoundError as exc:  # pragma: no cover - guarded above
            raise RuntimeError(f"docker not found: {exc}") from exc
        # Docker output is UTF-8; never let the host code page break the run.
        out = (completed.stdout or b"").decode("utf-8", "replace").strip()
        err = (completed.stderr or b"").decode("utf-8", "replace").strip()
        if check and completed.returncode != 0:
            raise RuntimeError(err or out or f"docker exited with {completed.returncode}")
        return completed.returncode or 0, out, err

    # -- detection --------------------------------------------------------- #
    def detect(self, probe: bool = False) -> ToolboxStatus:
        status = ToolboxStatus(
            docker_cli=docker_available(),
            container=self.config.container,
            image_name=self.config.image,
            edition=self.config.edition,
            mode=self.config.mode,
        )
        if not status.docker_cli:
            status.message = "Docker is not installed"
            return status

        code, _, _ = self._run("info", "--format", "{{.ServerVersion}}", timeout=25)
        status.daemon = code == 0
        if not status.daemon:
            status.message = "Docker is installed but the daemon is not running"
            return status

        code, out, _ = self._run(
            "images",
            "--format",
            "{{.Repository}}:{{.Tag}}",
            timeout=25,
        )
        status.image = self.config.image in out.splitlines()

        code, out, _ = self._run(
            "ps",
            "--filter",
            f"name=^{self.config.container}$",
            "--format",
            "{{.Names}}",
            timeout=25,
        )
        status.running = self.config.container in out.splitlines()

        if status.running:
            if probe:
                status.tools = self.probe_tools()
            status.message = "running"
        elif status.image:
            status.message = "image ready, container stopped"
        else:
            status.message = "image not built yet"
        return status

    def probe_tools(self) -> dict[str, bool]:
        """Which known tools exist inside the running container."""
        found: dict[str, bool] = {}
        for tool in KNOWN_TOOLS:
            code, out, _ = self._run(
                "exec",
                self.config.container,
                "sh",
                "-lc",
                f"command -v {tool} >/dev/null 2>&1 && echo yes",
                timeout=20,
            )
            found[tool] = code == 0 and "yes" in out
        return found

    # -- daemon ------------------------------------------------------------ #
    def start_daemon(self, wait: int = DAEMON_WAIT_SECONDS) -> tuple[bool, str]:
        """Try to bring the Docker engine up without user interaction."""
        if not docker_available():
            return False, "docker CLI not found"
        code, _, _ = self._run("info", timeout=20)
        if code == 0:
            return True, "already running"

        launched = self._launch_desktop()
        deadline = time.time() + wait
        while time.time() < deadline:
            code, _, _ = self._run("info", timeout=15)
            if code == 0:
                return True, "started"
            time.sleep(3)
        if launched:
            return False, "Docker Desktop was started but the engine did not answer in time"
        return False, "could not start Docker automatically"

    def _launch_desktop(self) -> bool:
        for candidate in DESKTOP_CANDIDATES:
            path = Path(candidate)
            if not path.exists():
                continue
            argv = ["open", str(path)] if sys.platform == "darwin" else [str(path)]
            try:
                proc.popen(argv, detach=True)
                return True
            except OSError:
                continue
        return False

    # -- image ------------------------------------------------------------- #
    def build(self, timeout: int = 1800) -> dict[str, Any]:
        if not DOCKERFILE.is_file():
            return {"ok": False, "error": f"Dockerfile not found at {DOCKERFILE}"}
        code, out, err = self._run(
            "build",
            "-f",
            str(DOCKERFILE),
            "--build-arg",
            f"EDITION={self.config.edition}",
            "-t",
            self.config.image,
            str(DOCKERFILE.parent.parent),
            timeout=timeout,
        )
        self._last_build_output = (out + "\n" + err)[-8000:]
        if code != 0:
            return {
                "ok": False,
                "error": "docker build failed",
                "output": self._last_build_output,
            }
        return {
            "ok": True,
            "image": self.config.image,
            "edition": self.config.edition,
            "output": self._last_build_output[-2000:],
        }

    def remove_image(self) -> None:
        self._run("rmi", "-f", self.config.image, timeout=60)

    # -- container --------------------------------------------------------- #
    def up(self, build_if_missing: bool = True, timeout: int = 1800) -> dict[str, Any]:
        status = self.detect()
        if not status.docker_cli:
            return {"ok": False, "error": "Docker is not installed"}
        if not status.daemon:
            if not self.config.auto_start:
                return {"ok": False, "error": "Docker daemon is not running"}
            started, message = self.start_daemon()
            if not started:
                return {"ok": False, "error": message}
            status = self.detect()

        if not status.image:
            if not build_if_missing:
                return {"ok": False, "error": "toolbox image is not built"}
            built = self.build(timeout=timeout)
            if not built["ok"]:
                return built

        self._ensure_network()
        self._run("rm", "-f", self.config.container, timeout=60)

        args = [
            "run",
            "-d",
            "--name",
            self.config.container,
            "--hostname",
            "splitagent",
            "--network",
            self._network_name(),
            "--cap-add",
            "NET_RAW",
            "--cap-add",
            "NET_ADMIN",
        ]
        if self.workspace_root is not None:
            self.workspace_root.mkdir(parents=True, exist_ok=True)
            args += ["-v", f"{self.workspace_root}:/workspace"]
        if self.config.network_mode == "host" and os.name != "nt":
            args += ["--network", "host"]
        if self.config.cpus:
            args += ["--cpus", self.config.cpus]
        if self.config.memory:
            args += ["--memory", self.config.memory]
        args += [self.config.image]

        code, out, err = self._run(*args, timeout=180)
        if code != 0:
            return {"ok": False, "error": err or "failed to start the toolbox"}
        return {"ok": True, "container": self.config.container, "id": out.splitlines()[-1]}

    def _network_name(self) -> str:
        return self.config.network or "splitagent-net"

    def _ensure_network(self) -> None:
        network = self._network_name()
        _code, out, _ = self._run("network", "ls", "--format", "{{.Name}}", timeout=30)
        if network in out.splitlines():
            return
        self._run("network", "create", network, timeout=60)

    def down(self) -> None:
        self._run("rm", "-f", self.config.container, timeout=60)

    def restart(self) -> dict[str, Any]:
        return self.up()

    def reset(self) -> dict[str, Any]:
        """Throw the container away and create a clean one."""
        self.down()
        return self.up()

    # -- execution --------------------------------------------------------- #
    def exec(
        self,
        argv: list[str],
        cwd: str = "/workspace/tools",
        timeout: int = 300,
        env: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Run a command inside the container.

        The container has a writable root, so commands run as root there and can
        use apt freely. The workspace bind-mount is the only host-visible path.
        """
        if not argv:
            return {"ok": False, "error": "empty command"}
        args = ["exec", "-w", cwd, "-e", "HOME=/root"]
        for key, value in (env or {}).items():
            args += ["-e", f"{key}={value}"]
        args.append(self.config.container)
        args += [str(a) for a in argv]
        try:
            code, out, err = self._run(*args, timeout=timeout)
        except RuntimeError as exc:
            return {"ok": False, "error": str(exc)}
        output = (out + "\n" + err).strip()
        return {
            "ok": code == 0,
            "command": " ".join(str(a) for a in argv),
            "exit_code": code,
            "output": output[-8000:],
            "where": "toolbox",
        }

    def exec_shell(self, script: str, timeout: int = 600) -> dict[str, Any]:
        return self.exec(["sh", "-lc", script], timeout=timeout)

    def install(self, manager: str, package: str, timeout: int = 900) -> dict[str, Any]:
        """Install a package inside the container.

        apt/pip/pipx/go/npm all work; the container is disposable so this is
        always safe. The workspace is mounted, so anything installed under
        ``/workspace/tools`` survives.
        """
        if not self.config.allow_install:
            return {"ok": False, "error": "installation is disabled in the toolbox"}

        if manager in ("apt", "apt-get"):
            script = f"apt-get update -qq && apt-get install -y --no-install-recommends {package}"
        elif manager == "pip":
            script = f"/opt/venv/bin/pip install --no-cache-dir {package} 2>/dev/null || pip install --break-system-packages --no-cache-dir {package}"
        elif manager == "pipx":
            script = f"pipx install {package}"
        elif manager == "go":
            script = f"GOBIN=/workspace/tools/bin go install {package}"
        elif manager == "npm":
            script = f"npm install -g --no-audit --no-fund {package}"
        elif manager == "cargo":
            script = f"cargo install {package}"
        elif manager == "git":
            name = package.rstrip("/").split("/")[-1].replace(".git", "")
            script = f"git clone --depth 1 {package} /workspace/tools/{name}"
        else:
            return {
                "ok": False,
                "error": f"manager '{manager}' is not supported inside the toolbox",
                "supported": ["apt", "pip", "pipx", "go", "npm", "cargo", "git"],
            }

        result = self.exec_shell(script, timeout=timeout)
        result.update({"manager": manager, "package": package})
        return result

    def which(self, name: str) -> str | None:
        """Resolve a binary inside the running container."""
        _code, out, _ = self._run(
            "exec",
            self.config.container,
            "sh",
            "-lc",
            f"command -v {name} || true",
            timeout=20,
        )
        path = out.strip().splitlines()[-1] if out.strip() else ""
        return path or None

    def logs(self, tail: int = 100) -> str:
        _, out, err = self._run("logs", "--tail", str(tail), self.config.container)
        return out or err


def resolve_mode(config: ExecutionConfig, status: ToolboxStatus) -> str:
    """Decide the effective execution backend."""
    if config.mode == "local":
        return "local"
    if config.mode == "toolbox":
        return "toolbox"
    # auto
    if not status.docker_cli:
        return "local"
    if status.daemon and (status.image or config.installed):
        return "toolbox"
    if status.running:
        return "toolbox"
    return "local"


def build_command(edition: str = "standard") -> list[str]:
    """The exact docker build command, surfaced to the operator."""
    repo_root = DOCKERFILE.parent.parent
    return [
        "docker",
        "build",
        "-f",
        str(DOCKERFILE),
        "--build-arg",
        f"EDITION={edition}",
        "-t",
        "splitagent-toolbox:latest",
        str(repo_root),
    ]


def estimated_size(edition: str) -> str:
    return "~450 MB" if edition == "standard" else "~2.5 GB"


async def _async_run(*args: str) -> tuple[int, str, str]:  # pragma: no cover
    proc = await asyncio.create_subprocess_exec(
        "docker",
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    return proc.returncode or 0, out.decode(), err.decode()
