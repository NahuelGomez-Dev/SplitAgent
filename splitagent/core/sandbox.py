"""Ephemeral Docker sandbox management.

The sandbox gives the agents a disposable target: a container is started on
an isolated bridge network, exercised for the duration of the audit and then
removed. When Docker is unavailable the framework degrades gracefully to
"local mode" (the agents operate against the configured target only).
"""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass
from typing import Any

from splitagent.config import SandboxConfig
from splitagent.core import proc
from splitagent.errors import SandboxError

# Ready-to-use intentionally vulnerable targets for demos / training.
# ``port_map`` is {host_port: container_port}: the publish argument is
# ``-p host:container`` and the URL is derived from the host port.
TARGET_PRESETS: dict[str, dict[str, Any]] = {
    "juice-shop": {
        "image": "bkimminich/juice-shop:latest",
        "port_map": {"3000": 3000},
        "url": "http://localhost:3000",
    },
    "dvwa": {
        "image": "vulnerables/web-dvwa:latest",
        "port_map": {"8080": 80},
        "url": "http://localhost:8080",
    },
    "bwapp": {
        "image": "raesene/bwapp:latest",
        "port_map": {"8081": 80},
        "url": "http://localhost:8081",
    },
    "webgoat": {
        "image": "webgoat/webgoat:latest",
        "port_map": {"8082": 8080},
        "url": "http://localhost:8082/WebGoat",
    },
}


@dataclass
class SandboxStatus:
    available: bool
    running: bool = False
    container_id: str = ""
    name: str = ""
    url: str = ""
    message: str = ""


class DockerSandbox:
    """Thin wrapper around the ``docker`` CLI."""

    def __init__(self, config: SandboxConfig, session_id: str = "run") -> None:
        self.config = config
        self.name = f"splitagent-target-{session_id}"
        self.container_id = ""
        self.url = ""
        self.engine = config.engine or "docker"

    # -- detection --------------------------------------------------------- #
    @staticmethod
    def docker_available() -> bool:
        return shutil.which("docker") is not None

    async def _run(self, *args: str, check: bool = False) -> tuple[int, str, str]:
        try:
            child = await asyncio.create_subprocess_exec(
                self.engine,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.DEVNULL,
                # No console window on Windows (the desktop app has none).
                creationflags=proc.hidden_flags(),
            )
        except FileNotFoundError as exc:  # pragma: no cover - guarded by detection
            raise SandboxError(
                f"'{self.engine}' was not found on PATH. Disable the sandbox or install Docker."
            ) from exc
        stdout, stderr = await child.communicate()
        code = child.returncode or 0
        out = stdout.decode("utf-8", "replace").strip()
        err = stderr.decode("utf-8", "replace").strip()
        if check and code != 0:
            raise SandboxError(err or out or f"{self.engine} exited with {code}")
        return code, out, err

    # -- lifecycle --------------------------------------------------------- #
    async def up(self) -> SandboxStatus:
        if not self.config.enabled:
            return SandboxStatus(available=head_ok(), message="sandbox disabled")
        if not self.docker_available():
            return SandboxStatus(
                available=False,
                message="Docker not found; running without sandbox.",
            )

        await self._ensure_network()
        await self.down(quiet=True)

        args = [
            "run",
            "-d",
            "--name",
            self.name,
            "--network",
            self.config.network or "splitagent-net",
        ]
        if self.config.auto_remove:
            args.append("--rm")
        for host_port, container_port in (self.config.port_map or {}).items():
            args += ["-p", f"{host_port}:{container_port}"]
        args.append(self.config.image)

        code, out, err = await self._run(*args)
        if code != 0:
            return SandboxStatus(
                available=True,
                running=False,
                message=err or "failed to start container",
            )
        self.container_id = out.splitlines()[-1].strip()
        self.url = self._infer_url()
        return SandboxStatus(
            available=True,
            running=True,
            container_id=self.container_id,
            name=self.name,
            url=self.url,
            message="sandbox started",
        )

    async def down(self, quiet: bool = False) -> None:
        if not self.docker_available():
            return
        await self._run("rm", "-f", self.name)
        self.container_id = ""

    async def status(self) -> SandboxStatus:
        if not self.docker_available():
            return SandboxStatus(available=False, message="Docker not found")
        code, out, _ = await self._run(
            "ps", "--filter", f"name={self.name}", "--format", "{{.ID}} {{.Names}}"
        )
        running = bool(out.strip()) and code == 0
        return SandboxStatus(
            available=True,
            running=running,
            name=self.name,
            message="running" if running else "stopped",
            url=self.url or self._infer_url(),
        )

    async def logs(self, tail: int = 100) -> str:
        _, out, err = await self._run("logs", "--tail", str(tail), self.name)
        return out or err

    async def exec(self, *command: str) -> str:
        code, out, err = await self._run("exec", self.name, *command)
        return out if code == 0 else (err or out)

    async def _ensure_network(self) -> None:
        network = self.config.network or "splitagent-net"
        _code, out, _ = await self._run("network", "ls", "--format", "{{.Name}}")
        if network in out.splitlines():
            return
        await self._run("network", "create", network)

    def _infer_url(self) -> str:
        if not self.config.port_map:
            return ""
        host_port = next(iter(self.config.port_map))
        return f"http://localhost:{host_port}"


def head_ok() -> bool:
    return True
