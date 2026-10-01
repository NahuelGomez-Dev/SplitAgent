"""Subprocess helpers that never flash a console window on Windows.

When SplitAgent runs under ``pythonw.exe`` (the desktop app) there is no
console attached. Any child process spawned without the right flags makes
Windows create one, which shows up as a storm of CMD windows spamming the
screen - especially during a Docker build or an apt install that spawns many
subprocesses. Every command SplitAgent runs goes through here.
"""

from __future__ import annotations

import os
import subprocess
from typing import Any

# Windows process-creation flags.
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200
DETACHED_PROCESS = 0x00000008

IS_WINDOWS = os.name == "nt"


def hidden_flags(detach: bool = False) -> int:
    """Creation flags that keep a child process invisible and independent."""
    if not IS_WINDOWS:
        return 0
    flags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
    if detach:
        flags |= DETACHED_PROCESS
    return flags


def run(
    argv: list[str],
    *,
    cwd: str | None = None,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
    text: bool = False,
    shell: bool = False,
) -> subprocess.CompletedProcess[Any]:
    """``subprocess.run`` with the console window suppressed on Windows."""
    return subprocess.run(
        argv,
        cwd=cwd,
        capture_output=True,
        timeout=timeout,
        env=env,
        check=False,
        shell=shell,
        creationflags=hidden_flags(),
    )


def popen(
    argv: list[str],
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    detach: bool = True,
) -> subprocess.Popen[Any]:
    """Launch a background process with no console window."""
    return subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        creationflags=hidden_flags(detach=detach),
        close_fds=True,
    )
