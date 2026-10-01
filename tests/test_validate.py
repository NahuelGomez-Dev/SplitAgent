from __future__ import annotations

import asyncio
import socket
import threading

import pytest

from splitagent.config import RunConfig, TargetConfig
from splitagent.core.context import SharedContext
from splitagent.tools.base import ToolContext
from splitagent.tools.registry import build_registry
from splitagent.tools.validate import (
    validate_ingreslock_shell,
    validate_mysql_anonymous,
    validate_root_shell,
    validate_vsftpd_backdoor,
)


# --- a tiny TCP server that speaks whatever banner we need ---------------- #
class BannerServer(threading.Thread):
    def __init__(self, banner: bytes, response: bytes = b""):
        super().__init__(daemon=True)
        self.banner = banner
        self.response = response
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = False

    def run(self) -> None:
        self.sock.settimeout(0.4)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            with conn:
                conn.settimeout(1.0)
                try:
                    if self.banner:
                        conn.sendall(self.banner)
                    conn.recv(512)
                    if self.response:
                        conn.sendall(self.response)
                except OSError:
                    pass

    def close(self) -> None:
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


@pytest.fixture()
def make_server():
    servers: list[BannerServer] = []

    def _make(banner: bytes, response: bytes = b"") -> BannerServer:
        server = BannerServer(banner, response)
        server.start()
        servers.append(server)
        return server

    yield _make
    for server in servers:
        server.close()


def _ctx(host: str = "127.0.0.1") -> ToolContext:
    return ToolContext(
        target=TargetConfig(url=f"http://{host}", scope=[host]),
        run=RunConfig(allow_network=True),
        context=SharedContext.create(target=host),
    )


# --- validators ----------------------------------------------------------- #
async def test_root_shell_is_validated(make_server):
    server = make_server(b"root@target:/# ")
    result = await validate_ingreslock_shell(_ctx(), "127.0.0.1", server.port)
    assert result["validated"] is True
    assert result["root_shell"] is True
    assert result["confidence"] == "high"
    assert "root@" in result["evidence"]


async def test_unauthenticated_shell_generic(make_server):
    server = make_server(b"root@target:/# ")
    result = await validate_root_shell(_ctx(), "127.0.0.1", server.port)
    assert result["validated"] is True
    assert result["root_shell"] is True


async def test_non_shell_banner_is_not_a_root_shell(make_server):
    server = make_server(b"220 (vsFTPd 2.3.4)\r\n")
    result = await validate_ingreslock_shell(_ctx(), "127.0.0.1", server.port)
    # It answered, but it is not a shell prompt.
    assert result["validated"] is True
    assert result["root_shell"] is False


async def test_vsftpd_backdoor_requires_the_port_to_open(make_server):
    """A vsftpd banner alone must NOT be reported as a working backdoor."""
    server = make_server(b"220 (vsFTPd 2.3.4)\r\n")
    result = await validate_vsftpd_backdoor(_ctx(), "127.0.0.1", server.port)
    assert result["cve"] == "CVE-2011-2523"
    # The trigger port is not listening in this test, so it must stay false.
    assert result["validated"] is False
    assert result["backdoor_opened"] is False
    assert "stayed closed" in result["evidence"]


async def test_mysql_version_parsed(make_server):
    handshake = b">\x00\x00\x00\n5.0.51a-3ubuntu5\x00\x07\x00\x00\x00"
    server = make_server(handshake)
    result = await validate_mysql_anonymous(_ctx(), "127.0.0.1", server.port)
    assert result["validated"] is True
    assert result["server_version"] == "5.0.51a-3ubuntu5"
    assert "mysql" in result["next_step"].lower()


async def test_unreachable_port_reports_cleanly():
    """A closed port must return validated=false, never raise."""
    result = await validate_ingreslock_shell(_ctx(), "127.0.0.1", 1)
    assert result["validated"] is False
    assert result["confidence"] == "low"

    result = await validate_vsftpd_backdoor(_ctx(), "127.0.0.1", 1)
    assert result["validated"] is False
    assert "not reachable" in result.get("reason", "")


async def test_out_of_scope_is_refused():
    ctx = ToolContext(
        target=TargetConfig(url="http://127.0.0.1", scope=["127.0.0.1"]),
        run=RunConfig(allow_network=False),
        context=SharedContext.create(target="127.0.0.1"),
    )
    result = await validate_ingreslock_shell(ctx, "evil.example.com", 1524)
    assert result["validated"] is False
    assert "error" in result


# --- registry wiring ------------------------------------------------------ #
def test_validators_are_registered_for_red():
    ctx = _ctx()
    registry = build_registry(ctx, "red")
    for name in (
        "validate_vsftpd_backdoor",
        "validate_root_shell",
        "validate_samba_usermap",
        "validate_mysql_blank_password",
        "validate_open_shell_port",
    ):
        tool = registry.get(name)
        assert tool is not None, name
        assert tool.scope == "red"

    # They must not run in parallel: they open sockets and alter target state.
    assert registry.get("validate_vsftpd_backdoor").parallel_safe is False


def test_validators_not_exposed_to_blue():
    registry = build_registry(_ctx(), "blue")
    assert registry.get("validate_vsftpd_backdoor") is None


def test_evidence_is_always_present():
    """Every validator returns evidence the report can quote."""

    async def run_all():
        results = [
            await validate_ingreslock_shell(_ctx(), "127.0.0.1", 1),
            await validate_vsftpd_backdoor(_ctx(), "127.0.0.1", 1),
            await validate_mysql_anonymous(_ctx(), "127.0.0.1", 1),
        ]
        return results

    for result in asyncio.get_event_loop_policy().new_event_loop().run_until_complete(run_all()):
        assert "evidence" in result or "reason" in result
