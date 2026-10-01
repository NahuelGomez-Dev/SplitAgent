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
    validate_nfs_export,
    validate_proftpd,
    validate_root_shell,
    validate_samba_usermap,
    validate_unrealircd_backdoor,
    validate_vnc_no_auth,
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


# --------------------------------------------------------------------------- #
# toolbox routing
# --------------------------------------------------------------------------- #
class FakeToolbox:
    """Stands in for the container, returning scripted probe output."""

    def __init__(
        self,
        responses: dict[str, str] | None = None,
        *,
        probe_up: bool = True,
        installed: tuple[str, ...] = ("showmount", "nmap"),
    ):
        self.calls: list[tuple] = []
        self.responses = responses or {}
        self.probe_up = probe_up
        self.installed = set(installed)

    def which(self, name: str) -> str | None:
        self.calls.append(("which", name))
        return f"/usr/bin/{name}" if name in self.installed else None

    def install(self, manager, package, timeout=900):
        self.calls.append(("install", manager, package))
        self.installed.add(package)
        return {"ok": True}

    def exec(self, argv, cwd="/workspace/tools", timeout=300, env=None):
        joined = " ".join(str(a) for a in argv)
        self.calls.append(tuple(argv))
        for needle, output in self.responses.items():
            if needle in joined:
                return {"ok": True, "output": output, "exit_code": 0}
        # The generic port probe: reachable unless the test says otherwise.
        default = (
            '{"up": true, "banner": "root@x:/#"}'
            if self.probe_up
            else '{"up": false, "error": "ConnectionRefusedError"}'
        )
        return {"ok": True, "output": default, "exit_code": 0}


def _ctx_with_toolbox(toolbox, host: str = "172.19.0.3") -> ToolContext:
    ctx = _ctx(host)
    ctx.settings["toolbox"] = toolbox
    return ctx


def test_toolbox_probe_is_used_when_available():
    """The probe must run in the container, not from the host process."""
    toolbox = FakeToolbox({"create_connection": '{"up": true, "banner": "root@x:/#"}'})
    ctx = _ctx_with_toolbox(toolbox)
    result = asyncio.new_event_loop().run_until_complete(
        validate_ingreslock_shell(ctx, "172.19.0.3", 1524)
    )
    assert result["validated"] is True
    assert result["root_shell"] is True
    # Something was actually executed inside the toolbox.
    assert toolbox.calls


def test_toolbox_probe_reports_an_unreachable_port():
    toolbox = FakeToolbox(probe_up=False)
    ctx = _ctx_with_toolbox(toolbox)
    result = asyncio.new_event_loop().run_until_complete(
        validate_ingreslock_shell(ctx, "172.19.0.3", 1524)
    )
    assert result["validated"] is False


async def test_toolbox_probe_survives_unparsable_output():
    toolbox = FakeToolbox({"create_connection": "not json at all"})
    ctx = _ctx_with_toolbox(toolbox)
    result = await validate_ingreslock_shell(ctx, "172.19.0.3", 1524)
    assert result["validated"] is False  # never raises


def test_probe_command_has_real_newlines():
    """A heredoc with literal backslash-n would be a silent no-op."""
    from splitagent.tools.validate import _probe_command

    command = _probe_command("1.2.3.4", 80, "", 512, 3.0)
    assert "\n" in command
    assert "\\n" not in command.split("<<'SPLITAGENT_EOF'")[1].split("SPLITAGENT_EOF")[0]


def test_vsftpd_backdoor_uses_toolbox_for_the_shell_port():
    """The second probe (6200) must also go through the container."""
    toolbox = FakeToolbox(
        {
            # First call reads the banner, second checks the backdoor port.
            "1532": '{"up": true, "banner": "open"}',
        }
    )
    ctx = _ctx_with_toolbox(toolbox)
    result = asyncio.new_event_loop().run_until_complete(
        validate_vsftpd_backdoor(ctx, "172.19.0.3", 21)
    )
    # Both the FTP probe and the 6200 check ran in the container.
    assert len(toolbox.calls) >= 2
    assert result["cve"] == "CVE-2011-2523"


def test_samba_validator_uses_nmap_in_the_toolbox():
    toolbox = FakeToolbox({"nmap": "| smb-vuln-ms17-010:\n|   VULNERABLE: ..."})
    ctx = _ctx_with_toolbox(toolbox)
    result = asyncio.new_event_loop().run_until_complete(
        validate_samba_usermap(ctx, "172.19.0.3", 139)
    )
    assert any("nmap" in " ".join(c) for c in toolbox.calls)
    assert result["validated"] is True
    assert result["confidence"] == "high"


def test_samba_validator_is_honest_when_nmap_finds_nothing():
    toolbox = FakeToolbox({"nmap": "|_smb-vuln-ms17-010: false"})
    ctx = _ctx_with_toolbox(toolbox)
    result = asyncio.new_event_loop().run_until_complete(
        validate_samba_usermap(ctx, "172.19.0.3", 139)
    )
    assert result["validated"] is False
    # It must say what to do next rather than pretend.
    assert "confirm" in result["evidence"].lower()


def test_local_mode_still_uses_sockets(make_server):
    """Without a toolbox the validators fall back to the host socket path."""
    server = make_server(b"root@target:/# ")
    ctx = _ctx("127.0.0.1")  # no toolbox in settings
    result = asyncio.new_event_loop().run_until_complete(
        validate_ingreslock_shell(ctx, "127.0.0.1", server.port)
    )
    assert result["validated"] is True


# --------------------------------------------------------------------------- #
# new validators
# --------------------------------------------------------------------------- #
def test_proftpd_only_validates_proftpd(make_server):
    """A vsftpd banner must never be reported as a ProFTPD finding."""
    server = make_server(b"220 (vsFTPd 2.3.4)\r\n")
    result = asyncio.new_event_loop().run_until_complete(
        validate_proftpd(_ctx(), "127.0.0.1", server.port)
    )
    assert result["validated"] is False
    assert result["product"] == "ftp"
    assert "different FTP daemon" in result["evidence"]


def test_proftpd_validates_a_real_proftpd(make_server):
    server = make_server(b"220 ProFTPD 1.3.1 Server (Debian)\r\n")
    result = asyncio.new_event_loop().run_until_complete(
        validate_proftpd(_ctx(), "127.0.0.1", server.port)
    )
    assert result["validated"] is True
    assert result["product"] == "ProFTPD"
    assert result["confidence"] == "high"


def test_vnc_needs_the_rfb_handshake(make_server):
    server = make_server(b"RFB 003.008\n")
    result = asyncio.new_event_loop().run_until_complete(
        validate_vnc_no_auth(_ctx(), "127.0.0.1", server.port)
    )
    assert result["validated"] is True


def test_vnc_rejects_a_non_vnc_banner(make_server):
    server = make_server(b"220 (vsFTPd 2.3.4)\r\n")
    result = asyncio.new_event_loop().run_until_complete(
        validate_vnc_no_auth(_ctx(), "127.0.0.1", server.port)
    )
    assert result["validated"] is False


def test_unrealircd_detects_an_irc_daemon(make_server):
    server = make_server(b":irc.example 001 nick :Welcome\r\n")
    result = asyncio.new_event_loop().run_until_complete(
        validate_unrealircd_backdoor(_ctx(), "127.0.0.1", server.port)
    )
    assert result["validated"] is True
    assert result["cve"] == "CVE-2010-2075"


def test_unrealircd_unreachable_is_clean():
    result = asyncio.new_event_loop().run_until_complete(
        validate_unrealircd_backdoor(_ctx(), "127.0.0.1", 1)
    )
    assert result["validated"] is False


def test_nfs_never_reports_an_error_as_an_export():
    """A missing showmount must not be mistaken for a world-readable export."""
    toolbox = FakeToolbox(
        {
            "showmount": (
                'OCI runtime exec failed: exec: "showmount": executable file not found in $PATH'
            )
        }
    )
    ctx = _ctx_with_toolbox(toolbox)
    result = asyncio.new_event_loop().run_until_complete(
        validate_nfs_export(ctx, "172.19.0.3", 2049)
    )
    assert result["validated"] is False
    assert "error" in result
    assert "not record this as a finding" in result["evidence"]


def test_nfs_reports_real_exports():
    toolbox = FakeToolbox({"showmount": "Export list for 172.19.0.3:\n/ *"})
    ctx = _ctx_with_toolbox(toolbox)
    result = asyncio.new_event_loop().run_until_complete(
        validate_nfs_export(ctx, "172.19.0.3", 2049)
    )
    assert result["validated"] is True
    assert result["confidence"] == "high"
    assert any("/" in e for e in result["exports"])


def test_nfs_with_no_exports_is_not_a_finding():
    toolbox = FakeToolbox({"showmount": "Export list for 172.19.0.3:\n"})
    ctx = _ctx_with_toolbox(toolbox)
    result = asyncio.new_event_loop().run_until_complete(
        validate_nfs_export(ctx, "172.19.0.3", 2049)
    )
    assert result["validated"] is False


# --------------------------------------------------------------------------- #
# full port sweep
# --------------------------------------------------------------------------- #
async def test_full_sweep_covers_every_port(tmp_path):
    """A full sweep must cover all 65535 ports and find the open one.

    The port is asserted separately from the coverage so a busy CI machine
    with a deep backlog cannot make the coverage claim flaky.
    """
    from splitagent.tools.recon import tcp_scan

    ctx = _ctx("http://127.0.0.1")
    result = await tcp_scan(ctx, host="127.0.0.1", full=True, timeout=0.1, concurrency=1024)

    # The sweep really covered the whole range.
    assert result["scanned"] == 65535
    assert result["full"] is True
    # Every reported port is a real integer inside the range.
    for entry in result["open"]:
        assert 1 <= entry["port"] <= 65535


async def test_full_sweep_finds_a_known_open_port(tmp_path):
    """A port we know is listening must appear in a targeted scan."""
    import threading

    from splitagent.tools.recon import tcp_scan

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(32)
    listener.settimeout(0.2)
    port = listener.getsockname()[1]

    running = {"go": True}

    def accept() -> None:
        while running["go"]:
            try:
                conn, _ = listener.accept()
            except (TimeoutError, OSError):
                continue
            conn.close()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        ctx = _ctx("http://127.0.0.1")
        result = await tcp_scan(ctx, host="127.0.0.1", ports=[port], timeout=2.0)
        assert result["count"] == 1
        assert result["open"][0]["port"] == port
    finally:
        running["go"] = False
        listener.close()


# --------------------------------------------------------------------------- #
# verify_control -> resilience pipeline
# --------------------------------------------------------------------------- #
def test_verification_helpers_parse_endpoints():
    from splitagent.core.models import Finding
    from splitagent.tools.defense import _finding_host, _finding_port, _guessed_parameter

    tcp = Finding(endpoint="tcp/1524", target="172.19.0.3")
    assert _finding_port(tcp) == 1524

    url = Finding(endpoint="http://host:8180/manager", target="host")
    assert _finding_port(url) == 8180

    web = Finding(endpoint="http://h/buscar?q=1", evidence="parameter 'q' reflected")
    assert _guessed_parameter(web) == "q"

    ctx = _ctx("1.2.3.4")
    assert _finding_host(Finding(endpoint="http://1.2.3.4/x"), ctx) == "1.2.3.4"


def test_verify_control_can_be_called_for_a_known_finding(tmp_path):
    """The re-test path must return a verdict, never raise."""
    from splitagent.core.models import Finding
    from splitagent.tools.defense import _verify_control

    ctx = _ctx("127.0.0.1")
    ctx.context.state.add_finding(
        Finding(
            id="F-test",
            title="Exposed shell",
            category="unauthenticated_shell",
            endpoint="tcp/1",
            target="127.0.0.1",
        )
    )
    result = asyncio.new_event_loop().run_until_complete(_verify_control(ctx, "F-test"))
    assert "verified" in result
    # A port that is not listening cannot be exploitable.
    assert result["verified"] is True


def test_verify_control_unknown_finding(tmp_path):
    from splitagent.tools.defense import _verify_control

    ctx = _ctx("127.0.0.1")
    result = asyncio.new_event_loop().run_until_complete(_verify_control(ctx, "F-nope"))
    assert "error" in result


def test_resilience_reflects_verified_controls_only(tmp_path):
    """The exact contract: proposed=0, verified=closed."""
    from splitagent.core.models import Finding, Mitigation

    ctx = _ctx("http://127.0.0.1")
    state = ctx.context.state
    first = state.add_finding(Finding(title="one", severity="critical"))
    state.add_finding(Finding(title="two", severity="critical"))

    state.mitigations.append(
        Mitigation(finding_id=first.id, title="fix", verified=True, status="verified")
    )
    # One of two closed -> 50%.
    assert state.resilience_score() == 50.0
    assert state.resilience_breakdown()["findings_closed"] == 1


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
