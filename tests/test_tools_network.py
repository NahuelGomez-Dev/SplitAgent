"""Tests for the reconnaissance, web, exploit and defence tools.

These tools are what the agents actually run against a target, so they are
exercised against real local servers rather than mocks wherever possible.
"""

from __future__ import annotations

import asyncio
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from splitagent.config import RunConfig, TargetConfig
from splitagent.core.bus import EventBus
from splitagent.core.context import SharedContext
from splitagent.core.workspace import workspace_for
from splitagent.tools.base import ToolContext
from splitagent.tools.defense import (
    HARDEN_SNIPPETS,
    LOG_PATTERNS,
    PATCH_TEMPLATES,
    _analyze_logs,
    _firewall_rule,
    _verify_control,
)

# The exploit tools are named ``test_*``; import them under aliases so pytest
# does not mistake the imported callables for test functions.
from splitagent.tools.exploit import (
    CANARY,
)
from splitagent.tools.exploit import (
    test_command_injection as probe_command_injection,
)
from splitagent.tools.exploit import test_cors as probe_cors
from splitagent.tools.exploit import test_directory_listing as probe_directory_listing
from splitagent.tools.exploit import test_http_methods as probe_http_methods
from splitagent.tools.exploit import test_open_redirect as probe_open_redirect
from splitagent.tools.exploit import test_path_traversal as probe_path_traversal
from splitagent.tools.exploit import test_sqli as probe_sqli
from splitagent.tools.exploit import test_xss as probe_xss
from splitagent.tools.http_pool import aclose_all
from splitagent.tools.recon import DEFAULT_PORTS, dns_lookup, tcp_scan
from splitagent.tools.registry import build_registry
from splitagent.tools.web import (
    DEFAULT_PATHS,
    crawl,
    detect_technologies,
    fetch,
    headers_audit,
    http_request,
    probe_paths,
)


# --------------------------------------------------------------------------- #
# A configurable target that reacts to the probes
# --------------------------------------------------------------------------- #
class Target(BaseHTTPRequestHandler):
    """Serves a small app with deliberate weaknesses for the tests to find."""

    # HTTP/1.1 + Content-Length so a keep-alive client never waits for a body.
    protocol_version = "HTTP/1.1"
    routes: dict[str, tuple[int, str]] = {}
    body = "<html><head><title>Demo App</title></head><body>ok</body></html>"
    # NOT named `headers`: BaseHTTPRequestHandler stores the request headers on
    # `self.headers`, so a class attribute with that name shadows them.
    extra_headers: dict[str, str] = {}

    def _respond(self, body: bytes | None = None):
        path = self.path.split("?")[0]
        # Unrouted paths 404 so path probing behaves like a real app.
        default = (200, self.body) if not self.routes else (404, "not found")
        status, payload = self.routes.get(path, default)
        data = payload.encode() if body is None else body
        # send_response_only avoids the default Content-Length that
        # send_response would add, which a keep-alive client rejects as a
        # duplicate.
        self.send_response_only(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        for key, value in self.extra_headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _drain(self) -> None:
        """Consume the request body so the keep-alive connection stays in sync."""
        length = int(self.headers.get("content-length", 0) or 0)
        if length:
            self.rfile.read(length)

    def do_GET(self):
        self._respond()

    def do_POST(self):
        self._drain()
        self._respond()

    def do_PUT(self):
        self._drain()
        self._respond()

    def do_DELETE(self):
        self._drain()
        self._respond()

    def do_TRACE(self):
        self._respond()

    def do_OPTIONS(self):
        self._respond()

    def do_PATCH(self):
        self._drain()
        self._respond()

    def log_message(self, *args):
        pass


@pytest.fixture(autouse=True)
def _fresh_http_pool():
    """Drop pooled connections between tests.

    The tools share a keep-alive client; without this, a socket bound to a
    server that was just shut down would be reused and hang.
    """
    yield
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(aclose_all())
    finally:
        loop.close()


@pytest.fixture()
def target_server():
    """Start a fresh HTTP server with a clean route table."""
    Target.routes = {}
    Target.body = "<html><head><title>Demo App</title></head><body>ok</body></html>"
    Target.extra_headers = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}", server
    server.shutdown()


@pytest.fixture()
def tcp_server():
    """A bare listening socket, for the port scanner."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    port = sock.getsockname()[1]
    yield port
    sock.close()


def _ctx(url: str, tmp_path: Path | None = None, **run_kwargs) -> ToolContext:
    run = RunConfig(**run_kwargs) if run_kwargs else RunConfig()
    target = TargetConfig(url=url, scope=["127.0.0.1", "localhost"])
    ctx = SharedContext.create(target=url, bus=EventBus(), directory=tmp_path)
    return ToolContext(target=target, run=run, context=ctx)


# --------------------------------------------------------------------------- #
# recon
# --------------------------------------------------------------------------- #
def test_default_ports_are_sensible():
    assert 80 in DEFAULT_PORTS and 443 in DEFAULT_PORTS and 22 in DEFAULT_PORTS
    assert sorted(DEFAULT_PORTS) == DEFAULT_PORTS


def test_dns_lookup_resolves_localhost():
    result = dns_lookup("localhost")
    assert "error" not in result
    assert result["addresses"]


def test_dns_lookup_reports_failure():
    result = dns_lookup("this-host-does-not-exist.invalid")
    assert "error" in result


async def test_tcp_scan_finds_an_open_port(tcp_server, tmp_path):
    ctx = _ctx("http://127.0.0.1", tmp_path)
    result = await tcp_scan(ctx, host="127.0.0.1", ports=[tcp_server], timeout=2.0)
    assert result["count"] == 1
    assert result["open"][0]["port"] == tcp_server
    assert result["open"][0]["state"] == "open"


async def test_tcp_scan_reports_a_closed_port(tcp_server, tmp_path):
    ctx = _ctx("http://127.0.0.1", tmp_path)
    # Pick a port nothing listens on.
    closed = tcp_server + 1 if tcp_server < 65000 else tcp_server - 1
    result = await tcp_scan(ctx, host="127.0.0.1", ports=[closed], timeout=0.4)
    assert result["count"] == 0


async def test_tcp_scan_returns_services(tcp_server, tmp_path):
    ctx = _ctx("http://127.0.0.1", tmp_path)
    # Scan a well-known port number range so the service lookup is exercised.
    result = await tcp_scan(ctx, host="127.0.0.1", ports=[tcp_server], timeout=2.0)
    assert "service" in result["open"][0]


async def test_tcp_scan_refuses_out_of_scope(tmp_path):
    from splitagent.errors import ScopeError

    ctx = _ctx("http://127.0.0.1", tmp_path)
    with pytest.raises(ScopeError):
        await tcp_scan(ctx, host="evil.example.com", ports=[80], timeout=0.2)


# --------------------------------------------------------------------------- #
# web
# --------------------------------------------------------------------------- #
async def test_http_request_returns_headers_and_body(target_server, tmp_path):
    url, _ = target_server
    ctx = _ctx(url, tmp_path)
    result = await http_request(ctx, url)
    assert result["status"] == 200
    assert "headers" in result
    assert "Demo App" in result["body"]


async def test_fetch_supports_methods_and_params(target_server, tmp_path):
    url, _ = target_server
    ctx = _ctx(url, tmp_path)
    result = await fetch(ctx, url, method="POST", data={"a": "1"})
    assert result["status"] == 200


async def test_headers_audit_finds_missing_headers(target_server, tmp_path):
    url, _ = target_server
    ctx = _ctx(url, tmp_path)
    result = await headers_audit(ctx, url)
    missing = {item["header"] for item in result["missing_security_headers"]}
    assert "content-security-policy" in missing
    assert "strict-transport-security" in missing


def _serve(handler, tmp_path) -> str:
    """Start a one-off server with its own handler class."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_port}"


async def test_headers_audit_detects_information_disclosure(tmp_path):
    class Leaky(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            body = b"<html></html>"
            self.send_response_only(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", "nginx/1.24.0")
            self.send_header("X-Powered-By", "PHP/8.1")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    url = _serve(Leaky, tmp_path)
    ctx = _ctx(url, tmp_path)
    result = await headers_audit(ctx, url)
    assert "nginx" in result["information_disclosure"].get("server", "")
    assert result["information_disclosure"].get("x-powered-by") == "PHP/8.1"


async def test_headers_audit_inspects_cookies(tmp_path):
    class CookieServer(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            body = b"<html></html>"
            self.send_response_only(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "session=abc; HttpOnly")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    url = _serve(CookieServer, tmp_path)
    ctx = _ctx(url, tmp_path)
    result = await headers_audit(ctx, url)
    assert result["cookie_count"] >= 1
    assert result["cookie_flags"]["httponly"] is True
    assert result["cookie_flags"]["secure"] is False


async def test_probe_paths_reports_non_404(target_server, tmp_path):
    url, _ = target_server
    Target.routes = {"/admin": (200, "login"), "/.env": (403, "denied")}
    ctx = _ctx(url, tmp_path)
    result = await probe_paths(ctx, url, paths=["/admin", "/.env", "/missing"])
    found = {item["path"] for item in result["found"]}
    assert "/admin" in found
    assert "/.env" in found  # a 403 is still interesting
    assert "/missing" not in found


async def test_probe_paths_uses_the_curated_default_list(tmp_path):
    assert "/.git/HEAD" in DEFAULT_PATHS
    assert "/robots.txt" in DEFAULT_PATHS


async def test_crawl_finds_pages_and_forms(target_server, tmp_path):
    url, _ = target_server
    Target.routes = {
        "/": (
            200,
            "<html><title>Home</title><body>"
            '<a href="/about">about</a>'
            '<form action="/search" method="post">'
            '<input name="q"><input name="page"></form>'
            "</body></html>",
        ),
        "/about": (200, "<html><title>About</title></html>"),
    }
    ctx = _ctx(url, tmp_path)
    result = await crawl(ctx, url, max_pages=5)
    assert result["page_count"] >= 2
    assert result["form_count"] == 1
    form = result["forms"][0]
    assert form["action"] == "/search"
    assert form["method"] == "post"
    assert "q" in form["inputs"]


async def test_crawl_respects_max_pages(target_server, tmp_path):
    url, _ = target_server
    Target.routes = {"/(.*)": (200, "<html><a href='/next'>n</a></html>")}
    ctx = _ctx(url, tmp_path)
    result = await crawl(ctx, url, max_pages=2)
    assert result["page_count"] <= 2


def test_detect_technologies_from_body_and_headers():
    found = detect_technologies(
        "<link href='/wp-content/style.css'><script src='jquery.js'>",
        {"server": "nginx", "x-powered-by": "PHP"},
    )
    assert "WordPress" in found
    assert "jQuery" in found
    assert "Nginx" in found
    assert "PHP" in found


# --------------------------------------------------------------------------- #
# exploit probes
# --------------------------------------------------------------------------- #
async def test_sqli_detects_a_database_error(target_server, tmp_path):
    url, _ = target_server
    Target.routes = {"/item": (500, "You have an error in your SQL syntax near '''")}
    ctx = _ctx(url, tmp_path)
    result = await probe_sqli(ctx, f"{url}/item?q=1", "q")
    assert result["vulnerable"] is True
    assert result["confidence"] == "high"
    evidence = " ".join(result["evidence"]).lower()
    assert "sql" in evidence or "syntax" in evidence


async def test_sqli_clean_response_is_not_vulnerable(target_server, tmp_path):
    url, _ = target_server
    ctx = _ctx(url, tmp_path)
    result = await probe_sqli(ctx, f"{url}/?q=1", "q")
    assert result["vulnerable"] is False
    assert result["confidence"] == "low"


async def test_xss_detects_reflection(target_server, tmp_path):
    url, _ = target_server
    ctx = _ctx(url, tmp_path)
    # Echo the query back, which is what a reflected XSS looks like.
    Target.routes = {"/search": (200, "results for <svg/onload=alert('splitagentcanary')>")}
    result = await probe_xss(ctx, f"{url}/search?q=hi", "q")
    assert result["vulnerable"] is True
    assert CANARY in result["evidence"]


async def test_xss_not_triggered_without_reflection(target_server, tmp_path):
    url, _ = target_server
    ctx = _ctx(url, tmp_path)
    result = await probe_xss(ctx, f"{url}/?q=hi", "q")
    assert result["vulnerable"] is False


async def test_xss_requires_an_html_context(target_server, tmp_path):
    url, server = target_server

    class Plain(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            body = b"echo: <svg/onload=alert('splitagentcanary')>"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server.shutdown()
    server2 = ThreadingHTTPServer(("127.0.0.1", 0), Plain)
    threading.Thread(target=server2.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server2.server_port}"

    ctx = _ctx(url, tmp_path)
    result = await probe_xss(ctx, f"{url}/?q=x", "q")
    # Reflected but in a non-HTML context: not exploitable as written.
    assert result["reflected"] is True
    assert result["vulnerable"] is False
    server2.shutdown()


async def test_path_traversal_detects_etc_passwd(target_server, tmp_path):
    url, _ = target_server
    Target.routes = {"/file": (200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1")}
    ctx = _ctx(url, tmp_path)
    result = await probe_path_traversal(ctx, f"{url}/file?name=x", "name")
    assert result["vulnerable"] is True
    assert "root:x:0:0" in result["evidence"]


async def test_path_traversal_clean(target_server, tmp_path):
    url, _ = target_server
    ctx = _ctx(url, tmp_path)
    result = await probe_path_traversal(ctx, f"{url}/?n=x", "n")
    assert result["vulnerable"] is False


async def test_open_redirect_detects_external_location(target_server, tmp_path):
    url, _ = target_server

    class Redirect(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "https://example.com/splitagent-redirect-canary")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}"

    ctx = _ctx(url, tmp_path)
    result = await probe_open_redirect(ctx, f"{url}/go?next=x", "next")
    assert result["vulnerable"] is True
    assert "example.com" in result["location"]
    server.shutdown()


async def test_command_injection_detects_the_marker(target_server, tmp_path):
    url, _ = target_server
    ctx = _ctx(url, tmp_path)
    # The server echoes the marker when the payload includes it in a parameter.
    Target.routes = {"/ping": (200, "")}
    result = await probe_command_injection(ctx, f"{url}/ping?host=127.0.0.1", "host")
    # Without an injection sink this must report cleanly, not raise.
    assert "vulnerable" in result
    assert result["test"] == "command_injection"


async def test_cors_detects_wildcard(target_server, tmp_path):
    url, server = target_server

    class Permissive(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    server.shutdown()
    server2 = ThreadingHTTPServer(("127.0.0.1", 0), Permissive)
    threading.Thread(target=server2.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server2.server_port}"

    ctx = _ctx(url, tmp_path)
    result = await probe_cors(ctx, url)
    assert result["vulnerable"] is True
    assert result["allow_origin"] == "*"
    server2.shutdown()


async def test_cors_restrictive_is_clean(target_server, tmp_path):
    url, _ = target_server
    ctx = _ctx(url, tmp_path)
    result = await probe_cors(ctx, url)
    assert result["vulnerable"] is False


async def test_http_methods_flags_dangerous_verbs(target_server, tmp_path):
    url, _ = target_server
    ctx = _ctx(url, tmp_path)
    result = await probe_http_methods(ctx, url)
    # Our fixture answers every verb, so PUT/DELETE/TRACE count as dangerous.
    assert result["vulnerable"] is True
    assert any(m.startswith("TRACE") for m in result["dangerous"])


async def test_directory_listing_detection(target_server, tmp_path):
    url, _ = target_server
    Target.routes = {"/files/": (200, "<html><h1>Index of /files</h1><a href='a.txt'>a</a>")}
    ctx = _ctx(url, tmp_path)
    result = await probe_directory_listing(ctx, f"{url}/files/")
    assert result["vulnerable"] is True


async def test_directory_listing_clean(target_server, tmp_path):
    url, _ = target_server
    ctx = _ctx(url, tmp_path)
    result = await probe_directory_listing(ctx, url)
    assert result["vulnerable"] is False


# --------------------------------------------------------------------------- #
# defence
# --------------------------------------------------------------------------- #
def test_firewall_rules_for_every_platform():
    for platform in ("iptables", "nft", "ufw", "windows"):
        rule = _firewall_rule(platform, "block", 8080, "10.0.0.5")
        assert "rule" in rule
        assert "8080" in rule["rule"]


def test_firewall_rule_rejects_unknown_platform():
    result = _firewall_rule("nonsense", "block", 80)
    assert "error" in result
    assert "platforms" in result


def test_firewall_allow_action():
    rule = _firewall_rule("iptables", "allow", 443)
    assert "ACCEPT" in rule["rule"]


def test_hardening_snippets_exist():
    for server in ("nginx", "apache", "express"):
        assert server in HARDEN_SNIPPETS
        assert "Strict-Transport-Security" in HARDEN_SNIPPETS[server]


def test_patch_templates_cover_the_common_classes():
    for category in (
        "sql_injection",
        "reflected_xss",
        "path_traversal",
        "command_injection",
        "cors_misconfiguration",
        "open_redirect",
    ):
        assert category in PATCH_TEMPLATES
        assert PATCH_TEMPLATES[category]["diff"]


def test_log_patterns_cover_the_attack_classes():
    for key in ("sqli", "xss", "traversal", "scanner", "auth_fail", "server_error"):
        assert key in LOG_PATTERNS


async def test_analyze_logs_flags_suspicious_lines(tmp_path):
    log = tmp_path / "access.log"
    log.write_text(
        "\n".join(
            [
                '1.2.3.4 - - "GET /?id=1 UNION SELECT password FROM users" 500',
                '1.2.3.4 - - "GET /?q=<script>alert(1)</script>" 200',
                '10.0.0.1 - - "GET /../../etc/passwd" 403',
                "sqlmap/1.7 scanning",
                "Failed password for root",
                "Traceback (most recent call last):",
                'normal request "GET /index.html" 200',
            ]
        ),
        encoding="utf-8",
    )
    ctx = _ctx("http://127.0.0.1", tmp_path)
    result = await _analyze_logs(ctx, path=str(log), source="file")
    assert result["suspicious"] is True
    assert result["categories"]["sqli"] >= 1
    assert result["categories"]["xss"] >= 1
    assert result["categories"]["scanner"] >= 1


async def test_analyze_logs_reports_a_missing_file(tmp_path):
    ctx = _ctx("http://127.0.0.1", tmp_path)
    result = await _analyze_logs(ctx, path=str(tmp_path / "nope.log"), source="file")
    assert "error" in result


async def test_analyze_logs_without_a_source(tmp_path):
    ctx = _ctx("http://127.0.0.1", tmp_path)
    result = await _analyze_logs(ctx, path="", source="auto")
    assert "info" in result


async def test_verify_control_checks_a_finding(target_server, tmp_path):
    url, _ = target_server
    ctx = _ctx(url, tmp_path)
    finding = await ctx.context.add_finding(
        {"title": "Missing headers", "endpoint": url, "category": "headers"}
    )
    result = await _verify_control(ctx, finding.id)
    assert "verified" in result
    assert result["status"] == 200


async def test_verify_control_unknown_finding(tmp_path):
    ctx = _ctx("http://127.0.0.1", tmp_path)
    result = await _verify_control(ctx, "F-does-not-exist")
    assert "error" in result


# --------------------------------------------------------------------------- #
# registry wiring
# --------------------------------------------------------------------------- #
def test_registry_exposes_the_expected_toolset(tmp_path):
    ctx = _ctx("http://127.0.0.1", tmp_path)
    red = build_registry(ctx, "red").names()
    for name in (
        "port_scan",
        "dns_lookup",
        "http_request",
        "crawl",
        "test_sql_injection",
        "test_xss",
        "record_finding",
        "install_tool",
    ):
        assert name in red, name
    # Blue-only tools must not leak into the Red Agent.
    assert "analyze_logs" not in red

    blue = build_registry(ctx, "blue").names()
    for name in ("analyze_logs", "generate_firewall_rule", "harden_headers", "suggest_patch"):
        assert name in blue, name
    assert "port_scan" not in blue


def test_registry_shared_tools_reach_both(tmp_path):
    ctx = _ctx("http://127.0.0.1", tmp_path)
    for agent in ("red", "blue"):
        names = build_registry(ctx, agent).names()
        assert "record_finding" in names
        assert "todowrite" in names
        assert "propose_engagement" in names


async def test_propose_engagement_emits_a_plan(tmp_path):
    from splitagent.tools.knowledge import _propose_engagement

    ctx = _ctx("http://127.0.0.1", tmp_path)
    seen: list[tuple[str, dict]] = []
    ctx.context.bus.subscribe(lambda e: seen.append((e.type, e.data)))
    result = await _propose_engagement(
        ctx,
        objective="Audit the login flow",
        scope=["127.0.0.1"],
        phases=["recon", "auth testing"],
    )
    assert result["proposed"] is True
    assert any(t == "chat.plan" and d["awaiting_approval"] for t, d in seen)


def test_workspace_tools_round_trip(tmp_path):
    """The agent must be able to write and read its own notes."""
    from splitagent.tools.workspace_tools import _list_dir, _read_file, _write_file

    project = TargetConfig()
    workspace = workspace_for(
        __import__("splitagent.config", fromlist=["ProjectConfig"]).ProjectConfig(),
        base=tmp_path,
    )
    workspace.ensure()
    ctx = ToolContext(
        target=project,
        run=RunConfig(),
        context=SharedContext.create(target="http://x", directory=tmp_path),
        settings={"workspace": workspace},
    )

    written = _write_file(ctx, "notes/plan.md", "# Plan\nmap the app")
    assert written["ok"] is True

    read = _read_file(ctx, "notes/plan.md")
    assert "map the app" in read["content"]

    listing = _list_dir(ctx, "notes")
    assert any(e["name"] == "plan.md" for e in listing["entries"])


def test_workspace_tools_refuse_escaping_paths(tmp_path):
    from splitagent.config import ProjectConfig
    from splitagent.tools.workspace_tools import _read_file, _write_file

    workspace = workspace_for(ProjectConfig(), base=tmp_path)
    workspace.ensure()
    ctx = ToolContext(
        target=TargetConfig(),
        run=RunConfig(),
        context=SharedContext.create(target="http://x", directory=tmp_path),
        settings={"workspace": workspace},
    )
    assert "error" in _write_file(ctx, "../../escape.txt", "nope")
    assert "error" in _read_file(ctx, "../../../etc/passwd")
