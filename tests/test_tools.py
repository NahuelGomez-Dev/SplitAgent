from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from splitagent.config import RunConfig, TargetConfig
from splitagent.core.bus import EventBus
from splitagent.core.context import SharedContext
from splitagent.errors import ScopeError
from splitagent.tools.base import ToolContext
from splitagent.tools.defense import _firewall_rule
from splitagent.tools.knowledge import _list_findings, _record_finding
from splitagent.tools.web import headers_audit


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>Test</title></head><body>hi</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "nginx/1.24.0")
        self.send_header("X-Powered-By", "PHP/8.1")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence
        pass


@pytest.fixture()
def web_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def _context(tmp_path, url: str) -> ToolContext:
    target = TargetConfig(url=url, scope=["127.0.0.1", "localhost"])
    ctx = SharedContext.create(target=url, bus=EventBus(), directory=tmp_path)
    return ToolContext(target=target, run=RunConfig(), context=ctx)


def test_firewall_rule_iptables():
    rule = _firewall_rule("iptables", "block", 8080, "10.0.0.5")
    assert "iptables" in rule["rule"]
    assert "DROP" in rule["rule"]


def test_firewall_rule_windows():
    rule = _firewall_rule("windows", "block", 3389)
    assert "New-NetFirewallRule" in rule["rule"]


def test_scope_enforcement(tmp_path):
    ctx = _context(tmp_path, "http://localhost")
    with pytest.raises(ScopeError):
        ctx.check_scope("http://evil.example.com")


async def test_headers_audit(tmp_path, web_server):
    ctx = _context(tmp_path, web_server)
    result = await headers_audit(ctx, web_server)
    assert result["status"] == 200
    missing = {item["header"] for item in result["missing_security_headers"]}
    assert "content-security-policy" in missing
    assert "nginx/1.24.0" in result["information_disclosure"].get("server", "")


async def test_record_finding(tmp_path):
    ctx = _context(tmp_path, "http://localhost")
    result = await _record_finding(
        ctx,
        title="Missing CSP",
        description="No content security policy",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    )
    assert result["recorded"] is True
    assert result["cvss_score"] == 6.1
    listing = _list_findings(ctx)
    assert listing["count"] == 1
