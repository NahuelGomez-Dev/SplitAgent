from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


class TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "nginx")
        self.end_headers()
        self.wfile.write(b"<html><title>Target</title><body>ok</body></html>")

    def log_message(self, *args):
        pass


class MockLLMHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path.rstrip("/").endswith("/models"):
            payload = json.dumps(
                {"object": "list", "data": [{"id": "mock-model", "object": "model"}]}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        messages = body.get("messages", [])
        blob = json.dumps(messages)
        # The engagement planner asks for a JSON plan; answer with one so the
        # audit-plan pipeline is exercised end to end.
        if "ENGAGEMENT PLANNER" in blob:
            payload = _text_stream(
                json.dumps(
                    {
                        "objective": "Audit the mock target",
                        "scope": ["localhost"],
                        "out_of_scope": [],
                        "phases": ["recon", "validate"],
                        "techniques": ["http_request"],
                        "cautions": ["non-destructive only"],
                        "noise": "normal",
                    }
                )
            )
        elif any(m.get("role") == "tool" for m in messages):
            payload = _text_stream("Analysis complete: no confirmed exploitable issues.")
        else:
            payload = _tool_stream("read_shared_context", "{}")
        data = payload.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def _tool_stream(name: str, arguments: str) -> str:
    chunk = {
        "choices": [
            {
                "delta": {
                    "tool_calls": [
                        {
                            "index": 0,
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": name, "arguments": arguments},
                        }
                    ]
                }
            }
        ]
    }
    return f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n"


def _text_stream(text: str) -> str:
    chunk = {"choices": [{"delta": {"content": text}}]}
    return f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n"


@pytest.fixture()
def llm_servers():
    target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
    llm = ThreadingHTTPServer(("127.0.0.1", 0), MockLLMHandler)
    for server in (target, llm):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    yield (
        f"http://127.0.0.1:{target.server_port}",
        f"http://127.0.0.1:{llm.server_port}/v1",
    )
    target.shutdown()
    llm.shutdown()
