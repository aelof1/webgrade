"""End-to-end test against a tiny local HTTP server (no Internet needed)."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from webgrade.cli import audit


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.29")
        self.send_header("Set-Cookie", "PHPSESSID=123; path=/")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(b"hello")

    def log_message(self, *args):
        pass


@pytest.fixture
def server(monkeypatch):
    for var in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"):
        monkeypatch.delenv(var, raising=False)
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_plain_http_site(server):
    rep = audit(server)
    names = {r.name: r for r in rep["results"]}
    assert not names["HTTPS"].ok
    assert names["Clickjacking protection"].ok
    assert not names["Cookie 'PHPSESSID'"].ok
    assert rep["grade"] in "EF"
