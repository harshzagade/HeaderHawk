"""Fetch tests against a localhost fixture server (no real targets)."""

import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from headerhawk.fetch import FetchError, fetch, normalize_url


class _Handler(BaseHTTPRequestHandler):
    def _send(self, status, headers):
        body = b"<html><body>hi</body></html>"
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/secure":
            self._send(200, {
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
            })
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/secure")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/error":
            self._send(500, {"X-Powered-By": "TestFixture/1.0"})
        else:
            self._send(200, {"Server": "FixtureServer"})

    def log_message(self, *args):
        pass  # keep test output clean


@pytest.fixture(scope="module")
def server():
    # Never route localhost through a proxy the environment may define.
    os.environ["no_proxy"] = os.environ.get("no_proxy", "") + ",127.0.0.1,localhost"
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def test_fetch_returns_headers_and_status(server):
    result = fetch(f"{server}/secure")
    assert result.status == 200
    assert result.headers["strict-transport-security"] == ["max-age=63072000; includeSubDomains"]
    assert result.redirects == 0
    assert result.final_url.endswith("/secure")


def test_fetch_follows_redirects_and_counts(server):
    result = fetch(f"{server}/redirect")
    assert result.status == 200
    assert result.redirects == 1
    assert result.final_url.endswith("/secure")


def test_fetch_records_redirect_chain(server):
    result = fetch(f"{server}/redirect")
    assert [(hop.status, hop.url) for hop in result.chain] == [
        (302, f"{server}/redirect"),
        (200, f"{server}/secure"),
    ]


def test_fetch_chain_is_single_hop_without_redirects(server):
    result = fetch(f"{server}/secure")
    assert [(hop.status, hop.url) for hop in result.chain] == [
        (200, f"{server}/secure"),
    ]


def test_fetch_still_returns_headers_on_http_error(server):
    result = fetch(f"{server}/error")
    assert result.status == 500
    assert result.headers["x-powered-by"] == ["TestFixture/1.0"]


def test_fetch_connection_refused_raises_fetch_error():
    with pytest.raises(FetchError):
        fetch("http://127.0.0.1:1/", timeout=1.0)


def test_normalize_url_adds_https():
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_url_rejects_non_http_scheme():
    with pytest.raises(FetchError):
        normalize_url("ftp://example.com/file")
