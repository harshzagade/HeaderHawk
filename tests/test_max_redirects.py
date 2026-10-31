"""--max-redirects: a chain longer than N is a fetch error, not an audit."""

import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from headerhawk.bulk import audit_targets
from headerhawk.cli import main
from headerhawk.fetch import FetchError, fetch


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
        if self.path == "/r1":
            self.send_response(302)
            self.send_header("Location", "/r2")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/r2":
            self.send_response(302)
            self.send_header("Location", "/r3")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/r3":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/final":
            self._send(200, {"X-Content-Type-Options": "nosniff"})
        elif self.path == "/.well-known/security.txt":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
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


def test_chain_within_cap_succeeds(server):
    result = fetch(f"{server}/r1", max_redirects=3)
    assert result.status == 200
    assert result.redirects == 3
    assert result.final_url.endswith("/final")


def test_chain_over_cap_is_fetch_error(server):
    with pytest.raises(FetchError) as excinfo:
        fetch(f"{server}/r1", max_redirects=2)
    assert "Redirect limit" in str(excinfo.value)
    assert "2" in str(excinfo.value)


def test_zero_cap_rejects_any_redirect_but_allows_direct(server):
    with pytest.raises(FetchError):
        fetch(f"{server}/r1", max_redirects=0)
    result = fetch(f"{server}/final", max_redirects=0)
    assert result.status == 200
    assert result.redirects == 0


def test_default_cap_still_allows_short_chain(server):
    result = fetch(f"{server}/r1")
    assert result.status == 200
    assert result.redirects == 3


def test_cli_rejects_negative_max_redirects(server, capsys):
    code = main([f"{server}/final", "--max-redirects", "-1"])
    assert code == 2
    assert "max-redirects" in capsys.readouterr().err


def test_cli_over_cap_is_fetch_error(server, capsys):
    code = main([f"{server}/r1", "--max-redirects", "2", "--no-color"])
    assert code == 2
    assert "Redirect limit" in capsys.readouterr().err


def test_bulk_over_cap_becomes_error_row(server):
    rows = audit_targets([f"{server}/r1"], timeout=10.0,
                         user_agent="test", max_redirects=2)
    assert len(rows) == 1
    assert rows[0].error
    assert "Redirect limit" in rows[0].error
    assert rows[0].report is None
