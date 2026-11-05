"""Per-target `# timeout=N` directives in bulk target files."""

import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from headerhawk.bulk import (BulkTarget, audit_targets, read_bulk_targets,
                             read_targets)


class _SlowHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/slow":
            time.sleep(0.6)
        body = b"<html>hi</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def slow_server():
    os.environ["no_proxy"] = os.environ.get("no_proxy", "") + ",127.0.0.1,localhost"
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _SlowHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _write(tmp_path, text):
    path = tmp_path / "targets.txt"
    path.write_text(text)
    return str(path)


def test_directive_applies_only_to_following_targets(tmp_path):
    path = _write(tmp_path,
                  "https://fast.example/\n"
                  "# timeout=2.5\n"
                  "https://slow.example/\n")
    targets = read_bulk_targets(path)
    assert targets == [BulkTarget(url="https://fast.example/", timeout=None),
                       BulkTarget(url="https://slow.example/", timeout=2.5)]


def test_directive_is_sticky_until_changed(tmp_path):
    path = _write(tmp_path,
                  "# TIMEOUT=3\n"
                  "https://a.example/\n"
                  "https://b.example/\n"
                  "#timeout=7.5\n"
                  "https://c.example/\n")
    targets = read_bulk_targets(path)
    assert [t.timeout for t in targets] == [3.0, 3.0, 7.5]
    assert [t.url for t in targets] == ["https://a.example/",
                                        "https://b.example/",
                                        "https://c.example/"]


def test_directive_only_file_has_no_targets(tmp_path):
    path = _write(tmp_path, "# timeout=5\n# just a comment\n\n")
    with pytest.raises(ValueError, match="No targets found"):
        read_bulk_targets(path)


@pytest.mark.parametrize("value", ["abc", "0", "-1"])
def test_invalid_directive_value_fails_fast(tmp_path, value):
    path = _write(tmp_path, f"# timeout={value}\nhttps://a.example/\n")
    with pytest.raises(ValueError, match="Invalid timeout"):
        read_bulk_targets(path)


def test_read_targets_still_returns_plain_urls(tmp_path):
    path = _write(tmp_path,
                  "# timeout=5\n"
                  "https://a.example/\n"
                  "https://b.example/\n")
    assert read_targets(path) == ["https://a.example/", "https://b.example/"]


def test_audit_targets_honors_per_target_timeout(slow_server):
    slow = f"{slow_server}/slow"
    rows = audit_targets(
        [BulkTarget(url=slow, timeout=0.1),   # too short: times out
         BulkTarget(url=slow, timeout=5.0),   # generous: succeeds
         slow],                               # plain string: run default
        timeout=5.0, user_agent="HeaderHawk-test")
    assert rows[0].error, "0.1s timeout should fail on a 0.6s endpoint"
    assert "timed out" in rows[0].error.lower() or "timeout" in rows[0].error.lower()
    assert rows[1].error == "" and rows[1].status_code == 200
    assert rows[2].error == "" and rows[2].status_code == 200
