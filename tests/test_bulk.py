"""Bulk-mode tests: target-file parsing and localhost table/JSON output."""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from headerhawk.bulk import BulkResult, audit_targets, read_targets
from headerhawk.cli import main
from headerhawk.report import render_bulk_json, render_bulk_table


class _Handler(BaseHTTPRequestHandler):
    def _send(self, status, headers):
        body = b"<html>hi</html>"
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
                "X-Frame-Options": "DENY",
            })
        elif self.path == "/bare":
            self._send(200, {"Server": "FixtureServer"})
        else:
            self._send(404, {})

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def server():
    os.environ["no_proxy"] = os.environ.get("no_proxy", "") + ",127.0.0.1,localhost"
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _targets_file(tmp_path, server):
    path = tmp_path / "targets.txt"
    path.write_text(
        "# comment line\n"
        "\n"
        f"{server}/secure\n"
        f"{server}/bare\n"
        "   \n"
        "http://127.0.0.1:1/dead\n"  # unreachable -> error row
    )
    return str(path)


def test_read_targets_skips_blanks_and_comments(tmp_path, server):
    targets = read_targets(_targets_file(tmp_path, server))
    assert targets == [f"{server}/secure", f"{server}/bare", "http://127.0.0.1:1/dead"]


def test_read_targets_empty_file_raises(tmp_path):
    path = tmp_path / "empty.txt"
    path.write_text("# nothing here\n\n")
    with pytest.raises(ValueError, match="No targets found"):
        read_targets(str(path))


def test_audit_targets_returns_rows_with_error_row(server):
    rows = audit_targets(
        [f"{server}/secure", "http://127.0.0.1:1/dead"], timeout=5.0,
        user_agent="HeaderHawk-test")
    assert len(rows) == 2
    assert rows[0].grade and rows[0].score >= 0 and not rows[0].error
    assert rows[1].error and rows[1].grade == "" and rows[1].score == -1


def test_bulk_table_mode_localhost(server, tmp_path, capsys):
    code = main(["--bulk", _targets_file(tmp_path, server), "--no-color"])
    assert code == 0
    out = capsys.readouterr().out
    assert "bulk audit (3 targets)" in out
    assert "/secure" in out and "/bare" in out
    assert "ERROR" in out  # unreachable row
    assert "unreachable" in out
    assert "avg score" in out


def test_bulk_json_mode_localhost(server, tmp_path, capsys):
    code = main(["--bulk", _targets_file(tmp_path, server), "--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["target_count"] == 3
    assert len(payload["targets"]) == 3
    graded = [t for t in payload["targets"] if not t["error"]]
    failed = [t for t in payload["targets"] if t["error"]]
    assert len(graded) == 2 and len(failed) == 1
    assert all(set(("url", "grade", "score", "status_code")) <= set(t) for t in graded)


def test_bulk_rejects_url_and_headers_combos(server, tmp_path, capsys):
    f = _targets_file(tmp_path, server)
    assert main(["--bulk", f, f"{server}/secure"]) == 2
    assert main(["--bulk", f, "--headers", "x.txt"]) == 2


def test_bulk_missing_file_is_error(capsys):
    assert main(["--bulk", "/nonexistent/targets.txt"]) == 2


def test_bulk_fail_below_gate(server, tmp_path, capsys):
    f = _targets_file(tmp_path, server)
    # "/bare" grades poorly, so a strict gate fails...
    assert main(["--bulk", f, "--fail-below", "A+", "--no-color"]) == 1
    # ...while the loosest gate passes (unreachable row still fails it though).
    assert main(["--bulk", f, "--fail-below", "F", "--no-color"]) == 1
    ok_file = tmp_path / "ok.txt"
    ok_file.write_text(f"{server}/secure\n")
    assert main(["--bulk", str(ok_file), "--fail-below", "F", "--no-color"]) == 0


def test_render_bulk_table_truncates_long_urls():
    long_url = "https://example.com/" + "a" * 100
    rows = [BulkResult(url=long_url, status_code=200, grade="A", score=95,
                       high=0, med=1, elapsed_ms=120)]
    out = render_bulk_table(rows, color=False)
    assert long_url not in out  # truncated, not wrapped
    assert "A" in out and "95" in out


def test_render_bulk_json_all_errors():
    rows = [BulkResult(url="http://127.0.0.1:1/", error="connection refused")]
    payload = json.loads(render_bulk_json(rows))
    assert payload["targets"][0]["error"] == "connection refused"
    assert payload["targets"][0]["score"] == -1
