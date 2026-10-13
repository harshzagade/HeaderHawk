"""End-to-end CLI tests. Live tests use the localhost fixture only."""

import io
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from headerhawk.cli import main


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def server():
    os.environ["no_proxy"] = os.environ.get("no_proxy", "") + ",127.0.0.1,localhost"
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _headers_file(tmp_path):
    path = tmp_path / "headers.txt"
    path.write_text(
        "HTTP/1.1 200 OK\n"
        "Server: nginx/1.24.0\n"
        "X-Powered-By: PHP/8.1.2\n"
    )
    return str(path)


def test_cli_offline_json_output(tmp_path, capsys):
    code = main(["--headers", _headers_file(tmp_path), "--json", "--no-color"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["grade"] == "F"
    assert payload["score"] == 35
    assert any(f["header"] == "Server" for f in payload["findings"])


def test_cli_fail_below_triggers_exit_1(tmp_path, capsys):
    code = main(["--headers", _headers_file(tmp_path), "--fail-below", "B", "--no-color"])
    assert code == 1


def test_cli_fail_below_passes_on_met_threshold(tmp_path, capsys):
    code = main(["--headers", _headers_file(tmp_path), "--fail-below", "F", "--no-color"])
    assert code == 0


def test_cli_stdin_pipe_mode(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("X-Frame-Options: DENY\n"))
    code = main(["--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["url"] == "<stdin>"


def test_cli_live_mode_against_localhost(server, capsys):
    code = main([server, "--no-color"])
    assert code == 0
    out = capsys.readouterr().out
    assert "GRADE:" in out
    assert "X-Content-Type-Options" in out


def test_cli_url_and_headers_conflict_is_error(capsys):
    code = main(["https://example.com", "--headers", "x.txt"])
    assert code == 2


def test_cli_raw_prints_headers_first(server, capsys):
    code = main([server, "--raw", "--no-color"])
    assert code == 0
    out = capsys.readouterr().out
    assert "x-content-type-options: nosniff" in out
    assert "GRADE:" in out


def test_cli_raw_neutralizes_terminal_injection(tmp_path, capsys):
    # OWASP review (2026-10-11): a hostile header value carrying an ANSI
    # escape sequence must not reach the terminal verbatim via --raw.
    path = tmp_path / "evil.txt"
    path.write_text("HTTP/1.1 200 OK\nServer: nginx\x1b[2J\x1b[1;1Hpwned\n")
    code = main(["--headers", str(path), "--raw", "--no-color"])
    assert code == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "server: nginx\\x1b[2J\\x1b[1;1Hpwned" in out


def test_cli_only_filters_to_high_severities(tmp_path, capsys):
    code = main(["--headers", _headers_file(tmp_path), "--no-color", "--only", "HIGH"])
    assert code == 0
    out = capsys.readouterr().out
    # Missing CSP/HSTS/XFO are HIGH and must still show.
    assert "Content-Security-Policy" in out
    assert "Strict-Transport-Security" in out
    # Server version disclosure is LOW and must be hidden.
    assert "Information disclosure" not in out
    assert "Showing only HIGH findings" in out


def test_cli_only_keeps_grade_and_score_honest(tmp_path, capsys):
    code = main(["--headers", _headers_file(tmp_path), "--no-color", "--only", "HIGH"])
    out = capsys.readouterr().out
    assert "GRADE: F" in out and "(score 35/100)" in out
    assert "still reflect all findings" in out


def test_cli_only_is_case_insensitive_and_multi(tmp_path, capsys):
    code = main(["--headers", _headers_file(tmp_path), "--no-color",
                 "--only", "high,med"])
    assert code == 0
    out = capsys.readouterr().out
    assert "X-Content-Type-Options" in out          # MED, shown
    assert "Information disclosure" not in out      # LOW, hidden
    assert "Showing only HIGH, MED findings" in out


def test_cli_only_does_not_touch_json(tmp_path, capsys):
    code = main(["--headers", _headers_file(tmp_path), "--json", "--no-color",
                 "--only", "HIGH"])
    assert code == 0
    payload = __import__("json").loads(capsys.readouterr().out)
    severities = {f["severity"] for f in payload["findings"]}
    assert "LOW" in severities  # JSON keeps every finding


def test_cli_only_rejects_unknown_severity(tmp_path, capsys):
    code = main(["--headers", _headers_file(tmp_path), "--only", "CRITICAL"])
    assert code == 2
    assert "unknown severity" in capsys.readouterr().err
