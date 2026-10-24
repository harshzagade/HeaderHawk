"""Unit + CLI tests for the --fail-on SEVERITY finding gate."""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from headerhawk import cli
from headerhawk.checks import analyze
from headerhawk.cli import _findings_at_or_above, _parse_fail_on, main


def _headers_file(tmp_path, body):
    path = tmp_path / "headers.txt"
    path.write_text(body)
    return str(path)


MINIMAL = (
    "HTTP/1.1 200 OK\n"
    "Server: nginx/1.24.0\n"
    "X-Powered-By: PHP/8.1.2\n"
)

HARDENED = (
    "HTTP/1.1 200 OK\n"
    "Strict-Transport-Security: max-age=63072000; includeSubDomains\n"
    "Content-Security-Policy: default-src 'self'\n"
)


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


# --- parsing ---------------------------------------------------------------

def test_parse_fail_on_ranks():
    assert _parse_fail_on("HIGH") == 0
    assert _parse_fail_on("med") == 1  # case-insensitive
    assert _parse_fail_on("Low") == 2
    assert _parse_fail_on("INFO") == 3
    assert _parse_fail_on("ok") == 4
    assert _parse_fail_on(None) is None


def test_parse_fail_on_rejects_unknown():
    with pytest.raises(ValueError, match="unknown severity"):
        _parse_fail_on("SEVERE")


def test_findings_at_or_above_boundary():
    report = analyze({"server": ["nginx/1.24.0"]}, scheme="https")
    at_high = _findings_at_or_above(report, 0)
    at_med = _findings_at_or_above(report, 1)
    assert at_high and all(f.severity == "HIGH" for f in at_high)
    assert len(at_med) >= len(at_high)
    assert all(f.severity in ("HIGH", "MED") for f in at_med)


# --- single-target CLI ------------------------------------------------------

def test_fail_on_high_exits_1(tmp_path, capsys):
    code = main(["--headers", _headers_file(tmp_path, MINIMAL),
                 "--fail-on", "HIGH", "--no-color"])
    assert code == 1
    assert "Finding gate failed" in capsys.readouterr().err


def test_fail_on_med_exits_1(tmp_path, capsys):
    code = main(["--headers", _headers_file(tmp_path, MINIMAL),
                 "--fail-on", "MED", "--no-color"])
    assert code == 1


def test_fail_on_passes_when_no_findings_at_severity(tmp_path, capsys):
    code = main(["--headers", _headers_file(tmp_path, HARDENED),
                 "--fail-on", "HIGH", "--no-color"])
    assert code == 0


def test_fail_on_med_still_fails_on_hardened(tmp_path, capsys):
    code = main(["--headers", _headers_file(tmp_path, HARDENED),
                 "--fail-on", "MED", "--no-color"])
    assert code == 1


def test_fail_on_unknown_severity_exits_2(tmp_path, capsys):
    code = main(["--headers", _headers_file(tmp_path, MINIMAL),
                 "--fail-on", "BOGUS", "--no-color"])
    assert code == 2
    assert "unknown severity" in capsys.readouterr().err


def test_fail_on_json_mode_stays_quiet(tmp_path, capsys):
    code = main(["--headers", _headers_file(tmp_path, MINIMAL),
                 "--fail-on", "HIGH", "--json", "--no-color"])
    assert code == 1
    out = capsys.readouterr()
    payload = json.loads(out.out)  # stdout is pure JSON
    assert payload["grade"] == "F"
    assert "Finding gate failed" not in out.out


def test_fail_on_live_server(server):
    code = main([server, "--fail-on", "HIGH", "--no-color"])
    assert code == 1


# --- bulk / compare / watch --------------------------------------------------

def test_bulk_fail_on_high(server, tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text(server + "\n")
    code = main(["--bulk", str(targets), "--fail-on", "HIGH", "--no-color"])
    assert code == 1


def test_bulk_fail_on_skips_unreachable(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("http://127.0.0.1:1/\n")  # nothing listens: error row
    code = main(["--bulk", str(targets), "--fail-on", "HIGH", "--no-color"])
    assert code == 0


def test_compare_fail_on_gates_url_b(server):
    code = main(["--compare", server, server, "--fail-on", "HIGH",
                 "--no-color"])
    assert code == 1


def test_watch_fail_on_gates_each_audit(monkeypatch, capsys):
    bad = analyze({}, scheme="https")
    it = iter([bad])

    def fake(url, *, timeout, user_agent, **kwargs):
        return next(it), {}

    class _Clock:
        def __init__(self):
            self.calls = 0

        def __call__(self, seconds):
            self.calls += 1
            raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_audit_one", fake)
    code = cli.run_watch(
        cli.build_parser().parse_args(
            ["example.com", "--watch", "1", "--fail-on", "MED", "--no-color"]),
        sleep=_Clock())
    assert code == 1
    assert "Finding gate failed" in capsys.readouterr().err
