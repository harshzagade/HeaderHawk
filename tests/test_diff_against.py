"""--diff-against tests: baseline reconstruction and CLI plumbing."""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from headerhawk.checks import Finding, Report, analyze
from headerhawk.cli import _load_baseline, main
from headerhawk.report import report_from_dict


def _sample_report():
    return analyze(
        {"content-security-policy": ["default-src 'self'"],
         "x-content-type-options": ["nosniff"]},
        scheme="https",
        meta={"url": "https://example.com", "final_url": "https://example.com",
              "status_code": 200, "headers_seen": 2},
    )


def test_report_from_dict_round_trip():
    original = _sample_report()
    rebuilt = report_from_dict(original.to_dict())
    assert rebuilt.url == original.url
    assert rebuilt.grade == original.grade
    assert rebuilt.score == original.score
    assert rebuilt.status_code == original.status_code
    assert len(rebuilt.findings) == len(original.findings)
    first = rebuilt.findings[0]
    assert isinstance(first, Finding)
    assert first.check == original.findings[0].check
    assert first.severity == original.findings[0].severity
    assert first.score_delta == original.findings[0].score_delta
    assert first.summary == original.findings[0].summary
    assert first.detail == original.findings[0].detail
    assert first.fix == original.findings[0].fix


def test_report_from_dict_sri_seen_survives():
    payload = {"url": "https://x/", "findings": [], "sri_seen": 3,
               "grade": "A+", "score": 100}
    rebuilt = report_from_dict(payload)
    assert rebuilt.sri_seen == 3
    assert rebuilt.grade == "A+"


def test_report_from_dict_rejects_garbage():
    with pytest.raises(ValueError):
        report_from_dict("not a dict")
    with pytest.raises(ValueError):
        report_from_dict({"findings": "nope"})
    with pytest.raises(ValueError):
        report_from_dict({"findings": ["nope"]})


def test_load_baseline_errors_are_human_readable(tmp_path):
    missing = tmp_path / "nope.json"
    with pytest.raises(ValueError, match="cannot read baseline"):
        _load_baseline(str(missing))
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        _load_baseline(str(bad))
    weird = tmp_path / "weird.json"
    weird.write_text(json.dumps({"findings": "nope"}))
    with pytest.raises(ValueError, match="baseline file"):
        _load_baseline(str(weird))


class _Handler(BaseHTTPRequestHandler):
    def _send(self, headers):
        body = b"ok"
        self.send_response(200)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/weak":
            self._send({"Server": "WeakFixture/1.0"})
        else:
            self._send({
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=()",
            })

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def server():
    os.environ["no_proxy"] = os.environ.get("no_proxy", "") + ",127.0.0.1,localhost"
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


@pytest.fixture()
def baseline_file(server, tmp_path, capsys):
    """A saved --json report of the /weak endpoint."""
    path = tmp_path / "baseline.json"
    code = main([f"{server}/weak", "--json", "--no-color",
                 "-o", str(path)])
    assert code == 0
    capsys.readouterr()
    return str(path)


def test_cli_diff_against_live(server, baseline_file, capsys):
    code = main([f"{server}/hard", "--diff-against", baseline_file,
                 "--no-color"])
    assert code == 0
    out = capsys.readouterr().out
    assert "compare" in out
    assert "Score change:" in out
    assert "Resolved" in out  # weak header findings gone in hardened /hard
    assert "New findings" in out  # new OK passes on /hard


def test_cli_diff_against_identical_shows_no_differences(server, capsys,
                                                          tmp_path):
    same = tmp_path / "same.json"
    assert main([f"{server}/weak", "--json", "--no-color",
                 "-o", str(same)]) == 0
    capsys.readouterr()
    assert main([f"{server}/weak", "--diff-against", str(same),
                 "--no-color"]) == 0
    assert "No differences" in capsys.readouterr().out


def test_cli_diff_against_json(server, baseline_file, capsys):
    code = main([f"{server}/hard", "--diff-against", baseline_file,
                 "--json", "--no-color"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["score_delta"] > 0
    assert payload["grade_before"] == "E"
    assert {row["verdict"] for row in payload["diff"]} >= {"new", "resolved"}


def test_cli_diff_against_missing_file(server, capsys):
    code = main([f"{server}/hard", "--diff-against", "/nope/missing.json"])
    assert code == 2
    assert "cannot read baseline" in capsys.readouterr().err


def test_cli_diff_against_invalid_json(server, capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    assert main([f"{server}/hard", "--diff-against", str(bad)]) == 2
    assert "not valid JSON" in capsys.readouterr().err


def test_cli_diff_against_rejects_combos(server, baseline_file):
    assert main(["--compare", f"{server}/a", f"{server}/b",
                 "--diff-against", baseline_file]) == 2
    assert main([f"{server}/hard", "--watch", "5",
                 "--diff-against", baseline_file]) == 2
    assert main(["--bulk", "x", "--diff-against", baseline_file]) == 2
    assert main([f"{server}/hard", "--diff-against", baseline_file,
                 "--raw"]) == 2
    assert main([f"{server}/hard", "--diff-against", baseline_file,
                 "--only", "HIGH"]) == 2
    assert main([f"{server}/hard", "--diff-against", baseline_file,
                 "--summary-line"]) == 2


def test_cli_diff_against_fail_below_gates_on_fresh(server, baseline_file,
                                                    capsys):
    # /hard is well-hardened: requiring F must pass, A+ must fail the gate.
    assert main([f"{server}/hard", "--diff-against", baseline_file,
                 "--fail-below", "F", "--no-color"]) == 0
    capsys.readouterr()
    assert main([f"{server}/hard", "--diff-against", baseline_file,
                 "--fail-below", "A+", "--no-color"]) == 1
