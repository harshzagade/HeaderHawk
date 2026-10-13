"""--compare mode tests: diff logic, rendering, and CLI plumbing."""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from headerhawk.checks import Finding, Report
from headerhawk.cli import main
from headerhawk.report import diff_reports, render_compare, render_compare_json


def _finding(summary, severity="MED", delta=-5, check="Test-Check",
             header="X-Test", status="weak"):
    return Finding(check=check, header=header, status=status,
                   severity=severity, score_delta=delta, summary=summary)


def _report(*findings, grade="C", score=70):
    return Report(url="http://a/", grade=grade, score=score,
                  findings=list(findings))


def test_diff_reports_classifies_all_verdicts():
    improved = _finding("same summary", severity="MED", delta=-5)
    improved_after = _finding("same summary", severity="LOW", delta=-2)
    regressed = _finding("other", severity="LOW", delta=-2, check="Other")
    regressed_after = _finding("other", severity="HIGH", delta=-15, check="Other")
    new_only = _finding("brand new", check="NewCheck")
    resolved_only = _finding("gone now", check="OldCheck")
    same = _finding("unchanged", check="SameCheck")

    before = _report(improved, regressed, resolved_only, same, grade="C", score=70)
    after = _report(improved_after, regressed_after, new_only, same,
                    grade="B", score=80)
    rows = diff_reports(before, after)
    by_verdict = {}
    for row in rows:
        by_verdict.setdefault(row.verdict, []).append(row.check)

    assert by_verdict["improved"] == ["Test-Check"]
    assert by_verdict["regressed"] == ["Other"]
    assert by_verdict["new"] == ["NewCheck"]
    assert by_verdict["resolved"] == ["OldCheck"]
    assert not any(r.check == "SameCheck" for r in rows)


def test_diff_reports_orders_regressions_first():
    rows = diff_reports(
        _report(_finding("a", check="A")),
        _report(_finding("b", check="B")),
    )
    assert [r.verdict for r in rows] == ["new", "resolved"]


def test_render_compare_shows_score_delta_and_sections():
    before = _report(_finding("CSP allows 'unsafe-inline' scripts.",
                              severity="MED", delta=-8,
                              check="Content-Security-Policy",
                              header="Content-Security-Policy"),
                     grade="F", score=30)
    before.final_url = "http://before/"
    after = _report(_finding("CSP allows 'unsafe-inline' scripts.",
                             severity="LOW", delta=-3, status="weak",
                             check="Content-Security-Policy",
                             header="Content-Security-Policy"),
                    _finding("CSP violation reporting uses report-uri.",
                             severity="INFO", delta=0, status="info",
                             check="Content-Security-Policy",
                             header="Content-Security-Policy"),
                    grade="D", score=59)
    after.final_url = "http://after/"
    out = render_compare(before, after, color=False)
    assert "Score change: +29" in out
    assert "F -> D" in out
    assert "Improved" in out
    assert "New findings" in out


def test_render_compare_no_differences():
    report = _report(_finding("unchanged", check="SameCheck"), grade="B", score=85)
    out = render_compare(report, report, color=False)
    assert "No differences" in out


def test_render_compare_json_shape():
    before = _report(_finding("old", check="OldCheck"), grade="C", score=70)
    after = _report(_finding("new", check="NewCheck"), grade="B", score=80)
    payload = json.loads(render_compare_json(before, after))
    assert payload["score_delta"] == 10
    assert payload["grade_before"] == "C"
    assert payload["grade_after"] == "B"
    verdicts = {row["verdict"] for row in payload["diff"]}
    assert verdicts == {"new", "resolved"}
    assert payload["before"]["findings"][0]["check"] == "OldCheck"


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
        if self.path == "/before":
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


def test_cli_compare_live(server, capsys):
    code = main(["--compare", f"{server}/before", f"{server}/after",
                 "--no-color"])
    assert code == 0
    out = capsys.readouterr().out
    assert "compare" in out
    assert "Score change:" in out
    # Hardening /after turns missing-header findings into new pass findings:
    # the diff shows up as Resolved + New findings.
    assert "Resolved" in out
    assert "New findings" in out


def test_cli_compare_json(server, capsys):
    code = main(["--compare", f"{server}/before", f"{server}/after",
                 "--json", "--no-color"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["score_delta"] > 0
    assert payload["diff"]


def test_cli_compare_rejects_url_combo(server, capsys):
    code = main([f"{server}/before", "--compare",
                 f"{server}/before", f"{server}/after"])
    assert code == 2
    assert "cannot be combined" in capsys.readouterr().err


def test_cli_compare_rejects_raw_and_only(server, capsys):
    assert main(["--compare", f"{server}/before", f"{server}/after",
                 "--raw"]) == 2
    assert main(["--compare", f"{server}/before", f"{server}/after",
                 "--only", "HIGH"]) == 2


def test_cli_compare_fail_below_gates_on_url_b(server, capsys):
    # /after is well-hardened: requiring B must pass...
    assert main(["--compare", f"{server}/before", f"{server}/after",
                 "--fail-below", "F", "--no-color"]) == 0
    # ...requiring A+ must fail (it is not A+).
    assert main(["--compare", f"{server}/before", f"{server}/after",
                 "--fail-below", "A+", "--no-color"]) == 1
