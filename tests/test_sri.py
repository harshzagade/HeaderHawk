"""--sri mode tests: HTML parsing, check wiring, and CLI plumbing."""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from headerhawk.checks import analyze, check_sri
from headerhawk.cli import main
from headerhawk.report import render_text
from headerhawk.sri import (count_protected_resources, fetch_html,
                            find_unprotected_resources)

HTML_MIXED = """<html><head>
<script src="https://cdn.example.com/lib.js"></script>
<script src="https://cdn.example.com/safe.js" integrity="sha384-abc123"
        crossorigin="anonymous"></script>
<script src="/static/local.js"></script>
<link rel="stylesheet" href="//fonts.example.com/css?family=x">
<link rel="stylesheet" href="https://cdn.example.com/theme.css"
      integrity="sha512-def456">
<link rel="icon" href="https://cdn.example.com/favicon.ico">
</head></html>"""


def test_find_unprotected_flags_only_external_without_integrity():
    found = find_unprotected_resources(HTML_MIXED)
    urls = {(r.tag, r.url) for r in found}
    assert urls == {
        ("script", "https://cdn.example.com/lib.js"),
        ("link", "//fonts.example.com/css?family=x"),
    }


def test_relative_paths_are_out_of_scope():
    found = find_unprotected_resources(
        '<script src="/js/app.js"></script><script src="js/other.js"></script>')
    assert found == []


def test_protected_count():
    assert count_protected_resources(HTML_MIXED) == 2


def test_data_and_inline_scripts_ignored():
    found = find_unprotected_resources(
        '<script src="data:text/javascript,alert(1)"></script>'
        "<script>alert('inline')</script>")
    assert found == []


def test_non_stylesheet_links_ignored():
    found = find_unprotected_resources(
        '<link rel="preconnect" href="https://cdn.example.com">')
    assert found == []


def test_rel_case_and_multiple_values():
    found = find_unprotected_resources(
        '<link REL="preload STYLESHEET" href="https://x.example.com/a.css">')
    assert [r.url for r in found] == ["https://x.example.com/a.css"]


def test_unquoted_attribute_value_is_parsed():
    found = find_unprotected_resources("<script src=https://x.example.com/a.js>")
    assert [r.url for r in found] == ["https://x.example.com/a.js"]


def test_check_sri_none_means_headers_only():
    assert check_sri(None) == []


def test_check_sri_findings_are_med():
    findings = check_sri(HTML_MIXED)
    assert len(findings) == 2
    for f in findings:
        assert f.check == "Subresource Integrity"
        assert f.severity == "MED" and f.score_delta == -4
        assert f.fix
    assert any("cdn.example.com/lib.js" in f.summary for f in findings)
    assert any("fonts.example.com" in f.summary for f in findings)


def test_check_sri_all_protected_is_ok_pass():
    (f,) = check_sri('<script src="https://x.example.com/a.js" '
                     'integrity="sha384-zzz"></script>')
    assert f.severity == "OK" and f.score_delta == 0
    assert "1 external resource" in f.summary


def test_check_sri_no_external_is_info():
    (f,) = check_sri("<html><body><p>hello</p></body></html>")
    assert f.severity == "INFO" and f.score_delta == 0


def test_analyze_wires_sri_and_score():
    report = analyze({}, scheme="https", meta={
        "url": "https://example.com",
        "sri_html": HTML_MIXED,
        "sri_seen": 4,
    })
    sri = [f for f in report.findings if f.check == "Subresource Integrity"]
    assert len(sri) == 2
    assert report.sri_seen == 4
    assert report.to_dict()["sri_seen"] == 4
    # Score reflects the SRI penalties on top of the (missing-header) ones.
    assert report.score == 100 + sum(f.score_delta for f in report.findings)
    assert sum(f.score_delta for f in sri) == -8


def test_footer_summarizes_sri_audit():
    report = analyze({}, scheme="https", meta={
        "url": "https://example.com",
        "sri_html": HTML_MIXED,
        "sri_seen": 4,
    })
    out = render_text(report, color=False)
    assert "Subresource Integrity on 4 external resources" in out


class _Handler(BaseHTTPRequestHandler):
    def _send(self, headers, body):
        self.send_response(200)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/page":
            self._send(
                {"Content-Type": "text/html; charset=utf-8",
                 "X-Content-Type-Options": "nosniff"},
                b"<html><head>"
                b'<script src="https://cdn.example.com/lib.js"></script>'
                b"</head></html>")
        else:
            self._send({"Content-Type": "application/json"}, b'{"ok": true}')

    def log_message(self, *args):
        pass


import pytest  # noqa: E402


@pytest.fixture(scope="module")
def server():
    os.environ["no_proxy"] = os.environ.get("no_proxy", "") + ",127.0.0.1,localhost"
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def test_fetch_html_live(server):
    page = fetch_html(f"{server}/page", user_agent="HeaderHawk-test")
    assert page.status == 200
    assert "cdn.example.com/lib.js" in page.html
    assert not page.truncated


def test_cli_sri_live(server, capsys):
    code = main([f"{server}/page", "--sri", "--no-color"])
    assert code == 0
    out = capsys.readouterr().out
    assert "Subresource Integrity" in out
    assert "cdn.example.com/lib.js" in out
    assert "Audited Subresource Integrity on 1 external resource" in out


def test_cli_sri_json_reports_sri_seen(server, capsys):
    code = main([f"{server}/page", "--sri", "--json", "--no-color"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["sri_seen"] == 1
    sri = [f for f in payload["findings"]
           if f["check"] == "Subresource Integrity"]
    assert len(sri) == 1 and sri[0]["severity"] == "MED"


def test_cli_sri_non_html_warns_but_still_audits(server, capsys):
    code = main([f"{server}/json", "--sri", "--no-color"])
    assert code == 0
    err = capsys.readouterr().err
    assert "--sri audit skipped" in err


def test_cli_sri_rejects_offline(tmp_path):
    headers_file = tmp_path / "headers.txt"
    headers_file.write_text("HTTP/1.1 200 OK\n")
    assert main(["--headers", str(headers_file), "--sri"]) == 2


def test_cli_sri_rejects_bulk_and_watch_and_compare(server, capsys):
    assert main(["--bulk", "x", "--sri"]) == 2
    assert main([f"{server}/page", "--watch", "5", "--sri"]) == 2
    assert main(["--compare", f"{server}/page", f"{server}/page",
                 "--sri"]) == 2
