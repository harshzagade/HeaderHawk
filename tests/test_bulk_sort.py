"""Bulk-mode --sort tests: worst-first ordering of the summary table.

Unit tests use BulkResult directly (no network); the CLI tests run a
localhost server so the table/JSON order is checked end to end.
"""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from headerhawk.bulk import BulkResult
from headerhawk.cli import main
from headerhawk.report import sort_bulk_rows


def _row(url, grade, score, error=""):
    return BulkResult(url=url, grade=grade, score=score, error=error)


def test_sort_by_grade_worst_first():
    rows = [_row("a", "A+", 100), _row("b", "F", 20), _row("c", "C", 70)]
    assert [r.url for r in sort_bulk_rows(rows, "grade")] == ["b", "c", "a"]


def test_sort_by_grade_tie_breaks_lowest_score_first():
    rows = [_row("a", "B", 80), _row("b", "B", 70), _row("c", "A", 95)]
    assert [r.url for r in sort_bulk_rows(rows, "grade")] == ["b", "a", "c"]


def test_sort_by_score_lowest_first():
    rows = [_row("a", "A", 90), _row("b", "C", 50), _row("c", "B", 70)]
    assert [r.url for r in sort_bulk_rows(rows, "score")] == ["b", "c", "a"]


def test_sort_by_score_tie_breaks_worst_grade_first():
    rows = [_row("a", "B", 70), _row("b", "C", 70), _row("c", "A", 95)]
    assert [r.url for r in sort_bulk_rows(rows, "score")] == ["b", "a", "c"]


def test_error_rows_always_sort_last_in_file_order():
    rows = [_row("err1", "", -1, error="boom"),
            _row("a", "A+", 100),
            _row("err2", "", -1, error="bust"),
            _row("b", "F", 20)]
    assert [r.url for r in sort_bulk_rows(rows, "grade")] == ["b", "a", "err1", "err2"]
    assert [r.url for r in sort_bulk_rows(rows, "score")] == ["b", "a", "err1", "err2"]


def test_full_ties_keep_file_order():
    rows = [_row("a", "B", 75), _row("b", "B", 75), _row("c", "B", 75)]
    assert [r.url for r in sort_bulk_rows(rows, "grade")] == ["a", "b", "c"]
    assert [r.url for r in sort_bulk_rows(rows, "score")] == ["a", "b", "c"]


def test_unknown_sort_key_is_error():
    with pytest.raises(ValueError, match="unknown bulk sort key"):
        sort_bulk_rows([_row("a", "A", 90)], "random")


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
    # /secure first in file order, /bare second: sorting must flip them.
    path = tmp_path / "targets.txt"
    path.write_text(f"{server}/secure\n{server}/bare\n", encoding="utf-8")
    return str(path)


def test_cli_sort_grade_puts_worst_first(server, tmp_path, capsys):
    assert main(["--bulk", _targets_file(tmp_path, server),
                 "--sort", "grade"]) == 0
    out = capsys.readouterr().out
    assert "sorted by grade, worst first" in out
    assert out.index("/bare") < out.index("/secure")


def test_cli_sort_score_puts_lowest_first(server, tmp_path, capsys):
    assert main(["--bulk", _targets_file(tmp_path, server),
                 "--sort", "score"]) == 0
    out = capsys.readouterr().out
    assert "sorted by score, lowest first" in out
    assert out.index("/bare") < out.index("/secure")


def test_cli_sort_json_carries_sorted_by_and_order(server, tmp_path, capsys):
    assert main(["--bulk", _targets_file(tmp_path, server),
                 "--sort", "grade", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["sorted_by"] == "grade"
    urls = [t["url"] for t in payload["targets"]]
    assert urls[0].endswith("/bare") and urls[1].endswith("/secure")


def test_cli_no_sort_keeps_file_order(server, tmp_path, capsys):
    assert main(["--bulk", _targets_file(tmp_path, server)]) == 0
    out = capsys.readouterr().out
    assert "sorted by" not in out
    assert out.index("/secure") < out.index("/bare")


def test_cli_sort_without_bulk_is_error(capsys):
    assert main(["--sort", "grade"]) == 2
    assert "--sort only applies with --bulk" in capsys.readouterr().err


def test_cli_sort_bad_choice_is_error(capsys):
    with pytest.raises(SystemExit):
        main(["--bulk", "targets.txt", "--sort", "random"])
