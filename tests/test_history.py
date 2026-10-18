"""Tests for grade history: --history append + --history-report trend."""

import json

import pytest

from headerhawk.cli import main
from headerhawk.history import HistoryEntry, append_run, read_history
from headerhawk.report import render_history_report


# --- history.py unit tests ----------------------------------------------

def test_append_writes_valid_jsonl_row(tmp_path):
    path = str(tmp_path / "history.jsonl")
    append_run(path, "https://example.com", "B", 82)
    with open(path, encoding="utf-8") as fh:
        payload = json.loads(fh.readline())
    assert payload["url"] == "https://example.com"
    assert payload["grade"] == "B" and payload["score"] == 82
    assert payload["timestamp"].endswith("Z") and "T" in payload["timestamp"]


def test_append_is_append_only_and_ordered(tmp_path):
    path = str(tmp_path / "history.jsonl")
    append_run(path, "https://a.example", "C", 70)
    append_run(path, "https://a.example", "A", 95)
    entries, skipped = read_history(path)
    assert skipped == 0
    assert [(e.url, e.grade, e.score) for e in entries] == [
        ("https://a.example", "C", 70),
        ("https://a.example", "A", 95),
    ]


def test_read_history_skips_malformed_lines(tmp_path):
    path = str(tmp_path / "history.jsonl")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write('{"timestamp": "2026-10-18T00:00:00Z", "url": "https://a.example",'
                 ' "grade": "B", "score": 85}\n')
        fh.write("this is not json\n")
        fh.write('{"url": "https://b.example", "grade": "A"}\n')  # missing fields
        fh.write('{"timestamp": "t", "url": "https://c.example", '
                 '"grade": "A", "score": "not-an-int"}\n')  # wrong type
        fh.write("\n")  # blank line is fine, not counted
    entries, skipped = read_history(path)
    assert len(entries) == 1 and entries[0].grade == "B"
    assert skipped == 3


def test_read_history_missing_file_raises(tmp_path):
    with pytest.raises(OSError):
        read_history(str(tmp_path / "nope.jsonl"))


def test_append_unwritable_path_raises(tmp_path):
    with pytest.raises(OSError):
        append_run(str(tmp_path / "no-such-dir" / "h.jsonl"), "u", "A", 100)


# --- render_history_report ----------------------------------------------

def _entries(*rows):
    return [HistoryEntry(timestamp=f"2026-10-{10 + i:02d}T09:00:00Z",
                         url=url, grade=grade, score=score)
            for i, (url, grade, score) in enumerate(rows)]


def test_render_empty_history():
    out = render_history_report([], color=False)
    assert "No history recorded yet" in out


def test_render_groups_by_url_with_trend():
    entries = _entries(
        ("https://a.example", "C", 70),
        ("https://b.example", "A", 95),
        ("https://a.example", "B", 85),
    )
    out = render_history_report(entries, color=False)
    assert "3 run(s) across 2 URL(s)" in out
    assert "https://a.example — improving: C -> B (score 70 -> 85, +15 over 2 run(s))" in out
    assert "https://b.example — steady: A -> A (score 95 -> 95, +0 over 1 run(s))" in out
    assert "+15" in out  # per-row change column


def test_render_declining_verdict():
    entries = _entries(("https://a.example", "A", 95),
                       ("https://a.example", "D", 55))
    out = render_history_report(entries, color=False)
    assert "declining: A -> D" in out
    assert "-40" in out


def test_render_mentions_skipped_lines():
    entries = _entries(("https://a.example", "B", 85))
    out = render_history_report(entries, skipped=2, color=False)
    assert "Skipped 2 malformed line(s)" in out


# --- CLI ----------------------------------------------------------------

def _headers_file(tmp_path):
    path = tmp_path / "headers.txt"
    path.write_text(
        "HTTP/1.1 200 OK\n"
        "X-Content-Type-Options: nosniff\n"
    )
    return str(path)


def test_cli_history_appends_offline_run(tmp_path):
    history = str(tmp_path / "history.jsonl")
    code = main(["--headers", _headers_file(tmp_path),
                 "--history", history, "--no-color"])
    assert code == 0
    entries, skipped = read_history(history)
    assert skipped == 0
    assert len(entries) == 1
    assert entries[0].url.endswith("headers.txt")
    assert entries[0].grade and isinstance(entries[0].score, int)


def test_cli_history_appends_on_json_run(tmp_path):
    history = str(tmp_path / "h.jsonl")
    code = main(["--headers", _headers_file(tmp_path),
                 "--history", history, "--json"])
    assert code == 0
    entries, _ = read_history(history)
    assert len(entries) == 1


def test_cli_history_unwritable_path_is_exit_2(tmp_path, capsys):
    code = main(["--headers", _headers_file(tmp_path),
                 "--history", str(tmp_path / "missing-dir" / "h.jsonl")])
    assert code == 2
    assert "cannot write history" in capsys.readouterr().err


def test_cli_history_report_prints_trend(tmp_path, capsys):
    history = str(tmp_path / "h.jsonl")
    append_run(history, "https://a.example", "C", 70)
    append_run(history, "https://a.example", "B", 85)
    code = main(["--history-report", history, "--no-color"])
    assert code == 0
    out = capsys.readouterr().out
    assert "2 run(s)" in out and "improving" in out


def test_cli_history_report_missing_file_is_exit_2(tmp_path, capsys):
    code = main(["--history-report", str(tmp_path / "nope.jsonl")])
    assert code == 2
    assert "cannot read history file" in capsys.readouterr().err


def test_cli_history_report_rejects_combos(tmp_path, capsys):
    code = main(["--history-report", str(tmp_path / "h.jsonl"),
                 "--history", str(tmp_path / "other.jsonl")])
    assert code == 2
    code = main(["--history-report", str(tmp_path / "h.jsonl"),
                 "https://example.com"])
    assert code == 2


def test_cli_history_rejected_in_bulk_compare_watch(tmp_path, capsys):
    code = main(["--bulk", _headers_file(tmp_path),
                 "--history", str(tmp_path / "h.jsonl")])
    assert code == 2
    code = main(["--compare", "https://a.example", "https://b.example",
                 "--history", str(tmp_path / "h.jsonl")])
    assert code == 2
    code = main(["--watch", "60", "--history", str(tmp_path / "h.jsonl"),
                 "https://a.example"])
    assert code == 2
    assert "--history" in capsys.readouterr().err
