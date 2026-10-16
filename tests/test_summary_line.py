"""Tests for --summary-line: one-line GRADE SCORE HOST output."""

import pytest

from headerhawk.checks import Report
from headerhawk.cli import main
from headerhawk.report import render_summary_line


def _report(**kw):
    base = dict(url="https://example.com/some/page", grade="B", score=84)
    base.update(kw)
    return Report(**base)


# --- renderer ---------------------------------------------------------------

def test_summary_line_format():
    assert render_summary_line(_report()) == "B 84 example.com\n"


def test_summary_line_prefers_final_url():
    report = _report(url="http://example.com",
                     final_url="https://www.example.com/")
    assert render_summary_line(report) == "B 84 www.example.com\n"


def test_summary_line_strips_port_and_userinfo():
    report = _report(url="https://example.com:8443/x")
    assert render_summary_line(report) == "B 84 example.com\n"


def test_summary_line_falls_back_to_raw_target():
    report = _report(url="<stdin>")
    assert render_summary_line(report) == "B 84 <stdin>\n"


# --- CLI ---------------------------------------------------------------------

def _headers_file(tmp_path):
    path = tmp_path / "headers.txt"
    path.write_text(
        "HTTP/1.1 200 OK\n"
        "Server: nginx/1.24.0\n"
    )
    return str(path)


def test_cli_summary_line_output(tmp_path, capsys):
    rc = main(["--headers", _headers_file(tmp_path), "--summary-line"])
    assert rc == 0
    out = capsys.readouterr().out
    parts = out.strip().split(" ", 2)
    assert len(parts) == 3
    grade, score, _target = parts
    assert grade in ("A+", "A", "B", "C", "D", "E", "F")
    assert score.isdigit()


def test_cli_summary_line_respects_fail_below(tmp_path, capsys):
    # nginx/1.24.0 alone grades F; the gate must trip.
    rc = main(["--headers", _headers_file(tmp_path), "--summary-line",
               "--fail-below", "A+"])
    assert rc == 1


def test_cli_summary_line_conflicts(tmp_path, capsys):
    headers = _headers_file(tmp_path)
    for extra in (["--json"], ["--raw"], ["--only", "HIGH"], ["--explain", "HIGH"]):
        rc = main(["--headers", headers, "--summary-line", *extra])
        assert rc == 2, extra
        assert "summary-line" in capsys.readouterr().err


def test_cli_summary_line_conflicts_with_modes(tmp_path, capsys):
    headers = _headers_file(tmp_path)
    rc = main(["--bulk", headers, "--summary-line"])
    assert rc == 2
    rc = main(["--compare", "https://a.example", "https://b.example",
               "--summary-line"])
    assert rc == 2
    rc = main(["https://example.com", "--watch", "60", "--summary-line"])
    assert rc == 2


def test_cli_summary_line_writes_to_output_file(tmp_path):
    out = tmp_path / "summary.txt"
    rc = main(["--headers", _headers_file(tmp_path), "--summary-line",
               "--output", str(out)])
    assert rc == 0
    assert out.read_text().strip().split(" ", 2)[1].isdigit()
