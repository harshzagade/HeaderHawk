"""Tests for --explain SEV: plain-English single-severity reports."""

import pytest

from headerhawk.checks import analyze
from headerhawk.cli import _parse_explain, main
from headerhawk.report import render_explain


def _headers_file(tmp_path):
    path = tmp_path / "headers.txt"
    path.write_text(
        "HTTP/1.1 200 OK\n"
        "Server: nginx/1.24.0\n"
        "X-Powered-By: PHP/8.1.2\n"
    )
    return str(path)


def _insecure_report():
    return analyze(
        {"server": ["nginx/1.24.0"], "x-powered-by": ["PHP/8.1.2"]},
        scheme="https",
        meta={"url": "https://example.com"},
    )


# --- parsing -------------------------------------------------------------

def test_parse_explain_accepts_single_severity_case_insensitive():
    assert _parse_explain("high") == "HIGH"
    assert _parse_explain(" OK ") == "OK"


def test_parse_explain_rejects_unknown():
    with pytest.raises(ValueError, match="unknown severity"):
        _parse_explain("CRITICAL")


def test_parse_explain_rejects_comma_list():
    with pytest.raises(ValueError, match="single severity"):
        _parse_explain("HIGH,MED")


def test_parse_explain_none_passthrough():
    assert _parse_explain(None) is None


# --- rendering -----------------------------------------------------------

def test_explain_shows_only_requested_severity():
    report = _insecure_report()
    out = render_explain(report, "HIGH", color=False)
    assert "Content-Security-Policy" in out
    assert "Strict-Transport-Security" in out
    # LOW severity findings (Server version disclosure) must be hidden.
    assert "Information disclosure" not in out
    # Grade/score still shown for context.
    assert f"grade {report.grade}" in out
    assert f"score {report.score}/100" in out


def test_explain_labels_meaning_and_action():
    out = render_explain(_insecure_report(), "HIGH", color=False)
    assert "What it means:" in out
    assert "What to do:" in out


def test_explain_closes_with_one_summary_paragraph():
    out = render_explain(_insecure_report(), "HIGH", color=False)
    assert "In plain English:" in out
    assert "high-severity" in out
    assert "web server" in out


def test_explain_no_findings_is_good_news():
    report = analyze({}, scheme="https", meta={"url": "https://example.com"})
    assert not any(f.severity == "OK" for f in report.findings)
    out = render_explain(report, "OK", color=False)
    assert "Good news: no OK findings" in out


def test_explain_ok_severity_needs_no_action():
    from headerhawk.checks import Finding, Report
    report = Report(
        url="https://example.com",
        score=100, grade="A+",
        findings=[Finding(check="X-Content-Type-Options",
                          header="X-Content-Type-Options",
                          status="pass", severity="OK", score_delta=0,
                          summary="X-Content-Type-Options: nosniff is set.")],
    )
    out = render_explain(report, "OK", color=False)
    assert "no action needed" in out


def test_explain_skips_empty_detail_and_fix_lines():
    from headerhawk.checks import Finding, Report
    report = Report(
        url="https://example.com",
        score=100, grade="A+",
        findings=[Finding(check="X-Frame-Options", header="X-Frame-Options",
                          status="pass", severity="OK", score_delta=0,
                          summary="set.")],
    )
    out = render_explain(report, "OK", color=False)
    assert "What it means:" not in out
    assert "What to do:" not in out


# --- CLI -----------------------------------------------------------------

def test_cli_explain_high(tmp_path, capsys):
    code = main(["--headers", _headers_file(tmp_path), "--no-color",
                 "--explain", "HIGH"])
    assert code == 0
    out = capsys.readouterr().out
    assert "in plain English" in out
    assert "Content-Security-Policy" in out
    assert "Information disclosure" not in out  # LOW, hidden


def test_cli_explain_unknown_severity_is_error(tmp_path, capsys):
    code = main(["--headers", _headers_file(tmp_path), "--explain",
                 "CRITICAL"])
    assert code == 2


def test_cli_explain_rejects_only_combo(tmp_path, capsys):
    code = main(["--headers", _headers_file(tmp_path), "--explain", "HIGH",
                 "--only", "HIGH"])
    assert code == 2


def test_cli_explain_rejects_json_combo(tmp_path, capsys):
    code = main(["--headers", _headers_file(tmp_path), "--explain", "HIGH",
                 "--json"])
    assert code == 2


def test_cli_explain_rejects_watch_combo(capsys):
    code = main(["https://example.com", "--watch", "60", "--explain",
                 "HIGH"])
    assert code == 2


def test_cli_explain_no_findings(tmp_path, capsys):
    # The insecure fixture has no OK findings at all.
    code = main(["--headers", _headers_file(tmp_path), "--no-color",
                 "--explain", "OK"])
    assert code == 0
    out = capsys.readouterr().out
    assert "Good news: no OK findings" in out
