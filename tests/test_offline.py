"""Tests for offline header parsing and fixture files."""

import pathlib

import pytest

from headerhawk.checks import analyze
from headerhawk.offline import load_headers, parse_raw_headers

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def test_parse_skips_status_line_and_blanks():
    headers = parse_raw_headers("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
    assert headers == {"content-type": ["text/html"]}


def test_parse_duplicate_headers_preserved():
    text = "Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n"
    headers = parse_raw_headers(text)
    assert headers["set-cookie"] == ["a=1", "b=2"]


def test_parse_is_case_insensitive():
    headers = parse_raw_headers("X-Frame-Options: DENY\nx-frame-options: SAMEORIGIN\n")
    assert headers["x-frame-options"] == ["DENY", "SAMEORIGIN"]


def test_parse_folded_continuation_line():
    text = "X-Long: part-one\r\n  part-two\r\n"
    headers = parse_raw_headers(text)
    assert headers["x-long"] == ["part-one part-two"]


def test_parse_empty_text_gives_empty_map():
    assert parse_raw_headers("") == {}


def test_secure_fixture_scores_a_plus():
    headers = load_headers(str(FIXTURES / "secure-headers.txt"))
    report = analyze(headers, scheme="https")
    assert report.grade == "A+"
    assert report.score == 100


def test_insecure_fixture_scores_f():
    headers = load_headers(str(FIXTURES / "insecure-headers.txt"))
    report = analyze(headers, scheme="https")
    assert report.grade == "F"
    # -15 HSTS, -20 CSP, -8 XCTO, -10 XFO, -5 referrer, -3 permissions,
    # -2 Server version, -2 X-Powered-By = -65
    assert report.score == 35


def test_load_headers_rejects_empty_file(tmp_path):
    empty = tmp_path / "empty.txt"
    empty.write_text("nothing useful here\n")
    with pytest.raises(ValueError):
        load_headers(str(empty))
