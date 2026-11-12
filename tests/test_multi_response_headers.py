"""Multi-response header dump tests: `curl -i` on a redirecting URL."""

import pathlib

import pytest

from headerhawk.checks import analyze
from headerhawk.offline import load_headers, parse_raw_headers

FIXTURES = pathlib.Path(__file__).parent / "fixtures"

# A curl -i dump of a redirecting URL: 301 hop, then the final 200.
# Note the 301 block sets a different X-Frame-Options and the 200's body
# contains colon lines that must never be read as headers.
REDIRECT_DUMP = (
    "HTTP/1.1 301 Moved Permanently\r\n"
    "Location: https://example.com/final\r\n"
    "X-Frame-Options: SAMEORIGIN\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "X-Frame-Options: DENY\r\n"
    "Strict-Transport-Security: max-age=63072000\r\n"
    "\r\n"
    "<html><body>{\"key\": \"value\"}\n"
    "Host: example.com\n"
)


def test_last_response_block_wins():
    headers = parse_raw_headers(REDIRECT_DUMP)
    assert headers["x-frame-options"] == ["DENY"]
    assert headers["strict-transport-security"] == ["max-age=63072000"]
    assert "location" not in headers
    assert "content-type" in headers


def test_body_lines_are_never_parsed_as_headers():
    headers = parse_raw_headers(REDIRECT_DUMP)
    # "Host: example.com" and '{"key": "value"}' live in the body, not headers.
    assert "host" not in headers
    assert '{"key"' not in headers


def test_three_blocks_take_the_final_one():
    dump = (
        "HTTP/1.1 301 Moved Permanently\r\nX-Frame-Options: DENY\r\n\r\n"
        "HTTP/1.1 302 Found\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n"
        "HTTP/2 200\r\nX-Frame-Options: DENY\r\n"
        "Content-Security-Policy: default-src 'self'\r\n\r\n"
        "<body>text</body>\n"
    )
    headers = parse_raw_headers(dump)
    assert headers["x-frame-options"] == ["DENY"]
    assert headers["content-security-policy"] == ["default-src 'self'"]


def test_single_block_dump_unchanged():
    headers = parse_raw_headers(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
    assert headers == {"content-type": ["text/html"]}


def test_header_only_dump_without_status_line_unchanged():
    text = "X-Frame-Options: DENY\n\nStrict-Transport-Security: max-age=1\n"
    headers = parse_raw_headers(text)
    assert headers == {"x-frame-options": ["DENY"],
                       "strict-transport-security": ["max-age=1"]}


def test_folded_lines_still_work_in_last_block():
    dump = ("HTTP/1.1 301 Moved Permanently\r\nX-Frame-Options: DENY\r\n\r\n"
            "HTTP/1.1 200 OK\r\nX-Long: part-one\r\n  part-two\r\n\r\n")
    assert parse_raw_headers(dump) == {"x-long": ["part-one part-two"]}


def test_status_line_only_dump_still_errors(tmp_path):
    path = tmp_path / "headers.txt"
    path.write_text("HTTP/1.1 301 Moved Permanently\r\n\r\n")
    with pytest.raises(ValueError):
        load_headers(str(path))


def test_redirect_dump_analyzes_final_response(tmp_path):
    path = tmp_path / "headers.txt"
    path.write_text(REDIRECT_DUMP)
    headers = load_headers(str(path))
    report = analyze(headers, scheme="https")
    # DENY from the final block: no X-Frame-Options finding; the 301's
    # SAMEORIGIN must not leak into the audit.
    assert not [f for f in report.findings
                if f.check == "X-Frame-Options"
                and f.severity not in ("OK", "INFO")]
