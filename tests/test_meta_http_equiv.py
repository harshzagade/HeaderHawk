"""Meta http-equiv fallback audit (--sri mode): parser + check wiring."""

from headerhawk.checks import analyze, check_meta_http_equiv
from headerhawk.sri import find_meta_http_equiv


def _meta_findings(report):
    return [f for f in report.findings if f.check == "Meta http-equiv"]


def test_parser_collects_tags_case_insensitively():
    html = ('<meta HTTP-EQUIV="Refresh" content="0; url=https://x.example/">'
            '<meta http-equiv="content-type" content="text/html">')
    tags = find_meta_http_equiv(html)
    assert [(t.name, t.content) for t in tags] == [
        ("refresh", "0; url=https://x.example/"),
        ("content-type", "text/html"),
    ]


def test_parser_ignores_meta_without_http_equiv():
    html = ('<meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width">')
    assert find_meta_http_equiv(html) == []


def test_check_silent_without_sri_html():
    # Headers-only analysis has no page HTML: the check opts out.
    assert check_meta_http_equiv(None) == []


def test_check_silent_without_meta_tags():
    assert check_meta_http_equiv(
        '<html><head><title>hi</title></head></html>') == []


def test_check_silent_for_non_security_tags():
    html = ('<meta http-equiv="content-type" content="text/html; charset=utf-8">'
            '<meta http-equiv="default-style" content="blue">')
    assert check_meta_http_equiv(html) == []


def test_meta_csp_flagged_as_info():
    findings = check_meta_http_equiv(
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src \'self\'">')
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "INFO"
    assert finding.score_delta == 0
    assert "frame-ancestors" in finding.detail
    assert "response header" in finding.fix


def test_meta_refresh_redirect_flagged():
    findings = check_meta_http_equiv(
        '<meta http-equiv="refresh" content="0; URL=https://b.example/">')
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "INFO"
    assert finding.score_delta == 0
    assert "redirect" in finding.summary.lower()
    assert "3xx" in finding.fix


def test_meta_refresh_pure_delay_is_silent():
    # An auto-reload with no URL is not a redirect: nothing to flag.
    assert check_meta_http_equiv(
        '<meta http-equiv="refresh" content="30">') == []


def test_meta_x_ua_compatible_flagged():
    findings = check_meta_http_equiv(
        '<meta http-equiv="X-UA-Compatible" content="IE=edge">')
    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert findings[0].score_delta == 0
    assert "Internet Explorer" in findings[0].detail


def test_meta_set_cookie_flagged():
    findings = check_meta_http_equiv(
        '<meta http-equiv="set-cookie" content="session=abc; HttpOnly">')
    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert findings[0].score_delta == 0
    assert "no cookie is actually set" in findings[0].detail


def test_multiple_tags_yield_one_finding_each():
    html = ('<meta http-equiv="refresh" content="0;url=https://b.example/">'
            '<meta http-equiv="x-ua-compatible" content="IE=edge">'
            '<meta http-equiv="set-cookie" content="a=b">')
    findings = check_meta_http_equiv(html)
    assert len(findings) == 3


def test_wired_into_analyze_and_costs_nothing():
    html = ('<html><head>'
            '<meta http-equiv="x-ua-compatible" content="IE=edge">'
            '</head></html>')
    report = analyze({}, scheme="https",
                     meta={"sri_html": html, "sri_seen": 0})
    findings = _meta_findings(report)
    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert findings[0].score_delta == 0
    # Sanity: this note must never move the grade by itself.
    assert all(f.score_delta == 0 for f in findings)


def test_wired_into_analyze_silent_without_sri():
    report = analyze({}, scheme="https")
    assert _meta_findings(report) == []
