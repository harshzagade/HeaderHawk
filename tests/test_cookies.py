"""Unit tests for the Set-Cookie flag audit (Secure/HttpOnly/SameSite)."""

from headerhawk.checks import analyze, check_cookies
from headerhawk.report import render_text


def _cookie_findings(*values):
    return check_cookies({"set-cookie": list(values)})


def test_no_cookies_nothing_to_audit():
    assert check_cookies({}) == []
    assert check_cookies({"content-type": ["text/html"]}) == []


def test_fully_flagged_cookie_is_ok_pass():
    findings = _cookie_findings("sessionid=abc; Secure; HttpOnly; SameSite=Lax")
    assert len(findings) == 1
    f = findings[0]
    assert f.status == "pass" and f.severity == "OK" and f.score_delta == 0
    assert "sessionid" in f.summary


def test_strict_samesite_is_ok_pass():
    (f,) = _cookie_findings("sid=1; Secure; HttpOnly; SameSite=Strict")
    assert f.severity == "OK"


def test_missing_secure_is_med():
    (f,) = _cookie_findings("sessionid=abc; HttpOnly; SameSite=Lax")
    assert f.severity == "MED" and f.score_delta == -5
    assert "Secure" in f.summary
    assert f.fix


def test_missing_httponly_is_med():
    (f,) = _cookie_findings("sessionid=abc; Secure; SameSite=Lax")
    assert f.severity == "MED" and f.score_delta == -3
    assert "HttpOnly" in f.summary


def test_missing_samesite_is_low():
    (f,) = _cookie_findings("sessionid=abc; Secure; HttpOnly")
    assert f.severity == "LOW" and f.score_delta == -2
    assert "SameSite" in f.summary


def test_samesite_none_without_secure_is_med():
    (f,) = [f for f in _cookie_findings("emb=1; SameSite=None; HttpOnly")
            if "SameSite=None" in f.summary]
    assert f.severity == "MED" and f.score_delta == -5
    assert "reject" in f.summary


def test_samesite_none_with_secure_is_low():
    (f,) = [f for f in _cookie_findings("emb=1; Secure; SameSite=None; HttpOnly")
            if "SameSite=None" in f.summary]
    assert f.severity == "LOW" and f.score_delta == -2


def test_unrecognized_samesite_value_is_low():
    (f,) = [f for f in _cookie_findings("sid=1; Secure; HttpOnly; SameSite=Maybe")
            if "SameSite" in f.summary]
    assert f.severity == "LOW" and f.score_delta == -2
    assert "Maybe" in f.summary


def test_attribute_matching_is_case_insensitive():
    (f,) = _cookie_findings("sid=1; SECURE; HTTPONLY; SAMESITE=Strict")
    assert f.severity == "OK"


def test_samesite_matching_is_case_insensitive():
    (f,) = _cookie_findings("sid=1; Secure; HttpOnly; samesite=lax")
    assert f.severity == "OK"


def test_cookies_audited_independently():
    findings = _cookie_findings("good=1; Secure; HttpOnly; SameSite=Lax",
                                "bad=2")
    by_cookie = {}
    for f in findings:
        by_cookie.setdefault("good" in f.summary, []).append(f)
    assert len(by_cookie[True]) == 1 and by_cookie[True][0].severity == "OK"
    bad = by_cookie[False]
    assert {f.severity for f in bad} == {"MED", "MED", "LOW"}


def test_analyze_wires_cookie_audit_and_count():
    report = analyze(
        {"set-cookie": ["a=1", "b=2; Secure; HttpOnly; SameSite=Strict"]},
        scheme="https",
        meta={"url": "https://example.com"},
    )
    assert report.cookies_seen == 2
    cookie_findings = [f for f in report.findings if f.check == "Cookie flags"]
    assert len(cookie_findings) == 4  # 3 issues for a=1 + 1 OK pass for b=2
    assert (sorted(f.score_delta for f in cookie_findings)
            == [-5, -3, -2, 0])
    payload = report.to_dict()
    assert payload["cookies_seen"] == 2


def test_no_cookies_seen_count_is_zero():
    report = analyze({}, scheme="https")
    assert report.cookies_seen == 0


def test_footer_summarizes_cookie_audit():
    report = analyze({"set-cookie": ["a=1"]}, scheme="https",
                     meta={"url": "https://example.com"})
    out = render_text(report, color=False)
    assert "audited cookie flags on 1 cookie (3 issues above)" in out


def test_footer_when_no_cookies():
    report = analyze({}, scheme="https", meta={"url": "https://example.com"})
    out = render_text(report, color=False)
    assert "No Set-Cookie headers seen; cookie flags not applicable" in out
