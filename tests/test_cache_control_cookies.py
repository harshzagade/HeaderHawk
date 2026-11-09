"""Tests for the Cache-Control: public + Set-Cookie clash check.

A ``public`` directive tells shared caches the response may be stored and
served to other users. Combined with Set-Cookie, the cached copy can carry
one user's session cookie to the next user, so the combination is a MED
finding. ``public`` on a cookie-free response (static assets) is fine, and
a cookie-setting response without ``public`` is fine too.
"""

from headerhawk.checks import analyze


def _cc_findings(headers):
    report = analyze(headers, scheme="https")
    return [f for f in report.findings if f.check == "Cache-Control"]


def test_public_with_cookie_is_med():
    findings = _cc_findings({
        "cache-control": ["public, max-age=3600"],
        "set-cookie": ["session=abc; Secure; HttpOnly; SameSite=Lax"],
    })
    assert len(findings) == 1
    assert findings[0].severity == "MED"
    assert findings[0].score_delta == -5
    assert "public" in findings[0].summary
    assert "private" in findings[0].fix


def test_public_without_cookies_is_silent():
    findings = _cc_findings({"cache-control": ["public, max-age=86400"]})
    assert findings == []


def test_cookies_without_public_is_silent():
    findings = _cc_findings({
        "cache-control": ["private, max-age=3600"],
        "set-cookie": ["session=abc; Secure; HttpOnly; SameSite=Lax"],
    })
    assert findings == []


def test_no_cache_control_with_cookies_is_silent():
    findings = _cc_findings({
        "set-cookie": ["session=abc; Secure; HttpOnly; SameSite=Lax"],
    })
    assert findings == []


def test_multiple_cookies_still_one_finding():
    findings = _cc_findings({
        "cache-control": ["public"],
        "set-cookie": [
            "a=1; Secure; HttpOnly; SameSite=Lax",
            "b=2; Secure; HttpOnly; SameSite=Lax",
            "c=3; Secure; HttpOnly; SameSite=Lax",
        ],
    })
    assert len(findings) == 1
    assert "3 cookies" in findings[0].detail


def test_directive_parsing_is_case_insensitive_and_param_tolerant():
    findings = _cc_findings({
        "cache-control": ["MAX-AGE=60, PUBLIC"],
        "set-cookie": ["session=abc; Secure; HttpOnly; SameSite=Lax"],
    })
    assert len(findings) == 1
    assert findings[0].severity == "MED"


def test_no_store_with_cookies_is_silent():
    findings = _cc_findings({
        "cache-control": ["no-store"],
        "set-cookie": ["session=abc; Secure; HttpOnly; SameSite=Lax"],
    })
    assert findings == []


def test_score_drops_by_five():
    headers = {
        "cache-control": ["public"],
        "set-cookie": ["session=abc; Secure; HttpOnly; SameSite=Lax"],
    }
    with_clash = analyze(headers, scheme="https").score
    without_clash = analyze(
        {"set-cookie": ["session=abc; Secure; HttpOnly; SameSite=Lax"]},
        scheme="https").score
    assert with_clash == without_clash - 5
