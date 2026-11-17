"""Tests for the ``Vary: *`` cache-busting note.

``Vary: *`` tells shared caches the response varies on headers they cannot
enumerate, so the response is effectively uncacheable. On its own that is
an INFO note; when the response also sets cookies it is a LOW finding —
every request is a fresh origin hit carrying Set-Cookie.
"""

from headerhawk.checks import analyze


def _vary_findings(headers, scheme="https"):
    report = analyze(headers, scheme=scheme)
    return [f for f in report.findings if f.check == "Vary"]


def test_vary_star_alone_is_info():
    findings = _vary_findings({"vary": ["*"]})
    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert findings[0].score_delta == 0
    assert "uncacheable" in findings[0].summary
    assert "Accept-Encoding" in findings[0].fix


def test_vary_star_with_cookie_is_low():
    findings = _vary_findings({
        "vary": ["*"],
        "set-cookie": ["session=abc; Secure; HttpOnly; SameSite=Lax"],
    })
    assert len(findings) == 1
    assert findings[0].severity == "LOW"
    assert findings[0].score_delta == -2
    assert "Set-Cookie" in findings[0].summary or "cookies" in findings[0].summary


def test_multiple_cookies_still_one_finding():
    findings = _vary_findings({
        "vary": ["Accept-Encoding, *"],
        "set-cookie": [
            "a=1; Secure; HttpOnly; SameSite=Lax",
            "b=2; Secure; HttpOnly; SameSite=Lax",
        ],
    })
    assert len(findings) == 1
    assert findings[0].severity == "LOW"
    assert "2 cookies" in findings[0].detail


def test_token_parsing_is_case_insensitive_and_space_tolerant():
    findings = _vary_findings({"vary": [" * , Accept-Encoding "]})
    assert len(findings) == 1
    assert findings[0].severity == "INFO"


def test_named_vary_values_are_silent():
    findings = _vary_findings({"vary": ["Accept-Encoding", "User-Agent"]})
    assert findings == []


def test_no_vary_is_silent():
    findings = _vary_findings({"content-type": ["text/html"]})
    assert findings == []


def test_vary_star_fires_on_http_too():
    findings = _vary_findings({"vary": ["*"]}, scheme="http")
    assert len(findings) == 1
    assert findings[0].severity == "INFO"


def test_score_drops_by_two_with_cookies():
    headers = {
        "vary": ["*"],
        "set-cookie": ["session=abc; Secure; HttpOnly; SameSite=Lax"],
    }
    with_star = analyze(headers, scheme="https").score
    without_star = analyze(
        {"set-cookie": ["session=abc; Secure; HttpOnly; SameSite=Lax"]},
        scheme="https").score
    assert with_star == without_star - 2
