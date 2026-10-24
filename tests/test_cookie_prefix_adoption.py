"""Unit tests for the cookie-prefix adoption note (INFO, HTTPS only)."""

from headerhawk.checks import check_cookie_prefix_adoption


def _findings(*values, scheme="https"):
    return check_cookie_prefix_adoption({"set-cookie": list(values)},
                                        scheme=scheme)


def test_no_cookies_no_findings():
    assert check_cookie_prefix_adoption({}, scheme="https") == []


def test_plain_http_targets_are_out_of_scope():
    findings = _findings("sessionid=abc; Secure; HttpOnly", scheme="http")
    assert findings == []


def test_non_session_cookies_are_silent():
    findings = _findings("theme=dark; Path=/", "prefs=1; Secure")
    assert findings == []


def test_already_prefixed_cookies_are_handled_elsewhere():
    findings = _findings("__Host-sid=1; Secure; Path=/",
                         "__Secure-token=2; Secure")
    assert findings == []


def test_sessionish_cookie_gets_info_nudge():
    (f,) = _findings("sessionid=abc; Secure; HttpOnly; SameSite=Lax")
    assert f.severity == "INFO" and f.status == "info" and f.score_delta == 0
    assert "sessionid" in f.summary
    assert "__Host-" in f.summary
    assert f.check == "Cookie name prefixes"
    assert f.fix


def test_token_style_names_match_case_insensitively():
    for name in ("AuthToken=1; Secure", "AUTH_TOKEN=1; Secure",
                 "app_session=1; Secure", "jwt=1; Secure",
                 "remember_me=1; Secure"):
        findings = _findings(name)
        assert len(findings) == 1, name


def test_close_but_non_session_names_do_not_match():
    # "authentication" is not a token-split of the name, so it stays silent
    # unless an exact/token match exists.
    findings = _findings("authentication=1; Secure")
    assert findings == []


def test_multiple_session_cookies_each_get_a_nudge():
    findings = _findings("sessionid=a; Secure", "csrf_token=b; Secure",
                         "theme=dark")
    assert len(findings) == 2
    names = [f.summary for f in findings]
    assert any("sessionid" in s for s in names)
    assert any("csrf_token" in s for s in names)
