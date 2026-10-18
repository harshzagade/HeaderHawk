"""Unit tests for the __Secure- / __Host- cookie-name prefix audit."""

from headerhawk.checks import analyze, check_cookie_prefixes


def _prefix_findings(*values):
    return check_cookie_prefixes({"set-cookie": list(values)})


def test_no_cookies_no_findings():
    assert check_cookie_prefixes({}) == []


def test_plain_cookies_not_prefixed():
    findings = _prefix_findings("sessionid=abc; Secure; HttpOnly; SameSite=Lax")
    assert findings == []


def test_secure_prefix_fully_compliant_is_ok_pass():
    (f,) = _prefix_findings("__Secure-sid=1; Secure; HttpOnly")
    assert f.status == "pass" and f.severity == "OK" and f.score_delta == 0
    assert "__Secure-" in f.summary


def test_secure_prefix_missing_secure_is_med():
    (f,) = _prefix_findings("__Secure-sid=1; HttpOnly; SameSite=Lax")
    assert f.severity == "MED" and f.score_delta == -5
    assert "Secure" in f.summary
    assert f.fix


def test_secure_prefix_match_is_case_insensitive():
    (f,) = _prefix_findings("__SECURE-sid=1; HttpOnly")
    assert f.severity == "MED"
    assert "__Secure-" in f.summary or "__SECURE" in f.summary


def test_host_prefix_fully_compliant_is_ok_pass():
    (f,) = _prefix_findings("__Host-sid=1; Secure; Path=/")
    assert f.status == "pass" and f.severity == "OK" and f.score_delta == 0
    assert "__Host-" in f.summary


def test_host_prefix_match_is_case_insensitive():
    (f,) = _prefix_findings("__HOST-sid=1; Secure; Path=/")
    assert f.severity == "OK"


def test_host_prefix_missing_secure_is_high():
    (f,) = _prefix_findings("__Host-sid=1; Path=/; HttpOnly")
    assert f.severity == "HIGH" and f.score_delta == -10
    assert "Secure" in f.summary


def test_host_prefix_with_domain_is_high():
    (f,) = _prefix_findings("__Host-sid=1; Secure; Path=/; Domain=example.com")
    assert f.severity == "HIGH" and f.score_delta == -10
    assert "Domain" in f.summary


def test_host_prefix_wrong_path_is_high():
    (f,) = _prefix_findings("__Host-sid=1; Secure; Path=/app")
    assert f.severity == "HIGH" and f.score_delta == -10
    assert "Path=/" in f.summary


def test_host_prefix_missing_path_is_high():
    (f,) = _prefix_findings("__Host-sid=1; Secure")
    assert f.severity == "HIGH"
    assert "Path=/" in f.summary


def test_host_prefix_multiple_violations_each_flagged():
    findings = _prefix_findings("__Host-sid=1; Path=/app; Domain=example.com")
    assert len(findings) == 3
    assert all(f.severity == "HIGH" and f.score_delta == -10
               for f in findings)


def test_near_prefix_names_are_ignored():
    # "__Hostx" is not the "__Host-" prefix (dash matters).
    assert _prefix_findings("__Hostx=1; HttpOnly") == []
    assert _prefix_findings("__Securex=1; HttpOnly") == []


def test_compliant_prefixed_cookie_yields_no_flag_findings_too():
    # A fully compliant prefixed cookie gets two OK passes (flags + prefix),
    # and no negative deltas anywhere.
    report = analyze(
        {"set-cookie": ["__Host-sid=1; Secure; HttpOnly; SameSite=Lax; Path=/"]},
        scheme="https",
        meta={"url": "https://example.com"},
    )
    prefix = [f for f in report.findings if f.check == "Cookie name prefixes"]
    assert len(prefix) == 1 and prefix[0].severity == "OK"
    cookie_flags = [f for f in report.findings if f.check == "Cookie flags"]
    assert len(cookie_flags) == 1 and cookie_flags[0].severity == "OK"
    assert all(f.score_delta == 0
               for f in prefix + cookie_flags)


def test_analyze_wires_prefix_audit_and_scoring():
    report = analyze(
        {"set-cookie": ["__Secure-sid=1; HttpOnly"]},
        scheme="https",
        meta={"url": "https://example.com"},
    )
    prefix = [f for f in report.findings if f.check == "Cookie name prefixes"]
    assert len(prefix) == 1
    assert prefix[0].severity == "MED" and prefix[0].score_delta == -5
