"""Tests for the CSP ``upgrade-insecure-requests`` missing-directive note.

On HTTPS targets with an enforcing CSP, a missing
``upgrade-insecure-requests`` directive is an INFO hardening note: it is
the one-line fix that auto-upgrades ``http://`` subresources so
mixed-content stragglers stop being blocked or downgraded. No CSP at all
is owned by the missing-policy HIGH finding, and plain-HTTP targets have
nothing to upgrade to.
"""

from headerhawk.checks import analyze


def _upgrade_findings(headers, scheme="https"):
    report = analyze(headers, scheme=scheme)
    return [f for f in report.findings
            if "upgrade-insecure-requests" in f.summary]


def test_missing_directive_on_https_is_info():
    findings = _upgrade_findings({
        "content-security-policy": ["default-src 'self'"],
    })
    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert findings[0].score_delta == 0
    assert findings[0].check == "Content-Security-Policy"
    assert "Add upgrade-insecure-requests" in findings[0].fix


def test_directive_present_is_silent():
    findings = _upgrade_findings({
        "content-security-policy": [
            "default-src 'self'; upgrade-insecure-requests"],
    })
    assert findings == []


def test_no_csp_is_silent():
    findings = _upgrade_findings({"server": ["nginx"]})
    assert findings == []


def test_http_scheme_is_silent():
    findings = _upgrade_findings({
        "content-security-policy": ["default-src 'self'"],
    }, scheme="http")
    assert findings == []


def test_report_only_only_is_silent():
    findings = _upgrade_findings({
        "content-security-policy-report-only": ["default-src 'self'"],
    })
    assert findings == []


def test_directive_present_among_other_directives_is_silent():
    findings = _upgrade_findings({
        "content-security-policy": [
            "default-src 'self'; script-src 'self'; "
            "upgrade-insecure-requests; object-src 'none'"],
    })
    assert findings == []
