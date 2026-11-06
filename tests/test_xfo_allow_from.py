"""Tests for the X-Frame-Options ALLOW-FROM deprecation flag (LOW, -3)."""

from headerhawk.checks import analyze


def h(**kwargs):
    """Build a header map: NAME='value' -> {'name': ['value']}."""
    return {k.lower().replace("_", "-"): [v] for k, v in kwargs.items()}


def _xfo_findings(report):
    return [f for f in report.findings if f.check == "X-Frame-Options"]


def test_allow_from_flagged_low():
    headers = h(x_frame_options="ALLOW-FROM https://example.com")
    report = analyze(headers, scheme="https")
    findings = _xfo_findings(report)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "LOW"
    assert finding.score_delta == -3
    assert finding.status == "weak"
    assert "ALLOW-FROM" in finding.summary
    assert "obsolete" in finding.summary.lower()
    assert "frame-ancestors" in finding.fix


def test_allow_from_case_insensitive():
    headers = h(x_frame_options="allow-from https://example.com")
    report = analyze(headers, scheme="https")
    findings = _xfo_findings(report)
    assert len(findings) == 1
    assert findings[0].severity == "LOW"
    assert "ALLOW-FROM" in findings[0].summary


def test_allow_from_without_origin_flagged_too():
    headers = h(x_frame_options="ALLOW-FROM")
    report = analyze(headers, scheme="https")
    findings = _xfo_findings(report)
    assert len(findings) == 1
    assert findings[0].severity == "LOW"


def test_deny_and_sameorigin_still_pass():
    for value in ("DENY", "SAMEORIGIN", "deny"):
        report = analyze(h(x_frame_options=value), scheme="https")
        findings = _xfo_findings(report)
        assert len(findings) == 1
        assert findings[0].severity == "OK"
        assert findings[0].score_delta == 0


def test_other_nonstandard_value_keeps_generic_message():
    headers = h(x_frame_options="GARBAGE")
    report = analyze(headers, scheme="https")
    findings = _xfo_findings(report)
    assert len(findings) == 1
    assert findings[0].severity == "LOW"
    assert findings[0].score_delta == -3
    assert "non-standard value" in findings[0].summary


def test_allow_from_with_csp_frame_ancestors_stays_info():
    # CSP frame-ancestors supersedes X-Frame-Options entirely, so the
    # obsolete value is moot when a frame-ancestors policy is present.
    headers = h(
        x_frame_options="ALLOW-FROM https://example.com",
        content_security_policy="default-src 'self'; frame-ancestors 'self'",
    )
    report = analyze(headers, scheme="https")
    findings = _xfo_findings(report)
    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert findings[0].score_delta == 0
