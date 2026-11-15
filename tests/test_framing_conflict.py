"""Tests for the CSP/XFO framing-conflict check (LOW, -2).

Browsers honor CSP frame-ancestors and silently ignore X-Frame-Options
when both are present, so a DENY next to frame-ancestors 'self' (or a
SAMEORIGIN next to a named host) is dead config that misleads readers.
"""

from headerhawk.checks import analyze


def h(**kwargs):
    """Build a header map: NAME='value' -> {'name': ['value']}."""
    return {k.lower().replace("_", "-"): [v] for k, v in kwargs.items()}


def _conflicts(report):
    return [f for f in report.findings
            if f.check == "X-Frame-Options" and f.severity == "LOW"
            and "conflict" in f.summary.lower()]


def test_deny_with_frame_ancestors_none_is_agreement():
    headers = h(x_frame_options="DENY",
                content_security_policy="frame-ancestors 'none'")
    report = analyze(headers, scheme="https")
    assert _conflicts(report) == []


def test_deny_with_frame_ancestors_self_conflicts():
    headers = h(x_frame_options="DENY",
                content_security_policy="frame-ancestors 'self'")
    report = analyze(headers, scheme="https")
    conflicts = _conflicts(report)
    assert len(conflicts) == 1
    assert conflicts[0].score_delta == -2
    assert conflicts[0].status == "weak"
    assert "DENY" in conflicts[0].summary
    assert "'self'" in conflicts[0].summary
    assert "frame-ancestors" in conflicts[0].fix


def test_deny_with_frame_ancestors_star_conflicts():
    headers = h(x_frame_options="DENY",
                content_security_policy="frame-ancestors *")
    report = analyze(headers, scheme="https")
    assert len(_conflicts(report)) == 1


def test_sameorigin_with_frame_ancestors_self_is_agreement():
    headers = h(x_frame_options="SAMEORIGIN",
                content_security_policy="frame-ancestors 'self'")
    report = analyze(headers, scheme="https")
    assert _conflicts(report) == []


def test_sameorigin_with_frame_ancestors_none_is_stricter_not_conflict():
    headers = h(x_frame_options="SAMEORIGIN",
                content_security_policy="frame-ancestors 'none'")
    report = analyze(headers, scheme="https")
    assert _conflicts(report) == []


def test_sameorigin_with_frame_ancestors_host_conflicts():
    headers = h(x_frame_options="SAMEORIGIN",
                content_security_policy="frame-ancestors https://example.com")
    report = analyze(headers, scheme="https")
    conflicts = _conflicts(report)
    assert len(conflicts) == 1
    assert conflicts[0].score_delta == -2
    assert "SAMEORIGIN" in conflicts[0].summary
    assert "https://example.com" in conflicts[0].summary


def test_sameorigin_with_self_plus_host_conflicts():
    headers = h(x_frame_options="SAMEORIGIN",
                content_security_policy="frame-ancestors 'self' https://example.com")
    report = analyze(headers, scheme="https")
    assert len(_conflicts(report)) == 1


def test_missing_xfo_with_frame_ancestors_is_silent():
    headers = h(content_security_policy="frame-ancestors 'self'")
    report = analyze(headers, scheme="https")
    assert _conflicts(report) == []


def test_allow_from_with_frame_ancestors_has_no_conflict_finding():
    # The obsolete ALLOW-FROM value is already covered by the XFO check
    # (which returns INFO once frame-ancestors is present); the conflict
    # check skips non-standard XFO values entirely.
    headers = h(x_frame_options="ALLOW-FROM https://example.com",
                content_security_policy="frame-ancestors 'self'")
    report = analyze(headers, scheme="https")
    assert _conflicts(report) == []


def test_no_frame_ancestors_is_silent():
    headers = h(x_frame_options="DENY",
                content_security_policy="default-src 'self'")
    report = analyze(headers, scheme="https")
    assert _conflicts(report) == []


def test_duplicate_xfo_values_are_the_duplicate_checks_case():
    # Two XFO values make the effective value ambiguous (browsers differ
    # on first vs last), so the conflict check stays silent and leaves
    # the duplicate finding to speak.
    headers = h(content_security_policy="frame-ancestors 'self'")
    headers["x-frame-options"] = ["DENY", "SAMEORIGIN"]
    report = analyze(headers, scheme="https")
    assert _conflicts(report) == []
