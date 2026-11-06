"""Tests for the Expect-CT deprecation note (INFO, never graded)."""

from headerhawk.checks import analyze


def h(**kwargs):
    """Build a header map: NAME='value' -> {'name': ['value']}."""
    return {k.lower().replace("_", "-"): [v] for k, v in kwargs.items()}


def _expect_ct_findings(report):
    return [f for f in report.findings if f.check == "Expect-CT"]


def test_expect_ct_present_is_info_note():
    headers = h(expect_ct="max-age=86400, enforce")
    report = analyze(headers, scheme="https")
    findings = _expect_ct_findings(report)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "INFO"
    assert finding.score_delta == 0
    assert finding.status == "info"
    assert "obsolete" in finding.summary.lower()
    assert "Remove" in finding.fix


def test_expect_ct_present_without_enforce_flagged_too():
    headers = h(expect_ct="max-age=86400")
    report = analyze(headers, scheme="https")
    assert len(_expect_ct_findings(report)) == 1


def test_expect_ct_absent_is_silent():
    report = analyze({}, scheme="https")
    assert _expect_ct_findings(report) == []


def test_expect_ct_costs_no_points():
    # A fully secure header set stays A+ / 100 with Expect-CT present:
    # the note is informational, never a penalty.
    headers = h(
        strict_transport_security="max-age=63072000; includeSubDomains; preload",
        content_security_policy=("default-src 'self'; script-src 'self'; "
                                 "object-src 'none'; base-uri 'self'; frame-ancestors 'self'"),
        x_content_type_options="nosniff",
        x_frame_options="DENY",
        referrer_policy="strict-origin-when-cross-origin",
        permissions_policy="camera=(), microphone=(), geolocation=()",
        cross_origin_opener_policy="same-origin",
        cross_origin_embedder_policy="require-corp",
        cross_origin_resource_policy="same-site",
        content_type="text/html",
        expect_ct="max-age=86400",
    )
    report = analyze(headers, scheme="https")
    assert report.score == 100
    assert report.grade == "A+"
    assert len(_expect_ct_findings(report)) == 1
