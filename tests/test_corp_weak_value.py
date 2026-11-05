"""Cross-Origin-Resource-Policy weak-value findings."""

from headerhawk.checks import analyze


def h(**kwargs):
    """Build a header map: NAME='value' -> {'name': ['value']}."""
    return {k.lower().replace("_", "-"): [v] for k, v in kwargs.items()}


def _corp_findings(value):
    report = analyze(h(cross_origin_resource_policy=value), scheme="https")
    return [f for f in report.findings
            if f.check == "Cross-Origin-Resource-Policy"]


def test_corp_cross_origin_is_low():
    findings = _corp_findings("cross-origin")
    assert len(findings) == 1
    assert findings[0].severity == "LOW"
    assert findings[0].score_delta == -2
    assert findings[0].status == "weak"
    assert "any origin" in findings[0].summary
    assert findings[0].fix == "Cross-Origin-Resource-Policy: same-site"


def test_corp_cross_origin_case_insensitive():
    findings = _corp_findings("Cross-Origin")
    assert len(findings) == 1
    assert findings[0].severity == "LOW"


def test_corp_unrecognized_value_is_low():
    findings = _corp_findings("bogus-value")
    assert len(findings) == 1
    assert findings[0].severity == "LOW"
    assert findings[0].score_delta == -2
    assert "unrecognized" in findings[0].summary


def test_corp_strong_values_stay_silent():
    for value in ("same-site", "same-origin", " SAME-SITE "):
        assert _corp_findings(value) == []


def test_corp_cross_origin_costs_two_points():
    report = analyze(h(
        strict_transport_security="max-age=63072000; includeSubDomains; preload",
        content_security_policy=("default-src 'self'; script-src 'self'; "
                                 "object-src 'none'; base-uri 'self'; "
                                 "frame-ancestors 'self'"),
        x_content_type_options="nosniff",
        x_frame_options="DENY",
        referrer_policy="strict-origin-when-cross-origin",
        permissions_policy="camera=(), microphone=(), geolocation=()",
        cross_origin_opener_policy="same-origin",
        cross_origin_embedder_policy="require-corp",
        cross_origin_resource_policy="cross-origin",
        content_type="text/html",
    ), scheme="https")
    assert report.score == 98
    assert report.grade == "A"
