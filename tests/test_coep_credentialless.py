"""COEP `credentialless` is a valid modern value, not an unrecognized one.

No network: analyze() is pure.
"""

from headerhawk.checks import analyze


def h(**kwargs):
    """Build a header map: NAME='value' -> {'name': ['value']}."""
    return {k.lower().replace("_", "-"): [v] for k, v in kwargs.items()}


def _coep_findings(value):
    report = analyze(h(cross_origin_embedder_policy=value), scheme="https")
    return [f for f in report.findings
            if f.check == "Cross-Origin-Embedder-Policy"]


def _isolation_findings(**kwargs):
    report = analyze(h(**kwargs), scheme="https")
    return [f for f in report.findings
            if f.check in ("Cross-Origin-Embedder-Policy",
                           "Cross-Origin-Resource-Policy",
                           "Cross-origin isolation")]


def test_credentialless_is_accepted_silently():
    assert _coep_findings("credentialless") == []


def test_credentialless_case_and_whitespace_tolerant():
    assert _coep_findings(" Credentialless ") == []


def test_require_corp_still_accepted():
    assert _coep_findings("require-corp") == []


def test_coep_unrecognized_value_is_low():
    findings = _coep_findings("bogus-value")
    assert len(findings) == 1
    assert findings[0].severity == "LOW"
    assert findings[0].score_delta == -2
    assert findings[0].status == "weak"
    assert "unrecognized" in findings[0].summary
    assert "credentialless" in findings[0].detail


def test_credentialless_full_config_earns_isolation_pass():
    findings = _isolation_findings(
        cross_origin_opener_policy="same-origin",
        cross_origin_embedder_policy="credentialless",
        cross_origin_resource_policy="same-site",
    )
    assert len(findings) == 1
    assert findings[0].check == "Cross-origin isolation"
    assert findings[0].severity == "OK"


def test_credentialless_with_missing_corp_notes_the_implication():
    findings = _isolation_findings(
        cross_origin_opener_policy="same-origin",
        cross_origin_embedder_policy="credentialless",
    )
    corp = [f for f in findings
            if f.check == "Cross-Origin-Resource-Policy"]
    assert len(corp) == 1
    assert corp[0].severity == "INFO"
    assert "credentialless" in corp[0].detail
    assert "credentials" in corp[0].detail


def test_require_corp_with_missing_corp_has_no_credentialless_note():
    findings = _isolation_findings(
        cross_origin_opener_policy="same-origin",
        cross_origin_embedder_policy="require-corp",
    )
    corp = [f for f in findings
            if f.check == "Cross-Origin-Resource-Policy"]
    assert len(corp) == 1
    assert "credentialless" not in corp[0].detail


def test_credentialless_costs_no_points():
    report = analyze(h(
        strict_transport_security="max-age=63072000; includeSubDomains; preload",
        content_security_policy=("default-src 'self'; script-src 'self'; "
                                 "object-src 'none'; base-uri 'self'; "
                                 "frame-ancestors 'self'"),
        x_content_type_options="nosniff",
        x_frame_options="SAMEORIGIN",
        referrer_policy="strict-origin-when-cross-origin",
        permissions_policy="camera=(), microphone=(), geolocation=()",
        cross_origin_opener_policy="same-origin",
        cross_origin_embedder_policy="credentialless",
        cross_origin_resource_policy="same-site",
        content_type="text/html",
    ), scheme="https")
    assert report.score == 100
    assert report.grade == "A+"
