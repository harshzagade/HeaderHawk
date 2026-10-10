"""Unit tests for the header checks and scoring."""

import pytest

from headerhawk.checks import analyze, grade_for


def h(**kwargs):
    """Build a header map: NAME='value' -> {'name': ['value']}."""
    return {k.lower().replace("_", "-"): [v] for k, v in kwargs.items()}


SECURE = h(
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
)


def test_secure_config_scores_a_plus():
    report = analyze(SECURE, scheme="https")
    assert report.score == 100
    assert report.grade == "A+"


def test_empty_headers_scores_f():
    report = analyze({}, scheme="https")
    # -15 HSTS, -20 CSP, -8 XCTO, -10 XFO, -5 referrer, -3 permissions = -61
    assert report.grade == "F"
    assert report.score == 39


def test_csp_unsafe_inline_flagged():
    headers = h(content_security_policy="default-src 'self'; script-src 'self' 'unsafe-inline'")
    report = analyze(headers, scheme="https")
    med = [f for f in report.findings if f.severity == "MED" and "unsafe-inline" in f.summary]
    assert len(med) == 1
    assert med[0].score_delta == -8


def test_csp_unsafe_eval_flagged():
    headers = h(content_security_policy="script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'self'")
    report = analyze(headers, scheme="https")
    low = [f for f in report.findings if "unsafe-eval" in f.summary]
    assert low and low[0].severity == "LOW"


def test_csp_wildcard_script_src_flagged():
    headers = h(content_security_policy="script-src *; object-src 'none'; base-uri 'self'")
    report = analyze(headers, scheme="https")
    weak = [f for f in report.findings if "overly broad" in f.summary]
    assert weak and weak[0].severity == "MED"


def test_csp_missing_default_src_flagged():
    headers = h(content_security_policy="script-src 'self'; object-src 'none'; base-uri 'self'")
    report = analyze(headers, scheme="https")
    missing = [f for f in report.findings if "no default-src" in f.summary]
    assert missing and missing[0].severity == "MED"


def test_hsts_short_max_age_flagged():
    headers = h(strict_transport_security="max-age=86400; includeSubDomains")
    report = analyze(headers, scheme="https")
    short = [f for f in report.findings if "max-age is only" in f.summary]
    assert short and short[0].severity == "MED"
    assert short[0].score_delta == -5


def test_hsts_missing_include_subdomains_flagged():
    headers = h(strict_transport_security="max-age=63072000")
    report = analyze(headers, scheme="https")
    sub = [f for f in report.findings if "includeSubDomains" in f.summary]
    assert sub and sub[0].severity == "LOW"


def test_hsts_not_applicable_over_http():
    report = analyze({}, scheme="http")
    info = [f for f in report.findings if f.check == "Strict-Transport-Security"]
    assert len(info) == 1
    assert info[0].severity == "INFO"
    assert info[0].score_delta == 0


def test_xcto_wrong_value_flagged():
    report = analyze(h(x_content_type_options="sniff"), scheme="https")
    weak = [f for f in report.findings if f.check == "X-Content-Type-Options"]
    assert weak[0].status == "weak"
    assert weak[0].severity == "MED"


def test_xfo_missing_flagged():
    report = analyze({}, scheme="https")
    missing = [f for f in report.findings if f.check == "X-Frame-Options"]
    assert missing[0].status == "missing"
    assert missing[0].severity == "MED"


def test_xfo_covered_by_csp_frame_ancestors():
    headers = h(content_security_policy="default-src 'self'; frame-ancestors 'none'")
    report = analyze(headers, scheme="https")
    xfo = [f for f in report.findings if f.check == "X-Frame-Options"]
    assert xfo[0].severity == "INFO"
    assert xfo[0].score_delta == 0


def test_referrer_policy_unsafe_url_flagged():
    report = analyze(h(referrer_policy="unsafe-url"), scheme="https")
    weak = [f for f in report.findings if f.check == "Referrer-Policy"]
    assert weak[0].severity == "MED"
    assert weak[0].score_delta == -3


def test_permissions_policy_pass():
    report = analyze(h(permissions_policy="camera=()"), scheme="https")
    ok = [f for f in report.findings if f.check == "Permissions-Policy"]
    assert ok[0].status == "pass"


def test_server_version_disclosure_flagged():
    report = analyze(h(server="nginx/1.24.0"), scheme="https")
    disc = [f for f in report.findings if f.header == "Server"]
    assert disc and disc[0].severity == "LOW"
    assert disc[0].fix  # a fix suggestion is always present


def test_every_finding_has_fix_or_is_pass():
    report = analyze({}, scheme="https")
    for finding in report.findings:
        if finding.status in ("missing", "weak"):
            assert finding.fix, f"no fix suggestion for {finding.check}: {finding.summary}"


@pytest.mark.parametrize("score,expected", [
    (100, "A+"), (99, "A"), (90, "A"), (89, "B"), (80, "B"),
    (79, "C"), (70, "C"), (69, "D"), (55, "D"),
    (54, "E"), (40, "E"), (39, "F"), (0, "F"),
])
def test_grade_boundaries(score, expected):
    assert grade_for(score) == expected
