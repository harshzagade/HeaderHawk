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


def _dup_findings(headers_map):
    return [f for f in analyze(headers_map, scheme="https").findings
            if f.check == "Duplicate headers"]


def test_conflicting_duplicates_flagged():
    report = analyze(SECURE | {"x-frame-options": ["DENY", "SAMEORIGIN"]},
                     scheme="https")
    dups = [f for f in report.findings if f.check == "Duplicate headers"]
    assert len(dups) == 1
    f = dups[0]
    assert f.status == "weak" and f.severity == "MED"
    assert f.score_delta == -5
    assert "X-Frame-Options" in f.summary
    assert "conflicting" in f.summary
    assert f.fix
    # secure config scored 100; one conflict drops 5
    assert report.score == 95


def test_identical_duplicates_are_info_only():
    report = analyze(SECURE | {"x-frame-options": ["DENY", "deny "]},
                     scheme="https")
    dups = _dup_findings(SECURE | {"x-frame-options": ["DENY", "deny "]})
    assert len(dups) == 1
    assert dups[0].status == "info" and dups[0].severity == "INFO"
    assert dups[0].score_delta == 0
    assert report.score == 100  # no penalty


def test_set_cookie_exempt_from_duplicate_check():
    headers_map = SECURE | {"set-cookie": ["a=1; Secure", "b=2; Secure"]}
    assert _dup_findings(headers_map) == []


def test_single_headers_produce_no_duplicate_findings():
    assert _dup_findings(SECURE) == []


def test_duplicate_conflicts_reported_per_header_sorted():
    headers_map = {"x-frame-options": ["DENY", "SAMEORIGIN"],
                   "referrer-policy": ["no-referrer", "unsafe-url"]}
    dups = _dup_findings(headers_map)
    assert [f.header for f in dups] == ["Referrer-Policy", "X-Frame-Options"]


def test_duplicate_finding_always_has_fix():
    dups = _dup_findings({"x-frame-options": ["DENY", "SAMEORIGIN"]})
    assert all(f.fix for f in dups if f.status == "weak")


def _csp_findings(headers):
    return [f for f in analyze(headers, scheme="https").findings
            if f.check == "Content-Security-Policy" and "report" in f.summary.lower()]


def test_csp_without_reporting_directive_is_info():
    headers = h(content_security_policy="default-src 'self'; script-src 'self'; "
                                        "object-src 'none'; base-uri 'self'")
    rep = _csp_findings(headers)
    assert len(rep) == 1
    assert rep[0].severity == "INFO" and rep[0].score_delta == 0
    assert "report-uri" in rep[0].summary and "report-to" in rep[0].summary


def test_csp_report_uri_noted_as_deprecated():
    headers = h(content_security_policy="default-src 'self'; "
                                        "report-uri https://example.com/csp")
    rep = _csp_findings(headers)
    assert len(rep) == 1
    assert rep[0].severity == "INFO" and rep[0].score_delta == 0
    assert "deprecated" in rep[0].summary


def test_csp_report_to_with_endpoints_header_is_pass():
    headers = h(content_security_policy="default-src 'self'; report-to csp-endpoint",
                reporting_endpoints='csp-endpoint="https://example.com/csp"')
    rep = _csp_findings(headers)
    assert len(rep) == 1
    assert rep[0].severity == "OK" and rep[0].status == "pass"


def test_csp_report_to_without_endpoints_header_is_low():
    headers = h(content_security_policy="default-src 'self'; report-to csp-endpoint")
    report = analyze(headers, scheme="https")
    rep = [f for f in report.findings
           if f.check == "Content-Security-Policy" and "go nowhere" in f.summary]
    assert len(rep) == 1
    assert rep[0].severity == "LOW" and rep[0].score_delta == -2


def test_reporting_check_never_dings_fully_secure_config():
    # SECURE has no reporting directives; the informational note must not cost score.
    report = analyze(SECURE, scheme="https")
    assert report.score == 100
    assert report.grade == "A+"


def _preload_findings(report):
    return [f for f in report.findings if f.check == "HSTS preload list"]


def test_hsts_preload_preloaded_is_ok():
    report = analyze(SECURE, scheme="https", meta={"hsts_preload": "preloaded"})
    assert report.score == 100
    assert report.grade == "A+"
    findings = _preload_findings(report)
    assert len(findings) == 1
    assert findings[0].severity == "OK"
    assert findings[0].score_delta == 0


def test_hsts_preload_unknown_is_low():
    report = analyze(SECURE, scheme="https", meta={"hsts_preload": "unknown"})
    findings = _preload_findings(report)
    assert len(findings) == 1
    assert findings[0].severity == "LOW"
    assert findings[0].score_delta == -2
    assert "hstspreload.org" in findings[0].summary
    assert report.score == 98


def test_hsts_preload_failed_query_is_info():
    report = analyze(SECURE, scheme="https", meta={"hsts_preload": None})
    findings = _preload_findings(report)
    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert findings[0].score_delta == 0
    assert report.score == 100


def test_hsts_preload_silent_without_meta_key():
    # Offline analysis never queries the API: no finding at all, score kept.
    report = analyze(SECURE, scheme="https")
    assert _preload_findings(report) == []
    assert report.score == 100


def test_hsts_preload_silent_without_preload_directive():
    headers = h(strict_transport_security="max-age=63072000; includeSubDomains")
    report = analyze(headers, scheme="https", meta={"hsts_preload": "preloaded"})
    assert _preload_findings(report) == []


def test_hsts_preload_silent_over_plain_http():
    report = analyze(SECURE, scheme="http", meta={"hsts_preload": "preloaded"})
    assert _preload_findings(report) == []

def _csp_ro_findings(report):
    return [f for f in report.findings
            if f.header == "Content-Security-Policy-Report-Only"]


def test_csp_report_only_alone_flagged_med():
    # Only Report-Only: the policy is NOT enforced (false confidence).
    headers = h(content_security_policy_report_only="default-src 'self'")
    report = analyze(headers, scheme="https")
    findings = _csp_ro_findings(report)
    assert findings and findings[0].severity == "MED"
    assert findings[0].score_delta == -5
    assert "NOT enforced" in findings[0].summary
    # Still counted as missing the enforcing header: empty-headers score 39 minus 5.
    assert report.score == 34


def test_csp_report_only_next_to_enforcing_is_info():
    headers = dict(SECURE)
    headers["content-security-policy-report-only"] = ["default-src 'self'"]
    report = analyze(headers, scheme="https")
    findings = _csp_ro_findings(report)
    assert findings and findings[0].severity == "INFO"
    assert report.score == 100


def test_csp_report_only_absent_is_silent():
    # No report-only header: no findings from this check at all.
    report = analyze(SECURE, scheme="https")
    assert _csp_ro_findings(report) == []
    report2 = analyze({}, scheme="https")
    assert _csp_ro_findings(report2) == []
