"""Unit tests for the Reporting-Endpoints present-but-unused note.

A Reporting-Endpoints header defines endpoint groups that only receive
reports when a CSP report-to directive or a NEL header's report_to names
them. An unreferenced group is dead config, so it gets an INFO note (no
penalty); fully-referenced groups earn an OK pass; no header stays silent.
"""

from headerhawk.checks import analyze, check_reporting_endpoints_unused


def h(**kwargs):
    """Build a header map: NAME='value' -> {'name': ['value']}."""
    return {k.lower().replace("_", "-"): [v] for k, v in kwargs.items()}


def _re_findings(headers, csp=None):
    return [f for f in check_reporting_endpoints_unused(headers, csp or {})
            if f.check == "Reporting-Endpoints"]


def test_no_reporting_endpoints_header_is_silent():
    assert check_reporting_endpoints_unused({}, {}) == []
    assert _re_findings(h(content_security_policy="default-src 'self'")) == []


def test_group_referenced_by_csp_report_to_is_pass():
    headers = h(reporting_endpoints='csp-endpoint="https://example.com/csp"')
    (f,) = _re_findings(headers, {"report-to": ["csp-endpoint"]})
    assert f.status == "pass" and f.severity == "OK" and f.score_delta == 0


def test_group_referenced_by_nel_is_pass():
    headers = h(
        reporting_endpoints='nel-endpoint="https://example.com/nel"',
        nel='{"report_to": "nel-endpoint", "max_age": 86400}',
    )
    (f,) = _re_findings(headers, {})
    assert f.status == "pass" and f.severity == "OK" and f.score_delta == 0


def test_unreferenced_group_is_info_naming_the_group():
    headers = h(reporting_endpoints='csp-endpoint="https://example.com/csp"')
    (f,) = _re_findings(headers, {})
    assert f.status == "info" and f.severity == "INFO" and f.score_delta == 0
    assert "csp-endpoint" in f.summary
    assert f.fix  # a fix suggestion is always present


def test_two_groups_one_used_one_unused_names_only_the_unused():
    headers = h(reporting_endpoints=(
        'csp-endpoint="https://example.com/csp", '
        'nel-endpoint="https://example.com/nel"'))
    (f,) = _re_findings(headers, {"report-to": ["csp-endpoint"]})
    assert f.severity == "INFO" and f.score_delta == 0
    assert "nel-endpoint" in f.summary
    assert "csp-endpoint" not in f.summary


def test_malformed_nel_json_is_no_reference_not_an_error():
    headers = h(
        reporting_endpoints='nel-endpoint="https://example.com/nel"',
        nel='{not json',
    )
    (f,) = _re_findings(headers, {})
    assert f.severity == "INFO" and "nel-endpoint" in f.summary


def test_nel_without_report_to_is_no_reference():
    headers = h(
        reporting_endpoints='nel-endpoint="https://example.com/nel"',
        nel='{"max_age": 86400}',
    )
    (f,) = _re_findings(headers, {})
    assert f.severity == "INFO" and "nel-endpoint" in f.summary


def test_legacy_report_to_header_alone_is_not_a_reference():
    # A legacy Report-To header defines its own groups; it does not
    # consume Reporting-Endpoints groups, so the group stays unused.
    headers = h(
        reporting_endpoints='csp-endpoint="https://example.com/csp"',
        report_to='{"group": "csp-endpoint", "max_age": 86400, "endpoints": []}',
    )
    (f,) = _re_findings(headers, {})
    assert f.severity == "INFO" and "csp-endpoint" in f.summary


def test_unquoted_endpoint_url_is_parsed():
    headers = h(reporting_endpoints="csp-endpoint=https://example.com/csp")
    (f,) = _re_findings(headers, {})
    assert "csp-endpoint" in f.summary


def test_group_matching_is_case_insensitive():
    headers = h(reporting_endpoints='CSP-Endpoint="https://example.com/csp"')
    (f,) = _re_findings(headers, {"report-to": ["csp-endpoint"]})
    assert f.severity == "OK"


def test_unused_group_costs_no_points_through_analyze():
    headers = h(
        strict_transport_security="max-age=63072000; includeSubDomains; preload",
        content_security_policy=("default-src 'self'; script-src 'self'; "
                                 "object-src 'none'; base-uri 'self'; frame-ancestors 'self'"),
        x_content_type_options="nosniff",
        x_frame_options="SAMEORIGIN",
        referrer_policy="strict-origin-when-cross-origin",
        permissions_policy="camera=(), microphone=(), geolocation=()",
        cross_origin_opener_policy="same-origin",
        cross_origin_embedder_policy="require-corp",
        cross_origin_resource_policy="same-site",
        content_type="text/html",
        reporting_endpoints='csp-endpoint="https://example.com/csp"',
    )
    report = analyze(headers, scheme="https")
    assert report.score == 100
    assert report.grade == "A+"
    re_f = [f for f in report.findings if f.check == "Reporting-Endpoints"]
    assert len(re_f) == 1 and re_f[0].severity == "INFO"
