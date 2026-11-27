"""Unit tests for the NEL dangling report_to note.

A NEL header's ``report_to`` only delivers reports when the named group is
defined by a Reporting-Endpoints header or a legacy Report-To header. A
name matching neither is dead config, so it gets an INFO note (no penalty);
a defined group earns an OK pass; NEL absent, malformed, or without a
``report_to`` stays silent.
"""

import json

from headerhawk.checks import analyze, check_nel_dangling_report_to


def h(**kwargs):
    """Build a header map: NAME='value' -> {'name': ['value']}."""
    return {k.lower().replace("_", "-"): [v] for k, v in kwargs.items()}


def _nel_findings(headers):
    return [f for f in check_nel_dangling_report_to(headers)
            if f.check == "NEL"]


def test_no_nel_header_is_silent():
    assert check_nel_dangling_report_to({}) == []
    assert _nel_findings(h(content_security_policy="default-src 'self'")) == []


def test_nel_without_report_to_is_silent():
    assert _nel_findings(h(nel='{"max_age": 86400}')) == []


def test_malformed_nel_json_is_silent():
    assert _nel_findings(h(nel='{not json')) == []


def test_group_defined_by_reporting_endpoints_is_pass():
    headers = h(
        nel='{"report_to": "nel-endpoint", "max_age": 86400}',
        reporting_endpoints='nel-endpoint="https://example.com/nel"',
    )
    (f,) = _nel_findings(headers)
    assert f.status == "pass" and f.severity == "OK" and f.score_delta == 0


def test_group_defined_by_legacy_report_to_is_pass():
    headers = h(
        nel='{"report_to": "nel-endpoint", "max_age": 86400}',
        report_to=json.dumps({"group": "nel-endpoint", "max_age": 86400,
                              "endpoints": []}),
    )
    (f,) = _nel_findings(headers)
    assert f.status == "pass" and f.severity == "OK" and f.score_delta == 0


def test_undefined_group_is_info_naming_the_group():
    headers = h(nel='{"report_to": "missing-group", "max_age": 86400}')
    (f,) = _nel_findings(headers)
    assert f.status == "info" and f.severity == "INFO" and f.score_delta == 0
    assert "missing-group" in f.summary
    assert f.fix  # a fix suggestion is always present


def test_group_matching_is_case_insensitive():
    headers = h(
        nel='{"report_to": "NEL-Endpoint", "max_age": 86400}',
        reporting_endpoints='nel-endpoint="https://example.com/nel"',
    )
    (f,) = _nel_findings(headers)
    assert f.severity == "OK"


def test_malformed_report_to_json_leaves_group_undefined():
    headers = h(
        nel='{"report_to": "nel-endpoint", "max_age": 86400}',
        report_to='{not json',
    )
    (f,) = _nel_findings(headers)
    assert f.severity == "INFO" and "nel-endpoint" in f.summary


def test_report_to_list_second_group_is_pass():
    headers = h(
        nel='{"report_to": "nel-endpoint", "max_age": 86400}',
        report_to=json.dumps([
            {"group": "csp-endpoint", "max_age": 86400, "endpoints": []},
            {"group": "nel-endpoint", "max_age": 86400, "endpoints": []},
        ]),
    )
    (f,) = _nel_findings(headers)
    assert f.severity == "OK"


def test_dangling_nel_costs_no_points_through_analyze():
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
        nel='{"report_to": "missing-group", "max_age": 86400}',
    )
    report = analyze(headers, scheme="https")
    assert report.score == 100
    assert report.grade == "A+"
    nel_f = [f for f in report.findings if f.check == "NEL"]
    assert len(nel_f) == 1 and nel_f[0].severity == "INFO"
