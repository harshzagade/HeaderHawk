"""Unit tests for the HSTS-over-plain-HTTP note.

RFC 6797 honors HSTS only on HTTPS responses, so a Strict-Transport-Security
header on a plain-HTTP response is ignored by browsers — dead config, not
protection. It gets its own INFO note (no penalty); the header-less HTTP
case keeps the existing "Not applicable" note unchanged.
"""

from headerhawk.checks import analyze, check_hsts


def h(**kwargs):
    """Build a header map: NAME='value' -> {'name': ['value']}."""
    return {k.lower().replace("_", "-"): [v] for k, v in kwargs.items()}


def _hsts_findings(headers, scheme):
    return [f for f in analyze(headers, scheme=scheme).findings
            if f.check == "Strict-Transport-Security"]


def test_hsts_header_over_http_is_ignored_info():
    headers = h(strict_transport_security="max-age=63072000; includeSubDomains")
    (f,) = _hsts_findings(headers, "http")
    assert f.status == "info" and f.severity == "INFO" and f.score_delta == 0
    assert "ignored" in f.summary
    assert f.fix  # a fix suggestion is always present


def test_hsts_header_over_http_costs_no_points():
    headers = h(strict_transport_security="max-age=63072000; includeSubDomains")
    with_hsts = analyze(headers, scheme="http")
    without_hsts = analyze({}, scheme="http")
    assert with_hsts.score == without_hsts.score


def test_hsts_absent_over_http_keeps_old_note():
    (f,) = _hsts_findings({}, "http")
    assert f.status == "info" and f.severity == "INFO" and f.score_delta == 0
    assert f.summary == "Not applicable over plain HTTP."


def test_hsts_over_https_still_graded_normally():
    # The HTTPS path is untouched: a missing header is still HIGH (-15).
    (f,) = [f for f in check_hsts({}, "https")]
    assert f.severity == "HIGH" and f.score_delta == -15
    headers = h(strict_transport_security="max-age=63072000; includeSubDomains; preload")
    (f,) = [f for f in check_hsts(headers, "https")]
    assert f.severity == "OK" and f.score_delta == 0
