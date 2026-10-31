"""HSTS preload eligibility: a preload candidate under 6 months max-age
gets a LOW nudge toward the 1-year preload minimum, on top of the
existing MED short-max-age finding."""

from headerhawk.checks import analyze


def h(**kwargs):
    """Build a header map: NAME='value' -> {'name': ['value']}."""
    return {k.lower().replace("_", "-"): [v] for k, v in kwargs.items()}


def _eligibility(report):
    return [f for f in report.findings
            if f.check == "HSTS preload eligibility"]


def test_preload_under_six_months_gets_low_nudge():
    headers = h(strict_transport_security=(
        "max-age=7776000; includeSubDomains; preload"))  # 90 days
    report = analyze(headers, scheme="https")
    found = _eligibility(report)
    assert len(found) == 1
    assert found[0].severity == "LOW"
    assert found[0].score_delta == -2
    assert "7776000" in found[0].summary
    assert "31536000" in found[0].summary
    # The generic short-max-age MED finding still fires alongside it.
    short = [f for f in report.findings if "max-age is only" in f.summary]
    assert short and short[0].severity == "MED"


def test_preload_two_years_is_silent():
    headers = h(strict_transport_security=(
        "max-age=63072000; includeSubDomains; preload"))
    assert _eligibility(analyze(headers, scheme="https")) == []


def test_no_preload_directive_is_silent():
    headers = h(strict_transport_security="max-age=7776000; includeSubDomains")
    assert _eligibility(analyze(headers, scheme="https")) == []


def test_preload_at_exactly_six_months_is_silent():
    headers = h(strict_transport_security=(
        "max-age=15768000; includeSubDomains; preload"))
    assert _eligibility(analyze(headers, scheme="https")) == []


def test_preload_without_max_age_is_silent():
    headers = h(strict_transport_security="includeSubDomains; preload")
    assert _eligibility(analyze(headers, scheme="https")) == []


def test_preload_under_six_months_over_http_is_silent():
    headers = h(strict_transport_security=(
        "max-age=7776000; includeSubDomains; preload"))
    report = analyze(headers, scheme="http")
    assert _eligibility(report) == []
