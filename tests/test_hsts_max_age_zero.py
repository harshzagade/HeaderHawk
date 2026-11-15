"""Tests for the HSTS max-age=0 explicit opt-out finding (MED, -8).

max-age=0 is not a short policy: it tells browsers to delete the stored
HSTS policy, so it gets its own finding instead of folding into the
generic short-max-age one, and the preload-eligibility nudge is skipped
with it (preload with max-age=0 is moot).
"""

from headerhawk.checks import analyze


def h(**kwargs):
    """Build a header map: NAME='value' -> {'name': ['value']}."""
    return {k.lower().replace("_", "-"): [v] for k, v in kwargs.items()}


def _hsts_findings(report):
    return [f for f in report.findings
            if f.check == "Strict-Transport-Security"]


def test_max_age_zero_is_own_med_finding():
    headers = h(strict_transport_security="max-age=0; includeSubDomains; preload")
    report = analyze(headers, scheme="https")
    findings = _hsts_findings(report)
    opt_outs = [f for f in findings if "max-age=0" in f.summary]
    assert len(opt_outs) == 1
    assert opt_outs[0].severity == "MED"
    assert opt_outs[0].score_delta == -8
    assert opt_outs[0].status == "weak"
    assert "opts out" in opt_outs[0].summary
    # The generic short-max-age finding must not fire alongside it.
    assert not [f for f in findings if "max-age is only" in f.summary]
    # Neither must the preload-eligibility nudge: preload with max-age=0
    # is moot, the policy is being deleted, not submitted.
    assert not [f for f in findings
                if f.check == "HSTS preload eligibility"]


def test_max_age_zero_without_includesubdomains_keeps_that_finding():
    headers = h(strict_transport_security="max-age=0")
    report = analyze(headers, scheme="https")
    findings = _hsts_findings(report)
    assert len([f for f in findings if "max-age=0" in f.summary]) == 1
    subdomains = [f for f in findings if "includeSubDomains" in f.summary]
    assert len(subdomains) == 1
    assert subdomains[0].severity == "LOW"
    assert subdomains[0].score_delta == -3


def test_max_age_zero_without_preload_keeps_info_note():
    headers = h(strict_transport_security="max-age=0; includeSubDomains")
    report = analyze(headers, scheme="https")
    findings = _hsts_findings(report)
    assert len([f for f in findings if "max-age=0" in f.summary]) == 1
    no_preload = [f for f in findings
                  if "no preload directive" in f.summary]
    assert len(no_preload) == 1
    assert no_preload[0].severity == "INFO"


def test_max_age_one_still_gets_generic_short_finding():
    headers = h(strict_transport_security="max-age=1")
    report = analyze(headers, scheme="https")
    findings = _hsts_findings(report)
    assert not [f for f in findings if "max-age=0" in f.summary]
    shorts = [f for f in findings if "max-age is only" in f.summary]
    assert len(shorts) == 1
    assert shorts[0].severity == "MED"
    assert shorts[0].score_delta == -5


def test_max_age_zero_over_plain_http_stays_not_applicable():
    headers = h(strict_transport_security="max-age=0")
    report = analyze(headers, scheme="http")
    findings = _hsts_findings(report)
    assert not [f for f in findings if "max-age=0" in f.summary]
    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert "plain HTTP" in findings[0].summary


def test_max_age_zero_with_preload_but_no_list_entry():
    # max-age=0 + preload still goes through the live preload-list check
    # (offline: "unchecked", so no preload-list finding) — only the
    # opt-out and the missing-includeSubDomains findings apply.
    headers = h(strict_transport_security="max-age=0; preload")
    report = analyze(headers, scheme="https")
    findings = _hsts_findings(report)
    assert len([f for f in findings if "max-age=0" in f.summary]) == 1
    assert not [f for f in report.findings
                if f.check == "HSTS preload eligibility"]
