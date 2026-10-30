"""Tests for the Referrer-Policy `no-referrer` value audit.

`no-referrer` used to be a silent OK pass. It is the strongest privacy
setting, but it also breaks analytics and attribution that read the
Referer header, so it now gets an INFO note (no score penalty) instead.
Missing stays LOW (-5) and `unsafe-url` stays MED (-3) per OWASP guidance.
"""

from headerhawk.checks import analyze


def _rp_findings(value):
    report = analyze({"referrer-policy": [value]}, scheme="https")
    return [f for f in report.findings if f.check == "Referrer-Policy"]


def test_no_referrer_is_info_not_pass():
    findings = _rp_findings("no-referrer")
    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert findings[0].score_delta == 0
    assert "no referrer" in findings[0].summary.lower()


def test_no_referrer_note_names_analytics_tradeoff():
    findings = _rp_findings("no-referrer")
    assert "analytics" in findings[0].detail
    assert "strict-origin-when-cross-origin" in findings[0].fix


def test_no_referrer_case_insensitive():
    findings = _rp_findings("No-Referrer")
    assert len(findings) == 1
    assert findings[0].severity == "INFO"


def test_no_referrer_costs_no_points():
    report = analyze({"referrer-policy": ["no-referrer"]}, scheme="https")
    good = analyze({"referrer-policy": ["strict-origin-when-cross-origin"]},
                   scheme="https")
    rp = [f for f in report.findings if f.check == "Referrer-Policy"]
    rp_good = [f for f in good.findings if f.check == "Referrer-Policy"]
    assert sum(f.score_delta for f in rp) == sum(f.score_delta for f in rp_good) == 0


def test_missing_still_low_and_unsafe_url_still_med():
    report = analyze({}, scheme="https")
    missing = [f for f in report.findings if f.check == "Referrer-Policy"]
    assert missing[0].severity == "LOW"
    assert missing[0].score_delta == -5
    unsafe = _rp_findings("unsafe-url")
    assert unsafe[0].severity == "MED"
    assert unsafe[0].score_delta == -3
