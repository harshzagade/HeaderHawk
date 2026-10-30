"""Tests for the Permissions-Policy interest-cohort note.

`interest-cohort=()` was the FLoC opt-out. FLoC was removed, so the
directive now does nothing; its successor, the Topics API, is gated by
`browsing-topics`. The directive therefore gets an INFO note (never a
penalty), with the note naming the Topics API state.
"""

from headerhawk.checks import analyze


def _pp_findings(value):
    report = analyze({"permissions-policy": [value]}, scheme="https")
    return [f for f in report.findings if f.check == "Permissions-Policy"]


def test_interest_cohort_opt_out_is_info_only():
    findings = _pp_findings("interest-cohort=()")
    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert findings[0].score_delta == 0
    assert "interest-cohort" in findings[0].summary


def test_interest_cohort_opt_out_points_at_topics_api():
    findings = _pp_findings("interest-cohort=()")
    assert "browsing-topics=()" in findings[0].detail
    assert "FLoC" in findings[0].detail


def test_interest_cohort_with_topics_present_notes_coverage():
    findings = _pp_findings("interest-cohort=(), browsing-topics=()")
    info = [f for f in findings if f.severity == "INFO"]
    assert len(info) == 1
    assert "browsing-topics is already present" in info[0].detail


def test_interest_cohort_nonempty_allowlist_still_legacy():
    findings = _pp_findings("interest-cohort=(self)")
    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert "does nothing" in findings[0].detail


def test_interest_cohort_case_insensitive_and_coexists_with_valid():
    findings = _pp_findings("Interest-Cohort=(), camera=()")
    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert not [f for f in findings if f.severity == "LOW"]


def test_valid_header_without_interest_cohort_still_passes():
    findings = _pp_findings("camera=(), microphone=()")
    assert len(findings) == 1
    assert findings[0].severity == "OK"
