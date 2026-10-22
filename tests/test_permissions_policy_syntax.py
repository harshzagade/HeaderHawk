"""Tests for Permissions-Policy syntax validation.

HeaderHawk parses the header value directive by directive: unknown feature
names and malformed ``=(...)`` values become LOW findings (browsers ignore
them, so the intended restriction is silently unenforced), while
deprecated-but-removed features get an INFO note (they simply do nothing).
"""

from headerhawk.checks import analyze


def h(value):
    return {"permissions-policy": [value]}


def _pp_findings(headers):
    report = analyze(headers, scheme="https")
    return [f for f in report.findings if f.check == "Permissions-Policy"]


def test_valid_multi_directive_passes():
    findings = _pp_findings(h("camera=(), microphone=(), geolocation=(self)"))
    assert len(findings) == 1
    assert findings[0].severity == "OK"


def test_origins_and_quoted_strings_valid():
    findings = _pp_findings(
        h('camera=("https://example.com"), microphone=(self "https://a.test:8443")'))
    assert all(f.severity == "OK" for f in findings)


def test_bare_host_allows_lenient():
    findings = _pp_findings(h("camera=(example.com)"))
    assert all(f.severity == "OK" for f in findings)


def test_case_insensitive_feature_and_keywords():
    findings = _pp_findings(h("Camera=(SELF)"))
    assert all(f.severity == "OK" for f in findings)


def test_typo_feature_is_low():
    findings = _pp_findings(h("camrea=(), camera=()"))
    low = [f for f in findings if f.severity == "LOW"]
    assert len(low) == 1
    assert low[0].score_delta == -2
    assert "unrecognized" in low[0].summary
    # the valid directive does not add a second finding
    assert len(findings) == 1


def test_deprecated_feature_is_info_only():
    findings = _pp_findings(h("oversized-images=(), camera=()"))
    info = [f for f in findings if f.severity == "INFO"]
    assert len(info) == 1
    assert info[0].score_delta == 0
    assert "deprecated" in info[0].summary
    assert not [f for f in findings if f.severity == "LOW"]


def test_missing_value_shape_is_malformed():
    findings = _pp_findings(h("camera"))
    low = [f for f in findings if f.severity == "LOW"]
    assert len(low) == 1
    assert "malformed" in low[0].summary


def test_unbalanced_paren_is_malformed():
    findings = _pp_findings(h("camera=("))
    low = [f for f in findings if f.severity == "LOW"]
    assert len(low) == 1
    assert "malformed" in low[0].summary


def test_invalid_allowlist_token_is_low():
    findings = _pp_findings(h("camera=(*)"))
    low = [f for f in findings if f.severity == "LOW"]
    assert len(low) == 1
    assert "invalid allowlist token" in low[0].summary


def test_empty_value_is_info():
    findings = _pp_findings(h(""))
    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert "empty" in findings[0].summary


def test_missing_header_still_low_with_feature_policy_note():
    findings = _pp_findings({"feature-policy": ["camera 'none'"]})
    low = [f for f in findings if f.severity == "LOW"]
    assert len(low) == 1
    assert low[0].score_delta == -3
    assert "missing" in low[0].summary
    assert any(f.severity == "INFO" and "Feature-Policy" in f.summary
               for f in findings)


def test_trailing_comma_tolerated():
    findings = _pp_findings(h("camera=(),"))
    assert len(findings) == 1
    assert findings[0].severity == "OK"


def test_score_impact_of_typo():
    report = analyze(h("camrea=()"), scheme="https")
    low = [f for f in report.findings
           if f.check == "Permissions-Policy" and f.severity == "LOW"]
    assert low and low[0].score_delta == -2
