"""Tests for per-directive 'unsafe-inline' CSP breakdown.

No network: analyze() is pure.
"""

from headerhawk.checks import analyze


def h(**kwargs):
    return {k.lower().replace("_", "-"): [v] for k, v in kwargs.items()}


def _inline_findings(policy):
    report = analyze(h(content_security_policy=policy), scheme="https")
    return [f for f in report.findings if "unsafe-inline" in f.summary]


def test_explicit_script_src_keeps_med_minus_8():
    findings = _inline_findings("default-src 'self'; script-src 'self' 'unsafe-inline'")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "MED"
    assert f.score_delta == -8
    assert "'script-src'" in f.summary
    assert "style-src" not in f.summary


def test_default_src_fallback_names_both_directives():
    findings = _inline_findings("default-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "MED"
    assert f.score_delta == -8
    assert "'script-src'" in f.summary and "'style-src'" in f.summary
    assert "default-src" in f.summary  # inherited via fallback


def test_style_src_only_is_low_and_says_scripts_unaffected():
    findings = _inline_findings(
        "script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'"
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "LOW"
    assert f.score_delta == -3
    assert "style-src" in f.summary
    assert "scripts are not affected" in f.summary


def test_style_only_via_default_src_fallback():
    findings = _inline_findings(
        "default-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'self'"
    )
    # script-src is set explicitly without unsafe-inline, so only styles apply
    assert len(findings) == 1
    assert findings[0].severity == "LOW"


def test_strict_policy_has_no_unsafe_inline_finding():
    findings = _inline_findings(
        "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'"
    )
    assert findings == []


def test_script_flagged_even_when_style_also_affected():
    findings = _inline_findings(
        "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "MED"  # script risk dominates
    assert f.score_delta == -8
    assert "'script-src'" in f.summary and "'style-src'" in f.summary
