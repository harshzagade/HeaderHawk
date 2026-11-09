"""Tests for the Permissions-Policy sensitive-feature allowlist audit.

A lone "*" is valid per the spec — it allows the feature for every origin
— so it is no longer a syntax error. For the sensitive features (camera,
microphone, geolocation) that breadth is a real exposure: any third-party
script on the page may use the device, so it is a MED finding. Other
features allowed to "*" stay valid and silent.
"""

from headerhawk.checks import analyze


def h(value):
    return {"permissions-policy": [value]}


def _pp_findings(headers):
    report = analyze(headers, scheme="https")
    return [f for f in report.findings if f.check == "Permissions-Policy"]


def test_camera_star_is_med():
    findings = _pp_findings(h("camera=(*)"))
    med = [f for f in findings if f.severity == "MED"]
    assert len(med) == 1
    assert med[0].score_delta == -5
    assert "camera" in med[0].summary
    assert "*" in med[0].summary
    assert "camera=(self)" in med[0].fix
    assert not [f for f in findings if f.severity == "LOW"]


def test_microphone_and_geolocation_star_each_flagged():
    findings = _pp_findings(h("microphone=(*), geolocation=(*)"))
    med = [f for f in findings if f.severity == "MED"]
    assert len(med) == 2
    assert {m.summary for m in med} == {
        "Permissions-Policy allows 'microphone' to every origin (*).",
        "Permissions-Policy allows 'geolocation' to every origin (*).",
    }
    assert all(m.score_delta == -5 for m in med)


def test_star_mixed_with_self_still_flagged():
    findings = _pp_findings(h("camera=(self *)"))
    med = [f for f in findings if f.severity == "MED"]
    assert len(med) == 1
    assert "camera" in med[0].summary


def test_self_only_is_clean():
    findings = _pp_findings(h("camera=(self), microphone=(self)"))
    assert len(findings) == 1
    assert findings[0].severity == "OK"


def test_empty_allowlist_is_clean():
    findings = _pp_findings(h("camera=(), microphone=(), geolocation=()"))
    assert len(findings) == 1
    assert findings[0].severity == "OK"


def test_specific_origin_is_clean():
    findings = _pp_findings(h('camera=("https://example.com")'))
    assert len(findings) == 1
    assert findings[0].severity == "OK"


def test_star_on_non_sensitive_feature_is_clean():
    findings = _pp_findings(h("fullscreen=(*), autoplay=(*)"))
    assert len(findings) == 1
    assert findings[0].severity == "OK"


def test_only_sensitive_feature_flagged_in_mixed_header():
    findings = _pp_findings(
        h("camera=(*), fullscreen=(*), geolocation=(self)"))
    med = [f for f in findings if f.severity == "MED"]
    assert len(med) == 1
    assert "camera" in med[0].summary


def test_score_drops_by_five_per_feature():
    report = analyze(h("camera=(*), microphone=(*)"), scheme="https")
    baseline = analyze(h("camera=(), microphone=()"), scheme="https")
    assert report.score == baseline.score - 10
