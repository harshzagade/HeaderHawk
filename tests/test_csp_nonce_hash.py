"""Tests for the CSP nonce/hash OK note.

No network: analyze() is pure.
"""

from headerhawk.checks import analyze


def h(**kwargs):
    return {k.lower().replace("_", "-"): [v] for k, v in kwargs.items()}


def _nonce_findings(policy):
    report = analyze(h(content_security_policy=policy), scheme="https")
    return [f for f in report.findings
            if f.check == "Content-Security-Policy"
            and ("nonce" in f.summary.lower() or "hash" in f.summary.lower())]


def test_nonce_in_script_src_is_ok_pass():
    findings = _nonce_findings(
        "default-src 'self'; script-src 'self' 'nonce-r4nd0m'; object-src 'none'; base-uri 'self'"
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "OK"
    assert f.score_delta == 0
    assert "nonce" in f.summary
    assert "unsafe-inline" in f.summary


def test_sha256_hash_in_script_src_is_ok_pass():
    findings = _nonce_findings(
        "default-src 'self'; script-src 'self' 'sha256-abc123'; object-src 'none'; base-uri 'self'"
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "OK"
    assert f.score_delta == 0
    assert "hash" in f.summary


def test_sha384_hash_counts_too():
    findings = _nonce_findings(
        "default-src 'self'; script-src 'self' 'sha384-xyz'; object-src 'none'; base-uri 'self'"
    )
    assert len(findings) == 1
    assert "hash" in findings[0].summary


def test_nonce_and_hash_both_named():
    findings = _nonce_findings(
        "default-src 'self'; script-src 'self' 'nonce-abc' 'sha512-def'; object-src 'none'; base-uri 'self'"
    )
    assert len(findings) == 1
    assert "nonce" in findings[0].summary and "hash" in findings[0].summary


def test_nonce_via_default_src_fallback():
    findings = _nonce_findings(
        "default-src 'self' 'nonce-r4nd0m'; object-src 'none'; base-uri 'self'"
    )
    assert len(findings) == 1
    assert findings[0].severity == "OK"


def test_nonce_plus_unsafe_inline_gets_no_credit():
    findings = _nonce_findings(
        "default-src 'self'; script-src 'self' 'nonce-abc' 'unsafe-inline'; object-src 'none'; base-uri 'self'"
    )
    assert findings == []
    report = analyze(h(content_security_policy=(
        "default-src 'self'; script-src 'self' 'nonce-abc' 'unsafe-inline'; "
        "object-src 'none'; base-uri 'self'")), scheme="https")
    med = [f for f in report.findings
           if f.severity == "MED" and "unsafe-inline" in f.summary]
    assert len(med) == 1


def test_plain_self_script_src_has_no_nonce_note():
    findings = _nonce_findings(
        "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'"
    )
    assert findings == []


def test_nonce_only_in_style_src_is_not_credited():
    findings = _nonce_findings(
        "default-src 'self'; script-src 'self'; style-src 'self' 'nonce-abc'; object-src 'none'; base-uri 'self'"
    )
    assert findings == []
