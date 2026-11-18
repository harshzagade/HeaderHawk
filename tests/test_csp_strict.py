"""Tests for the strict-CSP OK pass.

A CSP with `default-src 'none'` plus a nonce/hash `script-src` (and no
`'unsafe-inline'` anywhere) earns an explicit OK pass naming the strict
pattern. No network: analyze() is pure.
"""

from headerhawk.checks import analyze


def h(**kwargs):
    return {k.lower().replace("_", "-"): [v] for k, v in kwargs.items()}


def _csp_findings(policy):
    report = analyze(h(content_security_policy=policy), scheme="https")
    return [f for f in report.findings
            if f.check == "Content-Security-Policy"]


def _strict_findings(policy):
    return [f for f in _csp_findings(policy)
            if f.summary.startswith("CSP is strict:")]


def test_strict_nonce_policy_is_ok_pass():
    findings = _strict_findings(
        "default-src 'none'; script-src 'self' 'nonce-r4nd0m'; "
        "style-src 'self'; object-src 'none'; base-uri 'self'"
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "OK"
    assert f.score_delta == 0
    assert "nonce" in f.summary
    assert "default-src 'none'" in f.summary


def test_strict_hash_policy_is_ok_pass():
    findings = _strict_findings(
        "default-src 'none'; script-src 'self' 'sha256-abc123'; "
        "object-src 'none'; base-uri 'self'"
    )
    assert len(findings) == 1
    assert "hash" in findings[0].summary


def test_strict_policy_gets_no_duplicate_nonce_credit():
    findings = _csp_findings(
        "default-src 'none'; script-src 'self' 'nonce-r4nd0m'; "
        "object-src 'none'; base-uri 'self'"
    )
    credited = [f for f in findings
                if f.severity == "OK" and "nonce" in f.summary.lower()]
    assert len(credited) == 1
    assert credited[0].summary.startswith("CSP is strict:")


def test_default_src_self_with_nonce_is_not_strict():
    findings = _strict_findings(
        "default-src 'self'; script-src 'self' 'nonce-r4nd0m'; "
        "object-src 'none'; base-uri 'self'"
    )
    assert findings == []
    # ... but the plain nonce/hash credit still applies.
    credited = [f for f in _csp_findings(
        "default-src 'self'; script-src 'self' 'nonce-r4nd0m'; "
        "object-src 'none'; base-uri 'self'")
        if f.severity == "OK" and "nonce" in f.summary.lower()]
    assert len(credited) == 1


def test_default_src_none_without_nonce_is_not_strict():
    findings = _strict_findings(
        "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'self'"
    )
    assert findings == []


def test_default_src_none_alone_is_not_strict():
    findings = _strict_findings("default-src 'none'")
    assert findings == []


def test_unsafe_inline_in_style_src_disqualifies_strict():
    findings = _strict_findings(
        "default-src 'none'; script-src 'self' 'nonce-r4nd0m'; "
        "style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'"
    )
    assert findings == []


def test_unsafe_inline_in_script_src_disqualifies_strict():
    findings = _strict_findings(
        "default-src 'none'; script-src 'self' 'nonce-r4nd0m' 'unsafe-inline'; "
        "object-src 'none'; base-uri 'self'"
    )
    assert findings == []
    report = analyze(h(content_security_policy=(
        "default-src 'none'; script-src 'self' 'nonce-r4nd0m' 'unsafe-inline'; "
        "object-src 'none'; base-uri 'self'")), scheme="https")
    med = [f for f in report.findings
           if f.severity == "MED" and "unsafe-inline" in f.summary]
    assert len(med) == 1


def test_unsafe_inline_via_default_src_disqualifies_strict():
    # default-src 'none' is required, so the fallback cannot carry
    # 'unsafe-inline' here — but an explicit style-src inheriting nothing
    # still counts: covered above. This policy has no script-src at all,
    # so the effective script-src is default-src 'none' (no nonce).
    findings = _strict_findings(
        "default-src 'none'; style-src 'unsafe-inline'"
    )
    assert findings == []
