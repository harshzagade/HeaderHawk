"""Unit tests for the cookie Partitioned attribute note (CHIPS).

A SameSite=None cookie without Partitioned is an INFO note on HTTPS
targets only: Chrome increasingly restricts unpartitioned third-party
cookies, so the note tells the owner to opt into partitioned storage.
"""

from headerhawk.checks import analyze, check_cookie_partitioned


def _partitioned_findings(*values, scheme="https"):
    return check_cookie_partitioned({"set-cookie": list(values)}, scheme)


def test_no_cookies_nothing_to_note():
    assert _partitioned_findings() == []
    assert check_cookie_partitioned({}, "https") == []


def test_samesite_none_without_partitioned_is_info():
    (f,) = _partitioned_findings("emb=1; Secure; SameSite=None; HttpOnly")
    assert f.severity == "INFO" and f.score_delta == 0
    assert f.status == "info"
    assert f.check == "Cookie flags" and f.header == "Set-Cookie"
    assert "emb" in f.summary
    assert "Partitioned" in f.fix
    assert "CHIPS" in f.detail or "partitioned" in f.detail.lower()


def test_partitioned_cookie_is_silent():
    assert _partitioned_findings(
        "emb=1; Secure; SameSite=None; HttpOnly; Partitioned") == []


def test_partitioned_attribute_matching_is_case_insensitive():
    assert _partitioned_findings(
        "emb=1; Secure; samesite=none; HttpOnly; PARTITIONED") == []


def test_samesite_none_without_secure_still_gets_the_note():
    # The missing-Secure MED owns the rejection; the note still applies
    # because adding Secure alone leaves the cookie unpartitioned.
    (f,) = _partitioned_findings("emb=1; SameSite=None; HttpOnly")
    assert f.severity == "INFO"


def test_plain_http_targets_are_silent():
    assert _partitioned_findings("emb=1; SameSite=None; HttpOnly",
                                 scheme="http") == []


def test_lax_strict_and_missing_samesite_are_silent():
    assert _partitioned_findings("a=1; Secure; HttpOnly; SameSite=Lax") == []
    assert _partitioned_findings(
        "b=1; Secure; HttpOnly; SameSite=Strict") == []
    assert _partitioned_findings("c=1; Secure; HttpOnly") == []


def test_cookies_audited_independently():
    findings = _partitioned_findings(
        "good=1; Secure; SameSite=None; HttpOnly; Partitioned",
        "bad=2; Secure; SameSite=None; HttpOnly")
    assert len(findings) == 1
    assert "bad" in findings[0].summary


def test_analyze_wires_partitioned_note_on_https_only():
    report = analyze(
        {"set-cookie": ["emb=1; Secure; SameSite=None; HttpOnly"]},
        scheme="https")
    notes = [f for f in report.findings
             if "Partitioned" in f.summary]
    assert len(notes) == 1
    assert notes[0].severity == "INFO" and notes[0].score_delta == 0

    plain = analyze(
        {"set-cookie": ["emb=1; Secure; SameSite=None; HttpOnly"]},
        scheme="http")
    assert not [f for f in plain.findings if "Partitioned" in f.summary]


def test_partitioned_note_does_not_change_the_score():
    report = analyze(
        {"set-cookie": ["emb=1; Secure; SameSite=None; HttpOnly"]},
        scheme="https")
    # The only scored cookie finding is the SameSite=None LOW (-2).
    assert sum(f.score_delta for f in report.findings
               if f.check == "Cookie flags") == -2
