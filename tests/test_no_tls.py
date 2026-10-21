"""Tests for --no-tls: skip the TLS version/cipher probe for fast audits.

No real network: cli.fetch, cli.fetch_security_txt and cli.probe_tls are
stubbed; the stubbed probe_tls records calls so tests can assert the probe
did (or did not) run.
"""

from headerhawk import cli
from headerhawk.fetch import FetchResult


def _fake_fetch(url, **kwargs):
    return FetchResult(
        url=url,
        final_url="https://example.com/",
        status=200,
        headers={"Strict-Transport-Security": ["max-age=63072000"]},
        redirects=0,
        elapsed_ms=12,
        chain=[],
    )


def test_audit_one_probes_tls_by_default(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "fetch", _fake_fetch)
    monkeypatch.setattr(cli, "fetch_security_txt", lambda *a, **k: None)
    monkeypatch.setattr(cli, "probe_tls", lambda *a, **k: calls.append(a) or "unchecked")
    report, _ = cli._audit_one("https://example.com", timeout=1.0,
                               user_agent="test")
    assert len(calls) == 1


def test_audit_one_skips_tls_probe_with_no_tls(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "fetch", _fake_fetch)
    monkeypatch.setattr(cli, "fetch_security_txt", lambda *a, **k: None)
    monkeypatch.setattr(cli, "probe_tls", lambda *a, **k: calls.append(a) or "unchecked")
    report, _ = cli._audit_one("https://example.com", timeout=1.0,
                               user_agent="test", no_tls=True)
    assert calls == []
    # TLS check reports nothing rather than penalizing the grade
    assert not [f for f in report.findings
                if f.check == "TLS protocol versions"]
    assert report.grade == "F"  # HSTS-only headers: 54 points either way


def test_no_tls_flag_reaches_single_target_mode(monkeypatch, capsys):
    """--no-tls parses and flows into _audit_one for single-target audits."""
    seen = {}
    orig = cli._audit_one

    def spy(url, **kwargs):
        seen.update(kwargs)
        return orig(url, **kwargs)

    monkeypatch.setattr(cli, "_audit_one", spy)
    monkeypatch.setattr(cli, "fetch", _fake_fetch)
    monkeypatch.setattr(cli, "fetch_security_txt", lambda *a, **k: None)
    monkeypatch.setattr(cli, "probe_tls", lambda *a, **k: "unchecked")
    code = cli.main(["https://example.com", "--no-tls", "--no-color"])
    assert code == 0
    assert seen.get("no_tls") is True


def test_no_tls_defaults_off_in_compare_and_watch_args(monkeypatch, capsys):
    # --watch-log without --watch still fails fast: unrelated combo guard
    assert cli.main(["--watch-log", "/tmp/x", "--no-tls"]) == 2
