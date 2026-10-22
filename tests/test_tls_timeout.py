"""Tests for --tls-timeout: configure the TLS handshake probe timeout.

No real network: cli.fetch, cli.fetch_security_txt and cli.probe_tls are
stubbed; the stubbed probe_tls records the timeout it was called with.
"""

import pytest

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


def _probing_run(monkeypatch, **kwargs):
    seen = {}
    monkeypatch.setattr(cli, "fetch", _fake_fetch)
    monkeypatch.setattr(cli, "fetch_security_txt", lambda *a, **k: None)

    def fake_probe(host, **probe_kwargs):
        seen.update(probe_kwargs)
        return "unchecked"

    monkeypatch.setattr(cli, "probe_tls", fake_probe)
    cli._audit_one("https://example.com", timeout=10.0, user_agent="test",
                   **kwargs)
    return seen


def test_tls_probe_timeout_defaults_to_five(monkeypatch):
    seen = _probing_run(monkeypatch)
    assert seen.get("timeout") == 5.0


def test_tls_probe_timeout_custom_value(monkeypatch):
    seen = _probing_run(monkeypatch, tls_timeout=12.0)
    assert seen.get("timeout") == 12.0


def test_tls_timeout_flows_through_main(monkeypatch, capsys):
    """--tls-timeout parses and reaches _audit_one in single-target mode."""
    seen = {}
    orig = cli._audit_one

    def spy(url, **kwargs):
        seen.update(kwargs)
        return orig(url, **kwargs)

    monkeypatch.setattr(cli, "_audit_one", spy)
    monkeypatch.setattr(cli, "fetch", _fake_fetch)
    monkeypatch.setattr(cli, "fetch_security_txt", lambda *a, **k: None)
    monkeypatch.setattr(cli, "probe_tls", lambda *a, **k: "unchecked")
    code = cli.main(["https://example.com", "--tls-timeout", "12",
                     "--no-color"])
    assert code == 0
    assert seen.get("tls_timeout") == 12.0


def test_tls_timeout_zero_fails_fast(capsys):
    assert cli.main(["https://example.com", "--tls-timeout", "0",
                     "--no-color"]) == 2
    assert "--tls-timeout must be positive" in capsys.readouterr().err


def test_tls_timeout_negative_fails_fast(capsys):
    assert cli.main(["https://example.com", "--tls-timeout", "-3",
                     "--no-color"]) == 2


def test_tls_timeout_with_no_tls_fails_fast(capsys):
    assert cli.main(["https://example.com", "--no-tls", "--tls-timeout", "12",
                     "--no-color"]) == 2
    assert "--tls-timeout cannot be combined with --no-tls" in \
        capsys.readouterr().err


def test_no_tls_without_tls_timeout_still_ok(monkeypatch, capsys):
    """--no-tls alone is unaffected by the new combo guard."""
    monkeypatch.setattr(cli, "fetch", _fake_fetch)
    monkeypatch.setattr(cli, "fetch_security_txt", lambda *a, **k: None)
    monkeypatch.setattr(cli, "probe_tls", lambda *a, **k: "unchecked")
    assert cli.main(["https://example.com", "--no-tls", "--no-color"]) == 0


def test_tls_timeout_invalid_number_rejected(capsys):
    """argparse rejects non-numeric input itself (SystemExit 2)."""
    with pytest.raises(SystemExit) as exc:
        cli.main(["https://example.com", "--tls-timeout", "soon",
                  "--no-color"])
    assert exc.value.code == 2
