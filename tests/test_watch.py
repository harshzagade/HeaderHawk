"""Watch-mode tests. No real network: _audit_one is stubbed."""

import argparse
import urllib.error

import pytest

from headerhawk import cli
from headerhawk.checks import analyze
from headerhawk.fetch import FetchError, FetchResult


def _h(**kwargs):
    """Build a header map: NAME='value' -> {'name': ['value']}."""
    return {k.lower().replace("_", "-"): [v] for k, v in kwargs.items()}


SECURE = _h(
    strict_transport_security="max-age=63072000; includeSubDomains",
    content_security_policy=("default-src 'self'; script-src 'self'; "
                             "object-src 'none'; base-uri 'self'; frame-ancestors 'self'"),
    x_content_type_options="nosniff",
    x_frame_options="DENY",
    referrer_policy="strict-origin-when-cross-origin",
    permissions_policy="camera=(), microphone=(), geolocation=()",
    cross_origin_opener_policy="same-origin",
    cross_origin_embedder_policy="require-corp",
    cross_origin_resource_policy="same-site",
)
EMPTY = _h()


class _Clock:
    """Fake sleep: raises KeyboardInterrupt after N calls (stops the loop)."""

    def __init__(self, stop_after):
        self.calls = 0
        self.stop_after = stop_after

    def __call__(self, seconds):
        self.calls += 1
        if self.calls >= self.stop_after:
            raise KeyboardInterrupt


def _args(argv):
    return cli.build_parser().parse_args(argv)


def _stub_audit(reports):
    """Stub cli._audit_one to yield reports (or raise) in order."""
    it = iter(reports)

    def fake(url, *, timeout, user_agent, **kwargs):
        item = next(it)
        if isinstance(item, Exception):
            raise item
        return item, {}

    return fake


def test_watch_alerts_on_grade_change(monkeypatch, capsys):
    good = analyze(SECURE, scheme="https")
    bad = analyze(EMPTY, scheme="https")
    assert good.grade != bad.grade  # sanity: the stub really changes
    monkeypatch.setattr(cli, "_audit_one", _stub_audit([good, bad]))
    code = cli.run_watch(_args(["example.com", "--watch", "1", "--no-color"]),
                         sleep=_Clock(stop_after=2))
    assert code == 0
    out = capsys.readouterr().out
    assert "Baseline" in out
    assert "GRADE:" in out  # baseline prints the full report
    assert "CHANGE DETECTED" in out
    assert f"{good.grade} -> {bad.grade}" in out
    assert "Stopped watching example.com" in out


def test_watch_stays_quiet_when_nothing_changes(monkeypatch, capsys):
    report = analyze(SECURE, scheme="https")
    monkeypatch.setattr(cli, "_audit_one",
                        _stub_audit([report, report, report]))
    code = cli.run_watch(_args(["example.com", "--watch", "1", "--no-color"]),
                         sleep=_Clock(stop_after=3))
    assert code == 0
    out = capsys.readouterr().out
    assert "no change" in out
    assert "CHANGE DETECTED" not in out


def test_watch_first_fetch_failure_exits_2(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_audit_one",
                        _stub_audit([FetchError("dns blew up")]))
    code = cli.run_watch(_args(["example.com", "--watch", "1", "--no-color"]),
                         sleep=_Clock(stop_after=1))
    assert code == 2
    assert "dns blew up" in capsys.readouterr().err


def test_watch_fetch_failure_mid_run_keeps_watching(monkeypatch, capsys):
    report = analyze(SECURE, scheme="https")
    monkeypatch.setattr(
        cli, "_audit_one",
        _stub_audit([report, FetchError("timeout"), report]))
    code = cli.run_watch(_args(["example.com", "--watch", "1", "--no-color"]),
                         sleep=_Clock(stop_after=3))
    assert code == 0
    out = capsys.readouterr().out
    assert "fetch failed" in out
    assert "no change" in out  # recovered on the next audit


def test_watch_fail_below_gates_each_audit(monkeypatch, capsys):
    bad = analyze(EMPTY, scheme="https")
    monkeypatch.setattr(cli, "_audit_one", _stub_audit([bad]))
    code = cli.run_watch(
        _args(["example.com", "--watch", "1", "--fail-below", "B",
               "--no-color"]),
        sleep=_Clock(stop_after=5))
    assert code == 1
    assert "below the required B" in capsys.readouterr().err


def test_watch_rejects_bad_combinations(capsys):
    assert cli.main(["--watch", "5", "--bulk", "targets.txt"]) == 2
    assert cli.main(["example.com", "--watch", "5", "--compare",
                     "a.example", "b.example"]) == 2
    assert cli.main(["--watch", "5", "--headers", "h.txt"]) == 2
    assert cli.main(["--watch", "5"]) == 2  # no live URL
    assert cli.main(["example.com", "--watch", "0"]) == 2
    assert cli.main(["example.com", "--watch", "-3"]) == 2
    assert cli.main(["example.com", "--watch", "5", "--json"]) == 2
    assert cli.main(["example.com", "--watch", "5", "--raw"]) == 2
    assert "error" in capsys.readouterr().err


def _fetch_result(headers, final_url="https://example.com/"):
    return FetchResult(url="https://example.com/", final_url=final_url,
                       status=200, headers=headers, chain=[])


def test_preload_queried_when_directive_present(monkeypatch, capsys):
    headers = _h(strict_transport_security=
                 "max-age=63072000; includeSubDomains; preload")
    monkeypatch.setattr(cli, "fetch",
                        lambda url, timeout, user_agent: _fetch_result(headers))
    seen = {}

    def fake_preload(domain, timeout):
        seen["domain"] = domain
        return "unknown"

    monkeypatch.setattr(cli, "preload_status", fake_preload)
    code = cli.main(["example.com", "--no-color"])
    assert code == 0
    assert seen["domain"] == "example.com"
    out = capsys.readouterr().out
    assert "HSTS preload list" in out


def test_preload_not_queried_without_directive(monkeypatch, capsys):
    headers = _h(strict_transport_security="max-age=63072000; includeSubDomains")
    monkeypatch.setattr(cli, "fetch",
                        lambda url, timeout, user_agent: _fetch_result(headers))
    called = []
    monkeypatch.setattr(cli, "preload_status",
                        lambda domain, timeout: called.append(domain))
    code = cli.main(["example.com", "--no-color"])
    assert code == 0
    assert called == []
    assert "HSTS preload list" not in capsys.readouterr().out


def test_preload_skipped_for_ip_targets(monkeypatch):
    headers = _h(strict_transport_security=
                 "max-age=63072000; includeSubDomains; preload")
    called = []
    monkeypatch.setattr(cli, "preload_status",
                        lambda domain, timeout: called.append(domain))
    assert cli._hsts_preload_status("https://127.0.0.1/", headers, "https",
                                    10.0) == "unchecked"
    assert cli._hsts_preload_status("https://[::1]/", headers, "https",
                                    10.0) == "unchecked"
    assert called == []


def test_preload_failed_query_is_info_not_error(monkeypatch, capsys):
    headers = _h(strict_transport_security=
                 "max-age=63072000; includeSubDomains; preload")
    monkeypatch.setattr(cli, "fetch",
                        lambda url, timeout, user_agent: _fetch_result(headers))
    def fake_preload(domain, timeout):
        raise FetchError("hstspreload.org unreachable")

    monkeypatch.setattr(cli, "preload_status", fake_preload)
    code = cli.main(["example.com", "--no-color"])
    assert code == 0
    out = capsys.readouterr().out
    assert "could not be verified" in out
