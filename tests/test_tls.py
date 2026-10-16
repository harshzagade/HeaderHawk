"""Tests for the TLS version/cipher sniff (stdlib ssl, no live targets)."""

import ssl
from types import SimpleNamespace

import pytest

from headerhawk import tls as tls_mod
from headerhawk.checks import analyze, check_tls
from headerhawk.tls import TLSInfo, probe_tls


# --- fake network ----------------------------------------------------------

class _Raw:
    def close(self):
        pass


class _TLS:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)


class _FakeContext:
    """SSLContext stand-in: refuses versions not in `accepted`."""
    label_of = {}
    accepted = set()
    seen_sni = []

    def __init__(self, protocol=None):
        self.minimum_version = None
        self.maximum_version = None
        self.check_hostname = True
        self.verify_mode = None

    def wrap_socket(self, raw, server_hostname=None):
        _FakeContext.seen_sni.append(server_hostname)
        if self.minimum_version is None:
            return _TLS()  # default context: always handshakes in the fake
        label = _FakeContext.label_of.get(self.minimum_version)
        if label not in _FakeContext.accepted:
            raise ssl.SSLError("handshake failure")
        return _TLS()


@pytest.fixture
def fake_net(monkeypatch):
    _FakeContext.label_of = {v: label for label, v in tls_mod._VERSIONS}
    _FakeContext.accepted = {"TLSv1.2", "TLSv1.3"}
    _FakeContext.seen_sni = []
    fake_ssl = SimpleNamespace(
        SSLContext=_FakeContext,
        PROTOCOL_TLS_CLIENT="TLS_CLIENT",
        CERT_NONE=0,
        SSLError=ssl.SSLError,
        create_default_context=lambda: _FakeContext(),
    )
    monkeypatch.setattr(tls_mod, "ssl", fake_ssl)
    monkeypatch.setattr("socket.create_connection",
                        lambda addr, timeout=None: _Raw())
    return _FakeContext


# --- probe_tls -------------------------------------------------------------

def test_probe_lists_accepted_versions(fake_net):
    info = probe_tls("example.com")
    assert info.versions == ("TLSv1.2", "TLSv1.3")
    assert info.negotiated == "TLSv1.3"
    assert info.cipher == "TLS_AES_256_GCM_SHA384"
    assert info.cipher_bits == 256
    assert info.error == ""


def test_probe_sends_sni(fake_net):
    probe_tls("example.com")
    assert _FakeContext.seen_sni
    assert all(sni == "example.com" for sni in _FakeContext.seen_sni)


def test_probe_legacy_only_server(fake_net):
    _FakeContext.accepted = {"TLSv1"}
    info = probe_tls("old.example.com")
    assert info.versions == ("TLSv1",)


def test_probe_connection_failure_becomes_error(monkeypatch):
    import socket as real_socket
    monkeypatch.setattr("socket.create_connection",
                        lambda addr, timeout=None: (_ for _ in ()).throw(
                            real_socket.timeout("timed out")))
    info = probe_tls("down.example.com", timeout=0.1)
    assert info.versions == ()
    assert info.error != ""


# --- check_tls -------------------------------------------------------------

def _info(**kw):
    base = dict(host="example.com", port=443,
                versions=("TLSv1.2", "TLSv1.3"),
                negotiated="TLSv1.3",
                cipher="TLS_AES_256_GCM_SHA384", cipher_bits=256)
    base.update(kw)
    return TLSInfo(**base)


def test_check_tls_skipped_when_unchecked():
    assert check_tls("unchecked") == []
    assert check_tls(None) == []


def test_check_tls_modern_is_ok_pass():
    findings = check_tls(_info())
    assert len(findings) == 1
    assert findings[0].severity == "OK"
    assert findings[0].score_delta == 0


def test_check_tls_v10_is_high():
    findings = check_tls(_info(versions=("TLSv1", "TLSv1.2", "TLSv1.3"),
                               negotiated="TLSv1.2"))
    high = [f for f in findings if f.severity == "HIGH"]
    assert any("TLS 1.0" in f.summary for f in high)
    assert any(f.score_delta == -10 for f in high)


def test_check_tls_v11_only_is_med():
    findings = check_tls(_info(versions=("TLSv1.1", "TLSv1.2", "TLSv1.3"),
                               negotiated="TLSv1.2"))
    med = [f for f in findings if f.severity == "MED"]
    assert any("TLS 1.1" in f.summary for f in med)
    assert any(f.score_delta == -8 for f in med)


def test_check_tls_weak_cipher_is_high():
    for cipher in ("RC4-SHA", "ECDHE-RSA-DES-CBC3-SHA", "AES128-SHA",
                   "ECDHE-RSA-AES128-SHA"):
        weak = cipher in ("RC4-SHA", "ECDHE-RSA-DES-CBC3-SHA")
        findings = check_tls(_info(cipher=cipher))
        high = [f for f in findings if f.check == "TLS cipher"]
        assert (len(high) == 1) == weak, cipher


def test_check_tls_tls12_negotiated_is_info():
    findings = check_tls(_info(negotiated="TLSv1.2"))
    info = [f for f in findings if f.severity == "INFO"]
    assert any("TLSv1.2" in f.summary for f in info)


def test_check_tls_probe_error_is_info():
    findings = check_tls(TLSInfo(host="down.example.com",
                                 error="timed out"))
    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert findings[0].score_delta == 0


# --- analyze wiring --------------------------------------------------------

def test_analyze_includes_tls_findings():
    report = analyze({}, scheme="https",
                     meta={"url": "https://example.com",
                           "tls": _info(versions=("TLSv1",),
                                        negotiated="TLSv1",
                                        cipher="RC4-SHA")})
    checks = {f.check for f in report.findings}
    assert "TLS protocol versions" in checks
    assert "TLS cipher" in checks
    payload = report.to_dict()
    assert payload["tls"]["versions"] == ["TLSv1"]
    assert payload["tls"]["cipher"] == "RC4-SHA"


def test_analyze_skips_tls_when_unchecked():
    report = analyze({}, scheme="https", meta={"url": "https://example.com"})
    assert not [f for f in report.findings if f.check.startswith("TLS")]
    assert report.to_dict()["tls"] is None
