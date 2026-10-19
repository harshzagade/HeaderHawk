"""security.txt presence tests. No real network: urlopen is stubbed."""

import urllib.error

import pytest

from headerhawk.checks import analyze, check_security_txt
from headerhawk.fetch import FetchError, fetch_security_txt


class _FakeResponse:
    """Minimal urllib response stand-in for fetch_security_txt."""

    def __init__(self, status=200, body=b"Contact: mailto:s@example.com\n",
                 charset="utf-8"):
        self.status = status
        self._body = body
        self._charset = charset

    @property
    def headers(self):
        class _H:
            def __init__(self, charset):
                self._charset = charset

            def get_content_charset(self):
                return self._charset

        return _H(self._charset)

    def read(self, n=-1):
        return self._body if n < 0 else self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_urlopen(response=None, error=None, seen=None):
    def fake(request, timeout=None):
        if seen is not None:
            seen["url"] = request.full_url
        if error is not None:
            raise error
        return response
    return fake


# --- fetcher ---------------------------------------------------------------

def test_fetches_well_known_path_from_origin(monkeypatch):
    seen = {}
    monkeypatch.setattr(
        "urllib.request.urlopen",
        _fake_urlopen(_FakeResponse(), seen=seen))
    text = fetch_security_txt("https://example.com/some/deep/page")
    assert text == "Contact: mailto:s@example.com\n"
    assert seen["url"] == "https://example.com/.well-known/security.txt"


def test_preserves_non_default_port(monkeypatch):
    seen = {}
    monkeypatch.setattr(
        "urllib.request.urlopen",
        _fake_urlopen(_FakeResponse(), seen=seen))
    fetch_security_txt("https://example.com:8443/")
    assert seen["url"] == "https://example.com:8443/.well-known/security.txt"


def test_404_means_missing(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen", _fake_urlopen(_FakeResponse(status=404)))
    assert fetch_security_txt("https://example.com/") is None


def test_http_error_404_means_missing(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        _fake_urlopen(error=urllib.error.HTTPError(
            "https://example.com/.well-known/security.txt", 404,
            "Not Found", {}, None)))
    assert fetch_security_txt("https://example.com/") is None


def test_unexpected_status_raises(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen", _fake_urlopen(_FakeResponse(status=500)))
    with pytest.raises(FetchError, match="HTTP 500"):
        fetch_security_txt("https://example.com/")


def test_network_error_raises(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        _fake_urlopen(error=urllib.error.URLError("dns blew up")))
    with pytest.raises(FetchError, match="dns blew up"):
        fetch_security_txt("https://example.com/")


# --- check -----------------------------------------------------------------

def test_unchecked_is_silent():
    assert check_security_txt("unchecked") == []


def test_fetch_failure_is_info_not_error():
    (finding,) = check_security_txt(None)
    assert finding.severity == "INFO"
    assert finding.score_delta == 0
    assert "could not be checked" in finding.summary


def test_missing_file_is_info():
    (finding,) = check_security_txt((False, None))
    assert finding.severity == "INFO"
    assert finding.score_delta == 0
    assert "No security.txt published" in finding.summary
    assert "Contact:" in finding.fix


def test_present_with_contact_passes():
    (finding,) = check_security_txt(
        (True, "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n"))
    assert finding.severity == "OK"
    assert finding.score_delta == 0
    assert "1 contact line(s)" in finding.summary


def test_contact_match_is_case_insensitive_and_ignores_comments():
    (finding,) = check_security_txt(
        (True, "# contact: not-real\n   CONTACT: https://example.com/contact\n"))
    assert finding.severity == "OK"


def test_present_without_contact_is_info():
    (finding,) = check_security_txt((True, "Expires: 2027-01-01T00:00:00Z\n"))
    assert finding.severity == "INFO"
    assert finding.score_delta == 0
    assert "no Contact:" in finding.summary


# --- analyze() wiring ------------------------------------------------------

def test_analyze_wires_security_txt_meta():
    report = analyze({}, scheme="https", meta={"security_txt": (False, None)})
    assert any(f.check == "security.txt" for f in report.findings)


def test_analyze_silent_when_unset():
    report = analyze({}, scheme="https", meta={})
    assert not any(f.check == "security.txt" for f in report.findings)
