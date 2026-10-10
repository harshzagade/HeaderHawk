"""Live fetching of response headers. stdlib urllib only."""

from __future__ import annotations

import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from .checks import Headers


DEFAULT_USER_AGENT = "HeaderHawk/1.0 (+https://github.com/harshzagade/HeaderHawk)"


class FetchError(Exception):
    """Raised when the target cannot be fetched (network, DNS, TLS, timeout)."""


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    headers: Headers = field(default_factory=dict)
    redirects: int = 0
    elapsed_ms: int = 0


class _RedirectCounter(urllib.request.HTTPRedirectHandler):
    """Redirect handler that counts how many redirects were followed."""

    def __init__(self, max_redirects: int = 5):
        self.count = 0
        self.max_redirections = max_redirects

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.count += 1
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def normalize_url(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise FetchError(f"Unsupported URL scheme: {parts.scheme!r} (use http/https)")
    return url


def fetch(url: str, timeout: float = 10.0, user_agent: str = DEFAULT_USER_AGENT,
          max_redirects: int = 5) -> FetchResult:
    """GET the URL, follow redirects, and return the final response headers."""
    url = normalize_url(url)
    redirector = _RedirectCounter(max_redirects)
    opener = urllib.request.build_opener(redirector)
    request = urllib.request.Request(url, headers={"User-Agent": user_agent})

    start = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(1)  # touch the body; headers are what we need
            _ = body
            msg = response.headers
            headers: Headers = {}
            for key in msg.keys():
                headers.setdefault(key.lower(), []).extend(msg.get_all(key))
            return FetchResult(
                url=url,
                final_url=response.geturl(),
                status=response.status,
                headers=headers,
                redirects=redirector.count,
                elapsed_ms=int((time.monotonic() - start) * 1000),
            )
    except urllib.error.HTTPError as exc:
        # HTTP error responses (4xx/5xx) still carry headers worth analyzing.
        msg = exc.headers
        headers = {}
        if msg is not None:
            for key in msg.keys():
                headers.setdefault(key.lower(), []).extend(msg.get_all(key))
        return FetchResult(
            url=url,
            final_url=exc.geturl() or url,
            status=exc.code,
            headers=headers,
            redirects=redirector.count,
            elapsed_ms=int((time.monotonic() - start) * 1000),
        )
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise FetchError(f"Could not fetch {url}: {reason}") from exc
