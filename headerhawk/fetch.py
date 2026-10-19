"""Live fetching of response headers. stdlib urllib only."""

from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from functools import lru_cache

from .checks import Headers, RedirectHop


DEFAULT_USER_AGENT = "HeaderHawk/1.0 (+https://github.com/harshzagade/HeaderHawk)"
SECURITY_TXT_PATH = "/.well-known/security.txt"
MAX_SECURITY_TXT_BYTES = 32 * 1024


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
    chain: list[RedirectHop] = field(default_factory=list)
    """Every response served while fetching, in order: (status, url).

    The last entry is the final response; the rest are redirects that were
    followed. A direct (no-redirect) fetch has a single-entry chain."""


class _RedirectCounter(urllib.request.HTTPRedirectHandler):
    """Redirect handler that records the redirect chain.

    Each hop stores the URL that served the redirect response and the 3xx
    status that pointed onward, so the chain can be audited for HTTPS
    downgrades and excessive length.
    """

    def __init__(self, max_redirects: int = 5):
        self.count = 0
        self.max_redirections = max_redirects
        self.chain: list[RedirectHop] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.count += 1
        self.chain.append(RedirectHop(url=req.get_full_url(), status=code))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@lru_cache(maxsize=256)
def preload_status(domain: str, timeout: float = 10.0) -> str:
    """Ask hstspreload.org whether *domain* is on the HSTS preload list.

    Returns the API's status string verbatim (``"preloaded"``, ``"unknown"``,
    ``"removed"``, ...). Raises FetchError when the API is unreachable or the
    response is not parseable. Results are cached per process, so repeated
    audits of the same domain (e.g. ``--watch``) do not hammer the API.
    """
    api_url = ("https://hstspreload.org/api/v2/status?domain="
               + urllib.parse.quote(domain, safe=""))
    request = urllib.request.Request(api_url,
                                     headers={"User-Agent": DEFAULT_USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError,
            ValueError) as exc:
        raise FetchError(
            f"Could not query hstspreload.org for {domain}: {exc}") from exc
    status = payload.get("status") if isinstance(payload, dict) else None
    if not isinstance(status, str) or not status:
        raise FetchError(
            f"Unexpected hstspreload.org response for {domain}: {payload!r}")
    return status


def fetch_security_txt(url: str, timeout: float = 10.0,
                       user_agent: str = DEFAULT_USER_AGENT) -> str | None:
    """Fetch ``/.well-known/security.txt`` from the URL's origin (RFC 9116).

    Returns the file text on a 200 response, or None when the server answers
    404/410 (the file is simply not published). Raises FetchError when the
    file cannot be retrieved at all — network errors, DNS failures, or an
    unexpected HTTP status — so callers can distinguish "missing" from
    "could not check". The body is capped at ``MAX_SECURITY_TXT_BYTES``;
    security.txt files are tiny by design, and this keeps a misbehaving
    server from filling memory.
    """
    parts = urllib.parse.urlsplit(normalize_url(url))
    host = parts.hostname or ""
    if not host:
        raise FetchError(f"Cannot derive a security.txt origin from {url!r}")
    port = f":{parts.port}" if parts.port else ""
    target = f"{parts.scheme}://{host}{port}{SECURITY_TXT_PATH}"
    request = urllib.request.Request(target,
                                     headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.status
            if status in (404, 410):
                return None
            if status != 200:
                raise FetchError(
                    f"security.txt answered HTTP {status} on {target}")
            raw = response.read(MAX_SECURITY_TXT_BYTES + 1)[:MAX_SECURITY_TXT_BYTES]
            try:
                charset = response.headers.get_content_charset() or "utf-8"
                return raw.decode(charset, errors="replace")
            except LookupError:
                return raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 410):
            return None
        raise FetchError(
            f"security.txt answered HTTP {exc.code} on {target}") from exc
    except (urllib.error.URLError, socket.timeout, TimeoutError,
            OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise FetchError(f"Could not fetch {target}: {reason}") from exc


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
            chain = redirector.chain + [RedirectHop(url=response.geturl(),
                                                    status=response.status)]
            return FetchResult(
                url=url,
                final_url=response.geturl(),
                status=response.status,
                headers=headers,
                redirects=redirector.count,
                elapsed_ms=int((time.monotonic() - start) * 1000),
                chain=chain,
            )
    except urllib.error.HTTPError as exc:
        # HTTP error responses (4xx/5xx) still carry headers worth analyzing.
        msg = exc.headers
        headers = {}
        if msg is not None:
            for key in msg.keys():
                headers.setdefault(key.lower(), []).extend(msg.get_all(key))
        chain = redirector.chain + [RedirectHop(url=exc.geturl() or url,
                                                status=exc.code)]
        return FetchResult(
            url=url,
            final_url=exc.geturl() or url,
            status=exc.code,
            headers=headers,
            redirects=redirector.count,
            elapsed_ms=int((time.monotonic() - start) * 1000),
            chain=chain,
        )
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise FetchError(f"Could not fetch {url}: {reason}") from exc
