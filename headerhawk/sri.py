"""Subresource Integrity (SRI) audit: fetch a page's HTML and flag external
scripts/stylesheets that load without an ``integrity=`` attribute.

SRI lets a site pin a cross-origin script or stylesheet to a cryptographic
hash: if the CDN copy is tampered with, the browser refuses to load it.
A third-party script without SRI is a single point of compromise for every
visitor. stdlib only (``html.parser`` + ``urllib``).
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser

from .fetch import (DEFAULT_USER_AGENT, FetchError, _RedirectCounter,
                    normalize_url)

MAX_HTML_BYTES = 2 * 1024 * 1024  # 2 MB cap on the fetched HTML body


@dataclass
class Subresource:
    """One external script/stylesheet referenced by the page."""

    tag: str          # "script" | "link"
    url: str          # absolute URL as written in the HTML
    has_integrity: bool


class _SubresourceParser(HTMLParser):
    """Collect external <script src> and <link rel=stylesheet href> tags."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.resources: list[Subresource] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attrs_map = {name.lower(): (value or "") for name, value in attrs}
        if tag == "script":
            src = attrs_map.get("src", "").strip()
            if src:
                self.resources.append(Subresource(
                    tag="script", url=src,
                    has_integrity=bool(attrs_map.get("integrity", "").strip()),
                ))
        elif tag == "link":
            rel = attrs_map.get("rel", "").lower()
            # rel is space-separated ("stylesheet", "preload stylesheet"...).
            if "stylesheet" in rel.split():
                href = attrs_map.get("href", "").strip()
                if href:
                    self.resources.append(Subresource(
                        tag="link", url=href,
                        has_integrity=bool(attrs_map.get("integrity", "").strip()),
                    ))


def _is_external(url: str) -> bool:
    """True for cross-origin loads: absolute http(s) or protocol-relative URLs.

    Relative paths and same-document fragments are same-origin loads —
    SRI is a cross-origin trust mechanism, so those are out of scope.
    """
    lowered = url.strip().lower()
    return (lowered.startswith("http://") or lowered.startswith("https://")
            or lowered.startswith("//"))


def find_unprotected_resources(html: str) -> list[Subresource]:
    """Return external scripts/stylesheets missing an ``integrity=`` hash.

    Returns the external subresources WITHOUT integrity attributes. An empty
    list means every external script/stylesheet is SRI-protected (or there
    are none to check); ``protected`` counts the SRI-covered ones for the
    OK-pass summary.
    """
    parser = _SubresourceParser()
    parser.feed(html)
    return [r for r in parser.resources if _is_external(r.url)
            and not r.has_integrity]


def count_protected_resources(html: str) -> int:
    """How many external scripts/stylesheets DO carry ``integrity=``."""
    parser = _SubresourceParser()
    parser.feed(html)
    return sum(1 for r in parser.resources
               if _is_external(r.url) and r.has_integrity)


@dataclass
class HTMLFetchResult:
    url: str
    final_url: str
    status: int
    html: str
    truncated: bool = False


def fetch_html(url: str, timeout: float = 10.0,
               user_agent: str = "HeaderHawk/1.0",
               max_bytes: int = MAX_HTML_BYTES) -> HTMLFetchResult:
    """GET the URL and return its HTML body (capped at ``max_bytes``).

    Follows redirects like :func:`headerhawk.fetch.fetch`. Raises
    :class:`headerhawk.fetch.FetchError` when the fetch fails, the
    Content-Type is not HTML, or the body cannot be decoded.
    """
    import urllib.error
    import urllib.request

    url = normalize_url(url)
    redirector = _RedirectCounter()
    opener = urllib.request.build_opener(redirector)
    request = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        with opener.open(request, timeout=timeout) as response:
            content_type = (response.headers.get("Content-Type") or "")
            if "html" not in content_type.lower():
                raise FetchError(
                    f"Not an HTML page (Content-Type: {content_type or 'none'}); "
                    "Subresource Integrity auditing needs page HTML.")
            raw = response.read(max_bytes + 1)
            truncated = len(raw) > max_bytes
            raw = raw[:max_bytes]
            charset = response.headers.get_content_charset() or "utf-8"
            try:
                html = raw.decode(charset, errors="replace")
            except LookupError as exc:
                raise FetchError(
                    f"Unknown charset {charset!r} in response.") from exc
            return HTMLFetchResult(
                url=url, final_url=response.geturl(), status=response.status,
                html=html, truncated=truncated)
    except urllib.error.HTTPError as exc:
        raise FetchError(
            f"Could not fetch page HTML for {url}: HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise FetchError(f"Could not fetch page HTML for {url}: {reason}") from exc
