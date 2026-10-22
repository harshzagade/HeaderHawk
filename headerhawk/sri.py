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
    """One external script/stylesheet/image referenced by the page."""

    tag: str          # "script" | "link" | "img"
    url: str          # absolute URL as written in the HTML
    has_integrity: bool
    has_crossorigin: bool = False


class _SubresourceParser(HTMLParser):
    """Collect external <script src>, <link rel=stylesheet href>, and <img src>."""

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
                    has_crossorigin="crossorigin" in attrs_map,
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
                        has_crossorigin="crossorigin" in attrs_map,
                    ))
        elif tag == "img":
            # Images are only relevant for the mixed-content check (SRI is
            # for scripts/stylesheets), but they ride in the same tag scan.
            src = attrs_map.get("src", "").strip()
            if src:
                self.resources.append(Subresource(
                    tag="img", url=src, has_integrity=False,
                    has_crossorigin="crossorigin" in attrs_map,
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
    OK-pass summary. ``<img>`` tags are out of SRI scope and are ignored
    here (they belong to the mixed-content check).
    """
    parser = _SubresourceParser()
    parser.feed(html)
    return [r for r in parser.resources if r.tag in ("script", "link")
            and _is_external(r.url) and not r.has_integrity]


def count_protected_resources(html: str) -> int:
    """How many external scripts/stylesheets DO carry ``integrity=``."""
    parser = _SubresourceParser()
    parser.feed(html)
    return sum(1 for r in parser.resources
               if r.tag in ("script", "link")
               and _is_external(r.url) and r.has_integrity)


def find_external_resources(html: str) -> list[Subresource]:
    """Every cross-origin script/stylesheet/image on the page (all tags)."""
    parser = _SubresourceParser()
    parser.feed(html)
    return [r for r in parser.resources if _is_external(r.url)]


def count_external_resources(html: str) -> int:
    """How many cross-origin subresources (scripts, stylesheets, images)
    the page loads — used for the text-report SRI footer count."""
    return len(find_external_resources(html))


def find_mixed_content(html: str) -> list[Subresource]:
    """Return subresources loaded over plain ``http://``.

    On an HTTPS page every ``http://`` load is mixed content: scripts and
    stylesheets are *active* mixed content (browsers block them, silently
    breaking the page), images are *passive* (browsers degrade and the padlock
    dies). Protocol-relative ``//`` URLs resolve to the page's own scheme and
    are not mixed content. The caller only runs this on HTTPS pages.
    """
    parser = _SubresourceParser()
    parser.feed(html)
    return [r for r in parser.resources
            if r.url.strip().lower().startswith("http://")]


def find_missing_crossorigin(html: str) -> list[Subresource]:
    """Return SRI-pinned external resources missing ``crossorigin=``.

    A cross-origin ``integrity=`` attribute is ignored unless the resource
    is fetched with CORS — i.e. the tag carries ``crossorigin="anonymous"``
    (or the empty/``use-credentials`` forms). Same-origin loads need no CORS
    and are out of scope here.
    """
    parser = _SubresourceParser()
    parser.feed(html)
    return [r for r in parser.resources if r.tag in ("script", "link")
            and _is_external(r.url) and r.has_integrity
            and not r.has_crossorigin]


@dataclass
class MetaHttpEquiv:
    """One ``<meta http-equiv="...">`` tag from the page head."""

    name: str     # lowercased http-equiv value, e.g. "refresh"
    content: str  # raw content attribute as written


class _MetaHttpEquivParser(HTMLParser):
    """Collect <meta http-equiv> tags."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[MetaHttpEquiv] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        if tag != "meta":
            return
        attrs_map = {name.lower(): (value or "") for name, value in attrs}
        http_equiv = attrs_map.get("http-equiv", "").strip()
        if http_equiv:
            self.tags.append(MetaHttpEquiv(
                name=http_equiv.lower(),
                content=attrs_map.get("content", "")))


def find_meta_http_equiv(html: str) -> list[MetaHttpEquiv]:
    """Return every ``<meta http-equiv="...">`` tag on the page.

    The audit in ``checks.check_meta_http_equiv()`` uses these to note
    security-relevant pragma directives and, crucially, which real response
    headers a meta tag can and cannot replace.
    """
    parser = _MetaHttpEquivParser()
    parser.feed(html)
    return parser.tags


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
