"""Bulk mode: audit many targets listed in a file, print a summary grade table.

Target file format: one URL per line (https:// assumed when the scheme is
omitted), blank lines and '#' comments skipped. Per-target fetch failures
become ERROR rows instead of aborting the run.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .checks import analyze
from .fetch import FetchError, fetch
from .sri import count_external_resources, fetch_html
from .tls import probe_tls

if TYPE_CHECKING:
    from .checks import Report


@dataclass
class BulkResult:
    """One row of a bulk audit."""

    url: str
    final_url: str = ""
    status_code: int = 0
    grade: str = ""
    score: int = -1
    high: int = 0
    med: int = 0
    low: int = 0
    info: int = 0
    elapsed_ms: int = 0
    error: str = ""
    # Negotiated TLS version from the --bulk-tls probe ("" when the probe
    # did not run, the target is plain HTTP, or the probe failed).
    tls_version: str = ""
    # Full per-target report (None for error rows). Kept out of to_dict()
    # so the bulk JSON table stays a compact summary; --bulk-output writes
    # these reports to per-target files.
    report: Report | None = field(default=None, repr=False)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "grade": self.grade,
            "score": self.score,
            "high_findings": self.high,
            "medium_findings": self.med,
            "low_findings": self.low,
            "info_findings": self.info,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
            "tls_version": self.tls_version,
        }


def read_targets(path: str) -> list[str]:
    """Read target URLs from a file. Raises ValueError/OSError on problems."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    targets = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    if not targets:
        raise ValueError(f"No targets found in {path!r} "
                         "(expected one URL per line)")
    return targets


def audit_targets(urls: list[str], timeout: float, user_agent: str,
                  sri: bool = False, tls: bool = False,
                  tls_timeout: float = 5.0) -> list[BulkResult]:
    """Fetch and analyze each URL. Unreachable targets become error rows.

    With ``sri=True`` each reachable target also gets one bounded HTML
    fetch for the Subresource Integrity audit (the same check single-URL
    ``--sri`` runs); a failed HTML fetch fails open for that target alone
    — the header audit still runs, just without SRI findings.
    With ``tls=True`` each reachable HTTPS target also gets the TLS
    version/cipher probe (the same probe single-URL audits run); the
    negotiated version lands in the row's ``tls_version`` for the bulk
    table. A failed probe fails open — display only, never a finding and
    never a grade penalty — and plain-HTTP targets are not probed.
    """
    rows: list[BulkResult] = []
    for url in urls:
        try:
            result = fetch(url, timeout=timeout, user_agent=user_agent)
        except FetchError as exc:
            rows.append(BulkResult(url=url, error=str(exc)))
            continue
        scheme = urllib.parse.urlsplit(result.final_url).scheme or "https"
        tls_version = ""
        if tls and scheme == "https":
            parts = urllib.parse.urlsplit(result.final_url)
            if parts.hostname:
                try:
                    info = probe_tls(parts.hostname,
                                     port=parts.port or 443,
                                     timeout=tls_timeout)
                    tls_version = info.negotiated if not info.error else ""
                except Exception:  # noqa: BLE001 - probe fails open
                    tls_version = ""
        sri_html: str | None = None
        sri_seen = 0
        if sri:
            try:
                page = fetch_html(url, timeout=timeout, user_agent=user_agent)
                sri_html = page.html
                sri_seen = count_external_resources(sri_html)
            except FetchError:
                pass  # fail open per target: header-only audit, no SRI
        meta = {
            "url": url,
            "final_url": result.final_url,
            "status_code": result.status,
            "redirects": result.redirects,
            "elapsed_ms": result.elapsed_ms,
            "redirect_chain": result.chain,
            "sri_html": sri_html,
            "sri_seen": sri_seen,
        }
        report = analyze(result.headers, scheme=scheme, meta=meta)
        rows.append(BulkResult(
            url=url,
            final_url=result.final_url,
            status_code=result.status,
            grade=report.grade,
            score=report.score,
            high=sum(1 for f in report.findings if f.severity == "HIGH"),
            med=sum(1 for f in report.findings if f.severity == "MED"),
            low=sum(1 for f in report.findings if f.severity == "LOW"),
            info=sum(1 for f in report.findings if f.severity == "INFO"),
            elapsed_ms=result.elapsed_ms,
            tls_version=tls_version,
            report=report,
        ))
    return rows


def bulk_report_filename(url: str, ext: str, used: set[str]) -> str:
    """Derive a filesystem-safe per-target report filename from *url*.

    Host + path with every run of unsafe characters collapsed to one
    underscore (``https://example.com/a/b`` -> ``example.com_a_b.txt``).
    The query string is ignored, so two targets that sanitize identically
    get ``-2``, ``-3`` suffixes; *used* tracks names already handed out
    and gains the returned name.
    """
    parsed = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
    host = parsed.hostname or "target"
    path = parsed.path.strip("/")
    base = host + ("_" + path if path else "")
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._") or "target"
    name = f"{base}.{ext}"
    if name not in used:
        used.add(name)
        return name
    suffix = 2
    while f"{base}-{suffix}.{ext}" in used:
        suffix += 1
    name = f"{base}-{suffix}.{ext}"
    used.add(name)
    return name
