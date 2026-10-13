"""Bulk mode: audit many targets listed in a file, print a summary grade table.

Target file format: one URL per line (https:// assumed when the scheme is
omitted), blank lines and '#' comments skipped. Per-target fetch failures
become ERROR rows instead of aborting the run.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass

from .checks import analyze
from .fetch import FetchError, fetch


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
    elapsed_ms: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "grade": self.grade,
            "score": self.score,
            "high_findings": self.high,
            "medium_findings": self.med,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
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


def audit_targets(urls: list[str], timeout: float, user_agent: str) -> list[BulkResult]:
    """Fetch and analyze each URL. Unreachable targets become error rows."""
    rows: list[BulkResult] = []
    for url in urls:
        try:
            result = fetch(url, timeout=timeout, user_agent=user_agent)
        except FetchError as exc:
            rows.append(BulkResult(url=url, error=str(exc)))
            continue
        scheme = urllib.parse.urlsplit(result.final_url).scheme or "https"
        meta = {
            "url": url,
            "final_url": result.final_url,
            "status_code": result.status,
            "redirects": result.redirects,
            "elapsed_ms": result.elapsed_ms,
            "redirect_chain": result.chain,
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
            elapsed_ms=result.elapsed_ms,
        ))
    return rows
