"""Report rendering: colorized text and machine-readable JSON."""

from __future__ import annotations

import json

from . import __version__
from .bulk import BulkResult
from .checks import GRADES, Finding, Report


_SEVERITY_ORDER = {"HIGH": 0, "MED": 1, "LOW": 2, "INFO": 3, "OK": 4}

_STATUS_ICON = {
    "pass": ("[+]", "green"),
    "missing": ("[-]", "red"),
    "weak": ("[!]", "yellow"),
    "info": ("[i]", "dim"),
}

_ANSI = {
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}

_GRADE_COLOR = {"A+": "green", "A": "green", "B": "cyan", "C": "yellow",
                "D": "yellow", "E": "red", "F": "red"}


def _paint(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_ANSI[color]}{text}{_ANSI['reset']}"


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings,
                  key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.check, f.header))


def render_text(report: Report, color: bool = True) -> str:
    """Human-readable report with grade, findings, and fix suggestions."""
    lines: list[str] = []
    paint = lambda t, c: _paint(t, c, color)  # noqa: E731

    lines.append(paint(f"HeaderHawk v{__version__} - HTTP security header audit", "bold"))
    target = report.final_url or report.url
    meta = f"Target: {target}"
    if report.status_code:
        meta += f"  (HTTP {report.status_code}"
        if report.redirects:
            meta += f", {report.redirects} redirect{'s' if report.redirects != 1 else ''}"
        meta += f", {report.elapsed_ms}ms)"
    lines.append(meta)
    lines.append("")

    grade_color = _GRADE_COLOR.get(report.grade, "reset")
    lines.append(paint(f"GRADE: {report.grade}   (score {report.score}/100)", grade_color))
    lines.append("")

    for finding in _sorted_findings(report.findings):
        icon, icon_color = _STATUS_ICON.get(finding.status, ("[?]", "dim"))
        head = f"{icon} {finding.check}"
        if finding.severity not in ("OK", "INFO"):
            head += f"  [{finding.severity}"
            if finding.score_delta:
                head += f" {finding.score_delta:+d}"
            head += "]"
        lines.append(paint(head, icon_color))
        lines.append(f"    {finding.summary}")
        if finding.detail:
            lines.append(paint(f"    Why: {finding.detail}", "dim"))
        if finding.fix:
            lines.append(paint(f"    Fix: {finding.fix}", "cyan"))
        lines.append("")

    lines.append(paint(
        f"Analyzed {report.headers_seen} response headers. "
        "Cookie flags are out of scope here - see the CookieScope project.",
        "dim"))
    return "\n".join(lines).rstrip() + "\n"


def render_json(report: Report) -> str:
    """Machine-readable report for piping into other tools."""
    payload = report.to_dict()
    payload["tool"] = f"HeaderHawk v{__version__}"
    return json.dumps(payload, indent=2) + "\n"


def grade_index(grade: str) -> int:
    """Position in the grade ladder (0 = best). Raises ValueError if unknown."""
    return GRADES.index(grade.upper())


def render_bulk_table(rows: list[BulkResult], color: bool = True) -> str:
    """Summary grade table for bulk mode: one row per target."""
    lines: list[str] = []
    paint = lambda t, c: _paint(t, c, color)  # noqa: E731

    ok = [r for r in rows if not r.error]
    failed = [r for r in rows if r.error]
    width = min(64, max((len(r.url) for r in rows), default=6))
    header = (f"{'Target':<{width}}  {'HTTP':>4}  {'Grade':<5}  "
              f"{'Score':>5}  {'High':>4}  {'Med':>3}")
    rule = "-" * len(header)

    noun = "target" if len(rows) == 1 else "targets"
    lines.append(paint(f"HeaderHawk v{__version__} - bulk audit ({len(rows)} {noun})", "bold"))
    lines.append(header)
    lines.append(rule)

    for row in rows:
        url = row.url if len(row.url) <= width else row.url[:width - 1] + "\u2026"
        if row.error:
            lines.append(f"{url:<{width}}  {'ERR':>4}  "
                         + paint(f"{'ERROR':<5}", "red")
                         + f"  {'-':>5}  {'-':>4}  {'-':>3}")
        else:
            grade_color = _GRADE_COLOR.get(row.grade, "reset")
            lines.append(f"{url:<{width}}  {row.status_code:>4}  "
                         + paint(f"{row.grade:<5}", grade_color)
                         + f"  {row.score:>5}  {row.high:>4}  {row.med:>3}")

    lines.append(rule)

    if ok:
        avg = sum(r.score for r in ok) // len(ok)
        worst = max(ok, key=lambda r: grade_index(r.grade)).grade
        summary = (f"{len(ok)} audited, avg score {avg}/100, "
                   f"worst grade {worst}")
    else:
        summary = "nothing audited"
    if failed:
        summary += f", {len(failed)} unreachable"
    lines.append(paint(summary, "dim"))
    for row in failed:
        lines.append(paint(f"  ! {row.url}: {row.error}", "red"))
    return "\n".join(lines).rstrip() + "\n"


def render_bulk_json(rows: list[BulkResult]) -> str:
    """Machine-readable bulk report: one object per target."""
    payload = {
        "tool": f"HeaderHawk v{__version__}",
        "target_count": len(rows),
        "targets": [r.to_dict() for r in rows],
    }
    return json.dumps(payload, indent=2) + "\n"
