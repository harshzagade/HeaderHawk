"""Report rendering: colorized text and machine-readable JSON."""

from __future__ import annotations

import json
from dataclasses import dataclass

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


def render_text(report: Report, color: bool = True,
                only: set[str] | None = None) -> str:
    """Human-readable report with grade, findings, and fix suggestions.

    ``only`` is an optional set of severities (e.g. {"HIGH", "MED"}) used to
    hide lower-priority findings from the display. Filtering is display-only:
    the grade and score are always computed from every finding.
    """
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

    findings = _sorted_findings(report.findings)
    if only is not None:
        shown = [f for f in findings if f.severity in only]
        hidden = len(findings) - len(shown)
        names = ", ".join(sorted(only, key=lambda s: _SEVERITY_ORDER.get(s, 9)))
        lines.append(paint(
            f"Showing only {names} findings "
            f"({hidden} lower-priority finding{'s' if hidden != 1 else ''} hidden; "
            "grade/score still reflect all findings).", "dim"))
        findings = shown
    lines.append("")

    for finding in findings:
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


# ---------------------------------------------------------------------------
# Compare mode: before/after diff of two reports
# ---------------------------------------------------------------------------

@dataclass
class CompareRow:
    """One changed finding between report A (before) and B (after)."""

    verdict: str  # "regressed" | "new" | "resolved" | "improved"
    check: str
    header: str
    before: Finding | None
    after: Finding | None


def _finding_key(finding: Finding) -> tuple:
    return (finding.check, finding.header, finding.summary)


def _finding_rank(finding: Finding) -> tuple[int, int]:
    """(severity rank, score delta); higher = better. OK=4 .. HIGH=0."""
    return (_SEVERITY_ORDER.get(finding.severity, 9), finding.score_delta)


def diff_reports(before: Report, after: Report) -> list[CompareRow]:
    """Diff two reports finding-by-finding.

    Findings are matched on (check, header, summary). A finding present in
    both with a worse severity/delta in ``after`` is a regression; with a
    better one, an improvement. Findings only in ``after`` are new; only in
    ``before`` are resolved. Unchanged findings are omitted.
    """
    before_map = {_finding_key(f): f for f in before.findings}
    after_map = {_finding_key(f): f for f in after.findings}
    rows: list[CompareRow] = []
    for key, old in before_map.items():
        new = after_map.get(key)
        if new is None:
            rows.append(CompareRow("resolved", old.check, old.header, old, None))
        elif _finding_rank(new) > _finding_rank(old):
            rows.append(CompareRow("improved", old.check, old.header, old, new))
        elif _finding_rank(new) < _finding_rank(old):
            rows.append(CompareRow("regressed", old.check, old.header, old, new))
    for key, new in after_map.items():
        if key not in before_map:
            rows.append(CompareRow("new", new.check, new.header, None, new))
    # Stable, readable order: regressions first, then new, resolved, improved.
    order = {"regressed": 0, "new": 1, "resolved": 2, "improved": 3}
    return sorted(rows, key=lambda r: (order[r.verdict], r.check, r.header))


def _verdict_line(row: CompareRow) -> str:
    """One-line description of what changed, for text rendering."""
    if row.verdict in ("improved", "regressed"):
        old, new = row.before, row.after
        return (f"{old.summary}  ->  "
                f"[{new.severity}{f' {new.score_delta:+d}' if new.score_delta else ''}] "
                f"{new.summary}")
    finding = row.after or row.before
    tag = ""
    if finding.severity not in ("OK", "INFO"):
        tag = f"  [{finding.severity}"
        if finding.score_delta:
            tag += f" {finding.score_delta:+d}"
        tag += "]"
    return f"{finding.summary}{tag}"


def render_compare(before: Report, after: Report, color: bool = True) -> str:
    """Side-by-side before/after comparison of two audit reports."""
    lines: list[str] = []
    paint = lambda t, c: _paint(t, c, color)  # noqa: E731

    lines.append(paint(f"HeaderHawk v{__version__} - compare", "bold"))
    lines.append(f"  Before: {before.final_url or before.url}  "
                 f"(grade {before.grade}, score {before.score}/100)")
    lines.append(f"  After:  {after.final_url or after.url}  "
                 f"(grade {after.grade}, score {after.score}/100)")
    delta = after.score - before.score
    lines.append(paint(f"  Score change: {delta:+d} "
                       f"({before.grade} -> {after.grade})",
                       "green" if delta > 0 else "red" if delta < 0 else "dim"))
    lines.append("")

    rows = diff_reports(before, after)
    if not rows:
        lines.append(paint("No differences: both targets produced identical findings.", "dim"))
        return "\n".join(lines).rstrip() + "\n"

    icons = {"regressed": ("[!]", "red"), "new": ("[-]", "yellow"),
             "resolved": ("[+]", "green"), "improved": ("[+]", "green")}
    titles = {"regressed": "Regressed", "new": "New findings",
              "resolved": "Resolved", "improved": "Improved"}
    for verdict in ("regressed", "new", "resolved", "improved"):
        group = [r for r in rows if r.verdict == verdict]
        if not group:
            continue
        icon, icon_color = icons[verdict]
        lines.append(paint(f"{titles[verdict]} ({len(group)})", icon_color))
        for row in group:
            lines.append(paint(f"  {icon} {row.check}  ({row.header})", icon_color))
            lines.append(f"      {_verdict_line(row)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_compare_json(before: Report, after: Report) -> str:
    """Machine-readable compare report: both reports plus the diff."""
    def finding_dict(finding: Finding | None) -> dict | None:
        if finding is None:
            return None
        return {
            "check": finding.check,
            "header": finding.header,
            "status": finding.status,
            "severity": finding.severity,
            "score_delta": finding.score_delta,
            "summary": finding.summary,
            "detail": finding.detail,
            "fix": finding.fix,
        }

    payload = {
        "tool": f"HeaderHawk v{__version__}",
        "before": before.to_dict(),
        "after": after.to_dict(),
        "score_delta": after.score - before.score,
        "grade_before": before.grade,
        "grade_after": after.grade,
        "diff": [
            {
                "verdict": row.verdict,
                "check": row.check,
                "header": row.header,
                "before": finding_dict(row.before),
                "after": finding_dict(row.after),
            }
            for row in diff_reports(before, after)
        ],
    }
    return json.dumps(payload, indent=2) + "\n"
