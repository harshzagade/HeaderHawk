"""Report rendering: colorized text and machine-readable JSON."""

from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass

from . import __version__
from .bulk import BulkResult
from .checks import GRADES, Finding, Report
from .history import HistoryEntry


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

    if report.cookies_seen:
        noun = "cookie" if report.cookies_seen == 1 else "cookies"
        cookie_issues = sum(1 for f in report.findings
                            if f.check == "Cookie flags"
                            and f.severity not in ("OK", "INFO"))
        noun_issue = "issue" if cookie_issues == 1 else "issues"
        footer = (f"Analyzed {report.headers_seen} response headers; audited "
                  f"cookie flags on {report.cookies_seen} {noun} "
                  f"({cookie_issues} {noun_issue} above).")
    else:
        footer = (f"Analyzed {report.headers_seen} response headers. "
                  "No Set-Cookie headers seen; cookie flags not applicable.")
    if report.sri_seen:
        sri_noun = "resource" if report.sri_seen == 1 else "resources"
        sri_issues = sum(1 for f in report.findings
                         if f.check == "Subresource Integrity"
                         and f.severity not in ("OK", "INFO"))
        sri_noun_issue = "issue" if sri_issues == 1 else "issues"
        footer += (f" Audited Subresource Integrity on "
                   f"{report.sri_seen} external {sri_noun} "
                   f"({sri_issues} {sri_noun_issue} above).")
    lines.append(paint(footer, "dim"))
    return "\n".join(lines).rstrip() + "\n"


def render_json(report: Report) -> str:
    """Machine-readable report for piping into other tools."""
    payload = report.to_dict()
    payload["tool"] = f"HeaderHawk v{__version__}"
    return json.dumps(payload, indent=2) + "\n"


_EXPLAIN_LEAD = {
    "HIGH": "the problems worth fixing before anything else, because these are the ones attackers look for first",
    "MED": "the problems worth fixing right after the HIGH ones",
    "LOW": "leftover hardening — worth fixing when convenient, not urgent",
    "INFO": "background notes, not problems: useful context, nothing to fix",
    "OK": "the things the site already does right: no action needed",
}


def _explain_paragraph(report: Report, severity: str, count: int) -> str:
    """One plain-English paragraph closing an --explain report."""
    target = report.final_url or report.url
    lead = _EXPLAIN_LEAD[severity]
    if severity in ("INFO", "OK"):
        return (f"In plain English: the items above are {lead}. "
                f"{target} needs nothing from you on this front.")
    noun = "issue" if count == 1 else "issues"
    return (f"In plain English: {target} has {count} {severity.lower()}-severity "
            f"{noun} — {lead}. The fix for each item is a setting on the web "
            f"server (usually a single response header to add or edit), not a "
            f"change to the website's code, so whoever runs the server can "
            f"normally clear this whole list in one sitting. The score is "
            f"currently {report.score}/100, and fixing every item above "
            f"pushes it up.")


def render_explain(report: Report, severity: str, color: bool = True) -> str:
    """Plain-English explainer for one severity, for non-security teammates.

    Shows only findings with ``severity`` (grade/score still reflect every
    finding) with "what it means" / "what to do" notes, and closes with one
    plain-English paragraph summarizing the list. Grade and score are shown
    for context, not re-computed from the filtered set.
    """
    lines: list[str] = []
    paint = lambda t, c: _paint(t, c, color)  # noqa: E731
    target = report.final_url or report.url

    lines.append(paint(
        f"HeaderHawk v{__version__} - {severity} findings, in plain English",
        "bold"))
    lines.append(f"Target: {target}   (grade {report.grade}, "
                 f"score {report.score}/100)")
    lines.append("")

    findings = [f for f in _sorted_findings(report.findings)
                if f.severity == severity]
    if not findings:
        lines.append(paint(f"Good news: no {severity} findings on {target}.",
                           "green"))
        if severity in ("HIGH", "MED", "LOW"):
            lines.append("Nothing in this severity band needs attention.")
        lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    for finding in findings:
        icon, icon_color = _STATUS_ICON.get(finding.status, ("[?]", "dim"))
        lines.append(paint(f"{icon} {finding.check}: {finding.summary}",
                           icon_color))
        if finding.detail:
            lines.append(f"    What it means: {finding.detail}")
        if finding.fix:
            lines.append(paint(f"    What to do: {finding.fix}", "cyan"))
        lines.append("")

    lines.append(paint(_explain_paragraph(report, severity, len(findings)),
                       "dim"))
    return "\n".join(lines).rstrip() + "\n"


def render_summary_line(report: Report) -> str:
    """One-line summary: ``A+ 100 example.com`` — for status bars / CI matrices.

    Grade, score, and the target host, nothing else. The host comes from the
    final URL after redirects; for offline (``--headers``) runs the raw
    header source is used when no host can be parsed.
    """
    target = report.final_url or report.url
    host = urllib.parse.urlsplit(target).hostname or target
    return f"{report.grade} {report.score} {host}\n"


def grade_index(grade: str) -> int:
    """Position in the grade ladder (0 = best). Raises ValueError if unknown."""
    return GRADES.index(grade.upper())


def _history_trend_verdict(rows: list[HistoryEntry]) -> str:
    """One-word verdict for a run series: improving/declining/steady."""
    if len(rows) < 2:
        return "steady"
    first, last = rows[0].score, rows[-1].score
    if last > first:
        return "improving"
    if last < first:
        return "declining"
    return "steady"


def render_history_report(entries: list[HistoryEntry], skipped: int = 0,
                           color: bool = True) -> str:
    """Render the recorded grade history as a per-URL trend report.

    Runs are grouped by URL (first-seen order); each group shows a run table
    with the score change versus the previous run, plus a one-line trend
    verdict. ``skipped`` is the number of malformed lines ignored while
    reading the history file.
    """
    lines: list[str] = []
    paint = lambda t, c: _paint(t, c, color)  # noqa: E731
    lines.append(paint(f"HeaderHawk v{__version__} - grade history", "bold"))

    if not entries:
        lines.append("No history recorded yet.")
        if skipped:
            lines.append(f"Skipped {skipped} malformed line(s).")
        return "\n".join(lines) + "\n"

    urls: dict[str, list[HistoryEntry]] = {}
    for entry in entries:
        urls.setdefault(entry.url, []).append(entry)
    lines.append(f"{len(entries)} run(s) across {len(urls)} URL(s).")
    if skipped:
        lines.append(paint(f"Skipped {skipped} malformed line(s) while "
                           f"reading the history file.", "dim"))
    lines.append("")

    for url, rows in urls.items():
        delta = rows[-1].score - rows[0].score
        verdict = _history_trend_verdict(rows)
        lines.append(paint(
            f"{url} — {verdict}: {rows[0].grade} -> {rows[-1].grade} "
            f"(score {rows[0].score} -> {rows[-1].score}, {delta:+d} "
            f"over {len(rows)} run(s))", "bold"))
        lines.append(f"  {'Timestamp':<20} {'Grade':<6} {'Score':<6} Change")
        prev: HistoryEntry | None = None
        for row in rows:
            ts = row.timestamp.replace("T", " ")[:19]
            if prev is None:
                change = "first run"
            else:
                d = row.score - prev.score
                change = f"{d:+d}" if d else "—"
            lines.append(f"  {ts:<20} {row.grade:<6} {row.score:<6} {change}")
            prev = row
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def report_from_dict(payload: dict) -> Report:
    """Rebuild a Report from a ``--json`` payload dict.

    Used by ``--diff-against``: replays a saved baseline so it can be diffed
    against a fresh audit with the standard compare renderer. Unknown or
    missing fields fall back to harmless defaults; anything that is not a
    dict at all raises ValueError.
    """
    if not isinstance(payload, dict):
        raise ValueError("baseline is not a JSON object")
    findings = []
    raw_findings = payload.get("findings", [])
    if not isinstance(raw_findings, list):
        raise ValueError("baseline 'findings' is not a list")
    for raw in raw_findings:
        if not isinstance(raw, dict):
            raise ValueError("baseline finding is not an object")
        findings.append(Finding(
            check=str(raw.get("check", "")),
            header=str(raw.get("header", "")),
            status=str(raw.get("status", "info")),
            severity=str(raw.get("severity", "INFO")),
            score_delta=int(raw.get("score_delta", 0) or 0),
            summary=str(raw.get("summary", "")),
            detail=str(raw.get("detail", "")),
            fix=str(raw.get("fix", "")),
        ))
    return Report(
        url=str(payload.get("url", "")),
        final_url=str(payload.get("final_url", "") or ""),
        status_code=int(payload.get("status_code", 0) or 0),
        redirects=int(payload.get("redirects", 0) or 0),
        elapsed_ms=int(payload.get("elapsed_ms", 0) or 0),
        scheme=str(payload.get("scheme", "")),
        score=int(payload.get("score", 100) or 0),
        grade=str(payload.get("grade", "")),
        findings=findings,
        headers_seen=int(payload.get("headers_seen", 0) or 0),
        cookies_seen=int(payload.get("cookies_seen", 0) or 0),
        sri_seen=int(payload.get("sri_seen", 0) or 0),
    )


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
