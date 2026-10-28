"""Command-line interface for HeaderHawk."""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import os
import sys
import time
import urllib.parse

from . import __version__
from .bulk import audit_targets, bulk_report_filename, read_targets
from .checks import Headers, Report, analyze, get
from .fetch import (DEFAULT_USER_AGENT, FetchError, fetch, fetch_security_txt,
                   preload_status)
from .history import append_run, read_history
from .offline import load_headers
from .report import (_SEVERITY_ORDER, diff_reports, grade_index,
                      render_bulk_json, render_bulk_table, render_bulk_worst,
                      render_compare, render_compare_json,
                      render_explain, render_history_report, render_json,
                      render_summary_line, render_text, report_from_dict,
                      worst_bulk_row)
from .sri import (count_external_resources, fetch_html)
from .tls import probe_tls


_VALID_SEVERITIES = ("HIGH", "MED", "LOW", "INFO", "OK")


def _parse_only(value: str | None) -> set[str] | None:
    """Parse --only into a severity set. Raises ValueError on unknown input."""
    if value is None:
        return None
    severities = {part.strip().upper() for part in value.split(",") if part.strip()}
    unknown = [s for s in severities if s not in _VALID_SEVERITIES]
    if unknown:
        raise ValueError(
            f"unknown severity {unknown[0]!r} in --only "
            f"(use one or more of {', '.join(_VALID_SEVERITIES)}).")
    return severities


def _parse_explain(value: str | None) -> str | None:
    """Parse --explain into a single severity. Raises ValueError on bad input."""
    if value is None:
        return None
    if "," in value:
        raise ValueError("--explain takes a single severity "
                         "(e.g. --explain HIGH); use --only for several.")
    severity = value.strip().upper()
    if severity not in _VALID_SEVERITIES:
        raise ValueError(
            f"unknown severity {severity!r} in --explain "
            f"(use one of {', '.join(_VALID_SEVERITIES)}).")
    return severity


def _parse_fail_on(value: str | None) -> int | None:
    """Parse --fail-on into a severity rank (lower = more severe).

    "At or above" means rank <= the threshold rank: --fail-on MED fails on
    HIGH and MED findings. Raises ValueError on unknown input.
    """
    if value is None:
        return None
    rank = _SEVERITY_ORDER.get(value.strip().upper())
    if rank is None:
        raise ValueError(
            f"unknown severity {value!r} in --fail-on "
            f"(use one of {', '.join(_VALID_SEVERITIES)}).")
    return rank


def _findings_at_or_above(report: Report, max_rank: int) -> list:
    """Return the report's findings whose severity is at or above the rank."""
    return [f for f in report.findings
            if _SEVERITY_ORDER.get(f.severity, 99) <= max_rank]



def _terminal_safe(text: str) -> str:
    """Render *text* safe for terminal output.

    Replaces non-printable characters (C0/C1 controls, DEL) with visible
    ``\\xNN`` escapes, so a hostile response header cannot inject ANSI/OSC
    escape sequences into the user's terminal via ``--raw``.
    """
    return "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headerhawk",
        description=("Audit a site's HTTP security headers, grade them A+..F, "
                     "and suggest fixes. Works live or fully offline on saved headers."),
    )
    parser.add_argument("url", nargs="?",
                        help="Target URL to fetch and analyze (https:// assumed).")
    parser.add_argument("--headers", metavar="FILE",
                        help="Analyze raw saved headers instead of fetching "
                             "(use '-' or omit FILE with piped stdin).")
    parser.add_argument("--json", action="store_true",
                        help="Emit a machine-readable JSON report.")
    parser.add_argument("--summary-line", action="store_true",
                        help="Print a one-line summary (GRADE SCORE HOST, "
                             "e.g. 'A+ 100 example.com') instead of the full "
                             "report. Made for status bars and CI matrices. "
                             "Cannot be combined with --json, --raw, --only, "
                             "--explain, --bulk, --compare, or --watch.")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colors in the text report.")
    parser.add_argument("--only", metavar="SEV",
                        help="Show only findings with these severities in the text "
                             "report (comma-separated, e.g. --only HIGH,MED). "
                             "Grade/score still reflect all findings; JSON "
                             "output is unaffected.")
    parser.add_argument("--explain", metavar="SEV",
                        help="Plain-English explainer for one severity "
                             "(e.g. --explain HIGH): show only findings with "
                             "this severity, each with 'what it means' and "
                             "'what to do' notes, plus a one-paragraph summary "
                             "for non-security teammates. Grade/score still "
                             "reflect all findings. Cannot be combined with "
                             "--only or --json.")
    parser.add_argument("--timeout", type=float, default=10.0, metavar="SEC",
                        help="Fetch timeout in seconds (default: 10).")
    parser.add_argument("--tls-timeout", type=float, default=5.0,
                        metavar="SEC",
                        help="TLS handshake probe timeout in seconds "
                             "(default: 5). Cannot be combined with --no-tls, "
                             "which skips the probe entirely.")
    parser.add_argument("--no-tls", action="store_true",
                        help="Skip the TLS version/cipher probe: header-only "
                             "audits for speed (the TLS check is skipped, not "
                             "penalized). Applies to single-target, --compare, "
                             "and --watch audits.")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, metavar="UA",
                        help="User-Agent string for live fetches.")
    parser.add_argument("--fail-below", metavar="GRADE",
                        help="Exit 1 unless the grade is at least GRADE "
                             "(e.g. --fail-below B for CI gates).")
    parser.add_argument("--fail-on", metavar="SEVERITY",
                        help="Exit 1 when any finding at or above SEVERITY "
                             "exists (e.g. --fail-on MED for CI gates). "
                             "Independent of --fail-below: a passing grade "
                             "can still hide a HIGH finding.")
    parser.add_argument("--raw", action="store_true",
                        help="Print the raw response headers before the report.")
    parser.add_argument("--bulk", metavar="FILE",
                        help="Bulk mode: read target URLs from FILE (one per line) "
                             "and print a summary grade table.")
    parser.add_argument("--bulk-output", metavar="DIR",
                        help="Bulk mode only: also write each target's full "
                             "report to DIR (one file per target, named from "
                             "its host and path; text files, or JSON with "
                             "--json). Unreachable targets get no file.")
    parser.add_argument("--bulk-worst", action="store_true",
                        help="Bulk mode only: after the summary table, print "
                             "the full text report of the single "
                             "worst-graded target, for triage without "
                             "re-running it. With --json, the worst target "
                             "and its full report appear as a 'worst_target' "
                             "key instead.")
    parser.add_argument("--bulk-tls", action="store_true",
                        help="Bulk mode only: run the TLS version/cipher "
                             "probe per reachable HTTPS target and add a "
                             "TLS column (negotiated version) to the bulk "
                             "table. A failed probe shows '-' and never "
                             "penalizes the grade. Cannot be combined with "
                             "--no-tls.")
    parser.add_argument("--compare", nargs=2, metavar=("URL_A", "URL_B"),
                        help="Compare two targets side by side: fetch URL_A and "
                             "URL_B, and show what changed (regressed, new, "
                             "resolved, improved findings). Made for before/after "
                             "hardening checks. --fail-below gates on URL_B. "
                             "Add --ignore-info to hide INFO/OK-only diffs.")
    parser.add_argument("--ignore-info", action="store_true",
                        help="Compare modes only: hide INFO/OK-only diffs in "
                             "--compare and --diff-against output so "
                             "before/after reviews focus on real changes. "
                             "A diff is hidden only when every finding it "
                             "carries is INFO or OK severity.")
    parser.add_argument("--diff-against", metavar="FILE",
                        help="Compare the fresh audit against a saved --json "
                             "baseline FILE: drift detection without needing "
                             "two live URLs. Prints the same before/after "
                             "diff as --compare; --fail-below gates on the "
                             "fresh audit. Works with --json for a "
                             "machine-readable diff. Cannot be combined with "
                             "--bulk, --compare, --watch, --raw, --only, "
                             "--explain, or --summary-line.")
    parser.add_argument("--watch", type=float, default=None, metavar="SEC",
                        help="Watch mode: re-audit the URL every SEC seconds "
                             "and print an alert only when the grade or "
                             "findings change (for monitoring your own site "
                             "after deploys). Ctrl-C stops. Single live-URL "
                             "mode only; cannot be combined with --bulk, "
                             "--compare, --headers, --raw, --only, --explain, "
                             "--output, or --json.")
    parser.add_argument("--watch-log", metavar="FILE",
                        help="Watch mode only: append timestamped events "
                             "(baseline, change alerts, fetch gaps, stop) to "
                             "FILE, so overnight runs leave an audit trail. "
                             "Requires --watch.")
    parser.add_argument("--sri", action="store_true",
                        help="Subresource Integrity audit: fetch the page HTML "
                             "and flag external scripts/stylesheets loading "
                             "without an integrity= hash (MED each). Live "
                             "single-URL and --bulk modes (one bounded HTML "
                             "fetch per bulk target; a failed fetch fails "
                             "open for that target); cannot be combined with "
                             "--headers, --watch, or --compare.")
    parser.add_argument("--history", metavar="FILE",
                        help="Grade history: append (timestamp, url, grade, "
                             "score) to FILE after this audit, for tracking "
                             "hardening progress over time. Single-target "
                             "mode only; cannot be combined with --bulk, "
                             "--compare, or --watch.")
    parser.add_argument("--history-report", metavar="FILE",
                        help="Print the grade-history trend report from FILE "
                             "(report-only mode; no audit is run). Cannot be "
                             "combined with any other mode or output option.")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Write the report to FILE instead of stdout.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _looks_like_ip(host: str) -> bool:
    """True for IP literals (v4/v6), where preload-list checks make no sense."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _hsts_preload_status(url: str, headers: Headers, scheme: str,
                         timeout: float) -> str | None:
    """Query hstspreload.org when the target advertises HSTS preload.

    Returns the list status (``"preloaded"``/``"unknown"``/...), ``"unchecked"``
    when the check does not apply (no preload directive, non-HTTPS, IP
    target), or None when the API could not be reached — the failed query
    surfaces as an informational finding via check_hsts_preload, never a
    hard error.
    """
    if scheme != "https":
        return "unchecked"
    hsts = get(headers, "strict-transport-security")
    if hsts is None or "preload" not in hsts.lower():
        return "unchecked"
    host = urllib.parse.urlsplit(url).hostname or ""
    if not host or _looks_like_ip(host):
        return "unchecked"
    try:
        return preload_status(host, timeout=timeout)
    except FetchError:
        return None


def _audit_one(url: str, *, timeout: float,
               user_agent: str, sri: bool = False,
               quiet_secondary: bool = False,
               no_tls: bool = False,
               tls_timeout: float = 5.0) -> tuple[Report, Headers]:
    """Fetch a URL once and return (report, raw headers).

    The HSTS preload-list status is queried when the response advertises a
    preload directive (cached per process inside fetch.preload_status).
    With ``sri=True`` the page HTML is fetched too (bounded at 2 MB) and
    audited for Subresource Integrity; an HTML fetch failure only prints a
    warning — the header audit still runs. ``quiet_secondary`` suppresses
    the stderr warnings for optional secondary fetches (--sri, security.txt)
    — used by --watch, where a per-interval warning would just be noise;
    the failure still surfaces as an INFO finding in each report.
    With ``no_tls=True`` (--no-tls) the TLS version/cipher probe is skipped
    entirely for fast header-only audits; the TLS check reports nothing
    rather than penalizing the grade. ``tls_timeout`` (--tls-timeout) caps
    each TLS handshake probe at that many seconds.
    """
    result = fetch(url, timeout=timeout, user_agent=user_agent)
    scheme = urllib.parse.urlsplit(result.final_url).scheme or "https"
    tls: object = "unchecked"
    if scheme == "https" and not no_tls:
        # TLS version/cipher sniff: only makes sense for HTTPS targets.
        # Never fatal — probe failures surface as an informational finding.
        parts = urllib.parse.urlsplit(result.final_url)
        host = parts.hostname or ""
        port = parts.port or 443
        if host:
            tls = probe_tls(host, port=port, timeout=tls_timeout)
    def _secondary_warning(exc: FetchError, message: str) -> None:
        if not quiet_secondary:
            print(f"warning: {message}: {exc}", file=sys.stderr)

    sri_html: str | None = None
    sri_seen = 0
    if sri:
        try:
            page = fetch_html(url, timeout=timeout, user_agent=user_agent)
            sri_html = page.html
            sri_seen = count_external_resources(sri_html)
        except FetchError as exc:
            _secondary_warning(exc, "--sri audit skipped")
    try:
        # security.txt lives at the origin, independent of the fetched path;
        # use the final (post-redirect) URL so it tracks the real target.
        security_body = fetch_security_txt(result.final_url, timeout=timeout,
                                           user_agent=user_agent)
        security_txt: tuple[bool, str | None] | None = (
            (True, security_body) if security_body is not None
            else (False, None))
    except FetchError as exc:
        _secondary_warning(exc, "security.txt check skipped")
        security_txt = None
    meta = {
        "url": url,
        "final_url": result.final_url,
        "status_code": result.status,
        "redirects": result.redirects,
        "elapsed_ms": result.elapsed_ms,
        "redirect_chain": result.chain,
        "tls": tls,
        "sri_html": sri_html,
        "sri_seen": sri_seen,
        "hsts_preload": _hsts_preload_status(result.final_url, result.headers,
                                             scheme, timeout),
        "security_txt": security_txt,
    }
    return analyze(result.headers, scheme=scheme, meta=meta), result.headers


def _now() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


def _load_baseline(path: str) -> Report:
    """Read a saved ``--json`` baseline report from *path*.

    Raises ValueError with a human-readable message when the file cannot be
    read, is not JSON, or does not look like a HeaderHawk report.
    """
    import json

    try:
        with open(path, encoding="utf-8") as fh:
            payload = json.load(fh)
    except OSError as exc:
        raise ValueError(f"cannot read baseline file {path!r}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"baseline file {path!r} is not valid JSON: {exc}") from exc
    try:
        return report_from_dict(payload)
    except ValueError as exc:
        raise ValueError(f"baseline file {path!r}: {exc}") from exc


def run_watch(args: argparse.Namespace, sleep=time.sleep) -> int:
    """Re-audit args.url on an interval; alert only when things change.

    ``sleep`` is injectable so tests can drive the loop without waiting.
    """
    interval = args.watch
    color = not args.no_color and sys.stdout.isatty()
    threshold = None
    if args.fail_below:
        try:
            threshold = grade_index(args.fail_below)
        except ValueError:
            print(f"error: unknown grade {args.fail_below!r} "
                  f"(use one of A+ A B C D E F).", file=sys.stderr)
            return 2

    max_fail_on_rank = None
    if args.fail_on:
        try:
            max_fail_on_rank = _parse_fail_on(args.fail_on)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    log_fh = None
    if args.watch_log:
        try:
            log_fh = open(args.watch_log, "a", encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write watch log to {args.watch_log!r}: "
                  f"{exc}", file=sys.stderr)
            return 2

    def _log(message: str) -> None:
        """Append a timestamped line to the --watch-log file, if any."""
        if log_fh is not None:
            stamp = datetime.datetime.now().isoformat(timespec="seconds")
            log_fh.write(f"{stamp} {message}\n")
            log_fh.flush()

    print(f"HeaderHawk v{__version__} - watching {args.url}: auditing every "
          f"{interval:g}s; alerting only when the grade or findings change "
          "(Ctrl-C to stop).")
    _log(f"START watching {args.url} every {interval:g}s")
    prev: Report | None = None
    audits = 0
    started = time.monotonic()
    try:
        while True:
            try:
                report, _ = _audit_one(args.url, timeout=args.timeout,
                                       user_agent=args.user_agent,
                                       quiet_secondary=True,
                                       no_tls=args.no_tls,
                                       tls_timeout=args.tls_timeout)
            except FetchError as exc:
                if prev is None:
                    print(f"error: {exc}", file=sys.stderr)
                    return 2
                print(f"[{_now()}] fetch failed: {exc} (keeping the last "
                      f"report; retrying in {interval:g}s)")
                _log(f"FETCH FAILED: {exc}")
            else:
                audits += 1
                if prev is None:
                    print(f"[{_now()}] Baseline: grade {report.grade} "
                          f"(score {report.score}/100).")
                    sys.stdout.write(render_text(report, color=color))
                    _log(f"BASELINE: grade {report.grade} "
                         f"(score {report.score}/100)")
                else:
                    changes = diff_reports(prev, report)
                    if changes:
                        delta = report.score - prev.score
                        direction = ("worse" if delta < 0
                                     else "better" if delta > 0 else "changed")
                        print(f"[{_now()}] CHANGE DETECTED ({direction}): "
                              f"{prev.grade} -> {report.grade} "
                              f"(score {prev.score} -> {report.score}, "
                              f"{delta:+d}); {len(changes)} finding(s) differ.")
                        sys.stdout.write(render_compare(prev, report,
                                                        color=color))
                        _log(f"CHANGE DETECTED ({direction}): "
                             f"{prev.grade} -> {report.grade} "
                             f"(score {prev.score} -> {report.score}, "
                             f"{delta:+d}); {len(changes)} finding(s) differ")
                    else:
                        print(f"[{_now()}] no change: grade {report.grade} "
                              f"(score {report.score}/100, audit #{audits}).")
                prev = report
                if threshold is not None and grade_index(report.grade) > threshold:
                    sys.stderr.write(
                        f"Grade {report.grade} is below the required "
                        f"{args.fail_below.upper()}.\n")
                    return 1
                if max_fail_on_rank is not None:
                    offending = _findings_at_or_above(report, max_fail_on_rank)
                    if offending:
                        sys.stderr.write(
                            f"Finding gate failed: {len(offending)} "
                            f"finding(s) at or above "
                            f"{args.fail_on.upper()} severity.\n")
                        return 1
            sleep(interval)
    except KeyboardInterrupt:
        elapsed = time.monotonic() - started
        last = f", last grade {prev.grade}" if prev is not None else ""
        print(f"\nStopped watching {args.url} after {audits} audit(s) in "
              f"{elapsed:.0f}s{last}.")
        _log(f"STOP after {audits} audit(s) in {elapsed:.0f}s{last}")
        return 0
    finally:
        if log_fh is not None:
            log_fh.close()


def run_history_report(args: argparse.Namespace) -> int:
    """Print the grade-history trend recorded in --history-report FILE."""
    try:
        entries, skipped = read_history(args.history_report)
    except OSError as exc:
        print(f"error: cannot read history file {args.history_report!r}: "
              f"{exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    color = not args.no_color and sys.stdout.isatty()
    sys.stdout.write(render_history_report(entries, skipped=skipped,
                                           color=color))
    return 0


def run_bulk(args: argparse.Namespace) -> int:
    try:
        targets = read_targets(args.bulk)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rows = audit_targets(targets, timeout=args.timeout, user_agent=args.user_agent,
                         sri=args.sri, tls=args.bulk_tls,
                         tls_timeout=args.tls_timeout)
    color = not args.no_color and sys.stdout.isatty()
    worst = worst_bulk_row(rows) if args.bulk_worst else None
    output = (render_bulk_json(rows, worst=worst) if args.json
              else render_bulk_table(rows, color=color,
                                     show_tls=args.bulk_tls))
    if args.bulk_worst and not args.json:
        output = output.rstrip() + "\n\n" + render_bulk_worst(worst, color=color)

    if args.bulk_output:
        try:
            os.makedirs(args.bulk_output, exist_ok=True)
        except OSError as exc:
            print(f"error: cannot create bulk output dir "
                  f"{args.bulk_output!r}: {exc}", file=sys.stderr)
            return 2
        used: set[str] = set()
        written = 0
        for row in rows:
            if row.error or row.report is None:
                continue
            ext = "json" if args.json else "txt"
            name = bulk_report_filename(row.url, ext, used)
            content = (render_json(row.report) if args.json
                       else render_text(row.report, color=False))
            try:
                with open(os.path.join(args.bulk_output, name), "w",
                          encoding="utf-8") as fh:
                    fh.write(content)
            except OSError as exc:
                print(f"error: cannot write bulk report {name!r}: {exc}",
                      file=sys.stderr)
                return 2
            written += 1
        skipped = sum(1 for r in rows if r.error)
        sys.stderr.write(
            f"Wrote {written} per-target report(s) to {args.bulk_output!r}")
        if skipped:
            sys.stderr.write(f" ({skipped} unreachable target(s) skipped)")
        sys.stderr.write(".\n")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
    else:
        sys.stdout.write(output)

    if args.fail_below:
        try:
            threshold = grade_index(args.fail_below)
        except ValueError:
            print(f"error: unknown grade {args.fail_below!r} "
                  f"(use one of A+ A B C D E F).", file=sys.stderr)
            return 2
        worst = max((grade_index(r.grade) for r in rows if r.grade), default=0)
        reasons = []
        if any(r.error for r in rows):
            reasons.append(f"{sum(1 for r in rows if r.error)} unreachable")
        if worst > threshold:
            reasons.append(f"worst grade below {args.fail_below.upper()}")
        if reasons:
            if not args.json:
                sys.stderr.write("Bulk gate failed: " + ", ".join(reasons) + ".\n")
            return 1
    if args.fail_on:
        try:
            max_rank = _parse_fail_on(args.fail_on)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        def _row_worst_rank(row) -> int:
            ranks = []
            if row.high:
                ranks.append(_SEVERITY_ORDER["HIGH"])
            if row.med:
                ranks.append(_SEVERITY_ORDER["MED"])
            if row.low:
                ranks.append(_SEVERITY_ORDER["LOW"])
            if row.info:
                ranks.append(_SEVERITY_ORDER["INFO"])
            return min(ranks, default=99)

        bad = [r for r in rows if not r.error and _row_worst_rank(r) <= max_rank]
        if bad:
            if not args.json:
                sys.stderr.write(
                    f"Finding gate failed: {len(bad)} target(s) with "
                    f"finding(s) at or above {args.fail_on.upper()} "
                    "severity.\n")
            return 1
    return 0


def run_compare(args: argparse.Namespace) -> int:
    """Fetch two targets and print a before/after diff of their reports."""
    reports = []
    for url in args.compare:
        try:
            report, _ = _audit_one(url, timeout=args.timeout,
                                   user_agent=args.user_agent,
                                   no_tls=args.no_tls,
                                   tls_timeout=args.tls_timeout)
        except FetchError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        reports.append(report)

    color = not args.no_color and sys.stdout.isatty()
    output = (render_compare_json(*reports, ignore_info=args.ignore_info)
              if args.json
              else render_compare(*reports, color=color,
                                  ignore_info=args.ignore_info))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
    else:
        sys.stdout.write(output)

    if args.fail_below:
        try:
            threshold = grade_index(args.fail_below)
        except ValueError:
            print(f"error: unknown grade {args.fail_below!r} "
                  f"(use one of A+ A B C D E F).", file=sys.stderr)
            return 2
        if grade_index(reports[1].grade) > threshold:
            if not args.json:
                sys.stderr.write(
                    f"Grade {reports[1].grade} (URL_B) is below the required "
                    f"{args.fail_below.upper()}.\n")
            return 1
    if args.fail_on:
        try:
            max_rank = _parse_fail_on(args.fail_on)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        offending = _findings_at_or_above(reports[1], max_rank)
        if offending:
            if not args.json:
                sys.stderr.write(
                    f"Finding gate failed: {len(offending)} finding(s) at or "
                    f"above {args.fail_on.upper()} severity on URL_B.\n")
            return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.ignore_info and not (args.compare or args.diff_against):
        print("error: --ignore-info only applies with --compare or "
              "--diff-against.", file=sys.stderr)
        return 2

    if args.tls_timeout <= 0:
        print(f"error: --tls-timeout must be positive (got {args.tls_timeout:g}s).",
              file=sys.stderr)
        return 2
    if args.no_tls and args.tls_timeout != build_parser().get_default("tls_timeout"):
        print("error: --tls-timeout cannot be combined with --no-tls (the TLS "
              "probe is skipped, so there is nothing to time out).",
              file=sys.stderr)
        return 2

    if args.bulk_output and not args.bulk:
        print("error: --bulk-output only applies with --bulk.",
              file=sys.stderr)
        return 2

    if args.bulk_worst and not args.bulk:
        print("error: --bulk-worst only applies with --bulk.",
              file=sys.stderr)
        return 2

    if args.bulk_tls and not args.bulk:
        print("error: --bulk-tls only applies with --bulk.",
              file=sys.stderr)
        return 2

    if args.bulk_tls and args.no_tls:
        print("error: --bulk-tls cannot be combined with --no-tls (the "
              "probe it runs is the one --no-tls skips).",
              file=sys.stderr)
        return 2

    if args.bulk:
        if args.url or args.headers or args.compare or args.explain \
                or args.summary_line or args.diff_against \
                or args.history:
            print("error: --bulk cannot be combined with a URL, --headers, "
                  "--compare, --explain, --summary-line, "
                  "--diff-against, or --history.", file=sys.stderr)
            return 2
        return run_bulk(args)

    if args.history_report:
        conflicting = (args.url, args.headers, args.bulk, args.compare,
                       args.watch, args.diff_against, args.sri, args.history,
                       args.raw, args.only, args.explain, args.summary_line,
                       args.json, args.output, args.fail_below, args.fail_on,
                       args.bulk_output)
        if any(conflicting):
            print("error: --history-report is a report-only mode; it cannot "
                  "be combined with any other mode or output option.",
                  file=sys.stderr)
            return 2
        return run_history_report(args)

    if args.compare:
        if args.url or args.headers:
            print("error: --compare cannot be combined with a URL or --headers.",
                  file=sys.stderr)
            return 2
        if args.raw or args.only or args.explain or args.summary_line \
                or args.sri or args.diff_against or args.history:
            print("error: --raw, --only, --explain, --summary-line, --sri, "
                  "--diff-against, and --history apply to single-target "
                  "mode, not --compare.", file=sys.stderr)
            return 2
        return run_compare(args)

    if args.watch_log and args.watch is None:
        print("error: --watch-log only applies in --watch mode.",
              file=sys.stderr)
        return 2

    if args.watch is not None:
        if args.bulk or args.compare or args.headers:
            print("error: --watch cannot be combined with --bulk, --compare, "
                  "or --headers.", file=sys.stderr)
            return 2
        if not args.url:
            print("error: --watch needs a live URL to re-audit.",
                  file=sys.stderr)
            return 2
        if args.raw or args.only or args.explain or args.output or args.json \
                or args.summary_line or args.sri or args.diff_against \
                or args.history:
            print("error: --raw, --only, --explain, --output, --json, "
                  "--summary-line, --sri, --diff-against, and --history do "
                  "not apply in --watch mode.", file=sys.stderr)
            return 2
        if args.watch <= 0:
            print(f"error: --watch interval must be positive "
                  f"(got {args.watch:g}s).", file=sys.stderr)
            return 2
        return run_watch(args)

    offline = args.headers is not None or (args.url is None and not sys.stdin.isatty())
    if args.url and args.headers:
        print("error: pass either a URL or --headers, not both.", file=sys.stderr)
        return 2
    if args.sri and offline:
        print("error: --sri needs a live URL; saved headers have no page "
              "HTML to audit.", file=sys.stderr)
        return 2

    try:
        if offline:
            headers = load_headers(args.headers)
            raw_headers = headers
            report = analyze(headers, scheme="https",
                             meta={"url": args.headers or "<stdin>"})
        else:
            if not args.url:
                print("error: no URL given and nothing piped on stdin.", file=sys.stderr)
                return 2
            report, raw_headers = _audit_one(args.url, timeout=args.timeout,
                                             user_agent=args.user_agent,
                                             sri=args.sri,
                                             no_tls=args.no_tls,
                                             tls_timeout=args.tls_timeout)
    except FetchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    color = not args.no_color and sys.stdout.isatty()
    if args.summary_line and (args.json or args.raw or args.only or args.explain):
        print("error: --summary-line cannot be combined with --json, --raw, "
              "--only, or --explain.", file=sys.stderr)
        return 2
    try:
        only = _parse_only(args.only)
        explain = _parse_explain(args.explain)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if explain and only:
        print("error: --explain and --only both filter findings; use one of "
              "them.", file=sys.stderr)
        return 2
    if explain and args.json:
        print("error: --explain is a text report; it cannot be combined with "
              "--json.", file=sys.stderr)
        return 2
    if args.diff_against and (args.raw or args.only or args.explain
                              or args.summary_line):
        print("error: --diff-against cannot be combined with --raw, --only, "
              "--explain, or --summary-line.", file=sys.stderr)
        return 2
    baseline = None
    if args.diff_against:
        try:
            baseline = _load_baseline(args.diff_against)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    chunks: list[str] = []
    if args.raw:
        for name, values in sorted(raw_headers.items()):
            for value in values:
                # OWASP review fix (2026-10-11): header names/values are
                # attacker-influenced, so never print control characters
                # verbatim to the terminal.
                chunks.append(f"{_terminal_safe(name)}: {_terminal_safe(value)}")
        chunks.append("")
    if baseline is not None:
        chunks.append(render_compare_json(baseline, report,
                                          ignore_info=args.ignore_info)
                      if args.json
                      else render_compare(baseline, report, color=color,
                                          ignore_info=args.ignore_info))
    elif args.summary_line:
        chunks.append(render_summary_line(report))
    elif explain:
        chunks.append(render_explain(report, explain, color=color))
    else:
        chunks.append(render_json(report) if args.json
                      else render_text(report, color=color, only=only))
    output = "\n".join(chunks)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
    else:
        sys.stdout.write(output)

    if args.history:
        try:
            append_run(args.history, report.final_url or report.url,
                       report.grade, report.score)
        except OSError as exc:
            print(f"error: cannot write history to {args.history!r}: {exc}",
                  file=sys.stderr)
            return 2

    if args.fail_below:
        try:
            threshold = grade_index(args.fail_below)
        except ValueError:
            print(f"error: unknown grade {args.fail_below!r} "
                  f"(use one of A+ A B C D E F).", file=sys.stderr)
            return 2
        if grade_index(report.grade) > threshold:
            if not args.json:
                sys.stderr.write(
                    f"Grade {report.grade} is below the required {args.fail_below.upper()}.\n")
            return 1
    if args.fail_on:
        try:
            max_rank = _parse_fail_on(args.fail_on)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        offending = _findings_at_or_above(report, max_rank)
        if offending:
            if not args.json:
                sys.stderr.write(
                    f"Finding gate failed: {len(offending)} finding(s) at or "
                    f"above {args.fail_on.upper()} severity.\n")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
