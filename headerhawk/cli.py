"""Command-line interface for HeaderHawk."""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import sys
import time
import urllib.parse

from . import __version__
from .bulk import audit_targets, read_targets
from .checks import Headers, Report, analyze, get
from .fetch import (DEFAULT_USER_AGENT, FetchError, fetch, preload_status)
from .offline import load_headers
from .report import (diff_reports, grade_index, render_bulk_json,
                      render_bulk_table, render_compare, render_compare_json,
                      render_json, render_text)


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
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colors in the text report.")
    parser.add_argument("--only", metavar="SEV",
                        help="Show only findings with these severities in the text "
                             "report (comma-separated, e.g. --only HIGH,MED). "
                             "Grade/score still reflect all findings; JSON "
                             "output is unaffected.")
    parser.add_argument("--timeout", type=float, default=10.0, metavar="SEC",
                        help="Fetch timeout in seconds (default: 10).")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, metavar="UA",
                        help="User-Agent string for live fetches.")
    parser.add_argument("--fail-below", metavar="GRADE",
                        help="Exit 1 unless the grade is at least GRADE "
                             "(e.g. --fail-below B for CI gates).")
    parser.add_argument("--raw", action="store_true",
                        help="Print the raw response headers before the report.")
    parser.add_argument("--bulk", metavar="FILE",
                        help="Bulk mode: read target URLs from FILE (one per line) "
                             "and print a summary grade table.")
    parser.add_argument("--compare", nargs=2, metavar=("URL_A", "URL_B"),
                        help="Compare two targets side by side: fetch URL_A and "
                             "URL_B, and show what changed (regressed, new, "
                             "resolved, improved findings). Made for before/after "
                             "hardening checks. --fail-below gates on URL_B.")
    parser.add_argument("--watch", type=float, default=None, metavar="SEC",
                        help="Watch mode: re-audit the URL every SEC seconds "
                             "and print an alert only when the grade or "
                             "findings change (for monitoring your own site "
                             "after deploys). Ctrl-C stops. Single live-URL "
                             "mode only; cannot be combined with --bulk, "
                             "--compare, --headers, --raw, --only, --output, "
                             "or --json.")
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
               user_agent: str) -> tuple[Report, Headers]:
    """Fetch a URL once and return (report, raw headers).

    The HSTS preload-list status is queried when the response advertises a
    preload directive (cached per process inside fetch.preload_status).
    """
    result = fetch(url, timeout=timeout, user_agent=user_agent)
    scheme = urllib.parse.urlsplit(result.final_url).scheme or "https"
    meta = {
        "url": url,
        "final_url": result.final_url,
        "status_code": result.status,
        "redirects": result.redirects,
        "elapsed_ms": result.elapsed_ms,
        "redirect_chain": result.chain,
        "hsts_preload": _hsts_preload_status(result.final_url, result.headers,
                                             scheme, timeout),
    }
    return analyze(result.headers, scheme=scheme, meta=meta), result.headers


def _now() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


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

    print(f"HeaderHawk v{__version__} - watching {args.url}: auditing every "
          f"{interval:g}s; alerting only when the grade or findings change "
          "(Ctrl-C to stop).")
    prev: Report | None = None
    audits = 0
    started = time.monotonic()
    try:
        while True:
            try:
                report, _ = _audit_one(args.url, timeout=args.timeout,
                                       user_agent=args.user_agent)
            except FetchError as exc:
                if prev is None:
                    print(f"error: {exc}", file=sys.stderr)
                    return 2
                print(f"[{_now()}] fetch failed: {exc} (keeping the last "
                      f"report; retrying in {interval:g}s)")
            else:
                audits += 1
                if prev is None:
                    print(f"[{_now()}] Baseline: grade {report.grade} "
                          f"(score {report.score}/100).")
                    sys.stdout.write(render_text(report, color=color))
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
                    else:
                        print(f"[{_now()}] no change: grade {report.grade} "
                              f"(score {report.score}/100, audit #{audits}).")
                prev = report
                if threshold is not None and grade_index(report.grade) > threshold:
                    sys.stderr.write(
                        f"Grade {report.grade} is below the required "
                        f"{args.fail_below.upper()}.\n")
                    return 1
            sleep(interval)
    except KeyboardInterrupt:
        elapsed = time.monotonic() - started
        last = f", last grade {prev.grade}" if prev is not None else ""
        print(f"\nStopped watching {args.url} after {audits} audit(s) in "
              f"{elapsed:.0f}s{last}.")
        return 0


def run_bulk(args: argparse.Namespace) -> int:
    try:
        targets = read_targets(args.bulk)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rows = audit_targets(targets, timeout=args.timeout, user_agent=args.user_agent)
    color = not args.no_color and sys.stdout.isatty()
    output = render_bulk_json(rows) if args.json else render_bulk_table(rows, color=color)

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
    return 0


def run_compare(args: argparse.Namespace) -> int:
    """Fetch two targets and print a before/after diff of their reports."""
    reports = []
    for url in args.compare:
        try:
            report, _ = _audit_one(url, timeout=args.timeout,
                                   user_agent=args.user_agent)
        except FetchError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        reports.append(report)

    color = not args.no_color and sys.stdout.isatty()
    output = (render_compare_json(*reports) if args.json
              else render_compare(*reports, color=color))

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
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.bulk:
        if args.url or args.headers or args.compare:
            print("error: --bulk cannot be combined with a URL, --headers, "
                  "or --compare.", file=sys.stderr)
            return 2
        return run_bulk(args)

    if args.compare:
        if args.url or args.headers:
            print("error: --compare cannot be combined with a URL or --headers.",
                  file=sys.stderr)
            return 2
        if args.raw or args.only:
            print("error: --raw and --only apply to single-target mode, "
                  "not --compare.", file=sys.stderr)
            return 2
        return run_compare(args)

    if args.watch is not None:
        if args.bulk or args.compare or args.headers:
            print("error: --watch cannot be combined with --bulk, --compare, "
                  "or --headers.", file=sys.stderr)
            return 2
        if not args.url:
            print("error: --watch needs a live URL to re-audit.",
                  file=sys.stderr)
            return 2
        if args.raw or args.only or args.output or args.json:
            print("error: --raw, --only, --output, and --json do not apply "
                  "in --watch mode.", file=sys.stderr)
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
                                             user_agent=args.user_agent)
    except FetchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    color = not args.no_color and sys.stdout.isatty()
    try:
        only = _parse_only(args.only)
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
    chunks.append(render_json(report) if args.json
                  else render_text(report, color=color, only=only))
    output = "\n".join(chunks)

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
        if grade_index(report.grade) > threshold:
            if not args.json:
                sys.stderr.write(
                    f"Grade {report.grade} is below the required {args.fail_below.upper()}.\n")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
