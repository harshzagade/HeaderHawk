"""Command-line interface for HeaderHawk."""

from __future__ import annotations

import argparse
import sys
import urllib.parse

from . import __version__
from .bulk import audit_targets, read_targets
from .checks import analyze
from .fetch import DEFAULT_USER_AGENT, FetchError, fetch
from .offline import load_headers
from .report import grade_index, render_bulk_json, render_bulk_table, render_json, render_text


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
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Write the report to FILE instead of stdout.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.bulk:
        if args.url or args.headers:
            print("error: --bulk cannot be combined with a URL or --headers.",
                  file=sys.stderr)
            return 2
        return run_bulk(args)

    offline = args.headers is not None or (args.url is None and not sys.stdin.isatty())
    if args.url and args.headers:
        print("error: pass either a URL or --headers, not both.", file=sys.stderr)
        return 2

    try:
        if offline:
            headers = load_headers(args.headers)
            scheme = "https"
            meta = {"url": args.headers or "<stdin>"}
            raw_headers = headers
        else:
            if not args.url:
                print("error: no URL given and nothing piped on stdin.", file=sys.stderr)
                return 2
            result = fetch(args.url, timeout=args.timeout, user_agent=args.user_agent)
            headers = result.headers
            scheme = urllib.parse.urlsplit(result.final_url).scheme or "https"
            meta = {
                "url": args.url,
                "final_url": result.final_url,
                "status_code": result.status,
                "redirects": result.redirects,
                "elapsed_ms": result.elapsed_ms,
                "redirect_chain": result.chain,
            }
            raw_headers = result.headers
    except FetchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = analyze(headers, scheme=scheme, meta=meta)
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
