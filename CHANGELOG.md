# Changelog

## Unreleased
### Added
- SRI `crossorigin` check in `--sri` mode: an `integrity=` hash on a
  cross-origin resource is ignored unless the tag fetches with CORS, so
  `sri.find_missing_crossorigin()` / `checks.check_sri_crossorigin()` flag
  every SRI-pinned external script/stylesheet missing `crossorigin=` as
  LOW (-2) — the pin is dead weight without it. Pages where every pinned
  resource carries `crossorigin=` get an OK pass; pages with no pinned
  resources stay silent (the main SRI check covers them). Empty and
  `use-credentials` attribute values count as present. Covered by 7 new
  tests in `tests/test_sri.py` (suite 253 green).
- Mixed-content check in `--sri` mode: on HTTPS targets, every `http://`
  subresource in the fetched HTML (scripts, stylesheets, and `<img>` tags —
  the tag scan now collects images too) is flagged as HIGH (-8) via new
  `sri.find_mixed_content()` / `checks.check_mixed_content()`. Scripts and
  stylesheets are called out as *active* mixed content (browsers block them)
  vs. images as *passive* in the finding detail; protocol-relative `//` URLs
  are not flagged, and plain-HTTP pages or missing HTML opt out silently.
  Clean HTTPS pages get an OK pass. The text-report SRI footer now counts
  all external subresources (including images) via `sri.count_external_resources()`.
  Covered by 10 new tests in `tests/test_sri.py` (suite 246 green).
- `__Host-` / `__Secure-` cookie-name prefix validation (RFC 6265bis, new
  `check_cookie_prefixes()` in `checks.py`, wired into `analyze()`). A
  `__Secure-` cookie without `Secure` is MED (-5); a `__Host-` cookie missing
  `Secure`, carrying a `Domain` attribute, or not scoped to `Path=/` is HIGH
  (-10) per violation — browsers silently ignore non-compliant prefixed
  cookies. Prefix matching is case-insensitive; fully compliant prefixed
  cookies get an OK pass. Covered by `tests/test_cookie_prefixes.py`.
- Grade history: `--history FILE` appends one (timestamp, url, grade, score)
  JSONL row per audit run (works with `--json`, `-o/--output`,
  `--summary-line`, and `--headers` offline mode; rejected with `--bulk`,
  `--compare`, and `--watch`), and `--history-report FILE` prints the trend
  from the file — per-URL run tables with score deltas plus an
  improving/declining/steady verdict. New `history.py` module
  (`append_run()`/`read_history()`; malformed lines are skipped with a
  count) and `report.render_history_report()`. Covered by
  `tests/test_history.py`.
- `--diff-against FILE`: compare a fresh audit against a saved `--json`
  baseline (drift detection without needing two live URLs). Rebuilds the
  baseline into a Report via a new `report.report_from_dict()` (lenient on
  missing fields, loud on malformed JSON) and renders the same
  regressed/new/resolved/improved diff as `--compare`; `--json` emits a
  machine-readable diff, and `--fail-below` gates on the fresh audit.
  Works in live single-URL mode and `--headers` offline mode; rejected with
  `--bulk`, `--compare`, `--watch`, `--raw`, `--only`, `--explain`, and
  `--summary-line`.
- `--sri` mode: Subresource Integrity audit. Fetches the page HTML (2 MB
  cap, live single-URL mode only) with a new stdlib-only `sri.py` module
  (`html.parser`-based tag scan + bounded `fetch_html()`), and flags every
  external `<script src>` / stylesheet `<link href>` loading without an
  `integrity=` hash as MED (-4): a tampered CDN copy would run unchallenged.
  Fully SRI-pinned pages get an OK pass; pages with no external
  subresources get an informational note. The text-report footer summarizes
  the SRI audit and `--json` carries an `sri_seen` count. Rejected with
  `--headers` (offline), `--bulk`, `--watch`, and `--compare`.
- CSP `Report-Only` presence check: when only `Content-Security-Policy-Report-Only`
  is set, the policy is NOT enforced — flagged as MED (-5) since a green "CSP
  present" check is a false sense of confidence (XSS protection is the same as
  having no CSP). Report-only alongside an enforcing policy is noted as
  informational (policy tuning mode).
- `--explain SEV`: plain-English explainer for one severity, made for
  non-security teammates. Shows only findings with that severity, each with
  "what it means" and "what to do" notes, and closes with a one-paragraph
  summary; grade/score still reflect all findings. Rejects combos with
  `--only`, `--json`, `--bulk`, `--compare`, and `--watch`.
- Cookie flag audit: every `Set-Cookie` is checked for the `Secure`,
  `HttpOnly`, and `SameSite` attributes. Missing `Secure` is MED (-5),
  missing `HttpOnly` MED (-3), missing `SameSite` LOW (-2, browsers now
  default to Lax), `SameSite=None` without `Secure` MED (-5, browsers reject
  the cookie), and unrecognized values LOW (-2); clean cookies are OK
  passes. The text-report footer now summarizes how many cookies were
  audited, and `--json` reports carry a `cookies_seen` count.
- Bulk mode (`--bulk FILE`): read target URLs from a file (one per line,
  `#` comments and blanks skipped), audit each, and print a summary grade
  table with HTTP status, score, and HIGH/MED finding counts. Unreachable
  targets show as ERROR rows instead of aborting the run. `--json` emits a
  machine-readable per-target list; `--fail-below` gates on the worst grade
  (unreachable targets fail the gate).
- "In simple words" plain-language intro line at the top of the README.
- Real terminal screenshot of a sample run against `example.com`
  (`assets/screenshots/sample-run.png`).
- Conflicting-duplicate detection: a header sent twice with different values
  (e.g. two `X-Frame-Options`) is flagged as MED (-5) since browsers disagree
  on which instance wins; identical duplicates are noted as informational.
- CSP violation-reporting check: flags a missing `report-uri` / `report-to`
  directive (informational, no penalty), notes deprecated `report-uri`, and
  catches a dangling `report-to` with no matching `Report-To` /
  `Reporting-Endpoints` header (LOW, -2, since reports go nowhere).
- `--only HIGH,MED` severity filter for the text report: hides lower-priority
  findings from the display (grade/score still reflect all findings); `--json`
  output keeps every finding; unknown severities exit with an error.
- Redirect-chain audit: every hop of the redirect chain is recorded (shown in
  `--json` as `redirect_chain`). HTTP→HTTPS upgrades are confirmed as OK;
  HTTPS→HTTP downgrades are HIGH (-10); chains longer than 3 redirects are
  flagged (LOW, -2); a final response still on plain HTTP is MED (-8).
- `--compare URL_A URL_B`: fetch two targets and print a before/after diff —
  regressed, new, resolved, and improved findings, with the score change.
  Made for checking hardening work; `--fail-below` gates on URL_B; `--json`
  emits both reports plus the diff.
- HSTS preload-list verification: when a live audit sees the `preload`
  directive, HeaderHawk queries the hstspreload.org status API and confirms
  the domain is actually submitted — a missing list entry is LOW (-2), since
  a bare directive is false confidence (first visits stay unprotected until
  submission). API failures surface as an informational note, never an
  error; skipped for IP targets, offline, and bulk runs (responses cached
  per process).
- `--watch SEC` mode: re-audit a URL on an interval and print an alert only
  when the grade or findings change (for monitoring your own site after
  deploys), reusing the `--compare` diff renderer for the alert. The first
  audit prints the full baseline report; later clean audits print one quiet
  heartbeat line; fetch failures mid-run are reported and retried. Ctrl-C
  stops with a summary; `--fail-below` gates every audit.
- TLS version/cipher sniff (live HTTPS audits only, stdlib `ssl` — no
  nmap/sslyze): handshakes restricted to each of TLS 1.0..1.3 reveal which
  versions the server still accepts. TLS 1.0 accepted is HIGH (-10), TLS 1.1
  MED (-8); a negotiated cipher with weak crypto (RC4, 3DES, NULL, anon,
  EXPORT suites) is HIGH (-10). A clean TLS 1.3 negotiation is an OK pass.
  Probe failures surface as informational, never as errors; skipped for
  offline, bulk, and plain-HTTP targets. `--json` reports carry the probe
  result under `tls`.
- `--summary-line`: one-line output (`A+ 100 example.com`) — grade, score,
  and host only — for status bars and CI matrices. Combines with
  `--fail-below` and `--output`; rejects combos with `--json`, `--raw`,
  `--only`, `--explain`, `--bulk`, `--compare`, and `--watch`.

## 1.0.0 - 2026-10-11
- Initial release: live + offline security-header auditing, A+..F grading,
  per-miss explanations with fix suggestions, text/JSON output, `--fail-below`
  CI gate.
