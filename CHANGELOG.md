# Changelog

## Unreleased
### Added
- `--bulk-output DIR`: bulk mode also writes each audited target's full
  report to a file in DIR (named from the target's host and path, with
  `-2`/`-3` suffixes on collisions; text files, or JSON with `--json`).
  Unreachable targets get no file and are counted in a stderr note; the
  summary table still prints (or goes to `--output`) as before. The
  directory is created when missing, and write failures exit 2. Covered
  by 6 new tests in `tests/test_bulk.py`.
- `--sri` in bulk mode: `--bulk` now accepts `--sri`, running one bounded
  HTML fetch per reachable target for the Subresource Integrity audit
  (plus the mixed-content, SRI-crossorigin, and meta-http-equiv checks
  that ride on the fetched HTML). A failed HTML fetch fails open for
  that target alone — the header audit still runs, just without SRI
  findings. Covered by 4 new tests in `tests/test_bulk.py`.
- Cookie-prefix adoption note: on HTTPS targets, session-ish cookies (name
  matches session/auth/token/login/remember patterns, split on `-`/`_`/.`)
  that do not use a `__Host-`/`__Secure-` prefix now get an INFO finding —
  a defense-in-depth nudge with no score penalty. Already-prefixed cookies
  keep their existing validation; plain-HTTP targets and non-session cookies
  stay silent. Covered by 8 new tests in
  `tests/test_cookie_prefix_adoption.py`.
- `--fail-on SEVERITY`: a second CI gate that exits 1 when any finding at or
  above the given severity exists — independent of `--fail-below`, so a
  passing grade can still fail the pipeline on a hidden HIGH. Applies to
  single-target, `--bulk` (any target), `--compare` (URL_B), `--diff-against`
  (the fresh audit), and `--watch` (each re-audit); invalid severities fail
  fast with exit 2, and `--json` mode stays quiet on stdout like `--fail-below`.
  Covered by 14 new tests in `tests/test_fail_on.py`.
- `<meta http-equiv>` fallback audit in `--sri` mode: the fetched page HTML
  is scanned for security-relevant pragma directives (`content-security-policy`,
  `refresh` redirects, `x-ua-compatible`, `set-cookie`), and each finding
  states which real response headers the pragma can and cannot replace —
  a meta CSP cannot enforce `frame-ancestors`/`sandbox`, meta refresh
  redirects are invisible to the redirect-chain audit, `X-UA-Compatible`
  replaces no security header, and `set-cookie` is ignored by every browser
  (no cookie is actually set). All INFO, never graded; the text footer
  notes the pragma check alongside the SRI audit. Covered by 13 new tests
  in `tests/test_meta_http_equiv.py`.
- `--tls-timeout SEC` for single-target, `--compare`, and `--watch` audits:
  caps each TLS handshake probe at SEC seconds (default 5, replacing the
  hard-coded cap) for slow or rate-limited servers; non-positive values fail
  fast, and combining it with `--no-tls` (probe skipped) exits 2. Covered
  by 8 new tests in `tests/test_tls_timeout.py`.
- Permissions-Policy syntax validation in `check_permissions_policy()`: the
  header value is parsed directive by directive — unrecognized feature names
  (LOW, -2: browsers ignore unknown directives, so a typo silently defeats
  the restriction) and malformed `=(...)` shapes or invalid allowlist
  tokens (LOW, -2) are flagged; removed-from-spec feature names get an INFO
  note (the directive does nothing). Valid headers keep the OK pass.
  Covered by 13 new tests in `tests/test_permissions_policy_syntax.py`.
- Per-directive `unsafe-inline` breakdown in `check_csp()`: the MED (-8)
  finding now names exactly which directives allow `'unsafe-inline'`
  (`script-src`, `style-src`, or both), and notes when it is inherited via
  the `default-src` fallback. A policy whose inline allowance is limited
  to `style-src` is a separate LOW (-3) finding instead: inline styles
  cannot execute scripts, so the risk is a fraction of script XSS (residual
  CSS-based exfiltration only). Covered by 6 new tests in
  `tests/test_csp_unsafe_inline.py`.
- `--no-tls` flag for single-target, `--compare`, and `--watch` audits: skips
  the stdlib TLS version/cipher probe entirely for fast header-only audits
  (CI speed). When skipped the TLS check reports nothing — it never
  penalizes the grade. Covered by 4 new tests in `tests/test_no_tls.py`.
- README "Interpreting your grade" section: remediation priority order based
  on the actual penalty weights (missing CSP -20 first, then missing HSTS
  -15, the -10s, active mixed content, MED -8s, and hygiene wins), so users
  know what to fix first for the biggest score gain.
- `--ignore-info` for `--compare` / `--diff-against`: hides INFO/OK-only diffs
  so before/after reviews focus on real changes. A diff row is dropped only
  when every finding it carries (before and/or after) is INFO or OK severity;
  rows where one side is MED or worse are kept. When every diff is filtered
  out, the text report says so explicitly instead of claiming no differences,
  and the machine-readable diff gains an `"ignore_info"` flag. Covered by 7
  new tests in `tests/test_compare.py`.
- `--watch-log FILE` for `--watch` mode: appends timestamped events to FILE
  (ISO-8601, one per line) — start, per-audit baseline, every `CHANGE DETECTED`
  alert, mid-run fetch gaps, and the Ctrl-C stop summary — so overnight watch
  runs leave an audit trail. The file is opened in append mode (fail-fast
  exit 2 when unwritable), flushed per event, and closed on stop; `--watch-log`
  without `--watch` exits 2. Covered by 6 new tests in `tests/test_watch.py`.
- `security.txt` presence check (RFC 9116): in live single-URL mode (including
  `--watch` re-audits) HeaderHawk now fetches `/.well-known/security.txt`
  from the target's origin via a new stdlib-only `fetch.fetch_security_txt()`
  (404/410 = missing, other fetch failures raise `FetchError`, 32 KB body cap)
  and `checks.check_security_txt()` notes a missing file or a published file
  with no `Contact:` field as INFO — never penalized; a published file with a
  contact gets an OK pass. Silent in offline and bulk mode. Covered by 14 new
  tests in `tests/test_security_txt.py`.
- TLS certificate expiry: the live stdlib-`ssl` probe now reads the leaf
  certificate's `notAfter` off the same handshake (no extra connection) into
  `TLSInfo.cert_days_left` / `cert_not_after` (surfaced in `--json` too).
  `checks.check_tls()` flags an already-expired certificate as HIGH (-10)
  and one expiring within 30 days as LOW (-2); healthy or unreadable certs
  stay silent. Covered by 8 new tests in `tests/test_tls.py`.
- CSP Trusted Types note: on enforcing CSPs, `checks.check_csp_trusted_types()`
  now notes Trusted Types adoption as INFO (never penalized). A policy with
  `require-trusted-types-for 'script'` gets an OK pass; a `trusted-types`
  allow-list without enforcement gets an INFO nudge to add it; a policy with
  neither gets an INFO hardening note explaining the DOM-XSS gap it closes.
  Covered by 4 new tests in `tests/test_checks.py`.
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

### Changed
- HSTS preload false-confidence escalated from LOW (-2) to MED (-5): an
  HSTS header advertising `preload` when hstspreload.org shows no list
  entry is not minor hygiene — the site claims a protection that does not
  exist while the first visit stays strippable. The finding's fix now names
  both exits explicitly: remove the directive, or submit the domain.
  Covered by the renamed `test_hsts_preload_unknown_is_med` in
  `tests/test_checks.py`; README "Interpreting your grade" re-ordered
  accordingly.

## 1.0.0 - 2026-10-11
- Initial release: live + offline security-header auditing, A+..F grading,
  per-miss explanations with fix suggestions, text/JSON output, `--fail-below`
  CI gate.
