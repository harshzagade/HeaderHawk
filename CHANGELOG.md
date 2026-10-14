# Changelog

## Unreleased
### Added
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

## 1.0.0 - 2026-10-11
- Initial release: live + offline security-header auditing, A+..F grading,
  per-miss explanations with fix suggestions, text/JSON output, `--fail-below`
  CI gate.
