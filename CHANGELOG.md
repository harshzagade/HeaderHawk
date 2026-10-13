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

## 1.0.0 - 2026-10-11
- Initial release: live + offline security-header auditing, A+..F grading,
  per-miss explanations with fix suggestions, text/JSON output, `--fail-below`
  CI gate.
