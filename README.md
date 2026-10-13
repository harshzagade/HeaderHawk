# HeaderHawk

Audit a site's HTTP security headers, grade them **A+..F**, and get the exact
header to add for every miss. Two modes: **live** (fetch a URL) and
**offline** (analyze headers saved from curl / Burp / ZAP without touching the
network again).

> **In simple words:** every website sends invisible name tags with each reply.
> HeaderHawk reads them, grades the site's safety setup from A+ to F, and tells
> you exactly which tags to add.

Stdlib-only Python. No dependencies, no API keys, nothing to install beyond
Python 3.9+.

Pairs well with [Xploit](https://github.com/harshzagade/Xploit): Xploit finds
the bugs, HeaderHawk hardens the headers.

## Install

```bash
git clone https://github.com/harshzagade/HeaderHawk.git
cd HeaderHawk
pip install .          # or: pip install -e .
```

Or run it straight from the source tree without installing:

```bash
python3 -m headerhawk.cli https://example.com
```

## Usage

```bash
# Live audit of a site (https:// is assumed if you omit the scheme)
headerhawk example.com

# Fully offline: analyze headers saved earlier (curl -i, Burp, ZAP...)
headerhawk --headers response-headers.txt
curl -sI https://example.com | headerhawk --json

# Machine-readable report for piping into other tools
headerhawk example.com --json | jq .grade

# CI gate: exit 1 unless the grade is at least B
headerhawk example.com --fail-below B

# See the raw headers too
headerhawk example.com --raw

# Save the report
headerhawk example.com -o report.txt

# Bulk mode: audit a list of targets (one URL per line, # comments ok),
# print a summary grade table (unreachable targets show as ERROR rows)
headerhawk --bulk targets.txt
headerhawk --bulk targets.txt --json | jq '.targets[].grade'
```

Options: `--timeout SEC`, `--user-agent UA`, `--no-color`, `-o/--output FILE`,
`--fail-below GRADE`, `--only SEV`, `--bulk FILE`, `--version`. Run `headerhawk --help` for
the full list.

## Sample output

`headerhawk https://example.com` (real run):

```
HeaderHawk v1.0.0 - HTTP security header audit
Target: https://example.com  (HTTP 200, 411ms)

GRADE: F   (score 39/100)

[-] Content-Security-Policy  [HIGH -20]
    No Content-Security-Policy header.
    Why: CSP is the strongest browser-side defense against XSS: it controls exactly which scripts, styles and objects a page may load. Without it, any injected script runs.
    Fix: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'

[-] Strict-Transport-Security  [HIGH -15]
    HSTS header is missing.
    Why: Without HSTS, a first-time visitor can be downgraded to plain HTTP by an active network attacker (SSL stripping), exposing cookies and credentials.
    Fix: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload

[-] X-Content-Type-Options  [MED -8]
    X-Content-Type-Options is missing.
    Why: Without nosniff, browsers may MIME-sniff responses: an uploaded 'image' served as text/html can execute as a stored-XSS payload in older browsers.
    Fix: X-Content-Type-Options: nosniff

[-] X-Frame-Options  [MED -10]
    X-Frame-Options is missing (no CSP frame-ancestors either).
    Why: The site can be embedded in an <iframe> on any origin, enabling clickjacking attacks against its users.
    Fix: X-Frame-Options: DENY  (or SAMEORIGIN if framing is needed)

[-] Permissions-Policy  [LOW -3]
    Permissions-Policy is missing.
    Why: Without it, any third-party script on the page can use the camera, microphone, geolocation, etc.
    Fix: Permissions-Policy: camera=(), microphone=(), geolocation=()

[-] Referrer-Policy  [LOW -5]
    Referrer-Policy is missing.
    Why: Without an explicit policy, browsers may send the full page URL (including query strings with tokens or IDs) as the Referer to third parties.
    Fix: Referrer-Policy: strict-origin-when-cross-origin

[i] Cross-Origin-Embedder-Policy
    Cross-Origin-Embedder-Policy is not set.
    Why: COEP: require-corp blocks no-cors cross-origin loads, a prerequisite for crossOriginIsolated (SharedArrayBuffer).
    Fix: Cross-Origin-Embedder-Policy: require-corp

[i] Cross-Origin-Opener-Policy
    Cross-Origin-Opener-Policy is not set.
    Why: COOP: same-origin breaks the window.opener link, blocking cross-origin XS-Leak and tab-nabbing style attacks.
    Fix: Cross-Origin-Opener-Policy: same-origin

[i] Cross-Origin-Resource-Policy
    Cross-Origin-Resource-Policy is not set.
    Why: CORP: same-site stops other sites from loading your resources no-cors (Spectre / resource-theft mitigation).
    Fix: Cross-Origin-Resource-Policy: same-site

Analyzed 12 response headers. Cookie flags are out of scope here - see the CookieScope project.
```

Real terminal capture of the same run (`headerhawk https://example.com` — a
documentation-reserved domain):

![HeaderHawk live scan of example.com](assets/screenshots/live-scan.png)

## What it checks

| Check | What it looks for |
|---|---|
| Content-Security-Policy | Missing policy; `unsafe-inline` / `unsafe-eval`; wildcard or scheme-wide script sources; missing `default-src`, `object-src`, `base-uri`; violation reporting (`report-uri` / `report-to`) presence — dangling `report-to` flagged |
| Strict-Transport-Security | Missing on HTTPS; short `max-age`; missing `includeSubDomains`; `preload` hint |
| X-Content-Type-Options | Must be `nosniff` |
| X-Frame-Options | Missing (unless CSP `frame-ancestors` covers it); non-standard values |
| Referrer-Policy | Missing; `unsafe-url`; lax browser default |
| Permissions-Policy | Missing (flags legacy `Feature-Policy` for migration) |
| COOP / COEP / CORP | Informational: missing or weak cross-origin isolation |
| Information disclosure | Version strings in `Server`, `X-Powered-By`, `X-AspNet-*` |
| Duplicate headers | Same header sent 2+ times: conflicting values flagged (browser honors first vs. last inconsistently); identical duplicates noted as informational |

Every finding explains **why it matters** and gives the **exact header to add**.

## Grading

Score starts at 100; each miss subtracts a weighted penalty. `A+` = 100,
`A` = 90+, `B` = 80+, `C` = 70+, `D` = 55+, `E` = 40+, `F` = below 40.

## Scope notes

- HeaderHawk audits **response headers only**. It does not crawl, inject
  payloads, or test for vulnerabilities. Only scan targets you own or are
  authorized to test.
- Cookie flag auditing (`Secure`, `HttpOnly`, `SameSite`) is intentionally
  out of scope here; it belongs to the planned **CookieScope** project.

## Development

```bash
python3 -m pytest -q     # 66 tests, localhost fixtures only, no real targets
```

## License

MIT. See [LICENSE](LICENSE).
