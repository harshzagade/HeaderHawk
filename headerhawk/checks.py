"""Security-header checks and scoring.

Each check inspects the response headers and returns a list of findings.
Every finding carries a score delta; the final score starts at 100 and is
clamped to 0..100, then mapped to a letter grade.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .tls import TLSInfo


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

import urllib.parse


@dataclass
class RedirectHop:
    """One response served while fetching a URL: the URL and its status.

    A redirect chain is a list of these in order; the last hop is the final
    response, the rest are the redirects that were followed.
    """

    url: str
    status: int


@dataclass
class Finding:
    """One check outcome for one header."""

    check: str          # human name of the check, e.g. "Content-Security-Policy"
    header: str         # header name examined
    status: str         # "pass" | "missing" | "weak" | "info"
    severity: str       # "HIGH" | "MED" | "LOW" | "INFO" | "OK"
    score_delta: int     # negative = penalty, 0 = informational
    summary: str         # one-line verdict
    detail: str = ""     # why it matters
    fix: str = ""        # suggested header value


@dataclass
class Report:
    """Full analysis result."""

    url: str
    final_url: str = ""
    status_code: int = 0
    redirects: int = 0
    elapsed_ms: int = 0
    scheme: str = ""
    score: int = 100
    grade: str = ""
    findings: list[Finding] = field(default_factory=list)
    headers_seen: int = 0
    cookies_seen: int = 0
    sri_seen: int = 0  # external scripts/styles found in page HTML (--sri)
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    tls_info: TLSInfo | None = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "redirects": self.redirects,
            "elapsed_ms": self.elapsed_ms,
            "scheme": self.scheme,
            "score": self.score,
            "grade": self.grade,
            "headers_seen": self.headers_seen,
            "cookies_seen": self.cookies_seen,
            "sri_seen": self.sri_seen,
            "tls": self.tls_info.to_dict() if self.tls_info else None,
            "redirect_chain": [
                {"url": hop.url, "status": hop.status}
                for hop in self.redirect_chain
            ],
            "findings": [
                {
                    "check": f.check,
                    "header": f.header,
                    "status": f.status,
                    "severity": f.severity,
                    "score_delta": f.score_delta,
                    "summary": f.summary,
                    "detail": f.detail,
                    "fix": f.fix,
                }
                for f in self.findings
            ],
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Headers are stored lowercased -> list of values (duplicates preserved).
Headers = dict[str, list[str]]


def get(headers: Headers, name: str) -> str | None:
    """Return the first value for a header, or None if absent."""
    values = headers.get(name.lower())
    return values[0] if values else None


def all_values(headers: Headers, name: str) -> list[str]:
    return headers.get(name.lower(), [])


_VERSION_RE = re.compile(r"\d+\.\d+")


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_hsts(headers: Headers, scheme: str) -> list[Finding]:
    """Strict-Transport-Security forces HTTPS and kills SSL-stripping."""
    name = "Strict-Transport-Security"
    if scheme != "https":
        return [Finding(
            check="Strict-Transport-Security", header=name, status="info",
            severity="INFO", score_delta=0,
            summary="Not applicable over plain HTTP.",
            detail="HSTS is only honored on HTTPS responses; enable HTTPS first.",
        )]
    value = get(headers, name)
    if value is None:
        return [Finding(
            check="Strict-Transport-Security", header=name, status="missing",
            severity="HIGH", score_delta=-15,
            summary="HSTS header is missing.",
            detail=("Without HSTS, a first-time visitor can be downgraded to "
                    "plain HTTP by an active network attacker (SSL stripping), "
                    "exposing cookies and credentials."),
            fix="Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
        )]
    findings: list[Finding] = []
    m = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    if not m:
        findings.append(Finding(
            check="Strict-Transport-Security", header=name, status="weak",
            severity="MED", score_delta=-8,
            summary="HSTS present but has no max-age directive; browsers ignore it.",
            detail="An HSTS header without max-age is invalid per RFC 6797.",
            fix="Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
        ))
        return findings
    max_age = int(m.group(1))
    if max_age < 31536000:
        days = max_age // 86400
        findings.append(Finding(
            check="Strict-Transport-Security", header=name, status="weak",
            severity="MED", score_delta=-5,
            summary=f"HSTS max-age is only {max_age}s (~{days} days).",
            detail=("A short max-age means protection lapses quickly if the "
                    "header is ever dropped. One year (31536000) is the "
                    "recommended minimum; two years for preload."),
            fix="Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
        ))
    if "includesubdomains" not in value.lower():
        findings.append(Finding(
            check="Strict-Transport-Security", header=name, status="weak",
            severity="LOW", score_delta=-3,
            summary="HSTS lacks includeSubDomains; subdomains stay downgradeable.",
            detail="An attacker can strip TLS on e.g. static.example.com while "
                   "the apex domain is protected.",
            fix="Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
        ))
    if "preload" not in value.lower():
        findings.append(Finding(
            check="Strict-Transport-Security", header=name, status="info",
            severity="INFO", score_delta=0,
            summary="HSTS has no preload directive.",
            detail=("Preload bakes the domain into browsers so even the very "
                    "first visit is HTTPS-only. Submit at hstspreload.org only "
                    "after includeSubDomains is live everywhere."),
        ))
    if not findings:
        findings.append(Finding(
            check="Strict-Transport-Security", header=name, status="pass",
            severity="OK", score_delta=0,
            summary=f"HSTS is well configured (max-age={max_age}).",
        ))
    return findings


def check_hsts_preload(headers: Headers, scheme: str,
                     preload: str | None) -> list[Finding]:
    """Verify the domain is actually on the HSTS preload list.

    A ``preload`` directive in the HSTS header only expresses *intent*:
    browsers honor it after the domain is submitted at hstspreload.org and
    shipped in the preload list. Sending the directive without a list entry
    is false confidence — the very first visit is still unprotected.

    ``preload`` is the list status queried from hstspreload.org
    (``"preloaded"``, ``"unknown"``, ...), None when the query was attempted
    but failed, or ``"unchecked"`` when the check did not run (offline or
    bulk analysis).
    """
    name = "Strict-Transport-Security"
    value = get(headers, name)
    if scheme != "https" or value is None or "preload" not in value.lower():
        return []
    if preload == "unchecked":
        return []
    if preload is None:
        return [Finding(
            check="HSTS preload list", header=name, status="info",
            severity="INFO", score_delta=0,
            summary="Preload-list status could not be verified in this run.",
            detail=("HeaderHawk could not reach hstspreload.org, so it cannot "
                    "confirm whether this preload directive is backed by a "
                    "real preload-list entry."),
        )]
    if preload == "preloaded":
        return [Finding(
            check="HSTS preload list", header=name, status="pass",
            severity="OK", score_delta=0,
            summary=("Domain is on the HSTS preload list "
                     "(verified via hstspreload.org)."),
        )]
    return [Finding(
        check="HSTS preload list", header=name, status="weak",
        severity="LOW", score_delta=-2,
        summary=(f"HSTS advertises preload, but hstspreload.org reports status "
                 f"{preload!r}: the domain is not actually submitted."),
        detail=("The preload directive takes effect only after the domain is "
                "submitted and accepted into the preload list; until then the "
                "very first visit is still vulnerable to SSL stripping."),
        fix=("Submit the domain at https://hstspreload.org (requires valid "
             "HSTS with includeSubDomains on the apex domain)."),
    )]


def parse_csp(value: str) -> dict[str, list[str]]:
    """Parse a CSP header value into {directive: [sources]} (lowercased)."""
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives


_STRONG_SCRIPT_SOURCES = {"'self'", "'none'"}


def check_csp(headers: Headers) -> list[Finding]:
    """Content-Security-Policy is the main XSS mitigation header."""
    values = all_values(headers, "content-security-policy")
    if not values:
        return [Finding(
            check="Content-Security-Policy", header="Content-Security-Policy",
            status="missing", severity="HIGH", score_delta=-20,
            summary="No Content-Security-Policy header.",
            detail=("CSP is the strongest browser-side defense against XSS: it "
                    "controls exactly which scripts, styles and objects a page "
                    "may load. Without it, any injected script runs."),
            fix=("Content-Security-Policy: default-src 'self'; script-src 'self'; "
                 "object-src 'none'; base-uri 'self'; frame-ancestors 'self'"),
        )] + check_csp_report_only(headers, enforcing_present=False)
    csp = parse_csp("; ".join(values))
    findings: list[Finding] = []
    script_src = csp.get("script-src", csp.get("default-src", []))

    if "'unsafe-inline'" in script_src:
        findings.append(Finding(
            check="Content-Security-Policy", header="Content-Security-Policy",
            status="weak", severity="MED", score_delta=-8,
            summary="CSP allows 'unsafe-inline' scripts.",
            detail=("'unsafe-inline' lets any inline <script> run, which "
                    "largely defeats the XSS protection CSP is meant to give. "
                    "Use nonces or hashes instead."),
            fix="Replace 'unsafe-inline' with a nonce: script-src 'self' 'nonce-<random>'",
        ))
    if "'unsafe-eval'" in script_src:
        findings.append(Finding(
            check="Content-Security-Policy", header="Content-Security-Policy",
            status="weak", severity="LOW", score_delta=-3,
            summary="CSP allows 'unsafe-eval' (eval, new Function).",
            detail="'unsafe-eval' re-enables string-to-code execution, a common "
                   "XSS sink. Remove it unless a library truly needs it.",
        ))
    broad = {"*", "http:", "https:", "data:"} & set(script_src)
    if broad:
        findings.append(Finding(
            check="Content-Security-Policy", header="Content-Security-Policy",
            status="weak", severity="MED", score_delta=-5,
            summary=f"CSP script sources are overly broad: {sorted(broad)}.",
            detail=("Wildcard or scheme-wide script sources let an attacker "
                    "load code from anywhere, weakening the policy to near "
                    "uselessness against XSS."),
            fix="script-src 'self' (plus explicit trusted hosts if needed)",
        ))
    if "default-src" not in csp:
        findings.append(Finding(
            check="Content-Security-Policy", header="Content-Security-Policy",
            status="weak", severity="MED", score_delta=-5,
            summary="CSP has no default-src fallback directive.",
            detail=("Directives not listed fall back to default-src; without it "
                    "they default to allowing everything."),
            fix="Add default-src 'self' to the policy.",
        ))
    for directive, recommended in (("object-src", "object-src 'none'"),
                                   ("base-uri", "base-uri 'self'")):
        if directive not in csp:
            findings.append(Finding(
                check="Content-Security-Policy", header="Content-Security-Policy",
                status="weak", severity="LOW", score_delta=-2,
                summary=f"CSP is missing {directive}.",
                detail=(f"Without {directive}, plugins/objects or the <base> tag "
                        "can be abused for hijacking."),
                fix=f"Add {recommended} to the policy.",
            ))
    findings += check_csp_reporting(headers, csp)
    findings += check_csp_report_only(headers, enforcing_present=True)
    if not findings:
        findings.append(Finding(
            check="Content-Security-Policy", header="Content-Security-Policy",
            status="pass", severity="OK", score_delta=0,
            summary="CSP is present and strict (no unsafe-inline/eval, no wildcards).",
        ))
    elif not any(f.severity in ("HIGH", "MED") for f in findings):
        findings.append(Finding(
            check="Content-Security-Policy", header="Content-Security-Policy",
            status="info", severity="INFO", score_delta=0,
            summary="CSP is present; only minor hardening left.",
        ))
    return findings


def check_csp_reporting(headers: Headers, csp: dict[str, list[str]]) -> list[Finding]:
    """CSP violation-reporting: report-uri / report-to presence check.

    A policy without a reporting directive works, but the site owner never
    hears about violations, so legitimate scripts blocked by a too-strict
    policy go unnoticed (and real attacks go unlogged). ``report-uri`` is
    deprecated but still honored; the modern pair is ``report-to`` plus a
    ``Reporting-Endpoints`` response header naming the endpoint group. A
    ``report-to`` that names a group no endpoint header defines is dead
    config: browsers drop the reports silently.
    """
    if "report-uri" in csp:
        return [Finding(
            check="Content-Security-Policy", header="Content-Security-Policy",
            status="info", severity="INFO", score_delta=0,
            summary="CSP violation reporting uses report-uri (deprecated but functional).",
            detail=("report-uri still works in all browsers, but the standard "
                    "going forward is the report-to directive paired with a "
                    "Reporting-Endpoints response header."),
            fix=("Add report-to csp-endpoint and "
                 "Reporting-Endpoints: csp-endpoint=\"https://example.com/csp-reports\""),
        )]
    if "report-to" in csp:
        if get(headers, "reporting-endpoints") is not None or \
                get(headers, "report-to") is not None:
            return [Finding(
                check="Content-Security-Policy", header="Content-Security-Policy",
                status="pass", severity="OK", score_delta=0,
                summary="CSP violation reporting is configured (report-to + endpoints header).",
            )]
        return [Finding(
            check="Content-Security-Policy", header="Content-Security-Policy",
            status="weak", severity="LOW", score_delta=-2,
            summary=("CSP uses report-to, but no Report-To or Reporting-Endpoints "
                     "header defines the endpoint group: violation reports go nowhere."),
            detail=("The report-to directive names an endpoint group; without a "
                    "matching header, browsers have nowhere to send the "
                    "reports, so the directive is silently dead."),
            fix=("Reporting-Endpoints: csp-endpoint=\"https://example.com/csp-reports\" "
                 "(group name must match the report-to value)"),
        )]
    return [Finding(
        check="Content-Security-Policy", header="Content-Security-Policy",
        status="info", severity="INFO", score_delta=0,
        summary="CSP has no violation-reporting directive (report-uri / report-to).",
        detail=("The policy is enforced, but nobody is told about violations: "
                "legitimate scripts blocked by an over-strict policy stay "
                "invisible, and attack probes leave no trace server-side."),
        fix="Add report-uri https://example.com/csp-reports (simple) or the report-to + Reporting-Endpoints pair",
    )]


def check_csp_report_only(headers: Headers, enforcing_present: bool) -> list[Finding]:
    """Content-Security-Policy-Report-Only presence vs. enforcement.

    ``Content-Security-Policy-Report-Only`` makes the browser send violation
    reports without enforcing anything: no script is ever blocked. A site
    sending only the report-only header has a false sense of confidence
    ("we have CSP") while remaining fully exposed to XSS. Report-only next
    to an enforcing policy is legitimate (tuning a stricter policy before
    rollout) and gets an INFO note.
    """
    if get(headers, "content-security-policy-report-only") is None:
        return []
    name = "Content-Security-Policy-Report-Only"
    if enforcing_present:
        return [Finding(
            check="Content-Security-Policy", header=name,
            status="info", severity="INFO", score_delta=0,
            summary="Report-Only variant is also sent (policy tuning mode).",
            detail=("An enforcing Content-Security-Policy is in place, so the "
                    "report-only copy only produces reports — typically used "
                    "to test a stricter policy before enforcing it. Make sure "
                    "the report-only policy matches the enforced one, or its "
                    "reports describe a policy that was never live."),
        )]
    return [Finding(
        check="Content-Security-Policy", header=name,
        status="weak", severity="MED", score_delta=-5,
        summary="Only Content-Security-Policy-Report-Only is set: the policy is NOT enforced.",
        detail=("Report-Only headers only trigger violation reports; nothing "
                "is ever blocked. Without a real Content-Security-Policy "
                "header, XSS protection is the same as having no CSP at all — "
                "a dashboard showing green checks for 'CSP present' is a "
                "false sense of security."),
        fix=("Promote the policy to an enforcing Content-Security-Policy "
             "header (keep the report-only variant only while tuning it)."),
    )]


def check_x_content_type_options(headers: Headers) -> list[Finding]:
    name = "X-Content-Type-Options"
    value = get(headers, name)
    if value is None:
        return [Finding(
            check="X-Content-Type-Options", header=name, status="missing",
            severity="MED", score_delta=-8,
            summary="X-Content-Type-Options is missing.",
            detail=("Without nosniff, browsers may MIME-sniff responses: an "
                    "uploaded 'image' served as text/html can execute as a "
                    "stored-XSS payload in older browsers."),
            fix="X-Content-Type-Options: nosniff",
        )]
    if value.strip().lower() != "nosniff":
        return [Finding(
            check="X-Content-Type-Options", header=name, status="weak",
            severity="MED", score_delta=-8,
            summary=f"X-Content-Type-Options has an unexpected value: {value!r}.",
            detail="The only defined value is 'nosniff'; anything else is ignored.",
            fix="X-Content-Type-Options: nosniff",
        )]
    return [Finding(
        check="X-Content-Type-Options", header=name, status="pass",
        severity="OK", score_delta=0, summary="X-Content-Type-Options: nosniff is set.",
    )]


def check_x_frame_options(headers: Headers, csp_directives: dict[str, list[str]]) -> list[Finding]:
    name = "X-Frame-Options"
    if "frame-ancestors" in csp_directives:
        return [Finding(
            check="X-Frame-Options", header=name, status="info",
            severity="INFO", score_delta=0,
            summary="Framing is controlled by CSP frame-ancestors (modern approach).",
            detail="CSP frame-ancestors supersede X-Frame-Options in modern browsers.",
        )]
    value = get(headers, name)
    if value is None:
        return [Finding(
            check="X-Frame-Options", header=name, status="missing",
            severity="MED", score_delta=-10,
            summary="X-Frame-Options is missing (no CSP frame-ancestors either).",
            detail=("The site can be embedded in an <iframe> on any origin, "
                    "enabling clickjacking attacks against its users."),
            fix="X-Frame-Options: DENY  (or SAMEORIGIN if framing is needed)",
        )]
    if value.strip().upper() not in ("DENY", "SAMEORIGIN"):
        return [Finding(
            check="X-Frame-Options", header=name, status="weak",
            severity="LOW", score_delta=-3,
            summary=f"X-Frame-Options has a non-standard value: {value!r}.",
            detail="Only DENY and SAMEORIGIN are consistently honored.",
            fix="X-Frame-Options: DENY",
        )]
    return [Finding(
        check="X-Frame-Options", header=name, status="pass",
        severity="OK", score_delta=0,
        summary=f"X-Frame-Options: {value.strip().upper()} is set.",
    )]


_GOOD_REFERRER_POLICIES = {
    "no-referrer", "same-origin", "strict-origin",
    "strict-origin-when-cross-origin", "origin", "origin-when-cross-origin",
}


def check_referrer_policy(headers: Headers) -> list[Finding]:
    name = "Referrer-Policy"
    value = get(headers, name)
    if value is None:
        return [Finding(
            check="Referrer-Policy", header=name, status="missing",
            severity="LOW", score_delta=-5,
            summary="Referrer-Policy is missing.",
            detail=("Without an explicit policy, browsers may send the full page "
                    "URL (including query strings with tokens or IDs) as the "
                    "Referer to third parties."),
            fix="Referrer-Policy: strict-origin-when-cross-origin",
        )]
    v = value.strip().lower().split(",")[0].strip()
    if v == "unsafe-url":
        return [Finding(
            check="Referrer-Policy", header=name, status="weak",
            severity="MED", score_delta=-3,
            summary="Referrer-Policy: unsafe-url leaks the full URL everywhere.",
            detail="Full URLs (including query strings with tokens/IDs) are sent "
                   "to every third party the page links to.",
            fix="Referrer-Policy: strict-origin-when-cross-origin",
        )]
    if v == "no-referrer-when-downgrade":
        return [Finding(
            check="Referrer-Policy", header=name, status="weak",
            severity="LOW", score_delta=-2,
            summary="Referrer-Policy is the lax browser default.",
            detail="no-referrer-when-downgrade still sends full URLs to HTTPS "
                   "third parties. Tighten it unless analytics needs it.",
            fix="Referrer-Policy: strict-origin-when-cross-origin",
        )]
    if v in _GOOD_REFERRER_POLICIES:
        return [Finding(
            check="Referrer-Policy", header=name, status="pass",
            severity="OK", score_delta=0,
            summary=f"Referrer-Policy: {v} is set.",
        )]
    return [Finding(
        check="Referrer-Policy", header=name, status="weak",
        severity="LOW", score_delta=-2,
        summary=f"Referrer-Policy has an unrecognized value: {value!r}.",
        fix="Referrer-Policy: strict-origin-when-cross-origin",
    )]


def check_permissions_policy(headers: Headers) -> list[Finding]:
    name = "Permissions-Policy"
    if get(headers, name) is not None:
        return [Finding(
            check="Permissions-Policy", header=name, status="pass",
            severity="OK", score_delta=0,
            summary="Permissions-Policy is set (restricts powerful browser features).",
        )]
    findings = [Finding(
        check="Permissions-Policy", header=name, status="missing",
        severity="LOW", score_delta=-3,
        summary="Permissions-Policy is missing.",
        detail=("Without it, any third-party script on the page can use the "
                "camera, microphone, geolocation, etc."),
        fix='Permissions-Policy: camera=(), microphone=(), geolocation=()',
    )]
    if get(headers, "feature-policy") is not None:
        findings.append(Finding(
            check="Permissions-Policy", header="Feature-Policy", status="info",
            severity="INFO", score_delta=0,
            summary="Legacy Feature-Policy header found; migrate to Permissions-Policy.",
            detail="Feature-Policy is deprecated; modern browsers only honor Permissions-Policy.",
        ))
    return findings


def check_cross_origin_policies(headers: Headers) -> list[Finding]:
    """COOP / COEP / CORP isolate the page from cross-origin attackers."""
    findings: list[Finding] = []
    coop = get(headers, "cross-origin-opener-policy")
    if coop is None:
        findings.append(Finding(
            check="Cross-Origin-Opener-Policy",
            header="Cross-Origin-Opener-Policy", status="info",
            severity="INFO", score_delta=0,
            summary="Cross-Origin-Opener-Policy is not set.",
            detail=("COOP: same-origin breaks the window.opener link, blocking "
                    "cross-origin XS-Leak and tab-nabbing style attacks."),
            fix="Cross-Origin-Opener-Policy: same-origin",
        ))
    elif coop.strip().lower() not in ("same-origin", "same-origin-allow-popups"):
        findings.append(Finding(
            check="Cross-Origin-Opener-Policy",
            header="Cross-Origin-Opener-Policy", status="weak",
            severity="LOW", score_delta=-2,
            summary=f"COOP has a weak value: {coop!r}.",
            fix="Cross-Origin-Opener-Policy: same-origin",
        ))
    coep = get(headers, "cross-origin-embedder-policy")
    if coep is None:
        findings.append(Finding(
            check="Cross-Origin-Embedder-Policy",
            header="Cross-Origin-Embedder-Policy", status="info",
            severity="INFO", score_delta=0,
            summary="Cross-Origin-Embedder-Policy is not set.",
            detail="COEP: require-corp blocks no-cors cross-origin loads, a "
                   "prerequisite for crossOriginIsolated (SharedArrayBuffer).",
            fix="Cross-Origin-Embedder-Policy: require-corp",
        ))
    corp = get(headers, "cross-origin-resource-policy")
    if corp is None:
        findings.append(Finding(
            check="Cross-Origin-Resource-Policy",
            header="Cross-Origin-Resource-Policy", status="info",
            severity="INFO", score_delta=0,
            summary="Cross-Origin-Resource-Policy is not set.",
            detail="CORP: same-site stops other sites from loading your "
                   "resources no-cors (Spectre / resource-theft mitigation).",
            fix="Cross-Origin-Resource-Policy: same-site",
        ))
    if not findings:
        findings.append(Finding(
            check="Cross-origin isolation", header="COOP/COEP/CORP",
            status="pass", severity="OK", score_delta=0,
            summary="Cross-origin isolation headers are present.",
        ))
    return findings


# Headers where multiple instances with different values are normal (not a
# conflict): each Set-Cookie sets a separate cookie, Vary and Warning combine
# per RFC, and WWW-Authenticate legitimately carries several challenges.
_DUPLICATE_EXEMPT = {"set-cookie", "set-cookie2", "vary", "warning",
                     "www-authenticate"}


def check_conflicting_duplicates(headers: Headers) -> list[Finding]:
    """Flag headers sent more than once with different values.

    fetch() and offline.parse_raw_headers() preserve every instance in order,
    but every other check only looks at the FIRST value. For headers whose
    semantics disagree about which instance wins (RFC 7034 forbids duplicate
    X-Frame-Options precisely because of this), a conflicting duplicate makes
    the enforced policy unpredictable: an attacker or a misconfigured
    proxy/CDN that injects a weaker earlier/later instance can silently win.
    """
    findings: list[Finding] = []
    for name in sorted(headers):
        values = headers[name]
        if len(values) < 2 or name in _DUPLICATE_EXEMPT:
            continue
        normalized = {v.strip().lower() for v in values}
        display_name = "-".join(part.capitalize() for part in name.split("-"))
        if len(normalized) == 1:
            findings.append(Finding(
                check="Duplicate headers", header=display_name, status="info",
                severity="INFO", score_delta=0,
                summary=(f"{display_name} is sent {len(values)} times with the "
                         "same value: harmless duplication."),
                detail=("Identical duplicates have no security impact, but they "
                        "usually mean a header is set in two places (e.g. app "
                        "plus CDN/proxy) and is worth deduplicating."),
            ))
            continue
        distinct = sorted({v.strip() for v in values})
        findings.append(Finding(
            check="Duplicate headers", header=display_name, status="weak",
            severity="MED", score_delta=-5,
            summary=(f"{display_name} is sent {len(values)} times with "
                     f"conflicting values: {', '.join(distinct)}."),
            detail=("Which instance a browser honors varies (first vs. last), "
                    "and HeaderHawk's other checks only evaluate the first, so "
                    "the enforced policy is unpredictable. A misconfigured "
                    "proxy/CDN, or an attacker who can inject a header "
                    "earlier/later in the chain, can silently override the "
                    "intended policy with a weaker one."),
            fix=f"Send {display_name} exactly once, with the intended value.",
        ))
    return findings


def check_redirect_chain(chain: list[RedirectHop]) -> list[Finding]:
    """Audit the redirect chain for HTTPS upgrades, downgrades, and length.

    A plain http:// URL that 301s to https:// is the standard, safe pattern
    (an OK finding confirms it). Any hop that steps DOWN from https:// to
    http:// re-exposes traffic, cookies, and auth tokens to passive network
    attackers, so it is HIGH. Chains longer than 3 redirects add latency and
    give open-redirect bugs more hops to hide behind (LOW). A final response
    still served over plain HTTP means everything is cleartext (MED).
    """
    if len(chain) < 2:
        return []  # served directly; nothing to audit
    findings: list[Finding] = []
    schemes = [urllib.parse.urlsplit(hop.url).scheme.lower() for hop in chain]

    downgraded_at = -1
    for i in range(1, len(schemes)):
        if schemes[i - 1] == "https" and schemes[i] == "http":
            downgraded_at = i
            break
    if downgraded_at != -1:
        findings.append(Finding(
            check="Redirect chain", header="(redirect chain)", status="weak",
            severity="HIGH", score_delta=-10,
            summary=(f"Chain downgrades HTTPS to HTTP at hop {downgraded_at + 1} "
                     f"({chain[downgraded_at].url})."),
            detail=("Everything after the downgrade — page content, cookies, "
                    "auth tokens — travels in cleartext, so a passive network "
                    "attacker can read and modify it. This usually comes from "
                    "a misconfigured redirect rule or a CDN origin set to "
                    "http://."),
            fix="Make every hop in the chain https://; never redirect back to http://.",
        ))
    elif schemes[0] == "http" and "https" in schemes:
        findings.append(Finding(
            check="Redirect chain", header="(redirect chain)", status="pass",
            severity="OK", score_delta=0,
            summary="Chain upgrades plain HTTP to HTTPS before serving content.",
        ))
    if schemes[-1] == "http" and "https" not in schemes:
        findings.append(Finding(
            check="Redirect chain", header="(redirect chain)", status="weak",
            severity="MED", score_delta=-8,
            summary="Entire chain is served over plain HTTP; nothing is encrypted.",
            detail=("No TLS anywhere means passive eavesdropping and active "
                    "content injection by anyone on the path (open Wi-Fi, ISP, "
                    "compromised middlebox)."),
            fix="Serve the site over HTTPS and redirect http:// to https://.",
        ))
    redirects = len(chain) - 1
    if redirects > 3:
        findings.append(Finding(
            check="Redirect chain", header="(redirect chain)", status="weak",
            severity="LOW", score_delta=-2,
            summary=(f"Long redirect chain: {redirects} redirects "
                     f"({len(chain)} hops)."),
            detail=("Each extra hop adds round-trip latency for every visitor "
                    "and gives open-redirect bugs more hops to hide behind. "
                    "Chains this long are usually stacked rules (apex -> www -> "
                    "locale -> trailing slash) that can be collapsed."),
            fix="Collapse the chain so the entry URL lands on the final URL in at most 2-3 redirects.",
        ))
    return findings


def check_disclosure(headers: Headers) -> list[Finding]:
    """Server/software version disclosure helps attackers fingerprint the stack."""
    findings: list[Finding] = []
    server = get(headers, "server")
    if server and _VERSION_RE.search(server):
        findings.append(Finding(
            check="Information disclosure", header="Server",
            status="weak", severity="LOW", score_delta=-2,
            summary=f"Server header discloses software version: {server!r}.",
            detail=("Version strings let attackers pick version-specific "
                    "exploits without probing. Hide or generalize them."),
            fix="Server: <generic>  (e.g. strip the version, keep the product or remove it)",
        ))
    for name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        value = get(headers, name)
        if value:
            findings.append(Finding(
                check="Information disclosure", header=name,
                status="weak", severity="LOW", score_delta=-2,
                summary=f"{name} header discloses stack details: {value!r}.",
                detail="Framework banners help attackers fingerprint the exact "
                       "stack. They serve no purpose for legitimate clients.",
                fix=f"Remove the {name} header.",
            ))
    return findings


def _parse_set_cookie(value: str) -> tuple[str, dict[str, str]]:
    """Split a Set-Cookie value into (cookie name, {attribute: value}).

    Attribute names are lowercased; valueless flags (Secure, HttpOnly) map
    to the empty string. A malformed cookie with no name gets "<unnamed>"
    so findings stay readable.
    """
    parts = value.split(";")
    name = parts[0].split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, _, val = part.partition("=")
            attrs[key.strip().lower()] = val.strip()
        else:
            attrs[part.lower()] = ""
    return name or "<unnamed>", attrs


def check_cookies(headers: Headers) -> list[Finding]:
    """Audit Set-Cookie flags: Secure, HttpOnly, SameSite.

    Three attributes make a cookie meaningfully safer. ``Secure`` stops the
    browser sending it over plain HTTP; ``HttpOnly`` hides it from
    JavaScript, so an XSS bug cannot steal it; ``SameSite`` limits when
    browsers send it on cross-site requests (the CSRF control). Browsers
    now default an absent SameSite to Lax, so a missing attribute is only
    LOW; everything else missing is a real exposure. A cookie carrying all
    three is an OK pass.
    """
    values = all_values(headers, "set-cookie")
    if not values:
        return []  # nothing set; nothing to audit
    findings: list[Finding] = []
    for raw in values:
        name, attrs = _parse_set_cookie(raw)
        before = len(findings)
        if "secure" not in attrs:
            findings.append(Finding(
                check="Cookie flags", header="Set-Cookie", status="weak",
                severity="MED", score_delta=-5,
                summary=f"Cookie {name!r} is missing the Secure flag.",
                detail=("Without Secure, the browser sends this cookie over "
                        "plain HTTP too, so anyone on the network path "
                        "(open Wi-Fi, ISP) can read or steal it."),
                fix=f"Add the Secure attribute: Set-Cookie: {name}=...; Secure",
            ))
        if "httponly" not in attrs:
            findings.append(Finding(
                check="Cookie flags", header="Set-Cookie", status="weak",
                severity="MED", score_delta=-3,
                summary=f"Cookie {name!r} is missing the HttpOnly flag.",
                detail=("Without HttpOnly, JavaScript can read this cookie "
                        "(document.cookie), so a single XSS bug turns into "
                        "session hijacking."),
                fix=f"Add the HttpOnly attribute: Set-Cookie: {name}=...; HttpOnly",
            ))
        samesite = attrs.get("samesite")
        if samesite is None:
            findings.append(Finding(
                check="Cookie flags", header="Set-Cookie", status="weak",
                severity="LOW", score_delta=-2,
                summary=f"Cookie {name!r} has no SameSite attribute.",
                detail=("Browsers currently default to SameSite=Lax, which is "
                        "a reasonable default, but older browsers fall back "
                        "to sending the cookie cross-site. Be explicit: "
                        "SameSite=Lax for logins, Strict for high-value "
                        "sessions."),
                fix=f"Add the attribute: Set-Cookie: {name}=...; SameSite=Lax",
            ))
        elif samesite.lower() == "none":
            if "secure" not in attrs:
                findings.append(Finding(
                    check="Cookie flags", header="Set-Cookie", status="weak",
                    severity="MED", score_delta=-5,
                    summary=(f"Cookie {name!r} uses SameSite=None without "
                             "Secure: browsers will reject the cookie."),
                    detail=("SameSite=None explicitly allows cross-site "
                            "sending, but browsers require the Secure flag "
                            "alongside it; without Secure the cookie is "
                            "dropped entirely, so logins or embeds relying on "
                            "it silently break."),
                    fix=(f"Add the Secure attribute: Set-Cookie: {name}=...; "
                         "Secure; SameSite=None"),
                ))
            else:
                findings.append(Finding(
                    check="Cookie flags", header="Set-Cookie", status="weak",
                    severity="LOW", score_delta=-2,
                    summary=(f"Cookie {name!r} uses SameSite=None: it is sent "
                             "on cross-site requests by design."),
                    detail=("SameSite=None is needed for cookies used in "
                            "third-party contexts (embedded widgets, some "
                            "SSO flows), but it opts out of the browser's "
                            "CSRF protection, so make sure the cookie is "
                            "meant to be cross-site."),
                ))
        elif samesite.lower() not in ("lax", "strict"):
            findings.append(Finding(
                check="Cookie flags", header="Set-Cookie", status="weak",
                severity="LOW", score_delta=-2,
                summary=(f"Cookie {name!r} has an unrecognized SameSite "
                         f"value: {samesite!r}."),
                detail=("Browsers only honor None, Lax, and Strict; anything "
                        "else is ignored and falls back to the Lax default."),
                fix=(f"Use a valid value: Set-Cookie: {name}=...; "
                     "SameSite=Lax"),
            ))
        if len(findings) == before:
            findings.append(Finding(
                check="Cookie flags", header="Set-Cookie", status="pass",
                severity="OK", score_delta=0,
                summary=(f"Cookie {name!r} sets Secure, HttpOnly, and "
                         "SameSite."),
            ))
    return findings


# Cipher-suite name fragments that indicate broken or obsolete crypto.
# "DES" catches 3DES (DES-CBC3); no modern cipher name contains it otherwise.
_WEAK_CIPHER_TOKENS = ("RC4", "DES", "NULL", "ANON", "EXPORT", "MD5")


def check_tls(tls: TLSInfo | str | None) -> list[Finding]:
    """Audit TLS protocol versions and the negotiated cipher (live audits).

    ``tls`` is a ``TLSInfo`` from ``tls.probe_tls()``, the string
    ``"unchecked"`` when the probe did not run (offline/``--headers``
    analysis, bulk mode, plain-HTTP targets), or None for older callers.
    A probe that failed outright surfaces as informational, never as a hard
    error: handshakes can fail for reasons (SNI quirks, filtering) that say
    nothing about the site's TLS posture.
    """
    if tls is None or tls == "unchecked":
        return []
    if tls.error and not tls.versions and not tls.negotiated:
        return [Finding(
            check="TLS protocol versions", header="(TLS handshake)",
            status="info", severity="INFO", score_delta=0,
            summary=f"TLS probe failed: {tls.error}.",
            detail=("HeaderHawk could not complete a TLS handshake with "
                    f"{tls.host}:{tls.port}, so protocol versions and the "
                    "cipher could not be audited. This does not mean the "
                    "site's TLS is bad — only that the probe could not "
                    "reach it."),
        )]
    findings: list[Finding] = []
    versions = set(tls.versions)
    if "TLSv1" in versions:
        findings.append(Finding(
            check="TLS protocol versions", header="(TLS handshake)",
            status="weak", severity="HIGH", score_delta=-10,
            summary="Server still accepts TLS 1.0.",
            detail=("TLS 1.0's cryptography is broken (BEAST, predictable IVs) "
                    "and every modern browser refuses it; a server that still "
                    "negotiates it lets a downgrade attacker push connections "
                    "onto breakable crypto."),
            fix="Disable TLS 1.0 and 1.1 on the server; keep TLS 1.2 and 1.3 only.",
        ))
    elif "TLSv1.1" in versions:
        findings.append(Finding(
            check="TLS protocol versions", header="(TLS handshake)",
            status="weak", severity="MED", score_delta=-8,
            summary="Server still accepts TLS 1.1.",
            detail=("TLS 1.1 is deprecated (RFC 8996) and disabled in all "
                    "modern browsers; keeping it enabled only serves "
                    "downgrade attacks."),
            fix="Disable TLS 1.0 and 1.1 on the server; keep TLS 1.2 and 1.3 only.",
        ))
    weak = [token for token in _WEAK_CIPHER_TOKENS
            if token in tls.cipher.upper()]
    if weak and tls.cipher:
        findings.append(Finding(
            check="TLS cipher", header="(TLS handshake)",
            status="weak", severity="HIGH", score_delta=-10,
            summary=(f"Negotiated cipher uses weak crypto: {tls.cipher} "
                     f"({', '.join(weak)})."),
            detail=("RC4 is fully broken, 3DES/DES fall to Sweet32 on long "
                    "sessions, and NULL/anon/EXPORT suites offer no (or "
                    "trivially breakable) encryption. A weak negotiated "
                    "cipher means the server's cipher preference list still "
                    "offers these to clients."),
            fix=("Remove weak suites (RC4, 3DES, NULL, anon, EXPORT, MD5) "
                 "from the server's cipher list; prefer "
                 "ECDHE+AESGCM or ChaCha20-Poly1305."),
        ))
    if not findings:
        if tls.negotiated == "TLSv1.3":
            findings.append(Finding(
                check="TLS protocol versions", header="(TLS handshake)",
                status="pass", severity="OK", score_delta=0,
                summary=("Modern TLS: negotiates TLS 1.3 and rejects legacy "
                         "protocol versions."),
            ))
        elif tls.negotiated:
            findings.append(Finding(
                check="TLS protocol versions", header="(TLS handshake)",
                status="info", severity="INFO", score_delta=0,
                summary=(f"Negotiates {tls.negotiated}; legacy versions "
                         "rejected."),
                detail=("No legacy protocol versions accepted. TLS 1.3 is "
                        "the current recommendation if the server and "
                        "clients support it."),
            ))
    return findings


def check_sri(html: str | None) -> list[Finding]:
    """Audit Subresource Integrity on external scripts/stylesheets (live only).

    ``html`` is the page body fetched by ``sri.fetch_html()``, or None when
    the audit runs without ``--sri`` (headers-only analysis has no HTML to
    inspect, so the check silently opts out). External ``<script src>`` and
    ``<link rel=stylesheet href>`` without an ``integrity=`` attribute are
    flagged MED: a compromised CDN or MITM can replace the file and the
    browser will run it without complaint.
    """
    if html is None:
        return []
    from .sri import count_protected_resources, find_unprotected_resources
    unprotected = find_unprotected_resources(html)
    findings: list[Finding] = []
    for resource in unprotected:
        findings.append(Finding(
            check="Subresource Integrity", header="(page HTML)",
            status="weak", severity="MED", score_delta=-4,
            summary=(f"External {resource.tag} loads without Subresource "
                     f"Integrity: {resource.url}"),
            detail=("Without an integrity= hash, the browser runs whatever "
                    "the third party serves. If the CDN account is "
                    "compromised or the connection is tampered with, every "
                    "visitor executes the attacker's code. SRI pins the file "
                    "to a sha384 hash so tampered content is refused."),
            fix=(f"Add the hash to the tag: integrity=\"sha384-...\" (generate "
                 f"with: openssl dgst -sha384 -binary file.js | openssl "
                 f"base64 -A), plus crossorigin=\"anonymous\"."),
        ))
    protected = count_protected_resources(html)
    if not findings:
        if protected:
            noun = "resource" if protected == 1 else "resources"
            findings.append(Finding(
                check="Subresource Integrity", header="(page HTML)",
                status="pass", severity="OK", score_delta=0,
                summary=(f"All {protected} external {noun} pinned with "
                         "Subresource Integrity."),
            ))
        else:
            findings.append(Finding(
                check="Subresource Integrity", header="(page HTML)",
                status="info", severity="INFO", score_delta=0,
                summary="No external scripts or stylesheets found to audit.",
                detail=("The page loads no cross-origin <script> or "
                        "stylesheet resources, so there is nothing for SRI "
                        "to pin."),
            ))
    return findings


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def grade_for(score: int) -> str:
    if score >= 100:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 55:
        return "D"
    if score >= 40:
        return "E"
    return "F"


GRADES = ["A+", "A", "B", "C", "D", "E", "F"]


def analyze(headers: Headers, scheme: str = "https", meta: dict | None = None) -> Report:
    """Run every check against a header map and return a scored report."""
    meta = meta or {}
    csp_values = all_values(headers, "content-security-policy")
    csp_directives = parse_csp("; ".join(csp_values)) if csp_values else {}

    findings: list[Finding] = []
    findings += check_hsts(headers, scheme)
    findings += check_hsts_preload(headers, scheme,
                                   meta.get("hsts_preload", "unchecked"))
    findings += check_csp(headers)
    findings += check_x_content_type_options(headers)
    findings += check_x_frame_options(headers, csp_directives)
    findings += check_referrer_policy(headers)
    findings += check_permissions_policy(headers)
    findings += check_cross_origin_policies(headers)
    findings += check_disclosure(headers)
    findings += check_cookies(headers)
    findings += check_conflicting_duplicates(headers)
    findings += check_redirect_chain(meta.get("redirect_chain", []))
    findings += check_tls(meta.get("tls", "unchecked"))
    sri_html = meta.get("sri_html")  # page body, only when --sri was requested
    findings += check_sri(sri_html)
    sri_seen = meta.get("sri_seen", 0)  # set by the --sri fetch path

    score = max(0, min(100, 100 + sum(f.score_delta for f in findings)))

    tls_info = meta.get("tls")
    return Report(
        url=meta.get("url", ""),
        final_url=meta.get("final_url", ""),
        status_code=meta.get("status_code", 0),
        redirects=meta.get("redirects", 0),
        elapsed_ms=meta.get("elapsed_ms", 0),
        scheme=scheme,
        score=score,
        grade=grade_for(score),
        findings=findings,
        headers_seen=len(headers),
        cookies_seen=len(all_values(headers, "set-cookie")),
        sri_seen=sri_seen,
        redirect_chain=list(meta.get("redirect_chain", [])),
        tls_info=tls_info if isinstance(tls_info, TLSInfo) else None,
    )
