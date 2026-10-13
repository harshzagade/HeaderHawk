"""Security-header checks and scoring.

Each check inspects the response headers and returns a list of findings.
Every finding carries a score delta; the final score starts at 100 and is
clamped to 0..100, then mapped to a letter grade.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

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
        )]
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
    findings += check_csp(headers)
    findings += check_x_content_type_options(headers)
    findings += check_x_frame_options(headers, csp_directives)
    findings += check_referrer_policy(headers)
    findings += check_permissions_policy(headers)
    findings += check_cross_origin_policies(headers)
    findings += check_disclosure(headers)
    findings += check_conflicting_duplicates(headers)

    score = max(0, min(100, 100 + sum(f.score_delta for f in findings)))

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
    )
