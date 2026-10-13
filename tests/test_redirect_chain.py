"""Redirect-chain audit tests: upgrades, downgrades, length, plain HTTP."""

from headerhawk.checks import RedirectHop, analyze, check_redirect_chain


def _chain(*hops):
    return [RedirectHop(url=url, status=status) for url, status in hops]


def test_no_redirects_produces_no_findings():
    assert check_redirect_chain(_chain(("https://example.com/", 200))) == []
    assert check_redirect_chain([]) == []


def test_http_to_https_upgrade_is_ok():
    findings = check_redirect_chain(_chain(
        ("http://example.com/", 301),
        ("https://example.com/", 200),
    ))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "OK"
    assert finding.status == "pass"
    assert finding.score_delta == 0
    assert "upgrades" in finding.summary.lower()


def test_https_to_http_downgrade_is_high():
    findings = check_redirect_chain(_chain(
        ("https://example.com/", 302),
        ("http://example.com/landing", 302),
        ("http://example.com/landing/", 200),
    ))
    highs = [f for f in findings if f.severity == "HIGH"]
    assert len(highs) == 1
    assert highs[0].score_delta == -10
    assert "downgrade" in highs[0].summary.lower()
    # A downgraded chain must not also earn the upgrade OK.
    assert not any(f.severity == "OK" for f in findings)


def test_entirely_plain_http_chain_is_med():
    findings = check_redirect_chain(_chain(
        ("http://example.com/", 301),
        ("http://www.example.com/", 200),
    ))
    meds = [f for f in findings if f.severity == "MED"]
    assert len(meds) == 1
    assert meds[0].score_delta == -8


def test_long_chain_is_flagged():
    findings = check_redirect_chain(_chain(
        ("https://example.com/", 301),
        ("https://www.example.com/", 302),
        ("https://www.example.com/en", 301),
        ("https://www.example.com/en/", 302),
        ("https://www.example.com/en/home", 200),
    ))
    lows = [f for f in findings if f.severity == "LOW"]
    assert len(lows) == 1
    assert lows[0].score_delta == -2
    assert "4 redirects" in lows[0].summary


def test_three_redirects_is_not_long():
    findings = check_redirect_chain(_chain(
        ("http://example.com/", 301),
        ("https://example.com/", 301),
        ("https://www.example.com/", 301),
        ("https://www.example.com/home", 200),
    ))
    assert not any(f.severity == "LOW" for f in findings)
    # ...but the upgrade still gets its OK.
    assert any(f.severity == "OK" for f in findings)


def test_downgrade_penalizes_analyze_score():
    report = analyze(
        {},
        scheme="https",
        meta={"redirect_chain": _chain(
            ("https://example.com/", 302),
            ("http://example.com/x", 200),
        )},
    )
    assert any(f.severity == "HIGH" and f.check == "Redirect chain"
               for f in report.findings)
    assert report.redirect_chain == [
        RedirectHop(url="https://example.com/", status=302),
        RedirectHop(url="http://example.com/x", status=200),
    ]


def test_chain_appears_in_json_dict():
    report = analyze(
        {},
        scheme="https",
        meta={"redirect_chain": _chain(("http://example.com/", 301),
                                      ("https://example.com/", 200))},
    )
    payload = report.to_dict()
    assert payload["redirect_chain"] == [
        {"url": "http://example.com/", "status": 301},
        {"url": "https://example.com/", "status": 200},
    ]
