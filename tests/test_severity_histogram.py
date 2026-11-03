"""JSON severity histogram tests: per-severity counts in Report.to_dict()."""

import json
import pathlib

from headerhawk.checks import Finding, Report
from headerhawk.cli import main

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def _finding(severity):
    return Finding(check="Test-Check", header="X-Test", status="weak",
                   severity=severity, score_delta=0, summary="test")


def test_severity_counts_includes_all_severities_at_zero():
    report = Report(url="https://example.com", grade="A+", score=100,
                    findings=[_finding("HIGH"), _finding("HIGH"),
                              _finding("MED"), _finding("OK")])
    assert report.severity_counts() == {"HIGH": 2, "MED": 1, "LOW": 0,
                                        "INFO": 0, "OK": 1}
    assert report.to_dict()["severity_counts"] == report.severity_counts()


def test_severity_counts_empty_report_is_all_zeros():
    report = Report(url="https://example.com", grade="A+", score=100)
    assert report.severity_counts() == {"HIGH": 0, "MED": 0, "LOW": 0,
                                        "INFO": 0, "OK": 0}


def test_json_output_carries_histogram_summing_to_findings(capsys):
    # Drive the real CLI offline path so the histogram is proven in --json,
    # not only on a hand-built Report.
    code = main(["--headers", str(FIXTURES / "insecure-headers.txt"),
                 "--json", "--no-color"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    counts = payload["severity_counts"]
    assert set(counts) == {"HIGH", "MED", "LOW", "INFO", "OK"}
    assert sum(counts.values()) == len(payload["findings"])
    assert counts["HIGH"] > 0
    # Every finding's severity is accounted for exactly once.
    for severity in ("HIGH", "MED", "LOW", "INFO", "OK"):
        assert counts[severity] == sum(
            1 for f in payload["findings"] if f["severity"] == severity)
