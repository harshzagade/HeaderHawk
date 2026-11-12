"""JSON `generated_at` timestamp tests: audit time in --json reports."""

import datetime
import json
import pathlib
import re

from headerhawk.checks import analyze
from headerhawk.cli import main
from headerhawk.report import report_from_dict

FIXTURES = pathlib.Path(__file__).parent / "fixtures"

_ISO_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _parseable_utc(stamp: str) -> datetime.datetime:
    parsed = datetime.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ")
    return parsed.replace(tzinfo=datetime.timezone.utc)


def test_analyze_stamps_utc_iso_timestamp():
    report = analyze({"strict-transport-security": ["max-age=63072000"]},
                     scheme="https")
    assert _ISO_Z.match(report.generated_at), report.generated_at
    # Within a minute of now: the stamp is the audit run's time, not a constant.
    now = datetime.datetime.now(datetime.timezone.utc)
    assert abs((now - _parseable_utc(report.generated_at)).total_seconds()) < 60


def test_to_dict_carries_generated_at():
    report = analyze({}, scheme="https")
    assert report.to_dict()["generated_at"] == report.generated_at


def test_meta_generated_at_is_honored():
    report = analyze({}, scheme="https",
                     meta={"generated_at": "2026-11-12T14:48:11Z"})
    assert report.generated_at == "2026-11-12T14:48:11Z"


def test_report_from_dict_round_trips_generated_at():
    report = analyze({}, scheme="https",
                     meta={"generated_at": "2026-11-12T14:48:11Z"})
    rebuilt = report_from_dict(report.to_dict())
    assert rebuilt.generated_at == "2026-11-12T14:48:11Z"


def test_report_from_dict_old_baseline_without_key_loads_empty():
    payload = {"url": "https://example.com", "grade": "A+", "score": 100,
               "findings": []}
    assert report_from_dict(payload).generated_at == ""


def test_cli_json_output_carries_generated_at(capsys):
    code = main(["--headers", str(FIXTURES / "secure-headers.txt"),
                 "--json", "--no-color"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert _ISO_Z.match(payload["generated_at"]), payload["generated_at"]
