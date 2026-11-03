"""--compare-headers mode tests: offline diff of two saved header dumps."""

import json
import pathlib

from headerhawk.cli import main

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
SECURE = str(FIXTURES / "secure-headers.txt")
INSECURE = str(FIXTURES / "insecure-headers.txt")


def test_cli_compare_headers_text_diff(capsys):
    code = main(["--compare-headers", INSECURE, SECURE, "--no-color"])
    assert code == 0
    out = capsys.readouterr().out
    assert "compare" in out
    assert "F -> A+" in out
    assert "Score change: +65" in out
    assert "Resolved" in out
    assert "New findings" in out


def test_cli_compare_headers_json_diff(capsys):
    code = main(["--compare-headers", INSECURE, SECURE, "--json",
                 "--no-color"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["grade_before"] == "F"
    assert payload["grade_after"] == "A+"
    assert payload["score_delta"] == 65
    assert payload["diff"]


def test_cli_compare_headers_identical_is_no_difference(capsys):
    code = main(["--compare-headers", SECURE, SECURE, "--no-color"])
    assert code == 0
    assert "No differences" in capsys.readouterr().out


def test_cli_compare_headers_missing_file_fails_fast(capsys):
    assert main(["--compare-headers", "/nonexistent-a.txt", SECURE]) == 2
    err = capsys.readouterr().err
    assert "cannot read" in err or "No such file" in err


def test_cli_compare_headers_empty_file_fails_fast(tmp_path, capsys):
    empty = tmp_path / "empty.txt"
    empty.write_text("nothing useful here\n")
    assert main(["--compare-headers", str(empty), SECURE]) == 2
    assert "No HTTP headers found" in capsys.readouterr().err


def test_cli_compare_headers_rejects_url_and_raw(capsys):
    assert main(["https://example.com", "--compare-headers",
                 INSECURE, SECURE]) == 2
    assert main(["--compare-headers", INSECURE, SECURE, "--raw"]) == 2


def test_cli_compare_headers_fail_below_gates_on_file_b(capsys):
    # FILE_B is A+: requiring A+ passes, requiring F on the reverse order fails.
    assert main(["--compare-headers", INSECURE, SECURE,
                 "--fail-below", "A+", "--no-color"]) == 0
    assert main(["--compare-headers", SECURE, INSECURE,
                 "--fail-below", "A+", "--no-color"]) == 1
