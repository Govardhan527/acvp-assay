"""Unit tests for the command-line interface."""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path

import pytest

from acvp_assay.cli import build_parser, main

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def test_info_prints_metadata(capsys: pytest.CaptureFixture[str]) -> None:
    """The info command emits parseable provider metadata."""
    exit_code = main(["info"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["provider"] == "OpenSSL (via cryptography)"
    assert payload["runner_version"] == "0.7.0"
    assert payload["cryptography_version"]
    assert payload["openssl_version"].startswith("OpenSSL ")
    assert payload["python_version"].startswith("3.12")


def test_parser_requires_a_subcommand() -> None:
    """The CLI contract rejects an omitted command."""
    parser = build_parser()

    try:
        parser.parse_args([])
    except SystemExit as error:
        assert error.code == 2
    else:
        raise AssertionError("parse_args should reject an omitted command")


def test_run_prints_json_report_and_exits_zero_on_pass(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A passing vector file is reported to stdout with a zero exit code."""
    vector_file = str(FIXTURES / "aes-gcm-valid-encrypt/prompt.json")

    exit_code = main(["run", vector_file])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["summary"] == {
        "total": 1,
        "passed": 1,
        "failed": 0,
        "errored": 0,
        "skipped": 0,
        "unsupported": 0,
    }


def test_run_exits_nonzero_on_case_error(capsys: pytest.CaptureFixture[str]) -> None:
    """A vector file with an authentication failure exits with a failure code."""
    vector_file = str(FIXTURES / "aes-gcm-invalid-decrypt-tag/prompt.json")

    exit_code = main(["run", vector_file])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert payload["summary"]["errored"] == 1


def test_run_writes_output_file_instead_of_stdout(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``--output`` redirects the JSON report to a file and prints nothing."""
    vector_file = str(FIXTURES / "aes-gcm-valid-decrypt/prompt.json")
    output_file = tmp_path / "result.json"

    exit_code = main(["run", vector_file, "--output", str(output_file)])

    assert exit_code == 0
    assert capsys.readouterr().out == ""
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["summary"]["passed"] == 1


def test_run_reports_a_load_error_with_exit_code_two(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A missing vector file is a bounded input error, not a crash."""
    exit_code = main(["run", str(tmp_path / "missing.json")])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "error:" in captured.err


def test_run_strict_fails_on_unsupported_iv_generation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``--strict`` turns an UNSUPPORTED case into a run failure."""
    prompt = json.loads((FIXTURES / "aes-gcm-valid-encrypt/prompt.json").read_text())
    prompt["testGroups"][0]["ivGen"] = "internal"
    (tmp_path / "prompt.json").write_text(json.dumps(prompt), encoding="utf-8")
    expected = (FIXTURES / "aes-gcm-valid-encrypt/expectedResults.json").read_text()
    (tmp_path / "expectedResults.json").write_text(expected, encoding="utf-8")

    lenient_exit_code = main(["run", str(tmp_path / "prompt.json")])
    capsys.readouterr()
    strict_exit_code = main(["run", str(tmp_path / "prompt.json"), "--strict"])
    payload = json.loads(capsys.readouterr().out)

    assert lenient_exit_code == 0
    assert strict_exit_code == 1
    assert payload["summary"]["unsupported"] == 1


def test_unsupported_algorithm_is_reported_clearly(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A vector file for an algorithm we do not implement names what we do."""
    prompt = tmp_path / "prompt.json"
    prompt.write_text(
        json.dumps({"vsId": 1, "algorithm": "ACVP-AES-CBC", "revision": "1.0", "testGroups": []}),
        encoding="utf-8",
    )
    (tmp_path / "expectedResults.json").write_text("{}", encoding="utf-8")

    exit_code = main(["run", str(prompt)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "unsupported algorithm 'ACVP-AES-CBC'" in captured.err
    assert "SHA2-256" in captured.err


def test_run_rejects_an_unusable_harness_before_running_cases(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A harness that cannot identify itself stops the run with one message.

    Without the up-front metadata probe this reported every case as an error
    and then crashed on the report, which is a confusing first experience for
    anyone wiring up their own harness.
    """
    vector_file = str(FIXTURES / "aes-gcm-valid-encrypt/prompt.json")

    exit_code = main(["run", vector_file, "--provider-command", "definitely-not-a-real-cmd-xyz"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "not found" in captured.err


def test_module_entry_point(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The module entry point delegates to the CLI and exits successfully."""
    monkeypatch.setattr(sys, "argv", ["acvp-assay", "info"])

    with pytest.raises(SystemExit) as error:
        runpy.run_module("acvp_assay", run_name="__main__")

    assert error.value.code == 0
    assert json.loads(capsys.readouterr().out)["provider"] == "OpenSSL (via cryptography)"
