"""Unit tests for the command-line interface."""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path

import pytest

from acvp_assay import __version__
from acvp_assay.cli import build_parser, main

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
REFERENCE = (
    f"{sys.executable} {Path(__file__).resolve().parents[2] / 'examples/reference_harness.py'}"
)


def test_info_prints_metadata(capsys: pytest.CaptureFixture[str]) -> None:
    """The info command emits parseable provider metadata."""
    exit_code = main(["info"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["provider"] == "built-in (cryptography and hashlib)"
    assert payload["provider_kind"] == "builtin"
    # Against the package, not a literal: a hard-coded version turns every
    # release into a test failure that says nothing about behaviour.
    assert payload["runner_version"] == __version__
    libraries = {entry["name"]: entry for entry in payload["provider_libraries"]}
    assert set(libraries) == {"cryptography", "hashlib"}
    for entry in libraries.values():
        assert entry["version"]
        assert entry["backend_version"].startswith("OpenSSL ")
    assert payload["python_version"].startswith("3.12")


def test_info_names_an_external_harness_by_what_it_declares(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The harness identifies itself, and the built-in library versions are absent."""
    exit_code = main(["info", "--provider-command", REFERENCE])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["provider"] == "reference-harness"
    assert payload["provider_kind"] == "external"
    assert payload["provider_command"].endswith("examples/reference_harness.py")
    assert payload["provider_build_id"].startswith("sha256:")
    assert payload["provider_build_id_absent_reason"] is None
    assert "provider_libraries" not in payload


def test_info_reports_a_harness_that_cannot_identify_itself(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A named harness that does not answer is an input error, not a built-in description."""
    exit_code = main(["info", "--provider-command", "definitely-not-a-real-command-xyz"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "not found" in captured.err


def test_a_harness_run_reports_its_provider_as_external(tmp_path: Path) -> None:
    """A run answered by a harness cannot be read as a built-in run."""
    output = tmp_path / "report.json"
    prompt = FIXTURES / "sha2-256-known-answers/prompt.json"

    exit_code = main(["run", str(prompt), "--provider-command", REFERENCE, "--output", str(output)])

    provider = json.loads(output.read_text(encoding="utf-8"))["provider"]
    assert exit_code == 0
    assert provider["kind"] == "external"
    assert provider["name"] == "reference-harness"
    assert provider["command"].endswith("examples/reference_harness.py")
    assert provider["buildId"].startswith("sha256:")
    assert provider["buildIdAbsentReason"] is None
    assert "openssl_version" not in provider


def test_a_built_in_run_reports_its_provider_as_built_in(tmp_path: Path) -> None:
    """The built-in path is unchanged apart from saying what it is."""
    output = tmp_path / "report.json"
    prompt = FIXTURES / "sha2-256-known-answers/prompt.json"

    exit_code = main(["run", str(prompt), "--output", str(output)])

    report = json.loads(output.read_text(encoding="utf-8"))
    provider = report["provider"]
    assert exit_code == 0
    assert report["runner"]["version"] == __version__
    assert set(report["runner"]) == {"version", "commit", "commitAbsentReason", "treeClean"}
    assert provider["kind"] == "builtin"
    assert provider["name"] == "hashlib-sha2-256"
    assert "command" not in provider
    assert "buildId" not in provider


def test_a_harness_that_names_no_build_is_noted_on_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The output records not_reported and the operator is told; nothing is failed."""
    script = tmp_path / "silent.py"
    script.write_text(
        "import json, sys\n"
        "for _line in sys.stdin:\n"
        '    print(json.dumps({"name": "silent", "libraryName": "l", "libraryVersion": "1", '
        '"backendName": "b", "backendVersion": "2"}), flush=True)\n'
    )

    exit_code = main(["info", "--provider-command", f"{sys.executable} {script}"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert json.loads(captured.out)["provider_build_id_absent_reason"] == "not_reported"
    assert "not_reported" in captured.err


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
        "unsupportedByReason": {
            "implementation_lacks": 0,
            "offline_undecidable": 0,
            "runner_lacks": 0,
            "vector_incomplete": 0,
        },
        "unsupportedByClaimant": {
            "harness": {"implementation_lacks": 0, "vector_incomplete": 0},
            "runner": {
                "implementation_lacks": 0,
                "offline_undecidable": 0,
                "runner_lacks": 0,
                "vector_incomplete": 0,
            },
        },
        "concentration": {"partition": "cases-by-tgId", "cardinality": 1, "largestTwoShare": 1.0},
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
        json.dumps({"vsId": 1, "algorithm": "ACVP-AES-FF1", "revision": "1.0", "testGroups": []}),
        encoding="utf-8",
    )
    (tmp_path / "expectedResults.json").write_text("{}", encoding="utf-8")

    exit_code = main(["run", str(prompt)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "unsupported algorithm 'ACVP-AES-FF1'" in captured.err
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
    assert json.loads(capsys.readouterr().out)["provider"] == "built-in (cryptography and hashlib)"


@pytest.mark.parametrize(
    ("descriptor", "message"),
    [(2, "reserved"), (77, "not an open descriptor")],
)
def test_a_bad_provider_descriptor_is_refused_before_anything_runs(
    descriptor: int, message: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Checked in the runner, not in the child, where it would surface mid-run."""
    exit_code = main(["info", "--provider-command", "true", "--provider-pass-fd", str(descriptor)])

    assert exit_code == 2
    assert message in capsys.readouterr().err
