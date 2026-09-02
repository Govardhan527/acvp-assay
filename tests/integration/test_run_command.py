"""Integration tests for the complete ``run`` command path."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"


def test_run_command_passes_against_the_tiny_encrypt_fixture() -> None:
    """The installed module CLI reports a clean PASS with exit code zero."""
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "acvp_runner",
            "run",
            str(FIXTURES / "aes-gcm-valid-encrypt/prompt.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(completed.stdout)
    assert completed.returncode == 0
    assert completed.stderr == ""
    assert payload["summary"]["passed"] == 1
    assert payload["provider"]["backend"]["name"] == "OpenSSL"


def test_run_command_writes_output_file(tmp_path: Path) -> None:
    """``--output`` produces the same report as a file, with no stdout noise."""
    output_file = tmp_path / "result.json"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "acvp_runner",
            "run",
            str(FIXTURES / "aes-gcm-valid-decrypt/prompt.json"),
            "--output",
            str(output_file),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    assert completed.stdout == ""
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["summary"]["passed"] == 1


def test_run_command_drives_an_external_harness() -> None:
    """``--provider-command`` runs every case through a separate process.

    This is the boundary that lets a customer test crypto this project cannot
    link against, so the report must attribute results to their harness rather
    than to the built-in provider.
    """
    example = ROOT / "examples/reference_harness.py"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "acvp_runner",
            "run",
            str(FIXTURES / "aes-gcm-valid-encrypt/prompt.json"),
            "--provider-command",
            f"{sys.executable} {example}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(completed.stdout)
    assert completed.returncode == 0
    assert payload["summary"]["passed"] == 1
    assert payload["provider"]["name"] == "reference-harness"


def test_run_command_reports_a_broken_harness_without_crashing(tmp_path: Path) -> None:
    """A harness that cannot run degrades into reported cases, not a traceback."""
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "acvp_runner",
            "run",
            str(FIXTURES / "aes-gcm-valid-encrypt/prompt.json"),
            "--provider-command",
            "definitely-not-a-real-command-xyz",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    assert "Traceback" not in completed.stderr
    assert "error:" in completed.stderr


def test_run_command_fails_visibly_on_the_intentionally_bad_fixture() -> None:
    """A deliberately corrupted tag produces a deterministic, non-zero exit.

    This is the A14 "intentionally bad fixture" gate: the fixture's tag is a
    single deterministically flipped hex digit (see fixtures/README.md), so
    the failure is reproducible on every clean checkout, not flaky.
    """
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "acvp_runner",
            "run",
            str(FIXTURES / "aes-gcm-invalid-decrypt-tag/prompt.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(completed.stdout)
    assert completed.returncode == 1
    assert payload["summary"]["errored"] == 1
    assert payload["cases"][0]["status"] == "ERROR"
    assert payload["cases"][0]["diagnostic"] == "authentication failed"
