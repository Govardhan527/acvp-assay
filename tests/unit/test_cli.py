"""Unit tests for the command-line interface."""

from __future__ import annotations

import json
import runpy
import sys

import pytest

from acvp_runner.cli import build_parser, main


def test_info_prints_metadata(capsys: pytest.CaptureFixture[str]) -> None:
    """The info command emits parseable provider metadata."""
    exit_code = main(["info"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["provider"] == "OpenSSL (via cryptography)"
    assert payload["runner_version"] == "0.0.0"
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


def test_module_entry_point(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The module entry point delegates to the CLI and exits successfully."""
    monkeypatch.setattr(sys, "argv", ["acvp-runner", "info"])

    with pytest.raises(SystemExit) as error:
        runpy.run_module("acvp_runner", run_name="__main__")

    assert error.value.code == 0
    assert json.loads(capsys.readouterr().out)["provider"] == "OpenSSL (via cryptography)"
