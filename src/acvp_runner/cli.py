"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from acvp_runner.algorithms import UnsupportedAlgorithmError, run_vector_file
from acvp_runner.diff import compare, diff_json, load_report, summarize_text
from acvp_runner.metadata import runtime_metadata
from acvp_runner.parser import AcvpValidationError
from acvp_runner.providers.subprocess_harness import DEFAULT_TIMEOUT_SECONDS
from acvp_runner.reporter import report_json, summarize
from acvp_runner.runner import ExpectedResultsMismatchError

EXIT_SUCCESS = 0
EXIT_CASE_FAILURES = 1
EXIT_INPUT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="acvp-runner",
        description="Run offline ACVP vectors through a cryptographic provider.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "info",
        help="print Python, cryptography, and OpenSSL provider metadata as JSON",
    )
    run_parser = subparsers.add_parser(
        "run",
        help="execute one ACVP AES-GCM vector file and report case results",
    )
    run_parser.add_argument(
        "vector_file",
        type=Path,
        help=(
            "path to an ACVP-shaped prompt.json vector file; an "
            "expectedResults.json file must exist alongside it"
        ),
    )
    run_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="RESULT_FILE",
        help="write the JSON report to this file instead of stdout",
    )
    run_parser.add_argument(
        "--strict",
        action="store_true",
        help="also fail the run if any case is SKIPPED or UNSUPPORTED",
    )
    run_parser.add_argument(
        "--provider-command",
        default=None,
        metavar="COMMAND",
        help=(
            "run every case through an external harness command instead of the "
            "built-in OpenSSL-backed provider; see examples/reference_harness.py"
        ),
    )
    run_parser.add_argument(
        "--provider-timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help=(
            f"per-operation timeout for an external harness (default: {DEFAULT_TIMEOUT_SECONDS:g})"
        ),
    )
    diff_parser = subparsers.add_parser(
        "diff",
        help="compare two run reports and report regressions",
    )
    diff_parser.add_argument("baseline", type=Path, help="the earlier JSON report")
    diff_parser.add_argument("current", type=Path, help="the later JSON report")
    diff_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="DIFF_FILE",
        help="write the JSON diff to this file instead of a text summary on stdout",
    )
    return parser


def _diff(baseline: Path, current: Path, output: Path | None) -> int:
    """Compare two reports and return an exit code.

    Exit codes: 0 (nothing got worse), 1 (a case regressed, or coverage was
    lost -- a case that used to run is now unsupported, skipped, or absent),
    2 (a report could not be read).

    Coverage loss counts as a regression on purpose: a run that quietly stops
    testing something still reports clean totals, which is exactly how a
    conformance break survives to the next validation cycle.
    """
    try:
        result = compare(load_report(baseline), load_report(current))
        rendered = diff_json(result)
        if output is not None:
            output.write_text(rendered, encoding="utf-8")
    except (AcvpValidationError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    print(summarize_text(result), end="")
    return EXIT_CASE_FAILURES if result.has_regressions else EXIT_SUCCESS


def _run(
    vector_file: Path,
    output: Path | None,
    strict: bool,
    provider_command: str | None = None,
    provider_timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> int:
    """Execute the ``run`` subcommand and return its process exit code.

    Exit codes: 0 (every executed case is a hard PASS, respecting
    ``--strict``), 1 (at least one case FAILED, ERRORED, or -- under
    ``--strict`` -- was SKIPPED/UNSUPPORTED), 2 (the run could not start:
    a missing file, malformed JSON, a schema violation, an expected-results
    file that does not match the vector set, or an external harness that
    cannot identify itself).

    Provider metadata is fetched before any case runs. A harness that cannot
    answer that first request is misconfigured, so the run stops with one
    clear message rather than reporting every case as an error.
    """
    expected_file = vector_file.parent / "expectedResults.json"
    try:
        results, provider_metadata = run_vector_file(
            vector_file,
            expected_file,
            provider_command=provider_command,
            provider_timeout=provider_timeout,
        )
        rendered = report_json(results, provider_metadata)
        if output is not None:
            output.write_text(rendered, encoding="utf-8")
    except (
        AcvpValidationError,
        ExpectedResultsMismatchError,
        UnsupportedAlgorithmError,
        ValueError,
        OSError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    if output is None:
        print(rendered, end="")

    summary = summarize(results)
    has_hard_failures = summary.failed > 0 or summary.errored > 0
    has_soft_failures = strict and (summary.skipped > 0 or summary.unsupported > 0)
    if has_hard_failures or has_soft_failures:
        return EXIT_CASE_FAILURES
    return EXIT_SUCCESS


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface and return a process exit code."""
    args = build_parser().parse_args(argv)
    if args.command == "diff":
        return _diff(args.baseline, args.current, args.output)
    if args.command == "run":
        return _run(
            args.vector_file,
            args.output,
            args.strict,
            args.provider_command,
            args.provider_timeout,
        )
    print(json.dumps(runtime_metadata(), indent=2, sort_keys=True))
    return EXIT_SUCCESS
