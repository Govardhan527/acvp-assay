"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from acvp_runner.metadata import runtime_metadata


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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface and return a process exit code."""
    build_parser().parse_args(argv)
    print(json.dumps(runtime_metadata(), indent=2, sort_keys=True))
    return 0
