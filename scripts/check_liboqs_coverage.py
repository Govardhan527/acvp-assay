#!/usr/bin/env python3
"""Run every pinned PQC set through the liboqs harness and check what it reaches.

This is the measurement ``examples/liboqs`` exists to make, kept honest by being
run rather than described. Each set is answered twice: once restricted to
liboqs's published API, and once allowed the entry points underneath it. The
first number is what a caller linking against ``OQS_SIG_*`` can get; the second
is what the library can actually answer.

The expected counts below are pinned, because everything they depend on is:
NIST's vectors at one ACVP-Server commit, liboqs at one commit, and a harness
that declines rather than improvises. A number that moves is liboqs having
changed what it exposes, or this harness having stopped reaching it, and either
is worth failing a build over.

    python3 scripts/check_liboqs_coverage.py [--print-table]
"""

from __future__ import annotations

import argparse
import collections
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "examples/liboqs/acvp_harness"
VECTORS = ROOT / "vectors"
RUNNER = [str(ROOT / ".venv/bin/python"), "-m", "acvp_assay"]
TIMEOUT_SECONDS = 3600


@dataclass(frozen=True, slots=True)
class Expectation:
    """What one vector set should report under one interface."""

    vector_set: str
    interface: str
    passed: int
    declines: dict[str, int]

    @property
    def total(self) -> int:
        """Every case in the set, whatever became of it."""
        return self.passed + sum(self.declines.values())


#: Measured against liboqs 0.16.0 (5a1a854) and ACVP-Server 975de31.
#:
#: Read the two interfaces side by side. ML-KEM is identical in both, because
#: ``keypair_derand`` and ``encaps_derand`` take the seeds ACVP supplies and are
#: part of the published API. ML-DSA is not: its published API takes no seed, no
#: ``rnd`` and no ``mu``, so every keyGen and sigGen case and three quarters of
#: sigVer are unreachable through it, and reachable immediately below it.
EXPECTED = (
    Expectation("ML-KEM-keyGen-FIPS203", "public", 75, {}),
    Expectation("ML-KEM-keyGen-FIPS203", "extended", 75, {}),
    Expectation("ML-KEM-encapDecap-FIPS203", "public", 165, {}),
    Expectation("ML-KEM-encapDecap-FIPS203", "extended", 165, {}),
    Expectation("ML-DSA-keyGen-FIPS204", "public", 0, {"interface_lacks": 75}),
    Expectation("ML-DSA-keyGen-FIPS204", "extended", 75, {}),
    Expectation("ML-DSA-sigGen-FIPS204", "public", 0, {"interface_lacks": 360}),
    Expectation("ML-DSA-sigGen-FIPS204", "extended", 335, {"implementation_lacks": 25}),
    Expectation("ML-DSA-sigVer-FIPS204", "public", 45, {"interface_lacks": 135}),
    Expectation("ML-DSA-sigVer-FIPS204", "extended", 165, {"implementation_lacks": 15}),
)


def run_one(expectation: Expectation, output: Path) -> dict[str, object]:
    """Answer one set through the harness and return its report."""
    prompt = VECTORS / expectation.vector_set / "prompt.json"
    if not prompt.is_file():
        raise SystemExit(
            f"missing {prompt.relative_to(ROOT)}; run "
            "scripts/fetch_vectors.py --only ML-KEM --only ML-DSA"
        )
    command = [
        *RUNNER,
        "run",
        str(prompt),
        "--provider-command",
        f"{HARNESS} --interface {expectation.interface}",
        "--provider-timeout",
        "120",
        "--output",
        str(output),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=TIMEOUT_SECONDS)
    # Exit 1 means cases failed, which the comparison below reports precisely;
    # exit 2 means the run could not start, which nothing below can explain.
    if completed.returncode == 2:
        raise SystemExit(f"the run could not start: {completed.stderr.strip()}")
    document: dict[str, object] = json.loads(output.read_text(encoding="utf-8"))
    return document


def check(report: dict[str, object], expectation: Expectation) -> list[str]:
    """Every way this report differs from what the pin says it should be."""
    summary = report["summary"]
    assert isinstance(summary, dict)
    problems: list[str] = []
    if summary["passed"] != expectation.passed:
        problems.append(f"passed {summary['passed']}, expected {expectation.passed}")
    for state in ("failed", "errored"):
        if summary[state]:
            problems.append(f"{state} {summary[state]}, expected 0")
    reasons = summary["unsupportedByReason"]
    assert isinstance(reasons, dict)
    for reason, count in reasons.items():
        wanted = expectation.declines.get(reason, 0)
        if count != wanted:
            problems.append(f"{reason} {count}, expected {wanted}")
    return problems


def coverage_rows(report: dict[str, object], vector_set: str) -> list[tuple[str, str, str, int]]:
    """Operation, parameter set, result state and case count, from one report.

    The report knows a case's group; the prompt knows what that group *is*. ACVP
    puts the operation and the parameter set on the group, so this reads them
    back out and joins on ``tgId``, which is the only identity the two documents
    share.
    """
    prompt = json.loads((VECTORS / vector_set / "prompt.json").read_text(encoding="utf-8"))
    mode = prompt["mode"]
    identity: dict[int, tuple[str, str]] = {}
    for group in prompt["testGroups"]:
        operation = group.get("function", mode)
        if mode in ("sigGen", "sigVer"):
            shape = "externalMu" if group.get("externalMu") else group.get("preHash", "pure")
            parts = [group.get("signatureInterface", "external"), shape]
            # sigGen groups say which randomness they use, and it decides whether
            # an API can express the case at all; sigVer groups do not have one.
            if "deterministic" in group:
                parts.append("deterministic" if group["deterministic"] else "hedged")
            operation = f"{mode} ({', '.join(parts)})"
        identity[group["tgId"]] = (operation, group["parameterSet"])

    counted: collections.Counter[tuple[str, str, str]] = collections.Counter()
    cases = report["cases"]
    assert isinstance(cases, list)
    for case in cases:
        operation, parameter_set = identity[case["tgId"]]
        state = case["status"]
        if state == "UNSUPPORTED":
            state = f"UNSUPPORTED / {case['declineReason']}"
        counted[(operation, parameter_set, state)] += 1
    return [(*key, count) for key, count in sorted(counted.items())]


def main(argv: list[str] | None = None) -> int:
    """Run every pinned PQC set through both interfaces and check the counts."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--print-table",
        action="store_true",
        help="also print the coverage table: operation x parameter set x result state",
    )
    arguments = parser.parse_args(argv)

    if not HARNESS.is_file():
        raise SystemExit(
            f"missing {HARNESS.relative_to(ROOT)}; build it with "
            "make -C examples/liboqs LIBOQS=<prefix>"
        )

    failures = 0
    rows: list[tuple[str, str, str, str, int]] = []
    with tempfile.TemporaryDirectory() as workspace:
        for expectation in EXPECTED:
            output = Path(workspace) / f"{expectation.vector_set}-{expectation.interface}.json"
            report = run_one(expectation, output)
            problems = check(report, expectation)
            label = f"{expectation.vector_set} [{expectation.interface}]"
            if problems:
                failures += 1
                print(f"MISMATCH {label}: {'; '.join(problems)}", file=sys.stderr)
            else:
                declined = ", ".join(f"{n} {r}" for r, n in expectation.declines.items())
                print(
                    f"ok       {label}: {expectation.passed} of {expectation.total} pass"
                    + (f", {declined}" if declined else "")
                )
            rows.extend(
                (expectation.interface, *row)
                for row in coverage_rows(report, expectation.vector_set)
            )

    if arguments.print_table:
        print("\n| interface | operation | parameter set | result | cases |")
        print("| --- | --- | --- | --- | ---: |")
        for interface, operation, parameter_set, state, count in rows:
            print(f"| {interface} | {operation} | {parameter_set} | {state} | {count} |")

    if failures:
        print(f"\n{failures} set(s) did not reach what the pin says they should", file=sys.stderr)
        return 1
    print(f"\nAll {len(EXPECTED)} runs match the pinned coverage")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
