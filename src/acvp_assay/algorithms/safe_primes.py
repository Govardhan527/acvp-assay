"""Parsing and execution for safePrimes keyGen and keyVer.

The two modes are one algorithm name and split the way key agreement does:
``keyVer`` supplies a pair and asks a question that can be answered here, while
``keyGen`` asks for a fresh key that nothing offline can compare against. The
second is declined with its reason rather than approximated, and answered in
full when the runner submits to ACVTS.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from acvp_assay.models import DeclineReason, ProviderMetadata, ResultStatus, TestCaseResult
from acvp_assay.parser import (
    AcvpValidationError,
    integer,
    list_field,
    mapping,
    optional_hex_bytes,
    optional_string,
    string_field,
)
from acvp_assay.providers.safe_primes import (
    ALGORITHM,
    SAFE_PRIME_GROUPS,
    PythonSafePrimes,
    SafePrimesProvider,
    SubprocessSafePrimes,
)
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

KEY_GEN = "keyGen"
KEY_VER = "keyVer"
MODES = (KEY_GEN, KEY_VER)


@dataclass(frozen=True, slots=True)
class SafePrimesCase:
    """One case: a pair to check, or nothing at all when generating."""

    tc_id: int
    x: bytes | None = None
    y: bytes | None = None


@dataclass(frozen=True, slots=True)
class SafePrimesGroup:
    """One group: the named prime group in force, and its cases."""

    tg_id: int
    safe_prime_group: str
    tests: tuple[SafePrimesCase, ...]


@dataclass(frozen=True, slots=True)
class SafePrimesVectorSet:
    """A parsed safePrimes vector set."""

    vs_id: int
    algorithm: str
    mode: str
    revision: str
    test_groups: tuple[SafePrimesGroup, ...]


def _parse_group(value: object, *, path: str) -> SafePrimesGroup:
    document = mapping(value, path=path)
    cases = []
    for index, item in enumerate(list_field(document, "tests", path=path)):
        case_path = f"{path}.tests[{index}]"
        case = mapping(item, path=case_path)
        cases.append(
            SafePrimesCase(
                tc_id=integer(case, "tcId", path=case_path),
                x=optional_hex_bytes(case, "x", path=case_path),
                y=optional_hex_bytes(case, "y", path=case_path),
            )
        )
    return SafePrimesGroup(
        tg_id=integer(document, "tgId", path=path),
        safe_prime_group=string_field(document, "safePrimeGroup", path=path),
        tests=tuple(cases),
    )


def parse_vector_set(value: object) -> SafePrimesVectorSet:
    """Parse a safePrimes vector set, preserving every ACVP id."""
    document = mapping(value, path="$")
    algorithm = string_field(document, "algorithm", path="$")
    if algorithm != ALGORITHM:
        raise AcvpValidationError("$.algorithm", f"expected {ALGORITHM!r}")
    mode = optional_string(document, "mode", path="$")
    if mode not in MODES:
        raise AcvpValidationError("$.mode", f"expected one of {list(MODES)}")
    groups = list_field(document, "testGroups", path="$")
    return SafePrimesVectorSet(
        vs_id=integer(document, "vsId", path="$"),
        algorithm=algorithm,
        mode=mode,
        revision=string_field(document, "revision", path="$"),
        test_groups=tuple(
            _parse_group(item, path=f"$.testGroups[{index}]") for index, item in enumerate(groups)
        ),
    )


def parse_expected_results(value: object) -> dict[tuple[int, int], dict[str, object]]:
    """The expected answer for every case, keyed by group and case."""
    document = mapping(value, path="$")
    found: dict[tuple[int, int], dict[str, object]] = {}
    for group_index, group_value in enumerate(list_field(document, "testGroups", path="$")):
        group_path = f"$.testGroups[{group_index}]"
        group = mapping(group_value, path=group_path)
        tg_id = integer(group, "tgId", path=group_path)
        for case_index, case_value in enumerate(list_field(group, "tests", path=group_path)):
            case_path = f"{group_path}.tests[{case_index}]"
            case = mapping(case_value, path=case_path)
            found[(tg_id, integer(case, "tcId", path=case_path))] = dict(case)
    return found


def _load_json(path: str | Path) -> object:
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def load_vector_set(path: str | Path) -> SafePrimesVectorSet:
    """Load and parse a safePrimes vector file."""
    return parse_vector_set(_load_json(path))


def load_expected_results(path: str | Path) -> dict[tuple[int, int], dict[str, object]]:
    """Load and parse a safePrimes expected-results file."""
    return parse_expected_results(_load_json(path))


def provider_for(provider_command: str | None, timeout_seconds: float) -> SafePrimesProvider:
    """The built-in provider, or a harness when one is named."""
    if provider_command is None:
        return PythonSafePrimes()
    return SubprocessSafePrimes.from_command_string(
        provider_command, timeout_seconds=timeout_seconds
    )


def metadata_for(provider: SafePrimesProvider) -> ProviderMetadata:
    """Report which implementation answered."""
    return provider.metadata()


def _unsupported(code: DeclineReason, tg_id: int, tc_id: int, reason: str) -> TestCaseResult:
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=ResultStatus.UNSUPPORTED,
        expected=None,
        actual=None,
        diagnostic=reason,
        decline_reason=code,
    )


def _verdict(tg_id: int, tc_id: int, *, expected: bool, actual: bool) -> TestCaseResult:
    passed = expected == actual
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=ResultStatus.PASS if passed else ResultStatus.FAIL,
        expected=None,
        actual=None,
        diagnostic=None if passed else f"expected testPassed={expected}, computed {actual}",
    )


def run_vector_set(
    vector_set: SafePrimesVectorSet,
    expected: dict[tuple[int, int], dict[str, object]],
    provider: SafePrimesProvider,
) -> list[TestCaseResult]:
    """Verify every keyVer case, and decline keyGen with its reason."""
    results: list[TestCaseResult] = []
    for group in vector_set.test_groups:
        known = group.safe_prime_group in SAFE_PRIME_GROUPS
        for case in group.tests:
            key = (group.tg_id, case.tc_id)
            if vector_set.mode == KEY_GEN:
                # The key is fresh every run, so there is nothing here to compare
                # it with. The server recomputes g^x mod p and can.
                results.append(
                    _unsupported(
                        DeclineReason.OFFLINE_UNDECIDABLE,
                        *key,
                        "keyGen produces a fresh key, so it cannot be compared with the "
                        "recorded value; submit to ACVTS, which recomputes it",
                    )
                )
                continue
            if not known:
                results.append(
                    _unsupported(
                        DeclineReason.RUNNER_LACKS,
                        *key,
                        f"safe prime group {group.safe_prime_group!r} is unknown",
                    )
                )
                continue
            if case.x is None or case.y is None:
                results.append(
                    _unsupported(
                        DeclineReason.VECTOR_INCOMPLETE,
                        *key,
                        "a keyVer case must supply both x and y",
                    )
                )
                continue
            recorded = expected.get(key)
            if recorded is None or not isinstance(recorded.get("testPassed"), bool):
                results.append(
                    _unsupported(
                        DeclineReason.OFFLINE_UNDECIDABLE, *key, "no expected verdict recorded"
                    )
                )
                continue
            try:
                computed = provider.key_ver(group=group.safe_prime_group, x=case.x, y=case.y)
            except HarnessUnsupportedError:
                results.append(
                    _unsupported(
                        DeclineReason.IMPLEMENTATION_LACKS, *key, "the harness declined this case"
                    )
                )
                continue
            results.append(_verdict(*key, expected=bool(recorded["testPassed"]), actual=computed))
    return results


__all__ = [
    "ALGORITHM",
    "KEY_GEN",
    "KEY_VER",
    "MODES",
    "SafePrimesCase",
    "SafePrimesGroup",
    "SafePrimesVectorSet",
    "load_expected_results",
    "load_vector_set",
    "metadata_for",
    "parse_expected_results",
    "parse_vector_set",
    "provider_for",
    "run_vector_set",
]
