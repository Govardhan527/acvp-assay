"""HMAC vector parsing and execution.

HMAC sets are AFT-only and simpler than SHA-2's, with one wrinkle: ``macLen``
is a *truncation*, so a group can ask for the leftmost 80 bits of a 256-bit
HMAC. Comparing the untruncated MAC would fail every such group.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from acvp_runner.models import DigestValues, ResultStatus, TestCaseResult
from acvp_runner.parser import (
    AcvpValidationError,
    hex_bytes,
    integer,
    list_field,
    mapping,
    string_field,
)
from acvp_runner.providers.digest import HASHLIB_ALGORITHMS, MacProvider


@dataclass(frozen=True, slots=True)
class HmacTestCase:
    """One keyed-MAC case."""

    tc_id: int
    key: bytes
    message: bytes


@dataclass(frozen=True, slots=True)
class HmacTestGroup:
    """HMAC cases sharing one key/message/MAC length contract."""

    tg_id: int
    mac_length_bits: int
    tests: tuple[HmacTestCase, ...]


@dataclass(frozen=True, slots=True)
class HmacVectorSet:
    """One normalized HMAC vector set."""

    vs_id: int
    algorithm: str
    revision: str
    test_groups: tuple[HmacTestGroup, ...]


@dataclass(frozen=True, slots=True)
class HmacExpectedSet:
    """One normalized HMAC expected-results document."""

    vs_id: int
    algorithm: str
    revision: str
    cases: Mapping[tuple[int, int], bytes]


def _parse_case(value: object, *, path: str) -> HmacTestCase:
    document = mapping(value, path)
    return HmacTestCase(
        tc_id=integer(document, "tcId", path),
        key=hex_bytes(document, "key", path),
        message=hex_bytes(document, "msg", path),
    )


def _parse_group(value: object, *, path: str) -> HmacTestGroup:
    document = mapping(value, path)
    test_type = string_field(document, "testType", path)
    if test_type != "AFT":
        raise AcvpValidationError(f"{path}.testType", f"unsupported test type {test_type!r}")
    tests = tuple(
        _parse_case(entry, path=f"{path}.tests[{index}]")
        for index, entry in enumerate(list_field(document, "tests", path))
    )
    return HmacTestGroup(
        tg_id=integer(document, "tgId", path),
        mac_length_bits=integer(document, "macLen", path),
        tests=tests,
    )


def parse_vector_set(value: object) -> HmacVectorSet:
    """Validate and normalize one HMAC vector-set document."""
    document = mapping(value, "$")
    algorithm = string_field(document, "algorithm", "$")
    if algorithm.removeprefix("HMAC-") not in HASHLIB_ALGORITHMS:
        raise AcvpValidationError("$.algorithm", f"unsupported algorithm {algorithm!r}")
    revision = string_field(document, "revision", "$")
    if revision != "1.0":
        raise AcvpValidationError("$.revision", f"unsupported revision {revision!r}")
    groups = tuple(
        _parse_group(entry, path=f"$.testGroups[{index}]")
        for index, entry in enumerate(list_field(document, "testGroups", "$"))
    )
    return HmacVectorSet(
        vs_id=integer(document, "vsId", "$"),
        algorithm=algorithm,
        revision=revision,
        test_groups=groups,
    )


def parse_expected_results(value: object) -> HmacExpectedSet:
    """Validate and normalize one HMAC expected-results document."""
    document = mapping(value, "$")
    cases: dict[tuple[int, int], bytes] = {}
    for group_index, group_value in enumerate(list_field(document, "testGroups", "$")):
        group_path = f"$.testGroups[{group_index}]"
        group = mapping(group_value, group_path)
        tg_id = integer(group, "tgId", group_path)
        for case_index, case_value in enumerate(list_field(group, "tests", group_path)):
            case_path = f"{group_path}.tests[{case_index}]"
            case = mapping(case_value, case_path)
            cases[(tg_id, integer(case, "tcId", case_path))] = hex_bytes(case, "mac", case_path)
    return HmacExpectedSet(
        vs_id=integer(document, "vsId", "$"),
        algorithm=string_field(document, "algorithm", "$"),
        revision=string_field(document, "revision", "$"),
        cases=cases,
    )


def load_vector_set(path: str | Path) -> HmacVectorSet:
    """Load and normalize an HMAC prompt file."""
    return parse_vector_set(json.loads(Path(path).read_text(encoding="utf-8")))


def load_expected_results(path: str | Path) -> HmacExpectedSet:
    """Load and normalize an HMAC expected-results file."""
    return parse_expected_results(json.loads(Path(path).read_text(encoding="utf-8")))


def run_vector_set(
    vector_set: HmacVectorSet,
    expected: HmacExpectedSet,
    provider: MacProvider,
) -> list[TestCaseResult]:
    """Execute every HMAC case and classify it against its expected MAC."""
    results: list[TestCaseResult] = []
    for group in vector_set.test_groups:
        for case in group.tests:
            want = expected.cases.get((group.tg_id, case.tc_id))
            if want is None:
                results.append(
                    TestCaseResult(
                        tg_id=group.tg_id,
                        tc_id=case.tc_id,
                        status=ResultStatus.UNSUPPORTED,
                        expected=None,
                        actual=None,
                        diagnostic="no expected result recorded",
                    )
                )
                continue
            got = provider.mac(
                key=case.key,
                message=case.message,
                mac_length_bits=group.mac_length_bits,
            )
            status = ResultStatus.PASS if want == got else ResultStatus.FAIL
            results.append(
                TestCaseResult(
                    tg_id=group.tg_id,
                    tc_id=case.tc_id,
                    status=status,
                    expected=DigestValues(mac=want),
                    actual=DigestValues(mac=got),
                    diagnostic=None if status is ResultStatus.PASS else "mac mismatch",
                )
            )
    return results


__all__ = [
    "HmacExpectedSet",
    "HmacVectorSet",
    "load_expected_results",
    "load_vector_set",
    "parse_expected_results",
    "parse_vector_set",
    "run_vector_set",
]
