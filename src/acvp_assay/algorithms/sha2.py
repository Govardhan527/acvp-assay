"""SHA-2 vector parsing and execution.

Real NIST SHA-2 sets contain three test types, and they are genuinely
different shapes rather than variations on one:

``AFT``
    Hash one message and compare the digest.
``MCT``
    A Monte Carlo chain: one seed produces one hundred digests, each derived
    from the last. The whole array is one case with one verdict.
``LDT``
    A large data test whose message expands to gigabytes. This is reported
    UNSUPPORTED rather than approximated.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from acvp_assay.models import DigestValues, ResultStatus, TestCaseResult
from acvp_assay.parser import (
    AcvpValidationError,
    hex_bytes,
    integer,
    list_field,
    mapping,
    optional_string,
    string_field,
)
from acvp_assay.providers.digest import HASHLIB_ALGORITHMS, HashProvider
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

SUPPORTED_MCT_VERSIONS = ("standard", "alternate")


class Sha2TestType(StrEnum):
    """SHA-2 test types this runner recognises."""

    AFT = "AFT"
    MCT = "MCT"
    LDT = "LDT"


@dataclass(frozen=True, slots=True)
class Sha2TestCase:
    """One SHA-2 case: a message, or a large-message descriptor."""

    tc_id: int
    message: bytes | None
    length_bits: int | None
    is_large: bool


@dataclass(frozen=True, slots=True)
class Sha2TestGroup:
    """SHA-2 cases sharing one test type."""

    tg_id: int
    test_type: Sha2TestType
    mct_version: str | None
    tests: tuple[Sha2TestCase, ...]


@dataclass(frozen=True, slots=True)
class Sha2VectorSet:
    """One normalized SHA-2 vector set."""

    vs_id: int
    algorithm: str
    revision: str
    is_sample: bool
    test_groups: tuple[Sha2TestGroup, ...]


@dataclass(frozen=True, slots=True)
class Sha2ExpectedCase:
    """Expected output for one SHA-2 case."""

    tc_id: int
    digest: bytes | None
    results_array: tuple[bytes, ...] | None


@dataclass(frozen=True, slots=True)
class Sha2ExpectedSet:
    """One normalized SHA-2 expected-results document."""

    vs_id: int
    algorithm: str
    revision: str
    cases: Mapping[tuple[int, int], Sha2ExpectedCase]


def _parse_case(value: object, *, path: str) -> Sha2TestCase:
    document = mapping(value, path)
    tc_id = integer(document, "tcId", path)
    if "largeMsg" in document:
        return Sha2TestCase(tc_id=tc_id, message=None, length_bits=None, is_large=True)
    length_bits = integer(document, "len", path)
    message = hex_bytes(document, "msg", path)
    if length_bits % 8 == 0:
        # ACVP pads a short or zero-length message; the declared bit length is
        # authoritative, so trim to it rather than trusting the hex width.
        message = message[: length_bits // 8]
    return Sha2TestCase(
        tc_id=tc_id,
        message=message,
        length_bits=length_bits,
        is_large=False,
    )


def _parse_group(value: object, *, path: str) -> Sha2TestGroup:
    document = mapping(value, path)
    raw_type = string_field(document, "testType", path)
    try:
        test_type = Sha2TestType(raw_type)
    except ValueError:
        raise AcvpValidationError(
            f"{path}.testType", f"unsupported test type {raw_type!r}"
        ) from None
    tests = tuple(
        _parse_case(entry, path=f"{path}.tests[{index}]")
        for index, entry in enumerate(list_field(document, "tests", path))
    )
    return Sha2TestGroup(
        tg_id=integer(document, "tgId", path),
        test_type=test_type,
        mct_version=optional_string(document, "mctVersion", path),
        tests=tests,
    )


def parse_vector_set(value: object) -> Sha2VectorSet:
    """Validate and normalize one SHA-2 vector-set document."""
    document = mapping(value, "$")
    algorithm = string_field(document, "algorithm", "$")
    if algorithm not in HASHLIB_ALGORITHMS:
        raise AcvpValidationError("$.algorithm", f"unsupported algorithm {algorithm!r}")
    revision = string_field(document, "revision", "$")
    if revision != "1.0":
        raise AcvpValidationError("$.revision", f"unsupported revision {revision!r}")
    groups = tuple(
        _parse_group(entry, path=f"$.testGroups[{index}]")
        for index, entry in enumerate(list_field(document, "testGroups", "$"))
    )
    return Sha2VectorSet(
        vs_id=integer(document, "vsId", "$"),
        algorithm=algorithm,
        revision=revision,
        is_sample=bool(document.get("isSample", False)),
        test_groups=groups,
    )


def parse_expected_results(value: object) -> Sha2ExpectedSet:
    """Validate and normalize one SHA-2 expected-results document."""
    document = mapping(value, "$")
    cases: dict[tuple[int, int], Sha2ExpectedCase] = {}
    for group_index, group_value in enumerate(list_field(document, "testGroups", "$")):
        group_path = f"$.testGroups[{group_index}]"
        group = mapping(group_value, group_path)
        tg_id = integer(group, "tgId", group_path)
        for case_index, case_value in enumerate(list_field(group, "tests", group_path)):
            case_path = f"{group_path}.tests[{case_index}]"
            case = mapping(case_value, case_path)
            tc_id = integer(case, "tcId", case_path)
            results: tuple[bytes, ...] | None = None
            if "resultsArray" in case:
                results = tuple(
                    hex_bytes(mapping(entry, f"{case_path}.resultsArray[{index}]"), "md", case_path)
                    for index, entry in enumerate(list_field(case, "resultsArray", case_path))
                )
            digest = hex_bytes(case, "md", case_path) if "md" in case else None
            cases[(tg_id, tc_id)] = Sha2ExpectedCase(
                tc_id=tc_id, digest=digest, results_array=results
            )
    return Sha2ExpectedSet(
        vs_id=integer(document, "vsId", "$"),
        algorithm=string_field(document, "algorithm", "$"),
        revision=string_field(document, "revision", "$"),
        cases=cases,
    )


def load_vector_set(path: str | Path) -> Sha2VectorSet:
    """Load and normalize a SHA-2 prompt file."""
    return parse_vector_set(json.loads(Path(path).read_text(encoding="utf-8")))


def load_expected_results(path: str | Path) -> Sha2ExpectedSet:
    """Load and normalize a SHA-2 expected-results file."""
    return parse_expected_results(json.loads(Path(path).read_text(encoding="utf-8")))


def _unsupported(tg_id: int, tc_id: int, reason: str) -> TestCaseResult:
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=ResultStatus.UNSUPPORTED,
        expected=None,
        actual=None,
        diagnostic=reason,
    )


def _compare(tg_id: int, tc_id: int, expected: bytes, actual: bytes) -> TestCaseResult:
    if expected == actual:
        return TestCaseResult(
            tg_id=tg_id,
            tc_id=tc_id,
            status=ResultStatus.PASS,
            expected=DigestValues(digest=expected),
            actual=DigestValues(digest=actual),
        )
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=ResultStatus.FAIL,
        expected=DigestValues(digest=expected),
        actual=DigestValues(digest=actual),
        diagnostic="md mismatch",
    )


def _run_mct(
    group: Sha2TestGroup,
    case: Sha2TestCase,
    expected: Sha2ExpectedCase,
    provider: HashProvider,
) -> TestCaseResult:
    version = group.mct_version or "standard"
    if version not in SUPPORTED_MCT_VERSIONS:
        return _unsupported(group.tg_id, case.tc_id, f"mctVersion {version!r} is not supported")
    if expected.results_array is None:
        return _unsupported(group.tg_id, case.tc_id, "MCT case has no expected resultsArray")
    assert case.message is not None
    produced = provider.digest_mct(case.message, alternate=version == "alternate")
    if len(produced) != len(expected.results_array):
        return TestCaseResult(
            tg_id=group.tg_id,
            tc_id=case.tc_id,
            status=ResultStatus.FAIL,
            expected=None,
            actual=None,
            diagnostic=(
                f"expected {len(expected.results_array)} Monte Carlo digests, got {len(produced)}"
            ),
        )
    for index, (want, got) in enumerate(zip(expected.results_array, produced, strict=True)):
        if want != got:
            return TestCaseResult(
                tg_id=group.tg_id,
                tc_id=case.tc_id,
                status=ResultStatus.FAIL,
                expected=DigestValues(digest=want),
                actual=DigestValues(digest=got),
                diagnostic=f"md mismatch at Monte Carlo iteration {index}",
            )
    return TestCaseResult(
        tg_id=group.tg_id,
        tc_id=case.tc_id,
        status=ResultStatus.PASS,
        expected=DigestValues(digest=expected.results_array[-1]),
        actual=DigestValues(digest=produced[-1]),
        diagnostic=f"{len(produced)} Monte Carlo iterations matched",
    )


def run_vector_set(
    vector_set: Sha2VectorSet,
    expected: Sha2ExpectedSet,
    provider: HashProvider,
) -> list[TestCaseResult]:
    """Execute every SHA-2 case and classify it against its expected digest."""
    results: list[TestCaseResult] = []
    for group in vector_set.test_groups:
        for case in group.tests:
            expected_case = expected.cases.get((group.tg_id, case.tc_id))
            if expected_case is None:
                results.append(_unsupported(group.tg_id, case.tc_id, "no expected result recorded"))
                continue
            if group.test_type is Sha2TestType.LDT or case.is_large:
                results.append(
                    _unsupported(
                        group.tg_id, case.tc_id, "large data tests (LDT) are not supported"
                    )
                )
                continue
            if case.length_bits is not None and case.length_bits % 8 != 0:
                results.append(
                    _unsupported(group.tg_id, case.tc_id, "bit-oriented messages are not supported")
                )
                continue
            if expected_case.digest is None and group.test_type is not Sha2TestType.MCT:
                results.append(_unsupported(group.tg_id, case.tc_id, "no expected digest recorded"))
                continue
            try:
                if group.test_type is Sha2TestType.MCT:
                    results.append(_run_mct(group, case, expected_case, provider))
                    continue
                assert case.message is not None
                assert expected_case.digest is not None
                results.append(
                    _compare(
                        group.tg_id, case.tc_id, expected_case.digest, provider.digest(case.message)
                    )
                )
            except HarnessUnsupportedError:
                results.append(
                    _unsupported(group.tg_id, case.tc_id, "the harness declined this case")
                )
    return results


__all__ = [
    "Sha2ExpectedSet",
    "Sha2TestType",
    "Sha2VectorSet",
    "load_expected_results",
    "load_vector_set",
    "parse_expected_results",
    "parse_vector_set",
    "run_vector_set",
]
