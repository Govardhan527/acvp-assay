"""ACVP-AES-CBC, ACVP-AES-CTR, ACVP-AES-OFB and ACVP-AES-CFB128.

Four chaining modes sharing one module because they share a case shape: a key,
an IV, and a payload named by direction. They also share a Monte Carlo chain --
CBC, OFB and CFB128 use identical pseudocode, differing only in the primitive.

CTR is the exception and is worth stating plainly: it has no Monte Carlo test.
ACVP gives it a ``CTR`` test type, but that is a server-side distinction. The
implementation under test processes those cases as ordinary functional tests,
because what the server checks is the IVs it back-computes from the answer, not
a chain the client runs.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from acvp_assay.models import AesGcmValues, ResultStatus, TestCaseResult
from acvp_assay.parser import (
    AcvpValidationError,
    hex_bytes,
    integer,
    list_field,
    mapping,
    optional_hex_bytes,
    string_field,
)
from acvp_assay.providers.aes_block import CHAINING_MODES, AesBlockProvider
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

SUPPORTED = tuple(CHAINING_MODES)
MCT = "MCT"
_RESULT_FIELDS = ("key", "iv", "pt", "ct")


@dataclass(frozen=True, slots=True)
class BlockCase:
    """One case: whichever of key, iv, pt and ct its direction uses."""

    tc_id: int
    fields: Mapping[str, bytes] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class BlockGroup:
    """Cases sharing a direction and test type."""

    tg_id: int
    test_type: str
    direction: str
    tests: tuple[BlockCase, ...]


@dataclass(frozen=True, slots=True)
class BlockVectorSet:
    """A parsed chaining-mode prompt file."""

    vs_id: int
    algorithm: str
    revision: str
    test_groups: tuple[BlockGroup, ...]


@dataclass(frozen=True, slots=True)
class BlockExpectedCase:
    """Expected values for one case, or its Monte Carlo chain."""

    tc_id: int
    values: Mapping[str, bytes]
    results_array: tuple[Mapping[str, bytes], ...] | None


@dataclass(frozen=True, slots=True)
class BlockExpectedSet:
    """Expected results, indexed by group and case."""

    vs_id: int
    cases: Mapping[tuple[int, int], BlockExpectedCase]


def _parse_case(value: object, *, path: str) -> BlockCase:
    document = mapping(value, path=path)
    values: dict[str, bytes] = {}
    for name in _RESULT_FIELDS:
        found = optional_hex_bytes(document, name, path=path)
        if found is not None:
            values[name] = found
    return BlockCase(tc_id=integer(document, "tcId", path=path), fields=values)


def _parse_group(value: object, *, path: str) -> BlockGroup:
    document = mapping(value, path=path)
    direction = string_field(document, "direction", path=path)
    if direction not in ("encrypt", "decrypt"):
        raise AcvpValidationError(f"{path}.direction", "expected 'encrypt' or 'decrypt'")
    cases = list_field(document, "tests", path=path)
    return BlockGroup(
        tg_id=integer(document, "tgId", path=path),
        test_type=string_field(document, "testType", path=path),
        direction=direction,
        tests=tuple(
            _parse_case(item, path=f"{path}.tests[{index}]") for index, item in enumerate(cases)
        ),
    )


def parse_vector_set(value: object) -> BlockVectorSet:
    """Parse a chaining-mode prompt document, rejecting anything malformed."""
    document = mapping(value, path="$")
    algorithm = string_field(document, "algorithm", path="$")
    if algorithm not in SUPPORTED:
        raise AcvpValidationError("$.algorithm", f"expected one of {list(SUPPORTED)}")
    groups = list_field(document, "testGroups", path="$")
    return BlockVectorSet(
        vs_id=integer(document, "vsId", path="$"),
        algorithm=algorithm,
        revision=string_field(document, "revision", path="$"),
        test_groups=tuple(
            _parse_group(item, path=f"$.testGroups[{index}]") for index, item in enumerate(groups)
        ),
    )


def _parse_expected_case(value: object, *, tg_id: int, path: str) -> BlockExpectedCase:
    document = mapping(value, path=path)
    values: dict[str, bytes] = {}
    for name in _RESULT_FIELDS:
        found = optional_hex_bytes(document, name, path=path)
        if found is not None:
            values[name] = found
    chain: tuple[Mapping[str, bytes], ...] | None = None
    if "resultsArray" in document:
        entries = list_field(document, "resultsArray", path=path)
        chain = tuple(
            {
                name: hex_bytes(
                    mapping(entry, path=f"{path}.resultsArray[{index}]"), name, path=path
                )
                for name in _RESULT_FIELDS
                if name in mapping(entry, path=f"{path}.resultsArray[{index}]")
            }
            for index, entry in enumerate(entries)
        )
    _ = tg_id
    return BlockExpectedCase(
        tc_id=integer(document, "tcId", path=path), values=values, results_array=chain
    )


def parse_expected_results(value: object) -> BlockExpectedSet:
    """Parse the expected results, keyed by group and case."""
    document = mapping(value, path="$")
    cases: dict[tuple[int, int], BlockExpectedCase] = {}
    for group_index, group_value in enumerate(list_field(document, "testGroups", path="$")):
        group_path = f"$.testGroups[{group_index}]"
        group = mapping(group_value, path=group_path)
        tg_id = integer(group, "tgId", path=group_path)
        for case_index, case_value in enumerate(list_field(group, "tests", path=group_path)):
            parsed = _parse_expected_case(
                case_value, tg_id=tg_id, path=f"{group_path}.tests[{case_index}]"
            )
            cases[(tg_id, parsed.tc_id)] = parsed
    return BlockExpectedSet(vs_id=integer(document, "vsId", path="$"), cases=cases)


def load_vector_set(path: str | Path) -> BlockVectorSet:
    """Read and parse a chaining-mode prompt file."""
    return parse_vector_set(json.loads(Path(path).read_text(encoding="utf-8")))


def load_expected_results(path: str | Path) -> BlockExpectedSet:
    """Read and parse a chaining-mode expected-results file."""
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


def _compare(tg_id: int, tc_id: int, name: str, expected: bytes, actual: bytes) -> TestCaseResult:
    values = (
        (AesGcmValues(ciphertext=expected), AesGcmValues(ciphertext=actual))
        if name == "ct"
        else (AesGcmValues(plaintext=expected), AesGcmValues(plaintext=actual))
    )
    passed = expected == actual
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=ResultStatus.PASS if passed else ResultStatus.FAIL,
        expected=values[0],
        actual=values[1],
        diagnostic=None if passed else f"{name} differs",
    )


def _run_monte_carlo(
    algorithm: str,
    group: BlockGroup,
    case: BlockCase,
    expected: BlockExpectedCase,
    provider: AesBlockProvider,
) -> TestCaseResult:
    """Run the chain and compare every outer iteration, not just the last."""
    if expected.results_array is None:
        return _unsupported(group.tg_id, case.tc_id, "MCT case has no expected resultsArray")
    encrypt = group.direction == "encrypt"
    name = "ct" if encrypt else "pt"
    produced = provider.monte_carlo(
        algorithm=algorithm,
        key=case.fields["key"],
        iv=case.fields["iv"],
        data=case.fields["pt" if encrypt else "ct"],
        encrypt=encrypt,
    )
    if len(produced) != len(expected.results_array):
        return TestCaseResult(
            tg_id=group.tg_id,
            tc_id=case.tc_id,
            status=ResultStatus.FAIL,
            expected=None,
            actual=None,
            diagnostic=(
                f"expected {len(expected.results_array)} Monte Carlo iterations, "
                f"got {len(produced)}"
            ),
        )
    for index, (want, got) in enumerate(zip(expected.results_array, produced, strict=True)):
        if name in want and want[name] != got[3]:
            return TestCaseResult(
                tg_id=group.tg_id,
                tc_id=case.tc_id,
                status=ResultStatus.FAIL,
                expected=AesGcmValues(ciphertext=want[name]),
                actual=AesGcmValues(ciphertext=got[3]),
                diagnostic=f"{name} mismatch at Monte Carlo iteration {index}",
            )
    return TestCaseResult(
        tg_id=group.tg_id,
        tc_id=case.tc_id,
        status=ResultStatus.PASS,
        expected=AesGcmValues(ciphertext=expected.results_array[-1].get(name)),
        actual=AesGcmValues(ciphertext=produced[-1][3]),
        diagnostic=None,
    )


def run_vector_set(
    vector_set: BlockVectorSet,
    expected: BlockExpectedSet,
    provider: AesBlockProvider,
) -> list[TestCaseResult]:
    """Execute every case, declaring the ones this provider cannot answer."""
    results: list[TestCaseResult] = []
    for group in vector_set.test_groups:
        encrypt = group.direction == "encrypt"
        name = "ct" if encrypt else "pt"
        for case in group.tests:
            wanted = expected.cases.get((group.tg_id, case.tc_id))
            if wanted is None:
                results.append(_unsupported(group.tg_id, case.tc_id, "no expected result recorded"))
                continue
            if group.test_type == MCT:
                try:
                    results.append(
                        _run_monte_carlo(vector_set.algorithm, group, case, wanted, provider)
                    )
                except HarnessUnsupportedError:
                    results.append(
                        _unsupported(group.tg_id, case.tc_id, "the harness declined this case")
                    )
                continue
            if name not in wanted.values:
                results.append(
                    _unsupported(group.tg_id, case.tc_id, f"no expected {name} recorded")
                )
                continue
            try:
                produced = provider.transform(
                    algorithm=vector_set.algorithm,
                    key=case.fields["key"],
                    iv=case.fields["iv"],
                    data=case.fields["pt" if encrypt else "ct"],
                    encrypt=encrypt,
                )
            except HarnessUnsupportedError:
                results.append(
                    _unsupported(group.tg_id, case.tc_id, "the harness declined this case")
                )
                continue
            results.append(_compare(group.tg_id, case.tc_id, name, wanted.values[name], produced))
    return results


__all__ = [
    "SUPPORTED",
    "BlockCase",
    "BlockExpectedCase",
    "BlockExpectedSet",
    "BlockGroup",
    "BlockVectorSet",
    "load_expected_results",
    "load_vector_set",
    "parse_expected_results",
    "parse_vector_set",
    "run_vector_set",
]
