"""Parsing and execution for ACVP-AES-CBC-CS1, -CS2 and -CS3.

AFT only. The server issues no Monte Carlo test for these names, which is the
one respect in which they are simpler than the chaining modes they extend --
see :mod:`acvp_assay.providers.aes_cs` for what ciphertext stealing does and
how the three variants differ.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from acvp_assay.models import AesGcmValues, ResultStatus, TestCaseResult
from acvp_assay.parser import (
    AcvpValidationError,
    hex_bytes,
    integer,
    list_field,
    mapping,
    optional_integer,
    string_field,
)
from acvp_assay.providers.aes_cs import (
    SUPPORTED,
    AesCsProvider,
    CryptographyAesCs,
    SubprocessAesCs,
)
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError


@dataclass(frozen=True, slots=True)
class CsCase:
    """One case: a key, an IV, and the payload named by direction."""

    tc_id: int
    key: bytes
    iv: bytes
    data: bytes
    payload_bits: int | None = None


@dataclass(frozen=True, slots=True)
class CsGroup:
    """One group: a direction and its cases."""

    tg_id: int
    direction: str
    tests: tuple[CsCase, ...]


@dataclass(frozen=True, slots=True)
class CsVectorSet:
    """A parsed ciphertext-stealing vector set."""

    vs_id: int
    algorithm: str
    revision: str
    test_groups: tuple[CsGroup, ...]


def _parse_group(value: object, *, path: str, encrypt_field: str) -> CsGroup:
    document = mapping(value, path=path)
    direction = string_field(document, "direction", path=path)
    if direction not in ("encrypt", "decrypt"):
        raise AcvpValidationError(f"{path}.direction", "expected 'encrypt' or 'decrypt'")
    field = encrypt_field if direction == "encrypt" else "ct"
    cases = []
    for index, item in enumerate(list_field(document, "tests", path=path)):
        case_path = f"{path}.tests[{index}]"
        case = mapping(item, path=case_path)
        cases.append(
            CsCase(
                tc_id=integer(case, "tcId", path=case_path),
                key=hex_bytes(case, "key", path=case_path),
                iv=hex_bytes(case, "iv", path=case_path),
                data=hex_bytes(case, field, path=case_path),
                payload_bits=optional_integer(case, "payloadLen", path=case_path),
            )
        )
    return CsGroup(
        tg_id=integer(document, "tgId", path=path), direction=direction, tests=tuple(cases)
    )


def parse_vector_set(value: object) -> CsVectorSet:
    """Parse a ciphertext-stealing vector set, preserving every ACVP id."""
    document = mapping(value, path="$")
    algorithm = string_field(document, "algorithm", path="$")
    if algorithm not in SUPPORTED:
        raise AcvpValidationError("$.algorithm", f"expected one of {list(SUPPORTED)}")
    groups = list_field(document, "testGroups", path="$")
    return CsVectorSet(
        vs_id=integer(document, "vsId", path="$"),
        algorithm=algorithm,
        revision=string_field(document, "revision", path="$"),
        test_groups=tuple(
            _parse_group(item, path=f"$.testGroups[{index}]", encrypt_field="pt")
            for index, item in enumerate(groups)
        ),
    )


def parse_expected_results(value: object) -> dict[tuple[int, int], Mapping[str, bytes]]:
    """The expected ct or pt for every case, keyed by group and case."""
    document = mapping(value, path="$")
    found: dict[tuple[int, int], Mapping[str, bytes]] = {}
    for group_index, group_value in enumerate(list_field(document, "testGroups", path="$")):
        group_path = f"$.testGroups[{group_index}]"
        group = mapping(group_value, path=group_path)
        tg_id = integer(group, "tgId", path=group_path)
        for case_index, case_value in enumerate(list_field(group, "tests", path=group_path)):
            case_path = f"{group_path}.tests[{case_index}]"
            case = mapping(case_value, path=case_path)
            values = {
                name: hex_bytes(case, name, path=case_path) for name in ("ct", "pt") if name in case
            }
            found[(tg_id, integer(case, "tcId", path=case_path))] = values
    return found


def _load_json(path: str | Path) -> object:
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def load_vector_set(path: str | Path) -> CsVectorSet:
    """Load and parse a ciphertext-stealing vector file."""
    return parse_vector_set(_load_json(path))


def load_expected_results(path: str | Path) -> dict[tuple[int, int], Mapping[str, bytes]]:
    """Load and parse a ciphertext-stealing expected-results file."""
    return parse_expected_results(_load_json(path))


def provider_for(provider_command: str | None, timeout_seconds: float) -> AesCsProvider:
    """The built-in provider, or a harness when one is named."""
    if provider_command is None:
        return CryptographyAesCs()
    return SubprocessAesCs.from_command_string(provider_command, timeout_seconds=timeout_seconds)


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


def run_vector_set(
    vector_set: CsVectorSet,
    expected: dict[tuple[int, int], Mapping[str, bytes]],
    provider: AesCsProvider,
) -> list[TestCaseResult]:
    """Transform every case and compare with the recorded output."""
    results: list[TestCaseResult] = []
    for group in vector_set.test_groups:
        encrypt = group.direction == "encrypt"
        name = "ct" if encrypt else "pt"
        for case in group.tests:
            wanted = expected.get((group.tg_id, case.tc_id))
            if wanted is None or name not in wanted:
                results.append(
                    _unsupported(group.tg_id, case.tc_id, f"no expected {name} recorded")
                )
                continue
            try:
                produced = provider.transform(
                    algorithm=vector_set.algorithm,
                    key=case.key,
                    iv=case.iv,
                    data=case.data,
                    encrypt=encrypt,
                )
            except HarnessUnsupportedError:
                results.append(
                    _unsupported(group.tg_id, case.tc_id, "the harness declined this case")
                )
                continue
            results.append(_compare(group.tg_id, case.tc_id, name, wanted[name], produced))
    return results


__all__ = [
    "SUPPORTED",
    "CsCase",
    "CsGroup",
    "CsVectorSet",
    "load_expected_results",
    "load_vector_set",
    "parse_expected_results",
    "parse_vector_set",
    "provider_for",
    "run_vector_set",
]
