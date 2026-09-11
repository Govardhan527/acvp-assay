"""Parsing and execution for PBKDF (SP 800-132).

AFT only, one group per HMAC. The parsing carries the one surprise in the
family: ACVP sends ``password`` as **text**, while every other byte string in a
vector set arrives hex-encoded. It is decoded here, once, so nothing downstream
has to remember which convention applies.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from acvp_assay.models import DeclineReason, ResultStatus, TestCaseResult
from acvp_assay.parser import (
    AcvpValidationError,
    hex_bytes,
    integer,
    list_field,
    mapping,
    string_field,
)
from acvp_assay.providers.pbkdf import (
    ALGORITHM,
    SUPPORTED_HMACS,
    HashlibPbkdf,
    PbkdfProvider,
    SubprocessPbkdf,
)
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError


@dataclass(frozen=True, slots=True)
class PbkdfCase:
    """One derivation: a password, a salt, a cost, and a length."""

    tc_id: int
    password: bytes
    salt: bytes
    iterations: int
    key_bits: int


@dataclass(frozen=True, slots=True)
class PbkdfGroup:
    """One group: the HMAC in force and its cases."""

    tg_id: int
    hmac_alg: str
    tests: tuple[PbkdfCase, ...]


@dataclass(frozen=True, slots=True)
class PbkdfVectorSet:
    """A parsed PBKDF vector set."""

    vs_id: int
    algorithm: str
    revision: str
    test_groups: tuple[PbkdfGroup, ...]


def _parse_group(value: object, *, path: str) -> PbkdfGroup:
    document = mapping(value, path=path)
    cases = []
    for index, item in enumerate(list_field(document, "tests", path=path)):
        case_path = f"{path}.tests[{index}]"
        case = mapping(item, path=case_path)
        # The password is characters, not hex. Everything else here is hex.
        password = string_field(case, "password", path=case_path)
        cases.append(
            PbkdfCase(
                tc_id=integer(case, "tcId", path=case_path),
                password=password.encode("utf-8"),
                salt=hex_bytes(case, "salt", path=case_path),
                iterations=integer(case, "iterationCount", path=case_path),
                key_bits=integer(case, "keyLen", path=case_path),
            )
        )
    return PbkdfGroup(
        tg_id=integer(document, "tgId", path=path),
        hmac_alg=string_field(document, "hmacAlg", path=path),
        tests=tuple(cases),
    )


def parse_vector_set(value: object) -> PbkdfVectorSet:
    """Parse a PBKDF vector set, preserving every ACVP id."""
    document = mapping(value, path="$")
    algorithm = string_field(document, "algorithm", path="$")
    if algorithm != ALGORITHM:
        raise AcvpValidationError("$.algorithm", f"expected {ALGORITHM!r}")
    groups = list_field(document, "testGroups", path="$")
    return PbkdfVectorSet(
        vs_id=integer(document, "vsId", path="$"),
        algorithm=algorithm,
        revision=string_field(document, "revision", path="$"),
        test_groups=tuple(
            _parse_group(item, path=f"$.testGroups[{index}]") for index, item in enumerate(groups)
        ),
    )


def parse_expected_results(value: object) -> dict[tuple[int, int], bytes]:
    """The expected derived key for every case, keyed by group and case."""
    document = mapping(value, path="$")
    found: dict[tuple[int, int], bytes] = {}
    for group_index, group_value in enumerate(list_field(document, "testGroups", path="$")):
        group_path = f"$.testGroups[{group_index}]"
        group = mapping(group_value, path=group_path)
        tg_id = integer(group, "tgId", path=group_path)
        for case_index, case_value in enumerate(list_field(group, "tests", path=group_path)):
            case_path = f"{group_path}.tests[{case_index}]"
            case = mapping(case_value, path=case_path)
            found[(tg_id, integer(case, "tcId", path=case_path))] = hex_bytes(
                case, "derivedKey", path=case_path
            )
    return found


def _load_json(path: str | Path) -> object:
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def load_vector_set(path: str | Path) -> PbkdfVectorSet:
    """Load and parse a PBKDF vector file."""
    return parse_vector_set(_load_json(path))


def load_expected_results(path: str | Path) -> dict[tuple[int, int], bytes]:
    """Load and parse a PBKDF expected-results file."""
    return parse_expected_results(_load_json(path))


def provider_for(provider_command: str | None, timeout_seconds: float) -> PbkdfProvider:
    """The built-in provider, or a harness when one is named."""
    if provider_command is None:
        return HashlibPbkdf()
    return SubprocessPbkdf.from_command_string(provider_command, timeout_seconds=timeout_seconds)


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


def run_vector_set(
    vector_set: PbkdfVectorSet,
    expected: dict[tuple[int, int], bytes],
    provider: PbkdfProvider,
) -> list[TestCaseResult]:
    """Derive every case and compare with the recorded key."""
    results: list[TestCaseResult] = []
    for group in vector_set.test_groups:
        for case in group.tests:
            want = expected.get((group.tg_id, case.tc_id))
            if want is None:
                results.append(
                    _unsupported(
                        DeclineReason.OFFLINE_UNDECIDABLE,
                        group.tg_id,
                        case.tc_id,
                        "no expected derivedKey recorded",
                    )
                )
                continue
            if group.hmac_alg not in SUPPORTED_HMACS:
                results.append(
                    _unsupported(
                        DeclineReason.RUNNER_LACKS,
                        group.tg_id,
                        case.tc_id,
                        f"hmacAlg {group.hmac_alg} is not supported",
                    )
                )
                continue
            try:
                produced = provider.derive(
                    hmac_alg=group.hmac_alg,
                    password=case.password,
                    salt=case.salt,
                    iterations=case.iterations,
                    key_bits=case.key_bits,
                )
            except HarnessUnsupportedError:
                results.append(
                    _unsupported(
                        DeclineReason.IMPLEMENTATION_LACKS,
                        group.tg_id,
                        case.tc_id,
                        "the harness declined this case",
                    )
                )
                continue
            passed = produced == want
            results.append(
                TestCaseResult(
                    tg_id=group.tg_id,
                    tc_id=case.tc_id,
                    status=ResultStatus.PASS if passed else ResultStatus.FAIL,
                    expected=None,
                    actual=None,
                    diagnostic=None if passed else "derivedKey differs",
                )
            )
    return results


__all__ = [
    "ALGORITHM",
    "PbkdfCase",
    "PbkdfGroup",
    "PbkdfVectorSet",
    "load_expected_results",
    "load_vector_set",
    "parse_expected_results",
    "parse_vector_set",
    "provider_for",
    "run_vector_set",
]
