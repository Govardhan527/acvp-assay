"""SHAKE-128 and SHAKE-256, revision FIPS202.

The difference from every other digest here is that the output length is an
input. A SHAKE case carries ``outLen`` alongside ``msg``, and the same message
squeezed to a different length is a different answer -- so the length has to
reach the implementation rather than being inferred from the algorithm name.

FIPS 202 is explicit that the XOFs are **not approved as hash functions**;
their approved uses are named in NIST Special Publications. This module tests
what ACVP asks for and makes no claim about where a SHAKE output may be used.

Only AFT is answered. The Demo server generates nothing else for a FIPS202
SHAKE registration, and a Monte Carlo chain implemented without vectors to
check it against would be a guess -- so an MCT group is declared rather than
attempted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from acvp_assay.models import DigestValues, ProviderMetadata, ResultStatus, TestCaseResult
from acvp_assay.parser import (
    AcvpValidationError,
    hex_bytes,
    integer,
    list_field,
    mapping,
    string_field,
)
from acvp_assay.providers.digest import (
    XOF_ALGORITHMS,
    HashlibXofProvider,
    SubprocessXofProvider,
    XofProvider,
)
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

REVISION = "FIPS202"
SUPPORTED = tuple(XOF_ALGORITHMS)
AFT = "AFT"


@dataclass(frozen=True, slots=True)
class ShakeCase:
    """One extendable-output case."""

    tc_id: int
    message: bytes
    output_bits: int


@dataclass(frozen=True, slots=True)
class ShakeGroup:
    """Cases sharing a test type."""

    tg_id: int
    test_type: str
    tests: tuple[ShakeCase, ...]


@dataclass(frozen=True, slots=True)
class ShakeVectorSet:
    """One normalized SHAKE vector set."""

    vs_id: int
    algorithm: str
    revision: str
    groups: tuple[ShakeGroup, ...]


def _parse_case(value: object, *, path: str) -> ShakeCase:
    document = mapping(value, path)
    message = hex_bytes(document, "msg", path)
    # ACVP gives the message length in bits and pads the hex to a byte
    # boundary, so a case with len 0 still carries a byte of msg.
    bits = integer(document, "len", path)
    if bits % 8:
        raise AcvpValidationError(path, "message lengths are whole bytes in this set")
    return ShakeCase(
        tc_id=integer(document, "tcId", path),
        message=message[: bits // 8],
        output_bits=integer(document, "outLen", path),
    )


def _parse_group(value: object, *, path: str) -> ShakeGroup:
    document = mapping(value, path)
    return ShakeGroup(
        tg_id=integer(document, "tgId", path),
        test_type=string_field(document, "testType", path),
        tests=tuple(
            _parse_case(case, path=f"{path}.tests[{index}]")
            for index, case in enumerate(list_field(document, "tests", path))
        ),
    )


def parse_vector_set(document: object) -> ShakeVectorSet:
    """Normalize a SHAKE prompt."""
    root = mapping(document, "$")
    return ShakeVectorSet(
        vs_id=integer(root, "vsId", "$"),
        algorithm=string_field(root, "algorithm", "$"),
        revision=string_field(root, "revision", "$"),
        groups=tuple(
            _parse_group(group, path=f"$.testGroups[{index}]")
            for index, group in enumerate(list_field(root, "testGroups", "$"))
        ),
    )


def parse_expected_results(document: object) -> dict[tuple[int, int], bytes]:
    """Index the expected output by ``(tgId, tcId)``."""
    root = mapping(document, "$")
    out: dict[tuple[int, int], bytes] = {}
    for index, group in enumerate(list_field(root, "testGroups", "$")):
        path = f"$.testGroups[{index}]"
        entry = mapping(group, path)
        tg_id = integer(entry, "tgId", path)
        for position, case in enumerate(list_field(entry, "tests", path)):
            case_path = f"{path}.tests[{position}]"
            values = mapping(case, case_path)
            out[(tg_id, integer(values, "tcId", case_path))] = hex_bytes(values, "md", case_path)
    return out


def load_vector_set(path: str | Path) -> ShakeVectorSet:
    """Read and normalize a prompt file."""
    return parse_vector_set(json.loads(Path(path).read_text(encoding="utf-8")))


def load_expected_results(path: str | Path) -> dict[tuple[int, int], bytes]:
    """Read and index an expected-results file."""
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


def provider_for(provider_command: str | None, timeout_seconds: float) -> XofProvider:
    """The built-in provider, or a harness when one is named."""
    if provider_command is None:
        return HashlibXofProvider()
    return SubprocessXofProvider.from_command_string(
        provider_command, timeout_seconds=timeout_seconds
    )


def run_vector_set(
    vector_set: ShakeVectorSet,
    expected: dict[tuple[int, int], bytes],
    provider: XofProvider,
) -> list[TestCaseResult]:
    """Squeeze every case to its requested length and compare."""
    results: list[TestCaseResult] = []
    for group in vector_set.groups:
        for case in group.tests:
            key = (group.tg_id, case.tc_id)
            if vector_set.algorithm not in XOF_ALGORITHMS:
                results.append(
                    _unsupported(*key, f"{vector_set.algorithm} is not an XOF this runner offers")
                )
                continue
            if group.test_type != AFT:
                results.append(
                    _unsupported(
                        *key,
                        f"test type {group.test_type!r} is not answered; the SHAKE Monte Carlo "
                        "chain is not implemented, so register only AFT for a submission",
                    )
                )
                continue
            if case.output_bits % 8:
                results.append(
                    _unsupported(*key, f"outLen {case.output_bits} is not a whole number of bytes")
                )
                continue
            want = expected.get(key)
            if want is None:
                results.append(_unsupported(*key, "no expected result recorded"))
                continue
            try:
                produced = provider.squeeze(
                    algorithm=vector_set.algorithm,
                    message=case.message,
                    output_bytes=case.output_bits // 8,
                )
            except HarnessUnsupportedError:
                results.append(_unsupported(*key, "the harness declined this case"))
                continue
            matched = produced == want
            results.append(
                TestCaseResult(
                    tg_id=group.tg_id,
                    tc_id=case.tc_id,
                    status=ResultStatus.PASS if matched else ResultStatus.FAIL,
                    expected=DigestValues(digest=want),
                    actual=DigestValues(digest=produced),
                    diagnostic=None if matched else "md mismatch",
                )
            )
    return results


def metadata_for(provider: XofProvider) -> ProviderMetadata:
    """Provider identity, for the report header."""
    return provider.metadata()


__all__ = [
    "AFT",
    "REVISION",
    "SUPPORTED",
    "ShakeVectorSet",
    "load_expected_results",
    "load_vector_set",
    "metadata_for",
    "parse_expected_results",
    "parse_vector_set",
    "provider_for",
    "run_vector_set",
]
