"""ECDSA vector parsing and execution.

This module introduces the two result shapes the AES-GCM and SHA-2 paths never
needed, and they are the reason PQC becomes tractable afterwards:

``sigVer`` — verdict-only
    The vector supplies a signature that may be deliberately invalid. The
    expected result is a boolean ``testPassed``, so the implementation is
    judged on the verdict it reaches, never on bytes it returns.

``sigGen`` — produce-and-verify
    The vector supplies only a message; the implementation generates its own
    key pair. The ``qx``/``qy``/``r``/``s`` recorded in ``expectedResults`` are
    NIST's own and cannot be reproduced by anyone else, so comparing against
    them would fail every conforming implementation. The signature is instead
    verified under the public key that produced it.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from acvp_assay.models import (
    ResultStatus,
    SignatureValues,
    TestCaseResult,
    VerdictValues,
)
from acvp_assay.parser import (
    AcvpValidationError,
    hex_bytes,
    integer,
    list_field,
    mapping,
    optional_hex_bytes,
    string_field,
)
from acvp_assay.providers.ecdsa import EcdsaProvider
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

SIG_GEN = "sigGen"
SIG_VER = "sigVer"


@dataclass(frozen=True, slots=True)
class EcdsaTestCase:
    """One ECDSA case. sigVer supplies a key and signature; sigGen does not."""

    tc_id: int
    message: bytes
    qx: bytes | None = None
    qy: bytes | None = None
    r: bytes | None = None
    s: bytes | None = None


@dataclass(frozen=True, slots=True)
class EcdsaTestGroup:
    """ECDSA cases sharing one curve and hash contract."""

    tg_id: int
    curve: str
    hash_algorithm: str
    component_test: bool
    tests: tuple[EcdsaTestCase, ...]


@dataclass(frozen=True, slots=True)
class EcdsaVectorSet:
    """One normalized ECDSA vector set."""

    vs_id: int
    algorithm: str
    revision: str
    mode: str
    test_groups: tuple[EcdsaTestGroup, ...]


@dataclass(frozen=True, slots=True)
class EcdsaExpectedSet:
    """Expected ECDSA results, keyed by group and case."""

    vs_id: int
    verdicts: Mapping[tuple[int, int], bool]


def _parse_case(value: object, *, path: str, mode: str) -> EcdsaTestCase:
    document = mapping(value, path)
    tc_id = integer(document, "tcId", path)
    message = hex_bytes(document, "message", path)
    if mode == SIG_GEN:
        return EcdsaTestCase(tc_id=tc_id, message=message)
    return EcdsaTestCase(
        tc_id=tc_id,
        message=message,
        qx=optional_hex_bytes(document, "qx", path),
        qy=optional_hex_bytes(document, "qy", path),
        r=optional_hex_bytes(document, "r", path),
        s=optional_hex_bytes(document, "s", path),
    )


def _parse_group(value: object, *, path: str, mode: str) -> EcdsaTestGroup:
    document = mapping(value, path)
    tests = tuple(
        _parse_case(entry, path=f"{path}.tests[{index}]", mode=mode)
        for index, entry in enumerate(list_field(document, "tests", path))
    )
    return EcdsaTestGroup(
        tg_id=integer(document, "tgId", path),
        curve=string_field(document, "curve", path),
        hash_algorithm=string_field(document, "hashAlg", path),
        component_test=bool(document.get("componentTest", False)),
        tests=tests,
    )


def parse_vector_set(value: object) -> EcdsaVectorSet:
    """Validate and normalize one ECDSA vector-set document."""
    document = mapping(value, "$")
    algorithm = string_field(document, "algorithm", "$")
    if algorithm != "ECDSA":
        raise AcvpValidationError("$.algorithm", f"unsupported algorithm {algorithm!r}")
    mode = string_field(document, "mode", "$")
    if mode not in (SIG_GEN, SIG_VER):
        raise AcvpValidationError("$.mode", f"unsupported mode {mode!r}")
    groups = tuple(
        _parse_group(entry, path=f"$.testGroups[{index}]", mode=mode)
        for index, entry in enumerate(list_field(document, "testGroups", "$"))
    )
    return EcdsaVectorSet(
        vs_id=integer(document, "vsId", "$"),
        algorithm=algorithm,
        revision=string_field(document, "revision", "$"),
        mode=mode,
        test_groups=groups,
    )


def parse_expected_results(value: object) -> EcdsaExpectedSet:
    """Validate and normalize ECDSA expected results.

    Only ``testPassed`` is retained. A sigGen file's ``qx``/``qy``/``r``/``s``
    are NIST's own outputs and are deliberately discarded, because treating
    them as comparable would fail every conforming implementation.
    """
    document = mapping(value, "$")
    verdicts: dict[tuple[int, int], bool] = {}
    for group_index, group_value in enumerate(list_field(document, "testGroups", "$")):
        group_path = f"$.testGroups[{group_index}]"
        group = mapping(group_value, group_path)
        tg_id = integer(group, "tgId", group_path)
        for case_index, case_value in enumerate(list_field(group, "tests", group_path)):
            case_path = f"{group_path}.tests[{case_index}]"
            case = mapping(case_value, case_path)
            tc_id = integer(case, "tcId", case_path)
            raw = case.get("testPassed")
            if isinstance(raw, bool):
                verdicts[(tg_id, tc_id)] = raw
    return EcdsaExpectedSet(vs_id=integer(document, "vsId", "$"), verdicts=verdicts)


def load_vector_set(path: str | Path) -> EcdsaVectorSet:
    """Load and normalize an ECDSA prompt file."""
    return parse_vector_set(json.loads(Path(path).read_text(encoding="utf-8")))


def load_expected_results(path: str | Path) -> EcdsaExpectedSet:
    """Load and normalize an ECDSA expected-results file."""
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


def _run_sig_ver(
    group: EcdsaTestGroup,
    case: EcdsaTestCase,
    expected: bool | None,
    provider: EcdsaProvider,
) -> TestCaseResult:
    if expected is None:
        return _unsupported(group.tg_id, case.tc_id, "no expected verdict recorded")
    if None in (case.qx, case.qy, case.r, case.s):
        return _unsupported(group.tg_id, case.tc_id, "case is missing a key or signature field")
    assert case.qx is not None and case.qy is not None
    assert case.r is not None and case.s is not None
    verdict = provider.verify(
        curve=group.curve,
        hash_algorithm=group.hash_algorithm,
        message=case.message,
        qx=case.qx,
        qy=case.qy,
        r=case.r,
        s=case.s,
    )
    status = ResultStatus.PASS if verdict == expected else ResultStatus.FAIL
    diagnostic = None
    if status is ResultStatus.FAIL:
        diagnostic = (
            "accepted a signature ACVP declares invalid"
            if verdict
            else "rejected a signature ACVP declares valid"
        )
    return TestCaseResult(
        tg_id=group.tg_id,
        tc_id=case.tc_id,
        status=status,
        expected=VerdictValues(passed=expected),
        actual=VerdictValues(passed=verdict),
        diagnostic=diagnostic,
    )


def _run_sig_gen(
    group: EcdsaTestGroup,
    case: EcdsaTestCase,
    provider: EcdsaProvider,
) -> TestCaseResult:
    produced = provider.sign(
        curve=group.curve,
        hash_algorithm=group.hash_algorithm,
        message=case.message,
    )
    verified = provider.verify(
        curve=group.curve,
        hash_algorithm=group.hash_algorithm,
        message=case.message,
        qx=produced.qx,
        qy=produced.qy,
        r=produced.r,
        s=produced.s,
    )
    values = SignatureValues(qx=produced.qx, qy=produced.qy, r=produced.r, s=produced.s)
    return TestCaseResult(
        tg_id=group.tg_id,
        tc_id=case.tc_id,
        status=ResultStatus.PASS if verified else ResultStatus.FAIL,
        expected=None,
        actual=values,
        diagnostic=(
            "signature verified under the generated public key"
            if verified
            else "generated signature did not verify under its own public key"
        ),
    )


def run_vector_set(
    vector_set: EcdsaVectorSet,
    expected: EcdsaExpectedSet,
    provider: EcdsaProvider,
) -> list[TestCaseResult]:
    """Execute every ECDSA case using the shape its mode requires."""
    results: list[TestCaseResult] = []
    for group in vector_set.test_groups:
        supported = provider.supports(curve=group.curve, hash_algorithm=group.hash_algorithm)
        for case in group.tests:
            if not supported:
                results.append(
                    _unsupported(
                        group.tg_id,
                        case.tc_id,
                        f"curve {group.curve!r} with {group.hash_algorithm!r} is not supported",
                    )
                )
                continue
            if group.component_test:
                results.append(
                    _unsupported(group.tg_id, case.tc_id, "component-only tests are not supported")
                )
                continue
            try:
                if vector_set.mode == SIG_VER:
                    results.append(
                        _run_sig_ver(
                            group, case, expected.verdicts.get((group.tg_id, case.tc_id)), provider
                        )
                    )
                else:
                    results.append(_run_sig_gen(group, case, provider))
            except HarnessUnsupportedError:
                results.append(
                    _unsupported(group.tg_id, case.tc_id, "the harness declined this case")
                )
    return results


__all__ = [
    "SIG_GEN",
    "SIG_VER",
    "EcdsaExpectedSet",
    "EcdsaVectorSet",
    "load_expected_results",
    "load_vector_set",
    "parse_expected_results",
    "parse_vector_set",
    "run_vector_set",
]
