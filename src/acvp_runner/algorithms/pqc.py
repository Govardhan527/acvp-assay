"""ML-KEM and ML-DSA vector parsing and execution.

Every shape these need already exists, which is the payoff from M04:

* ML-KEM ``encapsulation`` supplies the random ``m`` in the prompt, so the
  operation is deterministic and its ``c``/``k`` compare directly.
* ML-KEM ``decapsulation`` compares the recovered ``k``.
* ML-KEM ``encapsulationKeyCheck``/``decapsulationKeyCheck`` and ML-DSA
  ``sigVer`` are verdict-only, the shape ECDSA sigVer introduced.

Execution requires ``--provider-command``: see ``providers/pqc.py`` for why
there is no built-in implementation.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from acvp_runner.models import (
    DigestValues,
    ResultStatus,
    TestCaseResult,
    VerdictValues,
)
from acvp_runner.parser import (
    AcvpValidationError,
    integer,
    list_field,
    mapping,
    optional_hex_bytes,
    optional_string,
    string_field,
)
from acvp_runner.providers.pqc import (
    ML_DSA_PARAMETER_SETS,
    ML_KEM_PARAMETER_SETS,
    MlDsaProvider,
    MlKemProvider,
)

ENCAPSULATION = "encapsulation"
DECAPSULATION = "decapsulation"
ENCAP_KEY_CHECK = "encapsulationKeyCheck"
DECAP_KEY_CHECK = "decapsulationKeyCheck"
KEY_CHECKS = (ENCAP_KEY_CHECK, DECAP_KEY_CHECK)


@dataclass(frozen=True, slots=True)
class PqcCase:
    """One ML-KEM or ML-DSA case, holding whichever fields its function uses."""

    tc_id: int
    fields: Mapping[str, bytes] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PqcGroup:
    """Cases sharing one parameter set and function."""

    tg_id: int
    parameter_set: str
    function: str
    tests: tuple[PqcCase, ...]
    pre_hash: str = "pure"
    external_mu: bool = False
    signature_interface: str = "external"


@dataclass(frozen=True, slots=True)
class PqcVectorSet:
    """One normalized ML-KEM or ML-DSA vector set."""

    vs_id: int
    algorithm: str
    revision: str
    mode: str
    test_groups: tuple[PqcGroup, ...]


@dataclass(frozen=True, slots=True)
class PqcExpectedCase:
    """Expected output for one PQC case: bytes, a verdict, or both."""

    tc_id: int
    values: Mapping[str, bytes]
    test_passed: bool | None


@dataclass(frozen=True, slots=True)
class PqcExpectedSet:
    """Expected PQC results keyed by group and case."""

    vs_id: int
    cases: Mapping[tuple[int, int], PqcExpectedCase]


_CASE_FIELDS = ("ek", "dk", "c", "m", "pk", "message", "signature", "context", "mu")


def _parse_case(value: object, *, path: str) -> PqcCase:
    document = mapping(value, path)
    present: dict[str, bytes] = {}
    for name in _CASE_FIELDS:
        parsed = optional_hex_bytes(document, name, path)
        if parsed is not None:
            present[name] = parsed
    return PqcCase(tc_id=integer(document, "tcId", path), fields=present)


def _parse_group(value: object, *, path: str, mode: str) -> PqcGroup:
    document = mapping(value, path)
    tests = tuple(
        _parse_case(entry, path=f"{path}.tests[{index}]")
        for index, entry in enumerate(list_field(document, "tests", path))
    )
    return PqcGroup(
        tg_id=integer(document, "tgId", path),
        parameter_set=string_field(document, "parameterSet", path),
        function=optional_string(document, "function", path) or mode,
        tests=tests,
        pre_hash=optional_string(document, "preHash", path) or "pure",
        external_mu=bool(document.get("externalMu", False)),
        signature_interface=optional_string(document, "signatureInterface", path) or "external",
    )


def parse_vector_set(value: object) -> PqcVectorSet:
    """Validate and normalize one ML-KEM or ML-DSA vector-set document."""
    document = mapping(value, "$")
    algorithm = string_field(document, "algorithm", "$")
    if algorithm not in ("ML-KEM", "ML-DSA"):
        raise AcvpValidationError("$.algorithm", f"unsupported algorithm {algorithm!r}")
    mode = string_field(document, "mode", "$")
    groups = tuple(
        _parse_group(entry, path=f"$.testGroups[{index}]", mode=mode)
        for index, entry in enumerate(list_field(document, "testGroups", "$"))
    )
    return PqcVectorSet(
        vs_id=integer(document, "vsId", "$"),
        algorithm=algorithm,
        revision=string_field(document, "revision", "$"),
        mode=mode,
        test_groups=groups,
    )


def parse_expected_results(value: object) -> PqcExpectedSet:
    """Validate and normalize ML-KEM or ML-DSA expected results."""
    document = mapping(value, "$")
    cases: dict[tuple[int, int], PqcExpectedCase] = {}
    for group_index, group_value in enumerate(list_field(document, "testGroups", "$")):
        group_path = f"$.testGroups[{group_index}]"
        group = mapping(group_value, group_path)
        tg_id = integer(group, "tgId", group_path)
        for case_index, case_value in enumerate(list_field(group, "tests", group_path)):
            case_path = f"{group_path}.tests[{case_index}]"
            case = mapping(case_value, case_path)
            tc_id = integer(case, "tcId", case_path)
            values: dict[str, bytes] = {}
            for name in ("c", "k"):
                parsed = optional_hex_bytes(case, name, case_path)
                if parsed is not None:
                    values[name] = parsed
            raw = case.get("testPassed")
            cases[(tg_id, tc_id)] = PqcExpectedCase(
                tc_id=tc_id,
                values=values,
                test_passed=raw if isinstance(raw, bool) else None,
            )
    return PqcExpectedSet(vs_id=integer(document, "vsId", "$"), cases=cases)


def load_vector_set(path: str | Path) -> PqcVectorSet:
    """Load and normalize a PQC prompt file."""
    return parse_vector_set(json.loads(Path(path).read_text(encoding="utf-8")))


def load_expected_results(path: str | Path) -> PqcExpectedSet:
    """Load and normalize a PQC expected-results file."""
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


def _verdict_result(
    tg_id: int, tc_id: int, expected: bool, actual: bool, subject: str
) -> TestCaseResult:
    status = ResultStatus.PASS if expected == actual else ResultStatus.FAIL
    diagnostic = None
    if status is ResultStatus.FAIL:
        diagnostic = (
            f"accepted {subject} ACVP declares invalid"
            if actual
            else f"rejected {subject} ACVP declares valid"
        )
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=status,
        expected=VerdictValues(passed=expected),
        actual=VerdictValues(passed=actual),
        diagnostic=diagnostic,
    )


def _compare_bytes(
    tg_id: int, tc_id: int, expected: Mapping[str, bytes], actual: Mapping[str, bytes]
) -> TestCaseResult:
    mismatches = sorted(name for name in expected if expected[name] != actual.get(name))
    status = ResultStatus.PASS if not mismatches else ResultStatus.FAIL
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=status,
        expected=DigestValues(digest=expected.get("k")),
        actual=DigestValues(digest=actual.get("k")),
        diagnostic=None
        if status is ResultStatus.PASS
        else ", ".join(f"{name} mismatch" for name in mismatches),
    )


def run_ml_kem(
    vector_set: PqcVectorSet,
    expected: PqcExpectedSet,
    provider: MlKemProvider,
) -> list[TestCaseResult]:
    """Execute every ML-KEM case using the shape its function requires."""
    results: list[TestCaseResult] = []
    for group in vector_set.test_groups:
        supported = group.parameter_set in ML_KEM_PARAMETER_SETS
        for case in group.tests:
            expected_case = expected.cases.get((group.tg_id, case.tc_id))
            if not supported:
                results.append(
                    _unsupported(
                        group.tg_id,
                        case.tc_id,
                        f"parameter set {group.parameter_set!r} is not supported",
                    )
                )
                continue
            if expected_case is None:
                results.append(_unsupported(group.tg_id, case.tc_id, "no expected result recorded"))
                continue
            if group.function in KEY_CHECKS:
                if expected_case.test_passed is None:
                    results.append(
                        _unsupported(group.tg_id, case.tc_id, "no expected verdict recorded")
                    )
                    continue
                key_type = "ek" if group.function == ENCAP_KEY_CHECK else "dk"
                if key_type not in case.fields:
                    results.append(
                        _unsupported(group.tg_id, case.tc_id, f"case is missing {key_type}")
                    )
                    continue
                verdict = provider.check_key(
                    parameter_set=group.parameter_set,
                    key_type=key_type,
                    key=case.fields[key_type],
                )
                results.append(
                    _verdict_result(
                        group.tg_id, case.tc_id, expected_case.test_passed, verdict, "a key"
                    )
                )
                continue
            if group.function == ENCAPSULATION:
                if not {"ek", "m"} <= set(case.fields):
                    results.append(_unsupported(group.tg_id, case.tc_id, "case is missing ek or m"))
                    continue
                ciphertext, shared = provider.encapsulate(
                    parameter_set=group.parameter_set,
                    encapsulation_key=case.fields["ek"],
                    seed=case.fields["m"],
                )
                results.append(
                    _compare_bytes(
                        group.tg_id,
                        case.tc_id,
                        expected_case.values,
                        {"c": ciphertext, "k": shared},
                    )
                )
                continue
            if group.function == DECAPSULATION:
                if not {"dk", "c"} <= set(case.fields):
                    results.append(_unsupported(group.tg_id, case.tc_id, "case is missing dk or c"))
                    continue
                shared = provider.decapsulate(
                    parameter_set=group.parameter_set,
                    decapsulation_key=case.fields["dk"],
                    ciphertext=case.fields["c"],
                )
                results.append(
                    _compare_bytes(group.tg_id, case.tc_id, expected_case.values, {"k": shared})
                )
                continue
            results.append(
                _unsupported(
                    group.tg_id, case.tc_id, f"function {group.function!r} is not supported"
                )
            )
    return results


def run_ml_dsa(
    vector_set: PqcVectorSet,
    expected: PqcExpectedSet,
    provider: MlDsaProvider,
) -> list[TestCaseResult]:
    """Execute every ML-DSA verification case against its expected verdict."""
    results: list[TestCaseResult] = []
    for group in vector_set.test_groups:
        supported = group.parameter_set in ML_DSA_PARAMETER_SETS
        for case in group.tests:
            expected_case = expected.cases.get((group.tg_id, case.tc_id))
            if not supported:
                results.append(
                    _unsupported(
                        group.tg_id,
                        case.tc_id,
                        f"parameter set {group.parameter_set!r} is not supported",
                    )
                )
                continue
            if expected_case is None or expected_case.test_passed is None:
                results.append(
                    _unsupported(group.tg_id, case.tc_id, "no expected verdict recorded")
                )
                continue
            if group.external_mu or "mu" in case.fields:
                results.append(
                    _unsupported(
                        group.tg_id,
                        case.tc_id,
                        "externalMu groups supply a precomputed mu and are not supported",
                    )
                )
                continue
            if group.pre_hash != "pure":
                results.append(
                    _unsupported(
                        group.tg_id, case.tc_id, f"preHash {group.pre_hash!r} is not supported"
                    )
                )
                continue
            missing = [name for name in ("pk", "message", "signature") if name not in case.fields]
            if missing:
                results.append(
                    _unsupported(group.tg_id, case.tc_id, f"case is missing {', '.join(missing)}")
                )
                continue
            verdict = provider.verify(
                parameter_set=group.parameter_set,
                public_key=case.fields["pk"],
                message=case.fields["message"],
                signature=case.fields["signature"],
                context=case.fields.get("context", b""),
                signature_interface=group.signature_interface,
            )
            results.append(
                _verdict_result(
                    group.tg_id,
                    case.tc_id,
                    expected_case.test_passed,
                    verdict,
                    "a signature",
                )
            )
    return results


__all__ = [
    "PqcExpectedSet",
    "PqcVectorSet",
    "load_expected_results",
    "load_vector_set",
    "parse_expected_results",
    "parse_vector_set",
    "run_ml_dsa",
    "run_ml_kem",
]
