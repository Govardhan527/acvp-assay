"""AES-ECB, AES-GMAC, AES-KW, AES-KWP and CMAC-AES.

Five families sharing one module because they share a shape: an AES key, a
``direction``, and per-group lengths. Between them they reuse every result
shape already built — compare-output for ECB, GMAC generation, key wrapping
and CMAC generation; verdict-only for CMAC verification, GMAC verification and
a rejected unwrap.

``kwCipher: inverse`` is declared UNSUPPORTED: it reverses which AES direction
performs the wrap, and the binding exposes only the standard construction.
Declaring that is honest; approximating it would silently produce wrong
verdicts on half the upstream groups.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from acvp_assay.models import (
    AesGcmValues,
    DigestValues,
    ResultStatus,
    TestCaseResult,
    VerdictValues,
)
from acvp_assay.parser import (
    AcvpValidationError,
    integer,
    list_field,
    mapping,
    optional_hex_bytes,
    optional_string,
    string_field,
)
from acvp_assay.providers.aes_modes import AesModeProvider

ECB = "ACVP-AES-ECB"
GMAC = "ACVP-AES-GMAC"
KW = "ACVP-AES-KW"
KWP = "ACVP-AES-KWP"
CMAC = "CMAC-AES"

SUPPORTED = (ECB, GMAC, KW, KWP, CMAC)
STANDARD_KW_CIPHER = "cipher"


@dataclass(frozen=True, slots=True)
class AesCase:
    """One case, holding whichever hex fields its family uses."""

    tc_id: int
    fields: Mapping[str, bytes] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AesGroup:
    """Cases sharing a direction and per-group lengths."""

    tg_id: int
    test_type: str
    direction: str
    tests: tuple[AesCase, ...]
    mac_length_bits: int | None = None
    tag_length_bits: int | None = None
    kw_cipher: str = STANDARD_KW_CIPHER


@dataclass(frozen=True, slots=True)
class AesVectorSet:
    """One normalized vector set for an AES mode family."""

    vs_id: int
    algorithm: str
    revision: str
    test_groups: tuple[AesGroup, ...]


@dataclass(frozen=True, slots=True)
class AesExpectedCase:
    """Expected output: bytes, a verdict, or a Monte Carlo chain."""

    tc_id: int
    values: Mapping[str, bytes]
    test_passed: bool | None
    results_array: tuple[Mapping[str, bytes], ...] | None


@dataclass(frozen=True, slots=True)
class AesExpectedSet:
    """Expected results keyed by group and case."""

    vs_id: int
    cases: Mapping[tuple[int, int], AesExpectedCase]


_CASE_FIELDS = ("key", "pt", "ct", "iv", "aad", "tag", "mac", "message")
_RESULT_FIELDS = ("key", "pt", "ct", "tag", "mac")


def _parse_case(value: object, *, path: str) -> AesCase:
    document = mapping(value, path)
    present = {
        name: parsed
        for name in _CASE_FIELDS
        if (parsed := optional_hex_bytes(document, name, path)) is not None
    }
    return AesCase(tc_id=integer(document, "tcId", path), fields=present)


def _parse_group(value: object, *, path: str) -> AesGroup:
    document = mapping(value, path)
    tests = tuple(
        _parse_case(entry, path=f"{path}.tests[{index}]")
        for index, entry in enumerate(list_field(document, "tests", path))
    )
    mac_length = document.get("macLen")
    tag_length = document.get("tagLen")
    return AesGroup(
        tg_id=integer(document, "tgId", path),
        test_type=string_field(document, "testType", path),
        direction=string_field(document, "direction", path),
        tests=tests,
        mac_length_bits=mac_length if isinstance(mac_length, int) else None,
        tag_length_bits=tag_length if isinstance(tag_length, int) else None,
        kw_cipher=optional_string(document, "kwCipher", path) or STANDARD_KW_CIPHER,
    )


def parse_vector_set(value: object) -> AesVectorSet:
    """Validate and normalize one AES-mode vector-set document."""
    document = mapping(value, "$")
    algorithm = string_field(document, "algorithm", "$")
    if algorithm not in SUPPORTED:
        raise AcvpValidationError("$.algorithm", f"unsupported algorithm {algorithm!r}")
    groups = tuple(
        _parse_group(entry, path=f"$.testGroups[{index}]")
        for index, entry in enumerate(list_field(document, "testGroups", "$"))
    )
    return AesVectorSet(
        vs_id=integer(document, "vsId", "$"),
        algorithm=algorithm,
        revision=string_field(document, "revision", "$"),
        test_groups=groups,
    )


def parse_expected_results(value: object) -> AesExpectedSet:
    """Validate and normalize AES-mode expected results."""
    document = mapping(value, "$")
    cases: dict[tuple[int, int], AesExpectedCase] = {}
    for group_index, group_value in enumerate(list_field(document, "testGroups", "$")):
        group_path = f"$.testGroups[{group_index}]"
        group = mapping(group_value, group_path)
        tg_id = integer(group, "tgId", group_path)
        for case_index, case_value in enumerate(list_field(group, "tests", group_path)):
            case_path = f"{group_path}.tests[{case_index}]"
            case = mapping(case_value, case_path)
            chain: tuple[Mapping[str, bytes], ...] | None = None
            if "resultsArray" in case:
                chain = tuple(
                    {
                        name: parsed
                        for name in _RESULT_FIELDS
                        if (
                            parsed := optional_hex_bytes(
                                mapping(entry, f"{case_path}.resultsArray[{index}]"),
                                name,
                                case_path,
                            )
                        )
                        is not None
                    }
                    for index, entry in enumerate(list_field(case, "resultsArray", case_path))
                )
            raw = case.get("testPassed")
            cases[(tg_id, integer(case, "tcId", case_path))] = AesExpectedCase(
                tc_id=integer(case, "tcId", case_path),
                values={
                    name: parsed
                    for name in _RESULT_FIELDS
                    if (parsed := optional_hex_bytes(case, name, case_path)) is not None
                },
                test_passed=raw if isinstance(raw, bool) else None,
                results_array=chain,
            )
    return AesExpectedSet(vs_id=integer(document, "vsId", "$"), cases=cases)


def load_vector_set(path: str | Path) -> AesVectorSet:
    """Load and normalize an AES-mode prompt file."""
    return parse_vector_set(json.loads(Path(path).read_text(encoding="utf-8")))


def load_expected_results(path: str | Path) -> AesExpectedSet:
    """Load and normalize an AES-mode expected-results file."""
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
        (AesGcmValues(plaintext=expected), AesGcmValues(plaintext=actual))
        if name == "pt"
        else (AesGcmValues(ciphertext=expected), AesGcmValues(ciphertext=actual))
        if name == "ct"
        else (DigestValues(mac=expected), DigestValues(mac=actual))
        if name == "mac"
        else (AesGcmValues(tag=expected), AesGcmValues(tag=actual))
    )
    passed = expected == actual
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=ResultStatus.PASS if passed else ResultStatus.FAIL,
        expected=values[0],
        actual=values[1],
        diagnostic=None if passed else f"{name} mismatch",
    )


def _verdict(tg_id: int, tc_id: int, expected: bool, actual: bool, subject: str) -> TestCaseResult:
    passed = expected == actual
    diagnostic = None
    if not passed:
        diagnostic = (
            f"accepted {subject} ACVP declares invalid"
            if actual
            else f"rejected {subject} ACVP declares valid"
        )
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=ResultStatus.PASS if passed else ResultStatus.FAIL,
        expected=VerdictValues(passed=expected),
        actual=VerdictValues(passed=actual),
        diagnostic=diagnostic,
    )


def _run_ecb_mct(
    group: AesGroup, case: AesCase, expected: AesExpectedCase, provider: AesModeProvider
) -> TestCaseResult:
    if expected.results_array is None:
        return _unsupported(group.tg_id, case.tc_id, "MCT case has no expected resultsArray")
    encrypt = group.direction == "encrypt"
    start = case.fields["pt"] if encrypt else case.fields["ct"]
    produced = provider.ecb_monte_carlo(key=case.fields["key"], data=start, encrypt=encrypt)
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
    output_name = "ct" if encrypt else "pt"
    input_name = "pt" if encrypt else "ct"
    for index, (want, (used_key, first, last)) in enumerate(
        zip(expected.results_array, produced, strict=True)
    ):
        for name, got in (("key", used_key), (input_name, first), (output_name, last)):
            if name in want and want[name] != got:
                return TestCaseResult(
                    tg_id=group.tg_id,
                    tc_id=case.tc_id,
                    status=ResultStatus.FAIL,
                    expected=AesGcmValues(ciphertext=want[name]),
                    actual=AesGcmValues(ciphertext=got),
                    diagnostic=f"{name} mismatch at Monte Carlo iteration {index}",
                )
    return TestCaseResult(
        tg_id=group.tg_id,
        tc_id=case.tc_id,
        status=ResultStatus.PASS,
        expected=None,
        actual=None,
        diagnostic=f"{len(produced)} Monte Carlo iterations matched",
    )


def _run_case(
    algorithm: str,
    group: AesGroup,
    case: AesCase,
    expected: AesExpectedCase,
    provider: AesModeProvider,
) -> TestCaseResult:
    if algorithm == ECB:
        if group.test_type == "MCT":
            return _run_ecb_mct(group, case, expected, provider)
        encrypt = group.direction == "encrypt"
        name = "ct" if encrypt else "pt"
        if name not in expected.values:
            return _unsupported(group.tg_id, case.tc_id, f"no expected {name} recorded")
        produced = provider.ecb(
            key=case.fields["key"],
            data=case.fields["pt" if encrypt else "ct"],
            encrypt=encrypt,
        )
        return _compare(group.tg_id, case.tc_id, name, expected.values[name], produced)

    if algorithm == CMAC:
        assert group.mac_length_bits is not None
        produced = provider.cmac(
            key=case.fields["key"],
            message=case.fields.get("message", b""),
            mac_length_bits=group.mac_length_bits,
        )
        if group.direction == "gen":
            if "mac" not in expected.values:
                return _unsupported(group.tg_id, case.tc_id, "no expected mac recorded")
            return _compare(group.tg_id, case.tc_id, "mac", expected.values["mac"], produced)
        if expected.test_passed is None:
            return _unsupported(group.tg_id, case.tc_id, "no expected verdict recorded")
        return _verdict(
            group.tg_id,
            case.tc_id,
            expected.test_passed,
            produced == case.fields.get("mac"),
            "a MAC",
        )

    if algorithm == GMAC:
        assert group.tag_length_bits is not None
        produced = provider.gmac(
            key=case.fields["key"],
            iv=case.fields["iv"],
            aad=case.fields.get("aad", b""),
            tag_length_bits=group.tag_length_bits,
        )
        if group.direction == "encrypt":
            if "tag" not in expected.values:
                return _unsupported(group.tg_id, case.tc_id, "no expected tag recorded")
            return _compare(group.tg_id, case.tc_id, "tag", expected.values["tag"], produced)
        if expected.test_passed is None:
            return _unsupported(group.tg_id, case.tc_id, "no expected verdict recorded")
        return _verdict(
            group.tg_id,
            case.tc_id,
            expected.test_passed,
            produced == case.fields.get("tag"),
            "a tag",
        )

    # AES-KW and AES-KWP
    wrap = group.direction == "encrypt"
    name = "ct" if wrap else "pt"
    try:
        produced = provider.key_wrap(
            key=case.fields["key"],
            data=case.fields["pt" if wrap else "ct"],
            padded=algorithm == KWP,
            wrap=wrap,
        )
    except ValueError:
        if expected.test_passed is not None:
            return _verdict(group.tg_id, case.tc_id, expected.test_passed, False, "a wrapping")
        return _unsupported(group.tg_id, case.tc_id, "unwrapping failed with no expected verdict")
    if expected.test_passed is not None:
        return _verdict(group.tg_id, case.tc_id, expected.test_passed, True, "a wrapping")
    if name not in expected.values:
        return _unsupported(group.tg_id, case.tc_id, f"no expected {name} recorded")
    return _compare(group.tg_id, case.tc_id, name, expected.values[name], produced)


def run_vector_set(
    vector_set: AesVectorSet,
    expected: AesExpectedSet,
    provider: AesModeProvider,
) -> list[TestCaseResult]:
    """Execute every case using the shape its family and direction require."""
    results: list[TestCaseResult] = []
    for group in vector_set.test_groups:
        declined = None
        if vector_set.algorithm in (KW, KWP) and group.kw_cipher != STANDARD_KW_CIPHER:
            declined = f"kwCipher {group.kw_cipher!r} is not supported"
        for case in group.tests:
            expected_case = expected.cases.get((group.tg_id, case.tc_id))
            if declined is not None:
                results.append(_unsupported(group.tg_id, case.tc_id, declined))
                continue
            if expected_case is None:
                results.append(_unsupported(group.tg_id, case.tc_id, "no expected result recorded"))
                continue
            results.append(_run_case(vector_set.algorithm, group, case, expected_case, provider))
    return results


__all__ = [
    "SUPPORTED",
    "AesExpectedSet",
    "AesVectorSet",
    "load_expected_results",
    "load_vector_set",
    "parse_expected_results",
    "parse_vector_set",
    "run_vector_set",
]
