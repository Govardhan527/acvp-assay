"""Orchestrates execution of one vector set against one provider."""

from __future__ import annotations

from cryptography.exceptions import InvalidTag

from acvp_assay.comparator import compare_values, error_result
from acvp_assay.models import (
    AesGcmTestCase,
    AesGcmTestGroup,
    AesGcmValues,
    AesGcmVectorSet,
    Direction,
    ExpectedResultCase,
    ExpectedResultSet,
    ResultStatus,
    SafeDiagnostic,
    TestCaseResult,
)
from acvp_assay.providers.base import AesGcmProvider

SUPPORTED_IV_GENERATION = "external"


class ExpectedResultsMismatchError(ValueError):
    """The expected-results document does not identify the same vector set."""


def _check_identity(vector_set: AesGcmVectorSet, expected: ExpectedResultSet) -> None:
    if (vector_set.vs_id, vector_set.algorithm, vector_set.revision) != (
        expected.vs_id,
        expected.algorithm,
        expected.revision,
    ):
        raise ExpectedResultsMismatchError(
            "expected-results identity "
            f"(vsId={expected.vs_id}, algorithm={expected.algorithm!r}, "
            f"revision={expected.revision!r}) does not match the vector set "
            f"(vsId={vector_set.vs_id}, algorithm={vector_set.algorithm!r}, "
            f"revision={vector_set.revision!r})"
        )


def _expected_by_case(expected: ExpectedResultSet) -> dict[tuple[int, int], ExpectedResultCase]:
    return {(group.tg_id, case.tc_id): case for group in expected.groups for case in group.cases}


def _execute_case(
    provider: AesGcmProvider,
    group: AesGcmTestGroup,
    case: AesGcmTestCase,
) -> AesGcmValues:
    if group.direction is Direction.ENCRYPT:
        assert case.plaintext is not None
        return provider.encrypt(
            key=case.key,
            iv=case.iv,
            plaintext=case.plaintext,
            aad=case.aad,
            tag_length_bits=group.tag_length_bits,
        )
    assert case.ciphertext is not None
    assert case.tag is not None
    return provider.decrypt(
        key=case.key,
        iv=case.iv,
        ciphertext=case.ciphertext,
        aad=case.aad,
        tag=case.tag,
    )


def _run_case(
    provider: AesGcmProvider,
    group: AesGcmTestGroup,
    case: AesGcmTestCase,
    expected_by_case: dict[tuple[int, int], ExpectedResultCase],
) -> TestCaseResult:
    if group.iv_generation != SUPPORTED_IV_GENERATION:
        return TestCaseResult(
            tg_id=group.tg_id,
            tc_id=case.tc_id,
            status=ResultStatus.UNSUPPORTED,
            expected=None,
            actual=None,
            diagnostic=f"ivGen {group.iv_generation!r} is not supported",
        )
    expected_case = expected_by_case.get((group.tg_id, case.tc_id))
    if expected_case is None:
        return error_result(
            tg_id=group.tg_id,
            tc_id=case.tc_id,
            diagnostic=SafeDiagnostic.INVALID_CASE,
        )
    expects_failure = expected_case.expects_authentication_failure
    try:
        actual = _execute_case(provider, group, case)
    except InvalidTag:
        if expects_failure:
            return TestCaseResult(
                tg_id=group.tg_id,
                tc_id=case.tc_id,
                status=ResultStatus.PASS,
                expected=None,
                actual=None,
                diagnostic="authentication rejected as expected",
            )
        return error_result(
            tg_id=group.tg_id,
            tc_id=case.tc_id,
            diagnostic=SafeDiagnostic.AUTHENTICATION_FAILED,
            expected=expected_case.values,
        )
    except ValueError:
        return error_result(
            tg_id=group.tg_id,
            tc_id=case.tc_id,
            diagnostic=SafeDiagnostic.INVALID_CASE,
            expected=expected_case.values,
        )
    if expects_failure:
        return TestCaseResult(
            tg_id=group.tg_id,
            tc_id=case.tc_id,
            status=ResultStatus.FAIL,
            expected=expected_case.values,
            actual=actual,
            diagnostic="expected authentication failure, but the tag was accepted",
        )
    return compare_values(
        tg_id=group.tg_id,
        tc_id=case.tc_id,
        expected=expected_case.values,
        actual=actual,
    )


def run_vector_set(
    vector_set: AesGcmVectorSet,
    expected: ExpectedResultSet,
    provider: AesGcmProvider,
) -> list[TestCaseResult]:
    """Execute every case and classify it against its expected result.

    Groups whose ``ivGen`` is not ``external`` are marked UNSUPPORTED: this
    runner only supplies IVs from the vector file and cannot generate or
    report IVs of its own. Cases missing from ``expected`` are classified as
    ERROR/INVALID_CASE rather than skipped silently.

    Cases that ACVP marks ``testPassed: false`` invert the usual verdict: the
    implementation is *supposed* to reject the tag, so an ``InvalidTag`` is a
    PASS and a successful decryption is a FAIL. Roughly a third of NIST's own
    AES-GCM decrypt cases are of this kind.
    """
    _check_identity(vector_set, expected)
    expected_by_case = _expected_by_case(expected)
    return [
        _run_case(provider, group, case, expected_by_case)
        for group in vector_set.test_groups
        for case in group.tests
    ]


__all__ = ["ExpectedResultsMismatchError", "run_vector_set"]
