"""Tests for immutable ACVP internal models."""

from dataclasses import FrozenInstanceError

import pytest

from acvp_assay.models import (
    AesGcmTestCase,
    AesGcmTestGroup,
    AesGcmValues,
    AesGcmVectorSet,
    Direction,
    ResultStatus,
    SafeDiagnostic,
)
from acvp_assay.models import TestCaseResult as CaseResult
from acvp_assay.models import TestType as AcvpTestType


def make_vector_set() -> AesGcmVectorSet:
    """Build the smallest complete typed vector set."""
    case = AesGcmTestCase(
        tc_id=17,
        key=bytes.fromhex("000102030405060708090A0B0C0D0E0F"),
        iv=bytes.fromhex("101112131415161718191A1B"),
        aad=b"context",
        plaintext=b"payload",
    )
    group = AesGcmTestGroup(
        tg_id=11,
        test_type=AcvpTestType.AFT,
        direction=Direction.ENCRYPT,
        key_length_bits=128,
        iv_length_bits=96,
        payload_length_bits=56,
        aad_length_bits=56,
        tag_length_bits=128,
        iv_generation="external",
        iv_generation_mode="8.2.2",
        tests=(case,),
    )
    return AesGcmVectorSet(
        vs_id=900001,
        algorithm="ACVP-AES-GCM",
        revision="1.0",
        is_sample=True,
        test_groups=(group,),
    )


def test_models_preserve_vector_group_and_case_ids() -> None:
    """ACVP identities survive normalization as explicit typed fields."""
    vector_set = make_vector_set()
    group = vector_set.test_groups[0]
    case = group.tests[0]

    assert vector_set.vs_id == 900001
    assert group.tg_id == 11
    assert case.tc_id == 17
    assert group.direction is Direction.ENCRYPT
    assert group.test_type is AcvpTestType.AFT


def test_models_are_immutable_and_hashable() -> None:
    """Parsed evidence cannot be silently mutated after construction."""
    vector_set = make_vector_set()

    with pytest.raises(FrozenInstanceError):
        vector_set.vs_id = 2  # type: ignore[misc]

    assert hash(vector_set)


def test_result_preserves_identity_values_and_diagnostic() -> None:
    """A case result retains IDs and separately typed expected/actual data."""
    expected = AesGcmValues(ciphertext=b"expected", tag=b"tag")
    actual = AesGcmValues(ciphertext=b"actual", tag=b"tag")
    result = CaseResult(
        tg_id=11,
        tc_id=17,
        status=ResultStatus.FAIL,
        expected=expected,
        actual=actual,
        diagnostic="ciphertext mismatch",
    )

    assert result.tg_id == 11
    assert result.tc_id == 17
    assert result.status.value == "FAIL"
    assert result.expected == expected
    assert result.actual == actual
    assert result.diagnostic == "ciphertext mismatch"


def test_error_result_rejects_diagnostics_outside_the_safe_vocabulary() -> None:
    """A future caller cannot smuggle raw exception text into an ERROR result."""
    with pytest.raises(ValueError, match="ERROR diagnostic must be one of"):
        CaseResult(
            tg_id=1,
            tc_id=1,
            status=ResultStatus.ERROR,
            expected=None,
            actual=None,
            diagnostic="InvalidTag: some raw exception text",
        )


def test_error_result_accepts_every_safe_diagnostic() -> None:
    """Every closed SafeDiagnostic value is a valid ERROR diagnostic."""
    for diagnostic in SafeDiagnostic:
        result = CaseResult(
            tg_id=1,
            tc_id=1,
            status=ResultStatus.ERROR,
            expected=None,
            actual=None,
            diagnostic=diagnostic.value,
        )
        assert result.diagnostic == diagnostic.value


def test_enum_values_match_external_wire_values() -> None:
    """Enums retain the exact strings consumed or emitted at boundaries."""
    assert [direction.value for direction in Direction] == ["encrypt", "decrypt"]
    assert [test_type.value for test_type in AcvpTestType] == ["AFT"]
    assert [status.value for status in ResultStatus] == [
        "PASS",
        "FAIL",
        "ERROR",
        "SKIPPED",
        "UNSUPPORTED",
    ]
