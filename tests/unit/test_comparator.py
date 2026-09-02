"""Tests for per-case comparison and safe error output."""

from __future__ import annotations

import pytest

from acvp_runner.comparator import SafeDiagnostic, compare_values, error_result
from acvp_runner.models import AesGcmValues, ResultStatus


def test_equal_values_pass_without_a_diagnostic() -> None:
    """An exact direction-specific match is a clean PASS."""
    values = AesGcmValues(ciphertext=b"ciphertext", tag=b"tag")

    result = compare_values(tg_id=5, tc_id=9, expected=values, actual=values)

    assert result.tg_id == 5
    assert result.tc_id == 9
    assert result.status is ResultStatus.PASS
    assert result.expected is values
    assert result.actual is values
    assert result.diagnostic is None


@pytest.mark.parametrize(
    ("expected", "actual", "diagnostic"),
    [
        (
            AesGcmValues(plaintext=b"expected"),
            AesGcmValues(plaintext=b"wrong"),
            "plaintext mismatch",
        ),
        (
            AesGcmValues(ciphertext=b"ciphertext", tag=b"tag"),
            AesGcmValues(ciphertext=b"wrong", tag=b"tag"),
            "ciphertext mismatch",
        ),
        (
            AesGcmValues(ciphertext=b"ciphertext", tag=b"tag"),
            AesGcmValues(ciphertext=b"ciphertext", tag=b"wrong"),
            "tag mismatch",
        ),
        (
            AesGcmValues(ciphertext=b"ciphertext", tag=b"tag"),
            AesGcmValues(ciphertext=b"wrong", tag=b"wrong"),
            "ciphertext mismatch, tag mismatch",
        ),
    ],
)
def test_mismatched_values_fail_with_field_only_diagnostics(
    expected: AesGcmValues,
    actual: AesGcmValues,
    diagnostic: str,
) -> None:
    """A FAIL names mismatched fields without exposing their byte values."""
    result = compare_values(tg_id=5, tc_id=9, expected=expected, actual=actual)

    assert result.status is ResultStatus.FAIL
    assert result.expected is expected
    assert result.actual is actual
    assert result.diagnostic == diagnostic
    values = (
        expected.plaintext,
        expected.ciphertext,
        expected.tag,
        actual.plaintext,
        actual.ciphertext,
        actual.tag,
    )
    for value in values:
        if value:
            assert value.hex() not in diagnostic


@pytest.mark.parametrize("diagnostic", list(SafeDiagnostic))
def test_error_result_allows_only_bounded_diagnostics(diagnostic: SafeDiagnostic) -> None:
    """ERROR output uses a closed diagnostic set rather than exception text."""
    expected = AesGcmValues(plaintext=b"expected")

    result = error_result(
        tg_id=5,
        tc_id=9,
        diagnostic=diagnostic,
        expected=expected,
    )

    assert result.status is ResultStatus.ERROR
    assert result.expected is expected
    assert result.actual is None
    assert result.diagnostic == diagnostic.value
