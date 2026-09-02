"""Per-case comparison and bounded error classification."""

from __future__ import annotations

from enum import StrEnum

from acvp_runner.models import AesGcmValues, ResultStatus, TestCaseResult


class SafeDiagnostic(StrEnum):
    """Non-secret diagnostics allowed in machine-readable case output."""

    AUTHENTICATION_FAILED = "authentication failed"
    INVALID_CASE = "invalid case"
    PROVIDER_ERROR = "provider error"


def compare_values(
    *,
    tg_id: int,
    tc_id: int,
    expected: AesGcmValues,
    actual: AesGcmValues,
) -> TestCaseResult:
    """Compare direction-specific values and classify the case."""
    field_names = ("plaintext", "ciphertext", "tag")
    mismatches = [
        field_name
        for field_name in field_names
        if getattr(expected, field_name) != getattr(actual, field_name)
    ]
    if not mismatches:
        return TestCaseResult(
            tg_id=tg_id,
            tc_id=tc_id,
            status=ResultStatus.PASS,
            expected=expected,
            actual=actual,
        )
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=ResultStatus.FAIL,
        expected=expected,
        actual=actual,
        diagnostic=", ".join(f"{field_name} mismatch" for field_name in mismatches),
    )


def error_result(
    *,
    tg_id: int,
    tc_id: int,
    diagnostic: SafeDiagnostic,
    expected: AesGcmValues | None = None,
) -> TestCaseResult:
    """Create an ERROR result without copying a raw exception message."""
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=ResultStatus.ERROR,
        expected=expected,
        actual=None,
        diagnostic=diagnostic.value,
    )


__all__ = ["SafeDiagnostic", "compare_values", "error_result"]
