"""Tests for vector-set execution and case classification."""

from __future__ import annotations

from pathlib import Path

import pytest

from acvp_runner.models import (
    AesGcmTestCase,
    AesGcmTestGroup,
    AesGcmValues,
    AesGcmVectorSet,
    Direction,
    ExpectedResultCase,
    ExpectedResultGroup,
    ExpectedResultSet,
    ResultStatus,
)
from acvp_runner.models import TestType as AcvpTestType
from acvp_runner.parser import load_expected_results, load_vector_set
from acvp_runner.providers.cryptography_aesgcm import CryptographyAesGcmProvider
from acvp_runner.runner import ExpectedResultsMismatchError, run_vector_set

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def provider() -> CryptographyAesGcmProvider:
    """Return one OpenSSL-backed provider instance."""
    return CryptographyAesGcmProvider()


def one_case(
    *,
    direction: Direction = Direction.ENCRYPT,
    iv_generation: str = "external",
    tag_length_bits: int = 128,
    key: bytes = bytes.fromhex("000102030405060708090A0B0C0D0E0F"),
    iv: bytes = bytes.fromhex("101112131415161718191A1B"),
    aad: bytes = b"aad",
    plaintext: bytes | None = b"plaintext",
    ciphertext: bytes | None = None,
    tag: bytes | None = None,
) -> AesGcmVectorSet:
    """Build the smallest one-case vector set for a runner scenario."""
    case = AesGcmTestCase(
        tc_id=1,
        key=key,
        iv=iv,
        aad=aad,
        plaintext=plaintext,
        ciphertext=ciphertext,
        tag=tag,
    )
    group = AesGcmTestGroup(
        tg_id=1,
        test_type=AcvpTestType.AFT,
        direction=direction,
        key_length_bits=len(key) * 8,
        iv_length_bits=len(iv) * 8,
        payload_length_bits=8,
        aad_length_bits=8,
        tag_length_bits=tag_length_bits,
        iv_generation=iv_generation,
        iv_generation_mode="8.2.2",
        tests=(case,),
    )
    return AesGcmVectorSet(
        vs_id=1,
        algorithm="ACVP-AES-GCM",
        revision="1.0",
        is_sample=True,
        test_groups=(group,),
    )


def expected_with(
    values: AesGcmValues | None,
    *,
    vs_id: int = 1,
    test_passed: bool | None = None,
) -> ExpectedResultSet:
    """Build a matching expected-results set, or an empty one when values is None."""
    cases = (
        ()
        if values is None
        else (ExpectedResultCase(tc_id=1, values=values, test_passed=test_passed),)
    )
    return ExpectedResultSet(
        vs_id=vs_id,
        algorithm="ACVP-AES-GCM",
        revision="1.0",
        groups=(ExpectedResultGroup(tg_id=1, cases=cases),),
    )


def test_encrypt_fixture_passes_end_to_end() -> None:
    """A valid encrypt fixture round-trips through the CLI-shaped pipeline as PASS."""
    vector_set = load_vector_set(FIXTURES / "aes-gcm-valid-encrypt/prompt.json")
    expected = load_expected_results(FIXTURES / "aes-gcm-valid-encrypt/expectedResults.json")

    results = run_vector_set(vector_set, expected, provider())

    assert len(results) == 1
    assert results[0].status is ResultStatus.PASS


def test_decrypt_fixture_passes_end_to_end() -> None:
    """A valid decrypt fixture round-trips through the CLI-shaped pipeline as PASS."""
    vector_set = load_vector_set(FIXTURES / "aes-gcm-valid-decrypt/prompt.json")
    expected = load_expected_results(FIXTURES / "aes-gcm-valid-decrypt/expectedResults.json")

    results = run_vector_set(vector_set, expected, provider())

    assert len(results) == 1
    assert results[0].status is ResultStatus.PASS


def test_invalid_tag_fixture_reports_authentication_failed() -> None:
    """A deliberately corrupted tag is classified as ERROR/authentication failed."""
    vector_set = load_vector_set(FIXTURES / "aes-gcm-invalid-decrypt-tag/prompt.json")
    expected = load_expected_results(FIXTURES / "aes-gcm-invalid-decrypt-tag/expectedResults.json")

    results = run_vector_set(vector_set, expected, provider())

    assert len(results) == 1
    assert results[0].status is ResultStatus.ERROR
    assert results[0].diagnostic == "authentication failed"


def test_expected_authentication_failure_is_a_pass() -> None:
    """A case ACVP marks ``testPassed: false`` passes when the tag is rejected.

    Roughly a third of NIST's own AES-GCM decrypt cases are of this kind, so
    treating the rejection as an error would fail a correct implementation.
    """
    vector_set = load_vector_set(FIXTURES / "aes-gcm-decrypt-auth-failure/prompt.json")
    expected = load_expected_results(FIXTURES / "aes-gcm-decrypt-auth-failure/expectedResults.json")

    results = run_vector_set(vector_set, expected, provider())

    assert results[0].status is ResultStatus.PASS
    assert results[0].diagnostic == "authentication rejected as expected"


def test_accepting_a_forged_tag_is_a_failure() -> None:
    """Recovering plaintext where ACVP demands rejection is a loud FAIL.

    This is the security-critical direction: an implementation that accepts a
    forged tag must never be reported as passing.
    """
    key = bytes.fromhex("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF")
    iv = bytes.fromhex("A0A1A2A3A4A5A6A7A8A9AAAB")
    aad = bytes.fromhex("696E746567726974792D636865636B")
    ciphertext = bytes.fromhex("8997ABE975B757B994EB")
    valid_tag = bytes.fromhex("5333DD8833E1A1D0961819670A9A9FFA")
    vector_set = one_case(
        direction=Direction.DECRYPT,
        key=key,
        iv=iv,
        aad=aad,
        plaintext=None,
        ciphertext=ciphertext,
        tag=valid_tag,
    )
    expected = expected_with(AesGcmValues(), test_passed=False)

    results = run_vector_set(vector_set, expected, provider())

    assert results[0].status is ResultStatus.FAIL
    assert results[0].diagnostic == "expected authentication failure, but the tag was accepted"


def test_unsupported_iv_generation_is_not_executed() -> None:
    """A group whose IV is not externally supplied is UNSUPPORTED, not executed."""
    vector_set = one_case(iv_generation="internal")
    expected = expected_with(AesGcmValues(ciphertext=b"c", tag=b"t"))

    results = run_vector_set(vector_set, expected, provider())

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert results[0].expected is None
    assert results[0].actual is None


def test_case_missing_from_expected_results_is_invalid() -> None:
    """A case with no matching expected-results entry is ERROR/invalid case."""
    vector_set = one_case()
    expected = expected_with(None)

    results = run_vector_set(vector_set, expected, provider())

    assert results[0].status is ResultStatus.ERROR
    assert results[0].diagnostic == "invalid case"


def test_unsupported_tag_length_is_invalid_case() -> None:
    """A provider ValueError (e.g. an out-of-range tag length) is ERROR/invalid case."""
    vector_set = one_case(tag_length_bits=16)
    expected = expected_with(AesGcmValues(ciphertext=b"c", tag=b"t"))

    results = run_vector_set(vector_set, expected, provider())

    assert results[0].status is ResultStatus.ERROR
    assert results[0].diagnostic == "invalid case"


def test_mismatched_expected_results_identity_is_rejected() -> None:
    """Expected results identifying a different vector set raise before executing."""
    vector_set = one_case()
    expected = expected_with(AesGcmValues(ciphertext=b"c", tag=b"t"), vs_id=999)

    with pytest.raises(ExpectedResultsMismatchError, match="does not match the vector set"):
        run_vector_set(vector_set, expected, provider())
