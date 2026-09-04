"""ACVP-AES-CCM, revision 1.0.

The same three-way shape as AES-GCM. An encrypt case compares ciphertext with
the tag appended. A decrypt case either recovers plaintext or, when ACVP has
deliberately corrupted the tag, expects the implementation to *reject* it --
and rejecting is then a PASS, while accepting is a loud failure.

Getting that inversion wrong is the worst output this tool can produce: it
either tells a vendor their module is broken when it is behaving correctly, or
stays quiet about a module that accepts forgeries.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag

from acvp_assay.models import (
    AesGcmValues,
    ProviderMetadata,
    ResultStatus,
    TestCaseResult,
    VerdictValues,
)
from acvp_assay.parser import (
    AcvpValidationError,
    hex_bytes,
    integer,
    list_field,
    mapping,
    optional_boolean,
    optional_hex_bytes,
    string_field,
)
from acvp_assay.providers.aes_ccm import (
    ALGORITHM,
    TAG_LENGTHS,
    AesCcmProvider,
    CryptographyAesCcm,
    SubprocessAesCcm,
)
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

REVISION = "1.0"


@dataclass(frozen=True, slots=True)
class CcmCase:
    """One CCM transform."""

    tc_id: int
    key: bytes
    nonce: bytes
    aad: bytes
    payload: bytes


@dataclass(frozen=True, slots=True)
class CcmGroup:
    """Cases sharing a direction, key length, nonce length and tag length."""

    tg_id: int
    direction: str
    key_bits: int
    tag_bits: int
    tests: tuple[CcmCase, ...]


@dataclass(frozen=True, slots=True)
class CcmVectorSet:
    """One normalized AES-CCM vector set."""

    vs_id: int
    algorithm: str
    revision: str
    groups: tuple[CcmGroup, ...]


@dataclass(frozen=True, slots=True)
class CcmExpectation:
    """What ACVP records for a case: bytes, or a verdict for a forged tag."""

    payload: bytes | None
    test_passed: bool | None


def _parse_case(value: object, *, path: str, encrypt: bool) -> CcmCase:
    document = mapping(value, path)
    return CcmCase(
        tc_id=integer(document, "tcId", path),
        key=hex_bytes(document, "key", path),
        nonce=hex_bytes(document, "iv", path),
        aad=optional_hex_bytes(document, "aad", path) or b"",
        payload=hex_bytes(document, "pt" if encrypt else "ct", path),
    )


def _parse_group(value: object, *, path: str) -> CcmGroup:
    document = mapping(value, path)
    direction = string_field(document, "direction", path)
    return CcmGroup(
        tg_id=integer(document, "tgId", path),
        direction=direction,
        key_bits=integer(document, "keyLen", path),
        tag_bits=integer(document, "tagLen", path),
        tests=tuple(
            _parse_case(case, path=f"{path}.tests[{index}]", encrypt=direction == "encrypt")
            for index, case in enumerate(list_field(document, "tests", path))
        ),
    )


def parse_vector_set(document: object) -> CcmVectorSet:
    """Normalize an AES-CCM prompt."""
    root = mapping(document, "$")
    return CcmVectorSet(
        vs_id=integer(root, "vsId", "$"),
        algorithm=string_field(root, "algorithm", "$"),
        revision=string_field(root, "revision", "$"),
        groups=tuple(
            _parse_group(group, path=f"$.testGroups[{index}]")
            for index, group in enumerate(list_field(root, "testGroups", "$"))
        ),
    )


def parse_expected_results(document: object) -> dict[tuple[int, int], CcmExpectation]:
    """Index expectations by ``(tgId, tcId)``."""
    root = mapping(document, "$")
    out: dict[tuple[int, int], CcmExpectation] = {}
    for index, group in enumerate(list_field(root, "testGroups", "$")):
        path = f"$.testGroups[{index}]"
        entry = mapping(group, path)
        tg_id = integer(entry, "tgId", path)
        for position, case in enumerate(list_field(entry, "tests", path)):
            case_path = f"{path}.tests[{position}]"
            values = mapping(case, case_path)
            payload = optional_hex_bytes(values, "ct", case_path)
            if payload is None:
                payload = optional_hex_bytes(values, "pt", case_path)
            verdict = optional_boolean(values, "testPassed", case_path)
            if payload is None and verdict is None:
                raise AcvpValidationError(case_path, "expected a ct, pt or testPassed value")
            out[(tg_id, integer(values, "tcId", case_path))] = CcmExpectation(payload, verdict)
    return out


def load_vector_set(path: str | Path) -> CcmVectorSet:
    """Read and normalize a prompt file."""
    return parse_vector_set(json.loads(Path(path).read_text(encoding="utf-8")))


def load_expected_results(path: str | Path) -> dict[tuple[int, int], CcmExpectation]:
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


def provider_for(provider_command: str | None, timeout_seconds: float) -> AesCcmProvider:
    """The built-in provider, or a harness when one is named."""
    if provider_command is None:
        return CryptographyAesCcm()
    return SubprocessAesCcm.from_command_string(provider_command, timeout_seconds=timeout_seconds)


def _decrypt_case(
    group: CcmGroup, case: CcmCase, want: CcmExpectation, provider: AesCcmProvider
) -> TestCaseResult:
    """Recover the plaintext, or report the verdict a forged tag deserves."""
    try:
        produced = provider.decrypt(
            key=case.key,
            nonce=case.nonce,
            ciphertext=case.payload,
            aad=case.aad,
            tag_bits=group.tag_bits,
        )
    except InvalidTag:
        # ACVP corrupts the tag on purpose. Rejecting is the correct answer,
        # so this is a PASS when a rejection was expected and a failure only
        # when ACVP says the case should have decrypted.
        rejected_correctly = want.test_passed is False
        return TestCaseResult(
            tg_id=group.tg_id,
            tc_id=case.tc_id,
            status=ResultStatus.PASS if rejected_correctly else ResultStatus.FAIL,
            expected=VerdictValues(passed=bool(want.test_passed)),
            actual=VerdictValues(passed=False),
            diagnostic=None if rejected_correctly else "rejected a tag ACVP declares valid",
        )
    if want.test_passed is False:
        return TestCaseResult(
            tg_id=group.tg_id,
            tc_id=case.tc_id,
            status=ResultStatus.FAIL,
            expected=VerdictValues(passed=False),
            actual=VerdictValues(passed=True),
            diagnostic="accepted a tag ACVP declares invalid",
        )
    if want.payload is None:
        return _unsupported(group.tg_id, case.tc_id, "no expected plaintext recorded")
    matched = produced == want.payload
    return TestCaseResult(
        tg_id=group.tg_id,
        tc_id=case.tc_id,
        status=ResultStatus.PASS if matched else ResultStatus.FAIL,
        expected=AesGcmValues(plaintext=want.payload),
        actual=AesGcmValues(plaintext=produced),
        diagnostic=None if matched else "pt mismatch",
    )


def run_vector_set(
    vector_set: CcmVectorSet,
    expected: dict[tuple[int, int], CcmExpectation],
    provider: AesCcmProvider,
) -> list[TestCaseResult]:
    """Execute every case in the appropriate shape for its direction."""
    results: list[TestCaseResult] = []
    for group in vector_set.groups:
        encrypt = group.direction == "encrypt"
        for case in group.tests:
            key = (group.tg_id, case.tc_id)
            if group.tag_bits not in TAG_LENGTHS:
                results.append(_unsupported(*key, f"tagLen {group.tag_bits} is not a CCM tag"))
                continue
            want = expected.get(key)
            if want is None:
                results.append(_unsupported(*key, "no expected result recorded"))
                continue
            try:
                if not encrypt:
                    results.append(_decrypt_case(group, case, want, provider))
                    continue
                produced = provider.encrypt(
                    key=case.key,
                    nonce=case.nonce,
                    plaintext=case.payload,
                    aad=case.aad,
                    tag_bits=group.tag_bits,
                )
            except HarnessUnsupportedError:
                results.append(_unsupported(*key, "the harness declined this case"))
                continue
            if want.payload is None:
                results.append(_unsupported(*key, "no expected ciphertext recorded"))
                continue
            matched = produced == want.payload
            results.append(
                TestCaseResult(
                    tg_id=group.tg_id,
                    tc_id=case.tc_id,
                    status=ResultStatus.PASS if matched else ResultStatus.FAIL,
                    expected=AesGcmValues(ciphertext=want.payload),
                    actual=AesGcmValues(ciphertext=produced),
                    diagnostic=None if matched else "ct mismatch",
                )
            )
    return results


def metadata_for(provider: AesCcmProvider) -> ProviderMetadata:
    """Provider identity, for the report header."""
    return provider.metadata()


__all__ = [
    "ALGORITHM",
    "REVISION",
    "TAG_LENGTHS",
    "CcmExpectation",
    "CcmVectorSet",
    "load_expected_results",
    "load_vector_set",
    "metadata_for",
    "parse_expected_results",
    "parse_vector_set",
    "provider_for",
    "run_vector_set",
]
