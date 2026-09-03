"""RSA: sigGen, sigVer, signaturePrimitive and decryptionPrimitive.

Four modes of one algorithm, and they use three different result shapes.

``sigGen`` is produce-and-verify. The implementation under test supplies its
own key, so NIST's recorded signature belongs to NIST's key and is not
comparable to ours; what is checkable offline is that our signature verifies
under the key we generated, which is the same arrangement ECDSA sigGen has.

``sigVer`` is verdict-only: the vector supplies a signature that may be
deliberately invalid, and the answer is the verdict reached.

The two primitives are compare-output *and* verdict at once. Each case is
either in range -- in which case the raw exponentiation is compared -- or out
of range, in which case the answer is ``testPassed: false`` and no value at
all. The two modes use different bounds; see `acvp_assay.providers.rsa`.

RSA ``keyGen`` is deliberately absent. Several of its modes require reporting
intermediate values such as the prime seeds, which this binding does not
expose, and a partial answer to keyGen is scored as wrong rather than
incomplete.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from acvp_assay.models import DigestValues, ResultStatus, TestCaseResult, VerdictValues
from acvp_assay.parser import (
    AcvpValidationError,
    integer,
    list_field,
    mapping,
    optional_hex_bytes,
    optional_integer,
    string_field,
)
from acvp_assay.providers.rsa import RsaProvider
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

ALGORITHM = "RSA"
SIG_GEN = "sigGen"
SIG_VER = "sigVer"
SIGNATURE_PRIMITIVE = "signaturePrimitive"
DECRYPTION_PRIMITIVE = "decryptionPrimitive"
SUPPORTED_MODES = (SIG_GEN, SIG_VER, SIGNATURE_PRIMITIVE, DECRYPTION_PRIMITIVE)
PRIMITIVES = (SIGNATURE_PRIMITIVE, DECRYPTION_PRIMITIVE)


@dataclass(frozen=True, slots=True)
class RsaCase:
    """One case; which fields are present depends on the mode."""

    tc_id: int
    message: bytes = b""
    signature: bytes = b""
    ciphertext: bytes = b""
    n: bytes = b""
    e: bytes = b""
    d: bytes = b""
    p: bytes = b""
    q: bytes = b""
    dmp1: bytes = b""
    dmq1: bytes = b""
    iqmp: bytes = b""


@dataclass(frozen=True, slots=True)
class RsaGroup:
    """Cases sharing a signature scheme, or a modulus for the primitives."""

    tg_id: int
    modulo: int
    signature_type: str
    hash_algorithm: str
    salt_length: int
    mask_function: str
    n: bytes
    e: bytes
    tests: tuple[RsaCase, ...]


@dataclass(frozen=True, slots=True)
class RsaVectorSet:
    """A parsed RSA prompt file."""

    vs_id: int
    algorithm: str
    mode: str
    revision: str
    test_groups: tuple[RsaGroup, ...]


@dataclass(frozen=True, slots=True)
class RsaExpectedCase:
    """Expected answer for one case: a value, a verdict, or both."""

    tc_id: int
    signature: bytes = b""
    plaintext: bytes = b""
    test_passed: bool | None = None


@dataclass(frozen=True, slots=True)
class RsaExpectedSet:
    """Expected results, indexed by case."""

    vs_id: int
    cases: dict[int, RsaExpectedCase]


def _parse_case(value: object, *, path: str) -> RsaCase:
    document = mapping(value, path=path)
    return RsaCase(
        tc_id=integer(document, "tcId", path=path),
        message=optional_hex_bytes(document, "message", path=path) or b"",
        signature=optional_hex_bytes(document, "signature", path=path) or b"",
        ciphertext=optional_hex_bytes(document, "ct", path=path) or b"",
        n=optional_hex_bytes(document, "n", path=path) or b"",
        e=optional_hex_bytes(document, "e", path=path) or b"",
        d=optional_hex_bytes(document, "d", path=path) or b"",
        p=optional_hex_bytes(document, "p", path=path) or b"",
        q=optional_hex_bytes(document, "q", path=path) or b"",
        dmp1=optional_hex_bytes(document, "dmp1", path=path) or b"",
        dmq1=optional_hex_bytes(document, "dmq1", path=path) or b"",
        iqmp=optional_hex_bytes(document, "iqmp", path=path) or b"",
    )


def _parse_group(value: object, *, path: str) -> RsaGroup:
    document = mapping(value, path=path)
    cases = list_field(document, "tests", path=path)
    modulo = integer(document, "modulo", path=path)
    if modulo <= 0 or modulo % 8 != 0:
        raise AcvpValidationError(f"{path}.modulo", "expected a positive multiple of 8")
    return RsaGroup(
        tg_id=integer(document, "tgId", path=path),
        modulo=modulo,
        signature_type=string_field(document, "sigType", path=path)
        if "sigType" in document
        else "",
        hash_algorithm=string_field(document, "hashAlg", path=path)
        if "hashAlg" in document
        else "",
        salt_length=optional_integer(document, "saltLen", path=path) or 0,
        mask_function=string_field(document, "maskFunction", path=path)
        if "maskFunction" in document
        else "",
        n=optional_hex_bytes(document, "n", path=path) or b"",
        e=optional_hex_bytes(document, "e", path=path) or b"",
        tests=tuple(
            _parse_case(item, path=f"{path}.tests[{index}]") for index, item in enumerate(cases)
        ),
    )


def parse_vector_set(value: object) -> RsaVectorSet:
    """Parse an RSA prompt document, rejecting anything malformed."""
    document = mapping(value, path="$")
    algorithm = string_field(document, "algorithm", path="$")
    if algorithm != ALGORITHM:
        raise AcvpValidationError("$.algorithm", f"expected {ALGORITHM!r}")
    mode = string_field(document, "mode", path="$")
    if mode not in SUPPORTED_MODES:
        raise AcvpValidationError("$.mode", f"expected one of {list(SUPPORTED_MODES)}")
    groups = list_field(document, "testGroups", path="$")
    return RsaVectorSet(
        vs_id=integer(document, "vsId", path="$"),
        algorithm=algorithm,
        mode=mode,
        revision=string_field(document, "revision", path="$"),
        test_groups=tuple(
            _parse_group(item, path=f"$.testGroups[{index}]") for index, item in enumerate(groups)
        ),
    )


def parse_expected_results(value: object) -> RsaExpectedSet:
    """Parse expected results, which may carry a value, a verdict, or both."""
    document = mapping(value, path="$")
    cases: dict[int, RsaExpectedCase] = {}
    for group_index, group_value in enumerate(list_field(document, "testGroups", path="$")):
        group_path = f"$.testGroups[{group_index}]"
        group = mapping(group_value, path=group_path)
        for case_index, case_value in enumerate(list_field(group, "tests", path=group_path)):
            case_path = f"{group_path}.tests[{case_index}]"
            case = mapping(case_value, path=case_path)
            verdict = case.get("testPassed")
            if verdict is not None and not isinstance(verdict, bool):
                raise AcvpValidationError(f"{case_path}.testPassed", "expected a boolean")
            cases[integer(case, "tcId", path=case_path)] = RsaExpectedCase(
                tc_id=integer(case, "tcId", path=case_path),
                signature=optional_hex_bytes(case, "signature", path=case_path) or b"",
                plaintext=optional_hex_bytes(case, "pt", path=case_path) or b"",
                test_passed=verdict,
            )
    return RsaExpectedSet(vs_id=integer(document, "vsId", path="$"), cases=cases)


def load_vector_set(path: str | Path) -> RsaVectorSet:
    """Read and parse an RSA prompt file."""
    return parse_vector_set(json.loads(Path(path).read_text(encoding="utf-8")))


def load_expected_results(path: str | Path) -> RsaExpectedSet:
    """Read and parse an RSA expected-results file."""
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


def _declined(tg_id: int, tc_id: int) -> TestCaseResult:
    """A harness said it does not implement this case."""
    return _unsupported(tg_id, tc_id, "the harness declined this case")


def _verdict(tg_id: int, tc_id: int, expected: bool, actual: bool, subject: str) -> TestCaseResult:
    passed = expected == actual
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=ResultStatus.PASS if passed else ResultStatus.FAIL,
        expected=VerdictValues(passed=expected),
        actual=VerdictValues(passed=actual),
        diagnostic=None
        if passed
        else f"{'accepted' if actual else 'rejected'} {subject} ACVP declares otherwise",
    )


def _run_primitive(
    mode: str, group: RsaGroup, case: RsaCase, expected: RsaExpectedCase, provider: RsaProvider
) -> TestCaseResult:
    """Answer one raw-primitive case: a value when in range, a verdict when not."""
    if not case.n:
        return _unsupported(group.tg_id, case.tc_id, "case carries no modulus")

    def number(field: bytes) -> int:
        return int.from_bytes(field, "big")

    n = number(case.n)
    if mode == SIGNATURE_PRIMITIVE:
        if case.d:
            produced = provider.signature_primitive(
                n=n, d=number(case.d), message=number(case.message)
            )
        elif case.p and case.q and case.dmp1 and case.dmq1 and case.iqmp:
            # keyMode "crt": the private exponent is never given, only the
            # CRT parameters derived from it.
            produced = provider.signature_primitive_crt(
                n=n,
                p=number(case.p),
                q=number(case.q),
                dmp1=number(case.dmp1),
                dmq1=number(case.dmq1),
                iqmp=number(case.iqmp),
                message=number(case.message),
            )
        else:
            return _unsupported(group.tg_id, case.tc_id, "case carries no usable private key")
        wanted = expected.signature
    else:
        if not case.d:
            return _unsupported(group.tg_id, case.tc_id, "case carries no private exponent")
        produced = provider.decryption_primitive(
            n=n, d=number(case.d), ciphertext=number(case.ciphertext)
        )
        wanted = expected.plaintext

    if expected.test_passed is None:
        return _unsupported(group.tg_id, case.tc_id, "no expected verdict recorded")
    if produced is None or not expected.test_passed:
        return _verdict(
            group.tg_id, case.tc_id, expected.test_passed, produced is not None, "an input"
        )
    if not wanted:
        return _unsupported(group.tg_id, case.tc_id, "no expected value recorded")

    actual = produced.to_bytes(group.modulo // 8, "big")
    passed = actual == wanted
    return TestCaseResult(
        tg_id=group.tg_id,
        tc_id=case.tc_id,
        status=ResultStatus.PASS if passed else ResultStatus.FAIL,
        expected=DigestValues(digest=wanted),
        actual=DigestValues(digest=actual),
        diagnostic=None if passed else "primitive output differs",
    )


def run_vector_set(
    vector_set: RsaVectorSet,
    expected: RsaExpectedSet,
    provider: RsaProvider,
) -> list[TestCaseResult]:
    """Execute every case, declaring the ones this provider cannot answer."""
    results: list[TestCaseResult] = []
    for group in vector_set.test_groups:
        signing = vector_set.mode in (SIG_GEN, SIG_VER)
        usable = not signing or provider.supports(
            signature_type=group.signature_type,
            hash_algorithm=group.hash_algorithm,
            mask_function=group.mask_function,
        )
        signed = None
        declined = ""
        if usable and vector_set.mode == SIG_GEN:
            # One key for the whole group: ACVP reports n and e at group level,
            # so the whole group is signed in one exchange. A harness declines
            # at that granularity too, which is why this is caught here rather
            # than per case.
            try:
                signed = provider.sign_group(
                    signature_type=group.signature_type,
                    hash_algorithm=group.hash_algorithm,
                    mask_function=group.mask_function,
                    modulo=group.modulo,
                    salt_length=group.salt_length,
                    messages=[case.message for case in group.tests],
                )
            except HarnessUnsupportedError:
                usable = False
                declined = "the harness declined this group"
        for index, case in enumerate(group.tests):
            if not usable:
                results.append(
                    _unsupported(
                        group.tg_id,
                        case.tc_id,
                        declined
                        or f"{group.signature_type} with {group.hash_algorithm}"
                        + (f" and {group.mask_function}" if group.mask_function else "")
                        + " is not supported",
                    )
                )
                continue
            wanted = expected.cases.get(case.tc_id)
            if wanted is None:
                results.append(_unsupported(group.tg_id, case.tc_id, "no expected result recorded"))
                continue
            if vector_set.mode in PRIMITIVES:
                try:
                    results.append(_run_primitive(vector_set.mode, group, case, wanted, provider))
                except HarnessUnsupportedError:
                    results.append(_declined(group.tg_id, case.tc_id))
                continue
            if vector_set.mode == SIG_VER:
                if wanted.test_passed is None:
                    results.append(
                        _unsupported(group.tg_id, case.tc_id, "no expected verdict recorded")
                    )
                    continue
                try:
                    verdict = provider.verify(
                        signature_type=group.signature_type,
                        hash_algorithm=group.hash_algorithm,
                        mask_function=group.mask_function,
                        salt_length=group.salt_length,
                        n=int.from_bytes(group.n, "big"),
                        e=int.from_bytes(group.e, "big"),
                        message=case.message,
                        signature=case.signature,
                    )
                except HarnessUnsupportedError:
                    # A harness declining a hash or a mask is stating a
                    # capability, not giving a wrong answer.
                    results.append(_declined(group.tg_id, case.tc_id))
                    continue
                results.append(
                    _verdict(group.tg_id, case.tc_id, wanted.test_passed, verdict, "a signature")
                )
                continue

            # sigGen: NIST's signature belongs to NIST's key, so the check is
            # that ours verifies under the key we just generated.
            assert signed is not None  # noqa: S101 - set whenever the mode is sigGen
            produced = signed.signatures[index]
            try:
                verified = provider.verify(
                    signature_type=group.signature_type,
                    hash_algorithm=group.hash_algorithm,
                    mask_function=group.mask_function,
                    salt_length=group.salt_length,
                    n=int.from_bytes(signed.n, "big"),
                    e=int.from_bytes(signed.e, "big"),
                    message=case.message,
                    signature=produced,
                )
            except HarnessUnsupportedError:
                results.append(_declined(group.tg_id, case.tc_id))
                continue
            results.append(
                TestCaseResult(
                    tg_id=group.tg_id,
                    tc_id=case.tc_id,
                    status=ResultStatus.PASS if verified else ResultStatus.FAIL,
                    expected=VerdictValues(passed=True),
                    actual=VerdictValues(passed=verified),
                    diagnostic=None if verified else "generated signature did not verify",
                )
            )
    return results


__all__ = [
    "ALGORITHM",
    "DECRYPTION_PRIMITIVE",
    "PRIMITIVES",
    "SIGNATURE_PRIMITIVE",
    "SIG_GEN",
    "SIG_VER",
    "SUPPORTED_MODES",
    "RsaCase",
    "RsaExpectedCase",
    "RsaExpectedSet",
    "RsaGroup",
    "RsaVectorSet",
    "load_expected_results",
    "load_vector_set",
    "parse_expected_results",
    "parse_vector_set",
    "run_vector_set",
]
