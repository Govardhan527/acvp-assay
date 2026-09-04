"""ACVP-AES-XTS, revision 2.0: the mode storage encryption is validated under.

Every case is a compare-output transform, so this is the simplest shape in the
project. What makes XTS worth its own module is the input handling rather than
the comparison: the key is two AES keys, the tweak arrives either as bytes or
as a little-endian sequence number, and a payload longer than ``dataUnitLen``
is several data units each with its own tweak. ``providers/aes_xts.py`` carries
the reasoning; this module parses and compares.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from acvp_assay.models import (
    AesGcmValues,
    ProviderMetadata,
    ResultStatus,
    SafeDiagnostic,
    TestCaseResult,
)
from acvp_assay.parser import (
    AcvpValidationError,
    hex_bytes,
    integer,
    list_field,
    mapping,
    optional_hex_bytes,
    optional_integer,
    string_field,
)
from acvp_assay.providers.aes_xts import (
    ALGORITHM,
    HEX_TWEAK,
    KEY_LENGTHS,
    NUMBER_TWEAK,
    AesXtsProvider,
    CryptographyAesXts,
    SubprocessAesXts,
    tweak_for,
)
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

REVISION = "2.0"


@dataclass(frozen=True, slots=True)
class XtsCase:
    """One XTS transform."""

    tc_id: int
    key: bytes
    data: bytes
    data_unit_bits: int
    tweak_value: bytes | None
    sequence_number: int | None


@dataclass(frozen=True, slots=True)
class XtsGroup:
    """Cases sharing a direction, key length and tweak convention."""

    tg_id: int
    direction: str
    key_bits: int
    tweak_mode: str
    tests: tuple[XtsCase, ...]


@dataclass(frozen=True, slots=True)
class XtsVectorSet:
    """One normalized AES-XTS vector set."""

    vs_id: int
    algorithm: str
    revision: str
    groups: tuple[XtsGroup, ...]


def _parse_case(value: object, *, path: str, encrypt: bool) -> XtsCase:
    document = mapping(value, path)
    return XtsCase(
        tc_id=integer(document, "tcId", path),
        key=hex_bytes(document, "key", path),
        data=hex_bytes(document, "pt" if encrypt else "ct", path),
        data_unit_bits=integer(document, "dataUnitLen", path),
        tweak_value=optional_hex_bytes(document, "tweakValue", path),
        sequence_number=optional_integer(document, "sequenceNumber", path),
    )


def _parse_group(value: object, *, path: str) -> XtsGroup:
    document = mapping(value, path)
    direction = string_field(document, "direction", path)
    return XtsGroup(
        tg_id=integer(document, "tgId", path),
        direction=direction,
        key_bits=integer(document, "keyLen", path),
        tweak_mode=string_field(document, "tweakMode", path),
        tests=tuple(
            _parse_case(case, path=f"{path}.tests[{index}]", encrypt=direction == "encrypt")
            for index, case in enumerate(list_field(document, "tests", path))
        ),
    )


def parse_vector_set(document: object) -> XtsVectorSet:
    """Normalize an AES-XTS prompt."""
    root = mapping(document, "$")
    return XtsVectorSet(
        vs_id=integer(root, "vsId", "$"),
        algorithm=string_field(root, "algorithm", "$"),
        revision=string_field(root, "revision", "$"),
        groups=tuple(
            _parse_group(group, path=f"$.testGroups[{index}]")
            for index, group in enumerate(list_field(root, "testGroups", "$"))
        ),
    )


def parse_expected_results(document: object) -> dict[tuple[int, int], bytes]:
    """Index the expected output bytes by ``(tgId, tcId)``."""
    root = mapping(document, "$")
    out: dict[tuple[int, int], bytes] = {}
    for index, group in enumerate(list_field(root, "testGroups", "$")):
        path = f"$.testGroups[{index}]"
        entry = mapping(group, path)
        tg_id = integer(entry, "tgId", path)
        for position, case in enumerate(list_field(entry, "tests", path)):
            case_path = f"{path}.tests[{position}]"
            values = mapping(case, case_path)
            produced = optional_hex_bytes(values, "ct", case_path)
            if produced is None:
                produced = optional_hex_bytes(values, "pt", case_path)
            if produced is None:
                raise AcvpValidationError(case_path, "expected a ct or pt value")
            out[(tg_id, integer(values, "tcId", case_path))] = produced
    return out


def load_vector_set(path: str | Path) -> XtsVectorSet:
    """Read and normalize a prompt file."""
    return parse_vector_set(json.loads(Path(path).read_text(encoding="utf-8")))


def load_expected_results(path: str | Path) -> dict[tuple[int, int], bytes]:
    """Read and index an expected-results file."""
    return parse_expected_results(json.loads(Path(path).read_text(encoding="utf-8")))


def tweak_of(group: XtsGroup, case: XtsCase) -> bytes | None:
    """The 16-byte tweak this case starts from, or None if it cannot be built."""
    if group.tweak_mode == HEX_TWEAK:
        return case.tweak_value
    if group.tweak_mode == NUMBER_TWEAK and case.sequence_number is not None:
        return tweak_for(case.sequence_number)
    return None


def _values(payload: bytes, encrypt: bool) -> AesGcmValues:
    """Report the transform's output under ACVP's ``ct``/``pt`` field name."""
    if encrypt:
        return AesGcmValues(ciphertext=payload)
    return AesGcmValues(plaintext=payload)


def _unsupported(tg_id: int, tc_id: int, reason: str) -> TestCaseResult:
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=ResultStatus.UNSUPPORTED,
        expected=None,
        actual=None,
        diagnostic=reason,
    )


def provider_for(provider_command: str | None, timeout_seconds: float) -> AesXtsProvider:
    """The built-in provider, or a harness when one is named."""
    if provider_command is None:
        return CryptographyAesXts()
    return SubprocessAesXts.from_command_string(provider_command, timeout_seconds=timeout_seconds)


def run_vector_set(
    vector_set: XtsVectorSet,
    expected: dict[tuple[int, int], bytes],
    provider: AesXtsProvider,
) -> list[TestCaseResult]:
    """Transform every case and compare with the recorded output."""
    results: list[TestCaseResult] = []
    for group in vector_set.groups:
        encrypt = group.direction == "encrypt"
        field = "ct" if encrypt else "pt"
        for case in group.tests:
            key = (group.tg_id, case.tc_id)
            if group.key_bits not in KEY_LENGTHS:
                results.append(_unsupported(*key, f"keyLen {group.key_bits} is not supported"))
                continue
            if len(case.key) != KEY_LENGTHS[group.key_bits]:
                results.append(
                    _unsupported(
                        *key,
                        f"an XTS key for keyLen {group.key_bits} is "
                        f"{KEY_LENGTHS[group.key_bits]} bytes, two AES keys concatenated",
                    )
                )
                continue
            tweak = tweak_of(group, case)
            if tweak is None:
                results.append(
                    _unsupported(*key, f"tweakMode {group.tweak_mode!r} is not supported")
                )
                continue
            want = expected.get(key)
            if want is None:
                results.append(_unsupported(*key, "no expected result recorded"))
                continue
            try:
                produced = provider.transform(
                    key=case.key,
                    tweak=tweak,
                    data=case.data,
                    data_unit_bytes=case.data_unit_bits // 8,
                    encrypt=encrypt,
                )
            except HarnessUnsupportedError:
                results.append(_unsupported(*key, "the harness declined this case"))
                continue
            except ValueError:
                # XTS forbids the two key halves being equal, and a provider is
                # entitled to refuse other malformed input. That is a bounded
                # error rather than a crash, and never carries the library's
                # own message, which can quote key material.
                results.append(
                    TestCaseResult(
                        tg_id=group.tg_id,
                        tc_id=case.tc_id,
                        status=ResultStatus.ERROR,
                        expected=None,
                        actual=None,
                        diagnostic=SafeDiagnostic.PROVIDER_ERROR,
                    )
                )
                continue
            matched = produced == want
            results.append(
                TestCaseResult(
                    tg_id=group.tg_id,
                    tc_id=case.tc_id,
                    status=ResultStatus.PASS if matched else ResultStatus.FAIL,
                    expected=_values(want, encrypt),
                    actual=_values(produced, encrypt),
                    diagnostic=None if matched else f"{field} mismatch",
                )
            )
    return results


def metadata_for(provider: AesXtsProvider) -> ProviderMetadata:
    """Provider identity, for the report header."""
    return provider.metadata()


__all__ = [
    "ALGORITHM",
    "KEY_LENGTHS",
    "REVISION",
    "XtsVectorSet",
    "load_expected_results",
    "load_vector_set",
    "metadata_for",
    "parse_expected_results",
    "parse_vector_set",
    "provider_for",
    "run_vector_set",
    "tweak_of",
]
