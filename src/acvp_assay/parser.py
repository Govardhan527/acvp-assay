"""Validation and normalization for ACVP AES-GCM vector sets."""

from __future__ import annotations

import json
import string
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from acvp_assay.models import (
    AesGcmTestCase,
    AesGcmTestGroup,
    AesGcmValues,
    AesGcmVectorSet,
    Direction,
    ExpectedResultCase,
    ExpectedResultGroup,
    ExpectedResultSet,
    TestType,
)


class AcvpValidationError(ValueError):
    """A safe validation failure tied to one JSON-style path."""

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        self.message = message
        super().__init__(f"{path}: {message}")


def _mapping(value: object, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise AcvpValidationError(path, "expected an object")
    return cast(Mapping[str, object], value)


def _required(document: Mapping[str, object], key: str, path: str) -> object:
    if key not in document:
        raise AcvpValidationError(f"{path}.{key}", "missing required field")
    return document[key]


def _integer(document: Mapping[str, object], key: str, path: str) -> int:
    value = _required(document, key, path)
    if type(value) is not int:
        raise AcvpValidationError(f"{path}.{key}", "expected an integer")
    return value


def _boolean(document: Mapping[str, object], key: str, path: str) -> bool:
    value = _required(document, key, path)
    if type(value) is not bool:
        raise AcvpValidationError(f"{path}.{key}", "expected a boolean")
    return value


def _string(document: Mapping[str, object], key: str, path: str) -> str:
    value = _required(document, key, path)
    if not isinstance(value, str):
        raise AcvpValidationError(f"{path}.{key}", "expected a string")
    return value


def _list(document: Mapping[str, object], key: str, path: str) -> list[object]:
    value = _required(document, key, path)
    if not isinstance(value, list):
        raise AcvpValidationError(f"{path}.{key}", "expected an array")
    return cast(list[object], value)


def _hex_bytes(document: Mapping[str, object], key: str, path: str) -> bytes:
    value = _string(document, key, path)
    return _hex_value(value, f"{path}.{key}")


def _hex_value(value: str, field_path: str) -> bytes:
    if len(value) % 2 != 0:
        raise AcvpValidationError(field_path, "expected an even number of hexadecimal digits")
    if any(character not in string.hexdigits for character in value):
        raise AcvpValidationError(field_path, "expected hexadecimal digits without separators")
    return bytes.fromhex(value)


def _optional_boolean(document: Mapping[str, object], key: str, path: str) -> bool | None:
    if key not in document:
        return None
    value = document[key]
    if type(value) is not bool:
        raise AcvpValidationError(f"{path}.{key}", "expected a boolean")
    return value


def _optional_integer(document: Mapping[str, object], key: str, path: str) -> int | None:
    if key not in document:
        return None
    value = document[key]
    if type(value) is not int:
        raise AcvpValidationError(f"{path}.{key}", "expected an integer")
    return value


def _optional_hex_bytes(document: Mapping[str, object], key: str, path: str) -> bytes | None:
    if key not in document:
        return None
    value = document[key]
    field_path = f"{path}.{key}"
    if not isinstance(value, str):
        raise AcvpValidationError(field_path, "expected a string")
    return _hex_value(value, field_path)


def _direction(document: Mapping[str, object], path: str) -> Direction:
    value = _string(document, "direction", path)
    try:
        return Direction(value)
    except ValueError:
        raise AcvpValidationError(
            f"{path}.direction",
            f"unsupported direction {value!r}",
        ) from None


def _test_type(document: Mapping[str, object], path: str) -> TestType:
    value = _string(document, "testType", path)
    try:
        return TestType(value)
    except ValueError:
        raise AcvpValidationError(
            f"{path}.testType",
            f"unsupported test type {value!r}",
        ) from None


def _parse_case(
    value: object,
    *,
    path: str,
    direction: Direction,
) -> AesGcmTestCase:
    document = _mapping(value, path)
    tc_id = _integer(document, "tcId", path)
    key = _hex_bytes(document, "key", path)
    iv = _hex_bytes(document, "iv", path)
    aad = _hex_bytes(document, "aad", path)
    if direction is Direction.ENCRYPT:
        return AesGcmTestCase(
            tc_id=tc_id,
            key=key,
            iv=iv,
            aad=aad,
            plaintext=_hex_bytes(document, "pt", path),
        )
    return AesGcmTestCase(
        tc_id=tc_id,
        key=key,
        iv=iv,
        aad=aad,
        ciphertext=_hex_bytes(document, "ct", path),
        tag=_hex_bytes(document, "tag", path),
    )


def _parse_group(value: object, *, path: str) -> AesGcmTestGroup:
    document = _mapping(value, path)
    direction = _direction(document, path)
    test_values = _list(document, "tests", path)
    tests = tuple(
        _parse_case(
            test_value,
            path=f"{path}.tests[{index}]",
            direction=direction,
        )
        for index, test_value in enumerate(test_values)
    )
    return AesGcmTestGroup(
        tg_id=_integer(document, "tgId", path),
        test_type=_test_type(document, path),
        direction=direction,
        key_length_bits=_integer(document, "keyLen", path),
        iv_length_bits=_integer(document, "ivLen", path),
        payload_length_bits=_integer(document, "payloadLen", path),
        aad_length_bits=_integer(document, "aadLen", path),
        tag_length_bits=_integer(document, "tagLen", path),
        iv_generation=_string(document, "ivGen", path),
        # Optional: ivGenMode qualifies *internal* IV construction, so the live
        # ACVTS server omits it whenever ivGen is "external" -- while the pinned
        # upstream sample file happens to carry it. Requiring it rejected every
        # real external vector set, which no static fixture would have revealed.
        iv_generation_mode=optional_string(document, "ivGenMode", path) or "",
        tests=tests,
    )


def parse_vector_set(value: object) -> AesGcmVectorSet:
    """Validate and normalize one ACVP AES-GCM vector-set object."""
    path = "$"
    document = _mapping(value, path)
    algorithm = _string(document, "algorithm", path)
    if algorithm != "ACVP-AES-GCM":
        raise AcvpValidationError("$.algorithm", f"unsupported algorithm {algorithm!r}")
    revision = _string(document, "revision", path)
    if revision != "1.0":
        raise AcvpValidationError("$.revision", f"unsupported revision {revision!r}")
    group_values = _list(document, "testGroups", path)
    groups = tuple(
        _parse_group(group_value, path=f"$.testGroups[{index}]")
        for index, group_value in enumerate(group_values)
    )
    return AesGcmVectorSet(
        vs_id=_integer(document, "vsId", path),
        algorithm=algorithm,
        revision=revision,
        is_sample=_boolean(document, "isSample", path),
        test_groups=groups,
    )


def _load_json(path: str | Path) -> object:
    source = Path(path)
    try:
        return json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise AcvpValidationError(
            "$",
            f"invalid JSON at line {error.lineno}, column {error.colno}",
        ) from None


def load_vector_set(path: str | Path) -> AesGcmVectorSet:
    """Load one UTF-8 JSON file and normalize it into the internal model."""
    return parse_vector_set(_load_json(path))


def _parse_expected_case(value: object, *, path: str) -> ExpectedResultCase:
    document = _mapping(value, path)
    return ExpectedResultCase(
        tc_id=_integer(document, "tcId", path),
        values=AesGcmValues(
            plaintext=_optional_hex_bytes(document, "pt", path),
            ciphertext=_optional_hex_bytes(document, "ct", path),
            tag=_optional_hex_bytes(document, "tag", path),
        ),
        test_passed=_optional_boolean(document, "testPassed", path),
    )


def _parse_expected_group(value: object, *, path: str) -> ExpectedResultGroup:
    document = _mapping(value, path)
    test_values = _list(document, "tests", path)
    cases = tuple(
        _parse_expected_case(test_value, path=f"{path}.tests[{index}]")
        for index, test_value in enumerate(test_values)
    )
    return ExpectedResultGroup(tg_id=_integer(document, "tgId", path), cases=cases)


def parse_expected_results(value: object) -> ExpectedResultSet:
    """Validate and normalize one ACVP AES-GCM expected-results object."""
    path = "$"
    document = _mapping(value, path)
    algorithm = _string(document, "algorithm", path)
    if algorithm != "ACVP-AES-GCM":
        raise AcvpValidationError("$.algorithm", f"unsupported algorithm {algorithm!r}")
    revision = _string(document, "revision", path)
    if revision != "1.0":
        raise AcvpValidationError("$.revision", f"unsupported revision {revision!r}")
    group_values = _list(document, "testGroups", path)
    groups = tuple(
        _parse_expected_group(group_value, path=f"$.testGroups[{index}]")
        for index, group_value in enumerate(group_values)
    )
    return ExpectedResultSet(
        vs_id=_integer(document, "vsId", path),
        algorithm=algorithm,
        revision=revision,
        groups=groups,
    )


def load_expected_results(path: str | Path) -> ExpectedResultSet:
    """Load one UTF-8 JSON expected-results file into the internal model."""
    return parse_expected_results(_load_json(path))


def optional_string(document: Mapping[str, object], key: str, path: str) -> str | None:
    """Read an optional string field, rejecting a present non-string value."""
    if key not in document:
        return None
    return _string(document, key, path)


#: Shared validation primitives for per-algorithm parsers. These keep every
#: algorithm reporting the same ``$.testGroups[0].tests[0].field`` paths and the
#: same bounded, non-secret messages.
mapping = _mapping
integer = _integer
boolean = _boolean
string_field = _string
list_field = _list
hex_bytes = _hex_bytes
optional_hex_bytes = _optional_hex_bytes
optional_integer = _optional_integer
optional_boolean = _optional_boolean

__all__ = [
    "AcvpValidationError",
    "boolean",
    "hex_bytes",
    "integer",
    "list_field",
    "load_expected_results",
    "load_vector_set",
    "mapping",
    "optional_hex_bytes",
    "optional_boolean",
    "optional_integer",
    "optional_string",
    "parse_expected_results",
    "parse_vector_set",
    "string_field",
]
