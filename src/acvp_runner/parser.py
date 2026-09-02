"""Validation and normalization for ACVP AES-GCM vector sets."""

from __future__ import annotations

import string
from collections.abc import Mapping
from typing import cast

from acvp_runner.models import (
    AesGcmTestCase,
    AesGcmTestGroup,
    AesGcmVectorSet,
    Direction,
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
    field_path = f"{path}.{key}"
    if len(value) % 2 != 0:
        raise AcvpValidationError(field_path, "expected an even number of hexadecimal digits")
    if any(character not in string.hexdigits for character in value):
        raise AcvpValidationError(field_path, "expected hexadecimal digits without separators")
    return bytes.fromhex(value)


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
        iv_generation_mode=_string(document, "ivGenMode", path),
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


__all__ = ["AcvpValidationError", "parse_vector_set"]
