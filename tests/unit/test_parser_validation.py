"""Negative tests for ACVP field validation."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, cast

import pytest

from acvp_assay.parser import AcvpValidationError, parse_vector_set

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures/aes-gcm-valid-encrypt/prompt.json"


def valid_document() -> dict[str, Any]:
    """Return an independently mutable valid fixture document."""
    return cast(dict[str, Any], json.loads(FIXTURE.read_text()))


def assert_invalid(document: object, path: str, message: str) -> None:
    """Assert a validation failure's safe path and message."""
    with pytest.raises(AcvpValidationError) as captured:
        parse_vector_set(document)

    assert captured.value.path == path
    assert captured.value.message == message
    assert str(captured.value) == f"{path}: {message}"


@pytest.mark.parametrize(
    ("level", "field", "path"),
    [
        ("top", "vsId", "$.vsId"),
        ("top", "algorithm", "$.algorithm"),
        ("top", "revision", "$.revision"),
        ("top", "isSample", "$.isSample"),
        ("top", "testGroups", "$.testGroups"),
        ("group", "tgId", "$.testGroups[0].tgId"),
        ("group", "testType", "$.testGroups[0].testType"),
        ("group", "direction", "$.testGroups[0].direction"),
        ("group", "keyLen", "$.testGroups[0].keyLen"),
        ("group", "ivLen", "$.testGroups[0].ivLen"),
        ("group", "payloadLen", "$.testGroups[0].payloadLen"),
        ("group", "aadLen", "$.testGroups[0].aadLen"),
        ("group", "tagLen", "$.testGroups[0].tagLen"),
        ("group", "ivGen", "$.testGroups[0].ivGen"),
        ("group", "tests", "$.testGroups[0].tests"),
        ("case", "tcId", "$.testGroups[0].tests[0].tcId"),
        ("case", "key", "$.testGroups[0].tests[0].key"),
        ("case", "iv", "$.testGroups[0].tests[0].iv"),
        ("case", "aad", "$.testGroups[0].tests[0].aad"),
        ("case", "pt", "$.testGroups[0].tests[0].pt"),
    ],
)
def test_missing_required_fields(level: str, field: str, path: str) -> None:
    """Every contract level reports the precise missing field path."""
    document = valid_document()
    targets = {
        "top": document,
        "group": document["testGroups"][0],
        "case": document["testGroups"][0]["tests"][0],
    }
    del targets[level][field]

    assert_invalid(document, path, "missing required field")


@pytest.mark.parametrize(
    ("field", "value", "path", "message"),
    [
        ("vsId", True, "$.vsId", "expected an integer"),
        ("isSample", "true", "$.isSample", "expected a boolean"),
        ("algorithm", 7, "$.algorithm", "expected a string"),
        ("testGroups", {}, "$.testGroups", "expected an array"),
    ],
)
def test_wrong_top_level_types(
    field: str,
    value: object,
    path: str,
    message: str,
) -> None:
    """Wrong scalar and container types are rejected explicitly."""
    document = valid_document()
    document[field] = value

    assert_invalid(document, path, message)


def test_non_object_root_is_rejected() -> None:
    """A JSON array cannot masquerade as a vector set."""
    assert_invalid([], "$", "expected an object")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("key", "ABC", "expected an even number of hexadecimal digits"),
        ("iv", "00GG", "expected hexadecimal digits without separators"),
        ("aad", "00  11", "expected hexadecimal digits without separators"),
    ],
)
def test_invalid_hex_is_rejected(field: str, value: str, message: str) -> None:
    """Hex fields must be unseparated, even-length hexadecimal strings."""
    document = valid_document()
    case = document["testGroups"][0]["tests"][0]
    case[field] = value

    assert_invalid(document, f"$.testGroups[0].tests[0].{field}", message)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("direction", "wrap", "unsupported direction 'wrap'"),
        ("testType", "MCT", "unsupported test type 'MCT'"),
    ],
)
def test_unsupported_group_modes_are_rejected(
    field: str,
    value: str,
    message: str,
) -> None:
    """The MVP rejects modes outside its frozen contract."""
    document = valid_document()
    document["testGroups"][0][field] = value

    assert_invalid(document, f"$.testGroups[0].{field}", message)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("algorithm", "ACVP-AES-CBC", "unsupported algorithm 'ACVP-AES-CBC'"),
        ("revision", "2.0", "unsupported revision '2.0'"),
    ],
)
def test_unsupported_vector_contract_is_rejected(
    field: str,
    value: str,
    message: str,
) -> None:
    """The parser does not silently reinterpret algorithms or revisions."""
    document = copy.deepcopy(valid_document())
    document[field] = value

    assert_invalid(document, f"$.{field}", message)


def test_non_object_group_and_case_are_rejected() -> None:
    """Nested arrays must contain objects rather than scalar values."""
    group_document = valid_document()
    group_document["testGroups"][0] = "group"
    assert_invalid(group_document, "$.testGroups[0]", "expected an object")

    case_document = valid_document()
    case_document["testGroups"][0]["tests"][0] = "case"
    assert_invalid(case_document, "$.testGroups[0].tests[0]", "expected an object")


def test_decrypt_requires_ciphertext_and_tag() -> None:
    """Direction controls the required case input fields."""
    document = valid_document()
    group = document["testGroups"][0]
    group["direction"] = "decrypt"

    assert_invalid(
        document,
        "$.testGroups[0].tests[0].ct",
        "missing required field",
    )

    case = group["tests"][0]
    case["ct"] = case.pop("pt")
    assert_invalid(
        document,
        "$.testGroups[0].tests[0].tag",
        "missing required field",
    )


def test_iv_generation_mode_is_optional() -> None:
    """The live ACVTS server omits ivGenMode whenever ivGen is "external".

    It qualifies *internal* IV construction, so it is absent from every real
    external vector set. The pinned upstream sample file happens to carry it,
    so requiring it looked correct until a live session rejected all 360 cases.
    """
    document = valid_document()
    del document["testGroups"][0]["ivGenMode"]

    vector_set = parse_vector_set(document)

    assert vector_set.test_groups[0].iv_generation == "external"
    assert vector_set.test_groups[0].iv_generation_mode == ""
