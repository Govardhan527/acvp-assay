"""Tests for expected-results validation and normalization."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from acvp_runner.parser import AcvpValidationError, load_expected_results, parse_expected_results

FIXTURE = (
    Path(__file__).resolve().parents[2] / "fixtures/aes-gcm-valid-encrypt/expectedResults.json"
)


def valid_document() -> dict[str, Any]:
    """Return an independently mutable valid expected-results document."""
    return cast(dict[str, Any], json.loads(FIXTURE.read_text()))


def test_valid_document_preserves_ids_and_values() -> None:
    """A well-formed document normalizes into typed groups, cases, and values."""
    result_set = parse_expected_results(valid_document())

    assert result_set.vs_id == 900001
    assert result_set.algorithm == "ACVP-AES-GCM"
    assert result_set.revision == "1.0"
    group = result_set.groups[0]
    case = group.cases[0]
    assert group.tg_id == 1
    assert case.tc_id == 1
    assert case.values.ciphertext == bytes.fromhex("8C4B6FC3606396AE548B0DD4")
    assert case.values.tag == bytes.fromhex("CEA4303CA9132112C1D14AE589AD15AF")
    assert case.values.plaintext is None


def test_test_passed_false_marks_an_expected_authentication_failure() -> None:
    """NIST encodes deliberate decrypt failures as ``testPassed: false``."""
    document = valid_document()
    case = document["testGroups"][0]["tests"][0]
    del case["ct"]
    del case["tag"]
    case["testPassed"] = False

    result_set = parse_expected_results(document)
    parsed = result_set.groups[0].cases[0]

    assert parsed.test_passed is False
    assert parsed.expects_authentication_failure is True


def test_absent_test_passed_does_not_expect_failure() -> None:
    """A case that simply records a value expects success, not rejection."""
    parsed = parse_expected_results(valid_document()).groups[0].cases[0]

    assert parsed.test_passed is None
    assert parsed.expects_authentication_failure is False


def test_non_boolean_test_passed_is_rejected() -> None:
    """``testPassed`` must be a real boolean, not a truthy string."""
    document = valid_document()
    document["testGroups"][0]["tests"][0]["testPassed"] = "false"

    with pytest.raises(AcvpValidationError) as captured:
        parse_expected_results(document)

    assert captured.value.path == "$.testGroups[0].tests[0].testPassed"
    assert captured.value.message == "expected a boolean"


def test_case_with_no_recorded_values_parses_as_all_none() -> None:
    """A case with only ``tcId`` declares an expected authentication failure."""
    document = valid_document()
    case = document["testGroups"][0]["tests"][0]
    del case["ct"]
    del case["tag"]

    result_set = parse_expected_results(document)

    values = result_set.groups[0].cases[0].values
    assert values.plaintext is None
    assert values.ciphertext is None
    assert values.tag is None


@pytest.mark.parametrize(
    ("field", "path"),
    [
        ("vsId", "$.vsId"),
        ("algorithm", "$.algorithm"),
        ("revision", "$.revision"),
        ("testGroups", "$.testGroups"),
    ],
)
def test_missing_top_level_fields_are_rejected(field: str, path: str) -> None:
    """Every required top-level field is enforced."""
    document = valid_document()
    del document[field]

    with pytest.raises(AcvpValidationError) as captured:
        parse_expected_results(document)

    assert captured.value.path == path
    assert captured.value.message == "missing required field"


def test_missing_group_and_case_fields_are_rejected() -> None:
    """Group and case identity fields are required."""
    document = valid_document()
    del document["testGroups"][0]["tgId"]
    with pytest.raises(AcvpValidationError) as captured:
        parse_expected_results(document)
    assert captured.value.path == "$.testGroups[0].tgId"

    document = valid_document()
    del document["testGroups"][0]["tests"][0]["tcId"]
    with pytest.raises(AcvpValidationError) as captured:
        parse_expected_results(document)
    assert captured.value.path == "$.testGroups[0].tests[0].tcId"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("algorithm", "ACVP-AES-CBC", "unsupported algorithm 'ACVP-AES-CBC'"),
        ("revision", "2.0", "unsupported revision '2.0'"),
    ],
)
def test_unsupported_contract_is_rejected(field: str, value: str, message: str) -> None:
    """Expected results outside the frozen MVP contract are rejected."""
    document = valid_document()
    document[field] = value

    with pytest.raises(AcvpValidationError) as captured:
        parse_expected_results(document)

    assert captured.value.path == f"$.{field}"
    assert captured.value.message == message


def test_non_object_root_group_and_case_are_rejected() -> None:
    """Every nesting level must be an object, not a scalar or array."""
    with pytest.raises(AcvpValidationError) as captured:
        parse_expected_results([])
    assert captured.value.path == "$"

    document = valid_document()
    document["testGroups"][0] = "group"
    with pytest.raises(AcvpValidationError) as captured:
        parse_expected_results(document)
    assert captured.value.path == "$.testGroups[0]"

    document = valid_document()
    document["testGroups"][0]["tests"][0] = "case"
    with pytest.raises(AcvpValidationError) as captured:
        parse_expected_results(document)
    assert captured.value.path == "$.testGroups[0].tests[0]"


@pytest.mark.parametrize("field", ["ct", "tag"])
def test_invalid_hex_values_are_rejected(field: str) -> None:
    """Present pt/ct/tag fields must be well-formed hexadecimal strings."""
    document = valid_document()
    document["testGroups"][0]["tests"][0][field] = "not-hex"

    with pytest.raises(AcvpValidationError) as captured:
        parse_expected_results(document)

    assert captured.value.path == f"$.testGroups[0].tests[0].{field}"


def test_non_string_hex_field_is_rejected() -> None:
    """A present but non-string value field is rejected before hex decoding."""
    document = valid_document()
    document["testGroups"][0]["tests"][0]["tag"] = 7

    with pytest.raises(AcvpValidationError) as captured:
        parse_expected_results(document)

    assert captured.value.path == "$.testGroups[0].tests[0].tag"
    assert captured.value.message == "expected a string"


def test_load_expected_results_reads_a_fixture_file() -> None:
    """The file-loading entry point parses a real fixture end to end."""
    result_set = load_expected_results(FIXTURE)

    assert result_set.vs_id == 900001


def test_load_expected_results_reports_invalid_json(tmp_path: Path) -> None:
    """Malformed JSON produces a bounded location-only diagnostic."""
    source = tmp_path / "invalid.json"
    source.write_text('{"secret": "do-not-echo",}', encoding="utf-8")

    with pytest.raises(AcvpValidationError) as captured:
        load_expected_results(source)

    assert captured.value.path == "$"
    assert "do-not-echo" not in str(captured.value)
