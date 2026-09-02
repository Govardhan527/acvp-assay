"""End-to-end fixture loading and normalization tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from acvp_assay.models import Direction
from acvp_assay.models import TestType as AcvpTestType
from acvp_assay.parser import AcvpValidationError, load_vector_set

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


@pytest.mark.parametrize(
    ("directory", "vs_id", "direction"),
    [
        ("aes-gcm-valid-encrypt", 900001, Direction.ENCRYPT),
        ("aes-gcm-valid-decrypt", 900002, Direction.DECRYPT),
    ],
)
def test_fixture_group_parses_without_losing_ids(
    directory: str,
    vs_id: int,
    direction: Direction,
) -> None:
    """File loading preserves vector, group, and case identity end to end."""
    vector_set = load_vector_set(FIXTURES / directory / "prompt.json")
    group = vector_set.test_groups[0]
    case = group.tests[0]

    assert vector_set.vs_id == vs_id
    assert vector_set.algorithm == "ACVP-AES-GCM"
    assert vector_set.revision == "1.0"
    assert vector_set.is_sample is True
    assert group.tg_id == 1
    assert group.test_type is AcvpTestType.AFT
    assert group.direction is direction
    assert case.tc_id == 1
    assert len(case.key) == group.key_length_bits // 8
    assert len(case.iv) == group.iv_length_bits // 8
    assert len(case.aad) == group.aad_length_bits // 8


def test_encrypt_and_decrypt_fields_normalize_by_direction() -> None:
    """Direction-specific hex fields become bytes in the correct model slots."""
    encrypt = load_vector_set(FIXTURES / "aes-gcm-valid-encrypt/prompt.json")
    decrypt = load_vector_set(FIXTURES / "aes-gcm-valid-decrypt/prompt.json")
    encrypt_case = encrypt.test_groups[0].tests[0]
    decrypt_case = decrypt.test_groups[0].tests[0]

    assert encrypt_case.plaintext == b"Hello, ACVP!"
    assert encrypt_case.ciphertext is None
    assert encrypt_case.tag is None
    assert decrypt_case.plaintext is None
    assert decrypt_case.ciphertext == bytes.fromhex("8997ABE975B757B994EB")
    assert decrypt_case.tag == bytes.fromhex("5333DD8833E1A1D0961819670A9A9FFA")


def test_invalid_json_reports_location_without_echoing_content(tmp_path: Path) -> None:
    """Malformed JSON produces a bounded diagnostic with line and column."""
    source = tmp_path / "invalid.json"
    source.write_text('{"secret": "do-not-echo",}', encoding="utf-8")

    with pytest.raises(AcvpValidationError) as captured:
        load_vector_set(source)

    assert captured.value.path == "$"
    assert captured.value.message == "invalid JSON at line 1, column 26"
    assert "do-not-echo" not in str(captured.value)
