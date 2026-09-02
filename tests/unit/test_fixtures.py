"""Cryptographic checks for the tiny local fixture pairs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def load_fixture_pair(name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load one prompt and its expected-results document."""
    directory = FIXTURES / name
    prompt = cast(dict[str, Any], json.loads((directory / "prompt.json").read_text()))
    expected = cast(
        dict[str, Any],
        json.loads((directory / "expectedResults.json").read_text()),
    )
    return prompt, expected


def assert_pair_identifiers(prompt: dict[str, Any], expected: dict[str, Any]) -> None:
    """Confirm that expected results identify the same set, group, and case."""
    assert expected["vsId"] == prompt["vsId"]
    assert expected["algorithm"] == prompt["algorithm"] == "ACVP-AES-GCM"
    assert expected["revision"] == prompt["revision"] == "1.0"
    assert expected["testGroups"][0]["tgId"] == prompt["testGroups"][0]["tgId"]
    assert (
        expected["testGroups"][0]["tests"][0]["tcId"] == prompt["testGroups"][0]["tests"][0]["tcId"]
    )


@pytest.mark.parametrize(
    "name",
    ("aes-gcm-valid-encrypt", "aes-gcm-valid-decrypt"),
)
def test_declared_bit_lengths_match_case_data(name: str) -> None:
    """Group bit-length metadata agrees with the encoded case fields."""
    prompt, expected = load_fixture_pair(name)
    assert_pair_identifiers(prompt, expected)
    group = prompt["testGroups"][0]
    case = group["tests"][0]

    assert group["keyLen"] == len(bytes.fromhex(case["key"])) * 8
    assert group["ivLen"] == len(bytes.fromhex(case["iv"])) * 8
    assert group["aadLen"] == len(bytes.fromhex(case["aad"])) * 8
    payload_field = "pt" if group["direction"] == "encrypt" else "ct"
    assert group["payloadLen"] == len(bytes.fromhex(case[payload_field])) * 8
    tag = expected["testGroups"][0]["tests"][0].get("tag", case.get("tag"))
    assert group["tagLen"] == len(bytes.fromhex(tag)) * 8


def test_encrypt_fixture_matches_expected_ciphertext_and_tag() -> None:
    """Recomputing the encrypt case produces its expected result exactly."""
    prompt, expected = load_fixture_pair("aes-gcm-valid-encrypt")
    case = prompt["testGroups"][0]["tests"][0]
    result = expected["testGroups"][0]["tests"][0]

    ciphertext_and_tag = AESGCM(bytes.fromhex(case["key"])).encrypt(
        bytes.fromhex(case["iv"]),
        bytes.fromhex(case["pt"]),
        bytes.fromhex(case["aad"]),
    )
    tag_bytes = prompt["testGroups"][0]["tagLen"] // 8

    assert ciphertext_and_tag[:-tag_bytes].hex().upper() == result["ct"]
    assert ciphertext_and_tag[-tag_bytes:].hex().upper() == result["tag"]


def test_decrypt_fixture_recovers_expected_plaintext() -> None:
    """The decrypt case authenticates and recovers its expected plaintext."""
    prompt, expected = load_fixture_pair("aes-gcm-valid-decrypt")
    case = prompt["testGroups"][0]["tests"][0]
    result = expected["testGroups"][0]["tests"][0]

    plaintext = AESGCM(bytes.fromhex(case["key"])).decrypt(
        bytes.fromhex(case["iv"]),
        bytes.fromhex(case["ct"] + case["tag"]),
        bytes.fromhex(case["aad"]),
    )

    assert plaintext.hex().upper() == result["pt"]
