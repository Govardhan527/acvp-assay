"""Tests for the OpenSSL-backed cryptography AES-GCM provider."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from acvp_assay.parser import load_vector_set
from acvp_assay.providers import AesGcmProvider, CryptographyAesGcmProvider

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def expected_encrypt_result() -> dict[str, Any]:
    """Load the independently stored result paired with the encrypt prompt."""
    path = FIXTURES / "aes-gcm-valid-encrypt/expectedResults.json"
    document = cast(dict[str, Any], json.loads(path.read_text()))
    return cast(dict[str, Any], document["testGroups"][0]["tests"][0])


def test_provider_identifies_binding_and_backend() -> None:
    """Metadata records both cryptography and the OpenSSL it exercises."""
    provider = CryptographyAesGcmProvider()
    metadata = provider.metadata()

    assert isinstance(provider, AesGcmProvider)
    assert metadata.name == "cryptography-aes-gcm"
    assert metadata.library_name == "cryptography"
    assert metadata.library_version
    assert metadata.backend_name == "OpenSSL"
    assert metadata.backend_version.startswith("OpenSSL ")


def test_encrypt_fixture_matches_ciphertext_and_tag_separately() -> None:
    """The adapter matches the stored case without joining output fields."""
    vector_set = load_vector_set(FIXTURES / "aes-gcm-valid-encrypt/prompt.json")
    group = vector_set.test_groups[0]
    case = group.tests[0]
    assert case.plaintext is not None

    result = CryptographyAesGcmProvider().encrypt(
        key=case.key,
        iv=case.iv,
        plaintext=case.plaintext,
        aad=case.aad,
        tag_length_bits=group.tag_length_bits,
    )
    expected = expected_encrypt_result()

    assert result.plaintext is None
    assert result.ciphertext == bytes.fromhex(expected["ct"])
    assert result.tag == bytes.fromhex(expected["tag"])


@pytest.mark.parametrize(
    ("plaintext", "aad"),
    [
        (b"", b"context"),
        (b"payload", b""),
        (b"", b""),
    ],
)
def test_encrypt_supports_zero_length_plaintext_and_aad(
    plaintext: bytes,
    aad: bytes,
) -> None:
    """Empty payload and AAD combinations match the high-level AESGCM API."""
    key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    iv = bytes.fromhex("0102030405060708090A0B0C")
    reference = AESGCM(key).encrypt(iv, plaintext, aad)

    result = CryptographyAesGcmProvider().encrypt(
        key=key,
        iv=iv,
        plaintext=plaintext,
        aad=aad,
        tag_length_bits=128,
    )

    assert result.ciphertext == reference[:-16]
    assert result.tag == reference[-16:]


def test_encrypt_returns_requested_truncated_tag() -> None:
    """The provider exposes supported ACVP tag lengths as separate bytes."""
    key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    iv = bytes.fromhex("0102030405060708090A0B0C")
    reference = AESGCM(key).encrypt(iv, b"payload", b"aad")

    result = CryptographyAesGcmProvider().encrypt(
        key=key,
        iv=iv,
        plaintext=b"payload",
        aad=b"aad",
        tag_length_bits=32,
    )

    assert result.ciphertext == reference[:-16]
    assert result.tag == reference[-16:-12]


@pytest.mark.parametrize("tag_length_bits", [0, 31, 33, 136])
def test_encrypt_rejects_invalid_tag_lengths(tag_length_bits: int) -> None:
    """Tag lengths outside the byte-aligned range fail before execution."""
    with pytest.raises(
        ValueError,
        match="tag_length_bits must be a multiple of 8 from 32 through 128",
    ):
        CryptographyAesGcmProvider().encrypt(
            key=bytes(16),
            iv=bytes(12),
            plaintext=b"",
            aad=b"",
            tag_length_bits=tag_length_bits,
        )


def test_decrypt_fixture_recovers_authenticated_plaintext() -> None:
    """The stored decrypt fixture authenticates and recovers plaintext."""
    vector_set = load_vector_set(FIXTURES / "aes-gcm-valid-decrypt/prompt.json")
    case = vector_set.test_groups[0].tests[0]
    expected_path = FIXTURES / "aes-gcm-valid-decrypt/expectedResults.json"
    expected_document = cast(dict[str, Any], json.loads(expected_path.read_text()))
    expected = expected_document["testGroups"][0]["tests"][0]
    assert case.ciphertext is not None
    assert case.tag is not None

    result = CryptographyAesGcmProvider().decrypt(
        key=case.key,
        iv=case.iv,
        ciphertext=case.ciphertext,
        aad=case.aad,
        tag=case.tag,
    )

    assert result.plaintext == bytes.fromhex(expected["pt"])
    assert result.ciphertext is None
    assert result.tag is None


@pytest.mark.parametrize("mutation", ["tag", "key", "iv", "ciphertext"])
def test_decrypt_rejects_modified_or_mismatched_inputs(mutation: str) -> None:
    """Every authenticated input change produces InvalidTag rather than plaintext."""
    vector_set = load_vector_set(FIXTURES / "aes-gcm-valid-decrypt/prompt.json")
    case = vector_set.test_groups[0].tests[0]
    assert case.ciphertext is not None
    assert case.tag is not None
    key = case.key
    iv = case.iv
    ciphertext = case.ciphertext
    tag = case.tag

    if mutation == "tag":
        tag = bytes([tag[0] ^ 1]) + tag[1:]
    elif mutation == "key":
        key = bytes([key[0] ^ 1]) + key[1:]
    elif mutation == "iv":
        iv = bytes([iv[0] ^ 1]) + iv[1:]
    else:
        ciphertext = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]

    with pytest.raises(InvalidTag):
        CryptographyAesGcmProvider().decrypt(
            key=key,
            iv=iv,
            ciphertext=ciphertext,
            aad=case.aad,
            tag=tag,
        )


def test_decrypt_accepts_supported_truncated_tag() -> None:
    """A generated 32-bit tag is accepted with an explicit minimum length."""
    provider = CryptographyAesGcmProvider()
    key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    iv = bytes.fromhex("0102030405060708090A0B0C")
    encrypted = provider.encrypt(
        key=key,
        iv=iv,
        plaintext=b"payload",
        aad=b"aad",
        tag_length_bits=32,
    )
    assert encrypted.ciphertext is not None
    assert encrypted.tag is not None

    decrypted = provider.decrypt(
        key=key,
        iv=iv,
        ciphertext=encrypted.ciphertext,
        aad=b"aad",
        tag=encrypted.tag,
    )

    assert decrypted.plaintext == b"payload"


@pytest.mark.parametrize("tag", [b"", bytes(3), bytes(17)])
def test_decrypt_rejects_invalid_tag_lengths(tag: bytes) -> None:
    """Invalid tags fail before creating a backend decryptor."""
    with pytest.raises(
        ValueError,
        match="tag_length_bits must be a multiple of 8 from 32 through 128",
    ):
        CryptographyAesGcmProvider().decrypt(
            key=bytes(16),
            iv=bytes(12),
            ciphertext=b"",
            aad=b"",
            tag=tag,
        )
