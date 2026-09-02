"""Tests for the OpenSSL-backed cryptography AES-GCM provider."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from acvp_runner.parser import load_vector_set
from acvp_runner.providers import AesGcmProvider, CryptographyAesGcmProvider

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
    """Tag lengths outside the MVP byte-aligned range fail before execution."""
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


def test_decrypt_is_explicitly_deferred_to_a09() -> None:
    """The concrete adapter cannot silently pretend decryption exists yet."""
    with pytest.raises(NotImplementedError):
        CryptographyAesGcmProvider().decrypt(
            key=bytes(16),
            iv=bytes(12),
            ciphertext=b"",
            aad=b"",
            tag=bytes(16),
        )
