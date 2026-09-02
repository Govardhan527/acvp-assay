"""Tests for the replaceable AES-GCM provider boundary."""

from __future__ import annotations

from dataclasses import dataclass

from acvp_assay.models import AesGcmValues, ProviderMetadata
from acvp_assay.providers import AesGcmProvider


@dataclass(frozen=True)
class StubProvider:
    """Minimal non-OpenSSL-specific provider used to prove substitutability."""

    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            name="stub",
            library_name="test-library",
            library_version="1.0",
            backend_name="test-backend",
            backend_version="2.0",
        )

    def encrypt(
        self,
        *,
        key: bytes,
        iv: bytes,
        plaintext: bytes,
        aad: bytes,
        tag_length_bits: int,
    ) -> AesGcmValues:
        del key, iv, aad
        return AesGcmValues(
            ciphertext=plaintext[::-1],
            tag=b"t" * (tag_length_bits // 8),
        )

    def decrypt(
        self,
        *,
        key: bytes,
        iv: bytes,
        ciphertext: bytes,
        aad: bytes,
        tag: bytes,
    ) -> AesGcmValues:
        del key, iv, aad, tag
        return AesGcmValues(plaintext=ciphertext[::-1])


def test_structural_provider_contract_supports_metadata_and_operations() -> None:
    """A non-OpenSSL implementation can satisfy the protocol structurally."""
    provider = StubProvider()

    assert isinstance(provider, AesGcmProvider)
    assert provider.metadata().backend_name == "test-backend"
    encrypted = provider.encrypt(
        key=b"key",
        iv=b"iv",
        plaintext=b"payload",
        aad=b"context",
        tag_length_bits=32,
    )
    assert encrypted == AesGcmValues(ciphertext=b"daolyap", tag=b"tttt")
    assert provider.decrypt(
        key=b"key",
        iv=b"iv",
        ciphertext=encrypted.ciphertext or b"",
        aad=b"context",
        tag=encrypted.tag or b"",
    ) == AesGcmValues(plaintext=b"payload")
