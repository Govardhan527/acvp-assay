"""Provider protocol for AES-GCM operations."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from acvp_runner.models import AesGcmValues, ProviderMetadata


@runtime_checkable
class AesGcmProvider(Protocol):
    """Replaceable AES-GCM operation and implementation-metadata boundary."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def encrypt(
        self,
        *,
        key: bytes,
        iv: bytes,
        plaintext: bytes,
        aad: bytes,
        tag_length_bits: int,
    ) -> AesGcmValues:
        """Encrypt and return ciphertext and authentication tag separately."""
        ...

    def decrypt(
        self,
        *,
        key: bytes,
        iv: bytes,
        ciphertext: bytes,
        aad: bytes,
        tag: bytes,
    ) -> AesGcmValues:
        """Authenticate, decrypt, and return plaintext."""
        ...


__all__ = ["AesGcmProvider"]
