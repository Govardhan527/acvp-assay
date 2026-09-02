"""OpenSSL-backed AES-GCM provider using the cryptography package."""

from __future__ import annotations

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from acvp_runner.models import AesGcmValues, ProviderMetadata

MINIMUM_TAG_LENGTH_BITS = 32
MAXIMUM_TAG_LENGTH_BITS = 128


def _tag_length_bytes(tag_length_bits: int) -> int:
    if (
        type(tag_length_bits) is not int
        or tag_length_bits < MINIMUM_TAG_LENGTH_BITS
        or tag_length_bits > MAXIMUM_TAG_LENGTH_BITS
        or tag_length_bits % 8 != 0
    ):
        raise ValueError("tag_length_bits must be a multiple of 8 from 32 through 128")
    return tag_length_bits // 8


class CryptographyAesGcmProvider:
    """AES-GCM operations backed by cryptography's OpenSSL binding."""

    def metadata(self) -> ProviderMetadata:
        """Identify both the Python binding and OpenSSL backend versions."""
        return ProviderMetadata(
            name="cryptography-aes-gcm",
            library_name="cryptography",
            library_version=cryptography.__version__,
            backend_name="OpenSSL",
            backend_version=backend.openssl_version_text(),
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
        """Encrypt and return ciphertext and the requested tag prefix."""
        tag_length_bytes = _tag_length_bytes(tag_length_bits)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return AesGcmValues(
            ciphertext=ciphertext,
            tag=encryptor.tag[:tag_length_bytes],
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
        """Authenticate and decrypt; implemented in A09."""
        raise NotImplementedError


__all__ = ["CryptographyAesGcmProvider"]
