"""AES-CCM: counter with CBC-MAC, the AEAD of 802.11 and constrained devices.

Structurally this is AES-GCM's twin -- authenticated encryption with a tag that
may be deliberately wrong -- and the same rule governs it: a rejected tag is an
*answer*, not a fault. Roughly a quarter of NIST's decrypt cases here are
forgeries where refusing is correct.

Two differences from GCM are worth naming, because both are easy to miss:

The tag is **appended to the ciphertext** rather than reported separately, so a
zero-length payload still produces a non-empty ``ct`` -- the tag alone. ACVP
reports it that way and so does ``cryptography``.

The tag length is a **property of the cipher object**, not of the call. CCM
admits 32 to 128 bits, and building the cipher with the wrong length fails
rather than truncating, which is the safe direction.
"""

from __future__ import annotations

from typing import Protocol

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from acvp_assay.models import ProviderMetadata
from acvp_assay.providers.subprocess_harness import HarnessClient, decode_hex

ALGORITHM = "ACVP-AES-CCM"

#: CCM admits these tag lengths in bits, and no others.
TAG_LENGTHS = (32, 48, 64, 80, 96, 112, 128)

#: The nonce is 7 to 13 bytes. Its length constrains the maximum payload,
#: which is why ACVP varies it across groups.
NONCE_LENGTHS = (56, 64, 72, 80, 88, 96, 104)


class AesCcmProvider(Protocol):
    """Replaceable AES-CCM boundary."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def encrypt(
        self, *, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes, tag_bits: int
    ) -> bytes:
        """Return ciphertext with the tag appended, as ACVP reports it."""
        ...

    def decrypt(
        self, *, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, tag_bits: int
    ) -> bytes:
        """Return the plaintext, or raise ``InvalidTag`` for a forged tag."""
        ...


class CryptographyAesCcm:
    """OpenSSL-backed AES-CCM through the ``cryptography`` package."""

    def metadata(self) -> ProviderMetadata:
        """Record the binding and the OpenSSL behind it."""
        return ProviderMetadata(
            name="cryptography-aes-ccm",
            library_name="cryptography",
            library_version=cryptography.__version__,
            backend_name="OpenSSL",
            backend_version=backend.openssl_version_text(),
        )

    def encrypt(
        self, *, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes, tag_bits: int
    ) -> bytes:
        """Encrypt, returning ciphertext || tag."""
        return AESCCM(key, tag_length=tag_bits // 8).encrypt(nonce, plaintext, aad or None)

    def decrypt(
        self, *, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, tag_bits: int
    ) -> bytes:
        """Decrypt, raising ``InvalidTag`` when the tag does not verify."""
        return AESCCM(key, tag_length=tag_bits // 8).decrypt(nonce, ciphertext, aad or None)


class SubprocessAesCcm(HarnessClient):
    """AES-CCM performed by an external harness."""

    def encrypt(
        self, *, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes, tag_bits: int
    ) -> bytes:
        """Ask the harness to encrypt, expecting ciphertext with the tag on it."""
        return decode_hex(
            self.invoke(
                {
                    "operation": "ccm-encrypt",
                    "key": key.hex().upper(),
                    "iv": nonce.hex().upper(),
                    "pt": plaintext.hex().upper(),
                    "aad": aad.hex().upper(),
                    "tagLen": tag_bits,
                }
            ),
            "ct",
        )

    def decrypt(
        self, *, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, tag_bits: int
    ) -> bytes:
        """Ask the harness to decrypt.

        A forged tag comes back as ``{"error": "authentication failed"}``, which
        the transport turns into ``InvalidTag`` -- the same exception the
        in-process provider raises, so the caller cannot tell them apart and
        does not have to.
        """
        return decode_hex(
            self.invoke(
                {
                    "operation": "ccm-decrypt",
                    "key": key.hex().upper(),
                    "iv": nonce.hex().upper(),
                    "ct": ciphertext.hex().upper(),
                    "aad": aad.hex().upper(),
                    "tagLen": tag_bits,
                }
            ),
            "pt",
        )


__all__ = [
    "ALGORITHM",
    "NONCE_LENGTHS",
    "TAG_LENGTHS",
    "AesCcmProvider",
    "CryptographyAesCcm",
    "SubprocessAesCcm",
]
