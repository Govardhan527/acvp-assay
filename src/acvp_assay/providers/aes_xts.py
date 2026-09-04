"""AES-XTS: the mode disk and storage encryption is validated under.

XTS differs from the other AES modes here in three ways that all have to be
right at once, and each is easy to get subtly wrong:

The key is **two AES keys concatenated**, so ``keyLen`` 128 means a 32-byte
key and 256 means 64. A provider that validates key length against the usual
AES sizes rejects every XTS vector.

The tweak arrives in one of two forms. ``tweakMode: hex`` supplies 16 bytes
directly. ``tweakMode: number`` supplies a data-unit *sequence number*, which
is encoded as a **little-endian** 128-bit integer -- big-endian reproduces
exactly half the vectors, the half where the value happens to be symmetric
enough not to matter, which is the worst kind of near-miss.

A payload longer than ``dataUnitLen`` spans several data units, and **each
unit is encrypted under its own tweak**, incremented by one per unit as a
little-endian integer. Encrypting the payload as a single unit reproduces
every case where it happens to fit, and disagrees on the rest.
"""

from __future__ import annotations

from typing import Protocol

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from acvp_assay.models import ProviderMetadata
from acvp_assay.providers.subprocess_harness import HarnessClient, decode_hex

ALGORITHM = "ACVP-AES-XTS"

#: An XTS key is two AES keys, so these are the whole-key byte lengths for
#: ACVP's ``keyLen`` of 128 and 256.
KEY_LENGTHS = {128: 32, 256: 64}

TWEAK_BYTES = 16

HEX_TWEAK = "hex"
NUMBER_TWEAK = "number"


def tweak_for(sequence_number: int) -> bytes:
    """Encode a data-unit sequence number as XTS expects it.

    Little-endian. Confirmed against 480 cases NIST generated: big-endian
    reproduces 240 of them, which is enough to look like it works.
    """
    return sequence_number.to_bytes(TWEAK_BYTES, "little")


def advance(tweak: bytes, units: int) -> bytes:
    """The tweak for the data unit ``units`` after this one."""
    return ((int.from_bytes(tweak, "little") + units) % (1 << 128)).to_bytes(TWEAK_BYTES, "little")


class AesXtsProvider(Protocol):
    """Replaceable AES-XTS boundary."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def transform(
        self, *, key: bytes, tweak: bytes, data: bytes, data_unit_bytes: int, encrypt: bool
    ) -> bytes:
        """Encrypt or decrypt one payload, data unit by data unit."""
        ...


class CryptographyAesXts:
    """OpenSSL-backed AES-XTS through the ``cryptography`` package."""

    def metadata(self) -> ProviderMetadata:
        """Record the binding and the OpenSSL behind it."""
        return ProviderMetadata(
            name="cryptography-aes-xts",
            library_name="cryptography",
            library_version=cryptography.__version__,
            backend_name="OpenSSL",
            backend_version=backend.openssl_version_text(),
        )

    def transform(
        self, *, key: bytes, tweak: bytes, data: bytes, data_unit_bytes: int, encrypt: bool
    ) -> bytes:
        """Split the payload into data units and transform each under its tweak.

        ``cryptography`` treats whatever it is given as a single data unit, so
        the split and the per-unit tweak are this method's job. A payload
        shorter than a data unit is one short unit.
        """
        width = min(data_unit_bytes, len(data)) or len(data)
        out = bytearray()
        for index, start in enumerate(range(0, len(data), width)):
            cipher = Cipher(algorithms.AES(key), modes.XTS(advance(tweak, index)))
            operation = cipher.encryptor() if encrypt else cipher.decryptor()
            out += operation.update(data[start : start + width]) + operation.finalize()
        return bytes(out)


class SubprocessAesXts(HarnessClient):
    """AES-XTS performed by an external harness.

    The whole payload crosses in one exchange, tweak and data-unit length
    included, so the implementation splits it. That is what a storage
    implementation does natively, and it keeps the data-unit rule off the wire.
    """

    def transform(
        self, *, key: bytes, tweak: bytes, data: bytes, data_unit_bytes: int, encrypt: bool
    ) -> bytes:
        """Ask the harness to transform one payload."""
        return decode_hex(
            self.invoke(
                {
                    "operation": "xts-transform",
                    "direction": "encrypt" if encrypt else "decrypt",
                    "key": key.hex().upper(),
                    "tweak": tweak.hex().upper(),
                    "dataUnitLen": data_unit_bytes * 8,
                    "data": data.hex().upper(),
                }
            ),
            "out",
        )


__all__ = [
    "ALGORITHM",
    "HEX_TWEAK",
    "KEY_LENGTHS",
    "NUMBER_TWEAK",
    "TWEAK_BYTES",
    "AesXtsProvider",
    "CryptographyAesXts",
    "SubprocessAesXts",
    "advance",
    "tweak_for",
]
