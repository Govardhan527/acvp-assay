"""AES mode provider boundary: ECB, GMAC, CMAC and key wrapping.

These are the algorithms that surround AES-GCM in a real module. A MACsec
device validates GCM and GMAC; almost every module validates CMAC or a key
wrap somewhere. They are grouped behind one provider because they share a
key and differ only in what they do with it.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import cryptography
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import cmac, keywrap
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from acvp_assay.models import ProviderMetadata

MCT_OUTER_ITERATIONS = 100
MCT_INNER_ITERATIONS = 1000

#: One outer Monte Carlo iteration: the key used, the input block, the output.
McTriple = tuple[bytes, bytes, bytes]


@runtime_checkable
class AesModeProvider(Protocol):
    """Replaceable boundary for AES modes other than GCM."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def ecb(self, *, key: bytes, data: bytes, encrypt: bool) -> bytes:
        """Transform one or more whole blocks in ECB mode."""
        ...

    def ecb_monte_carlo(self, *, key: bytes, data: bytes, encrypt: bool) -> list[McTriple]:
        """Run the AES Monte Carlo chain, returning (key, input, output) per iteration."""
        ...

    def cmac(self, *, key: bytes, message: bytes, mac_length_bits: int) -> bytes:
        """Compute a CMAC truncated to the requested length."""
        ...

    def gmac(self, *, key: bytes, iv: bytes, aad: bytes, tag_length_bits: int) -> bytes:
        """Authenticate AAD only, returning the tag. GMAC is GCM with no payload."""
        ...

    def key_wrap(self, *, key: bytes, data: bytes, padded: bool, wrap: bool) -> bytes:
        """Wrap or unwrap key material. Raises ValueError when unwrapping fails."""
        ...


def key_shuffle(key: bytes, last: bytes, previous: bytes) -> bytes:
    """Derive the next Monte Carlo key, per the ACVP symmetric specification.

    ``128: Key ^ CT[j]``,
    ``192: Key ^ (LSB(CT[j-1],64) || CT[j])``,
    ``256: Key ^ (CT[j-1] || CT[j])`` — where ``j`` is the final inner
    iteration. The wider key lengths reach back into the previous block
    because one 128-bit output is not enough material to refresh them.
    """
    if len(key) == 16:
        feed = last
    elif len(key) == 24:
        feed = previous[-8:] + last
    else:
        feed = previous + last
    return bytes(a ^ b for a, b in zip(key, feed, strict=True))


class CryptographyAesModeProvider:
    """AES modes backed by cryptography's OpenSSL binding."""

    def metadata(self) -> ProviderMetadata:
        """Identify both the Python binding and OpenSSL backend versions."""
        return ProviderMetadata(
            name="cryptography-aes-modes",
            library_name="cryptography",
            library_version=cryptography.__version__,
            backend_name="OpenSSL",
            backend_version=backend.openssl_version_text(),
        )

    def ecb(self, *, key: bytes, data: bytes, encrypt: bool) -> bytes:
        """Transform whole blocks in ECB mode."""
        cipher = Cipher(algorithms.AES(key), modes.ECB())  # noqa: S305 - ACVP tests ECB directly
        operation = cipher.encryptor() if encrypt else cipher.decryptor()
        return operation.update(data) + operation.finalize()

    def ecb_monte_carlo(self, *, key: bytes, data: bytes, encrypt: bool) -> list[McTriple]:
        """Run the 100 x 1000 AES chain, recording the key and block each round.

        Unlike SHA's Monte Carlo, every outer iteration reports three values —
        the key in force, the input block, and the final output — because the
        key itself is shuffled between iterations.
        """
        results: list[McTriple] = []
        for _ in range(MCT_OUTER_ITERATIONS):
            first = data
            previous = b"\x00" * 16
            last = b"\x00" * 16
            block = data
            for _ in range(MCT_INNER_ITERATIONS):
                produced = self.ecb(key=key, data=block, encrypt=encrypt)
                previous, last = last, produced
                block = produced
            results.append((key, first, last))
            key = key_shuffle(key, last, previous)
            data = last
        return results

    def cmac(self, *, key: bytes, message: bytes, mac_length_bits: int) -> bytes:
        """Compute a CMAC and truncate it to the requested bit length."""
        if mac_length_bits <= 0 or mac_length_bits % 8 != 0:
            raise ValueError("macLen must be a positive multiple of 8")
        context = cmac.CMAC(algorithms.AES(key))
        context.update(message)
        full = context.finalize()
        length = mac_length_bits // 8
        if length > len(full):
            raise ValueError("macLen exceeds the CMAC block length")
        return full[:length]

    def gmac(self, *, key: bytes, iv: bytes, aad: bytes, tag_length_bits: int) -> bytes:
        """Authenticate AAD with no payload, returning the requested tag prefix."""
        if tag_length_bits <= 0 or tag_length_bits % 8 != 0:
            raise ValueError("tagLen must be a positive multiple of 8")
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
        encryptor.authenticate_additional_data(aad)
        encryptor.finalize()
        return encryptor.tag[: tag_length_bits // 8]

    def key_wrap(self, *, key: bytes, data: bytes, padded: bool, wrap: bool) -> bytes:
        """Wrap or unwrap key material, raising ValueError on a rejected wrapping."""
        try:
            if wrap:
                return (
                    keywrap.aes_key_wrap_with_padding(key, data)
                    if padded
                    else keywrap.aes_key_wrap(key, data)
                )
            return (
                keywrap.aes_key_unwrap_with_padding(key, data)
                if padded
                else keywrap.aes_key_unwrap(key, data)
            )
        except (keywrap.InvalidUnwrap, InvalidSignature) as error:
            raise ValueError("key unwrapping failed") from error


__all__ = [
    "MCT_INNER_ITERATIONS",
    "MCT_OUTER_ITERATIONS",
    "AesModeProvider",
    "key_shuffle",
    "CryptographyAesModeProvider",
    "McTriple",
]
