"""PBKDF (SP 800-132): a password turned into a key, slowly and on purpose.

The derivation is PBKDF2-HMAC and `hashlib` already implements it, so almost
nothing here is arithmetic. What the module is for is the two details ACVP gets
to decide and a reader would otherwise assume:

* **The password is text, not hex.** Every other byte string in this project
  arrives hex-encoded; ACVP sends this one as the characters themselves. Reading
  it as hex fails on the first case containing a letter past ``f``, and worse,
  *succeeds* on the rare case that happens to be hex-shaped.
* **``keyLen`` is in bits**, as lengths are throughout ACVP, while `hashlib`
  wants bytes.

The iteration count is deliberately expensive -- that is the entire point of the
construction -- so a large registration is slow to answer rather than wrong.
"""

from __future__ import annotations

import hashlib
import platform
from typing import Protocol, runtime_checkable

from acvp_assay.models import ProviderMetadata
from acvp_assay.providers.digest import HASHLIB_ALGORITHMS, ssl_version_text
from acvp_assay.providers.subprocess_harness import HarnessClient, decode_hex

ALGORITHM = "PBKDF"

#: The HMACs SP 800-132 allows, which is every approved hash this project knows.
SUPPORTED_HMACS = tuple(HASHLIB_ALGORITHMS)


@runtime_checkable
class PbkdfProvider(Protocol):
    """Replaceable boundary for password-based key derivation."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def derive(
        self, *, hmac_alg: str, password: bytes, salt: bytes, iterations: int, key_bits: int
    ) -> bytes:
        """Derive ``key_bits`` bits of keying material from a password."""
        ...


class HashlibPbkdf:
    """PBKDF2-HMAC from the standard library."""

    def metadata(self) -> ProviderMetadata:
        """Identify hashlib and the OpenSSL build behind it."""
        return ProviderMetadata(
            name="hashlib-pbkdf",
            library_name="hashlib",
            library_version=platform.python_version(),
            backend_name="OpenSSL",
            backend_version=ssl_version_text(),
        )

    def derive(
        self, *, hmac_alg: str, password: bytes, salt: bytes, iterations: int, key_bits: int
    ) -> bytes:
        """Derive ``key_bits`` bits of keying material from a password."""
        if hmac_alg not in HASHLIB_ALGORITHMS:
            raise ValueError(f"unsupported hmacAlg {hmac_alg!r}")
        if key_bits % 8:
            raise ValueError(f"keyLen {key_bits} is not a whole number of bytes")
        if iterations < 1:
            raise ValueError("iterationCount must be at least 1")
        return hashlib.pbkdf2_hmac(
            HASHLIB_ALGORITHMS[hmac_alg], password, salt, iterations, dklen=key_bits // 8
        )


class SubprocessPbkdf(HarnessClient):
    """Password-based key derivation performed by an external harness."""

    def derive(
        self, *, hmac_alg: str, password: bytes, salt: bytes, iterations: int, key_bits: int
    ) -> bytes:
        """Ask the harness to derive the key."""
        response = self.invoke(
            {
                "operation": "pbkdf",
                "hmacAlg": hmac_alg,
                # Hex, though ACVP sends the password as text: everything else
                # on this wire is hex, and hex has no encoding question to get
                # wrong on the far side.
                "password": password.hex().upper(),
                "salt": salt.hex().upper(),
                "iterationCount": iterations,
                "keyLen": key_bits,
            }
        )
        return decode_hex(response, "derivedKey")


__all__ = [
    "ALGORITHM",
    "SUPPORTED_HMACS",
    "HashlibPbkdf",
    "PbkdfProvider",
    "SubprocessPbkdf",
]
