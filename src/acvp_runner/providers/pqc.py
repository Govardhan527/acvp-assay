"""ML-KEM and ML-DSA provider boundaries.

There is deliberately **no built-in implementation** here. The pinned
``cryptography`` 50.0.1 exposes neither ML-KEM nor ML-DSA, and PQC support
landed in OpenSSL 3.5, so nothing available in this project's dependency set
can perform these operations.

That is the right outcome rather than a gap to paper over. For post-quantum
work the implementation under test *is* the customer's — OpenSSL 3.5+, liboqs,
or their own module — so these operations are reached through an external
harness, exactly what the provider boundary exists for. Adding a
pure-Python ML-KEM or ML-DSA here would be inventing cryptography to test
cryptography, which is worse than declaring the dependency.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from acvp_runner.models import ProviderMetadata
from acvp_runner.providers.subprocess_harness import HarnessClient, decode_hex

ML_KEM_PARAMETER_SETS = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")
ML_DSA_PARAMETER_SETS = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")


@runtime_checkable
class MlKemProvider(Protocol):
    """Replaceable ML-KEM boundary."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def encapsulate(
        self, *, parameter_set: str, encapsulation_key: bytes, seed: bytes
    ) -> tuple[bytes, bytes]:
        """Encapsulate with supplied randomness, returning ``(ciphertext, shared_secret)``.

        ACVP supplies ``m``, so this is deterministic and its output is
        directly comparable to the expected ``c`` and ``k``.
        """
        ...

    def decapsulate(
        self, *, parameter_set: str, decapsulation_key: bytes, ciphertext: bytes
    ) -> bytes:
        """Decapsulate, returning the shared secret."""
        ...

    def check_key(self, *, parameter_set: str, key_type: str, key: bytes) -> bool:
        """Report whether a supplied key is well formed. Malformed keys are expected."""
        ...


@runtime_checkable
class MlDsaProvider(Protocol):
    """Replaceable ML-DSA boundary."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def verify(
        self,
        *,
        parameter_set: str,
        public_key: bytes,
        message: bytes,
        signature: bytes,
        context: bytes,
        signature_interface: str,
    ) -> bool:
        """Report whether the signature verifies. An invalid signature is a false verdict.

        ``signature_interface`` is load-bearing: ML-DSA's *internal* interface
        omits the domain separator and context prefix that the *external* one
        applies, so verifying an internal signature externally rejects it.
        """
        ...


def _verdict(response: object, field: str = "testPassed") -> bool:
    if not isinstance(response, dict):  # pragma: no cover - guarded by HarnessClient
        raise TypeError("expected a mapping response")
    value = response.get(field)
    if not isinstance(value, bool):
        from acvp_runner.providers.subprocess_harness import HarnessProtocolError

        raise HarnessProtocolError(f"harness response is missing a boolean {field!r}")
    return value


class SubprocessMlKemProvider(HarnessClient):
    """ML-KEM operations performed by an external harness."""

    def encapsulate(
        self, *, parameter_set: str, encapsulation_key: bytes, seed: bytes
    ) -> tuple[bytes, bytes]:
        """Encapsulate using the randomness ACVP supplies."""
        response = self.invoke(
            {
                "operation": "ml-kem-encapsulate",
                "parameterSet": parameter_set,
                "ek": encapsulation_key.hex().upper(),
                "m": seed.hex().upper(),
            }
        )
        return decode_hex(response, "c"), decode_hex(response, "k")

    def decapsulate(
        self, *, parameter_set: str, decapsulation_key: bytes, ciphertext: bytes
    ) -> bytes:
        """Decapsulate and return the shared secret."""
        response = self.invoke(
            {
                "operation": "ml-kem-decapsulate",
                "parameterSet": parameter_set,
                "dk": decapsulation_key.hex().upper(),
                "c": ciphertext.hex().upper(),
            }
        )
        return decode_hex(response, "k")

    def check_key(self, *, parameter_set: str, key_type: str, key: bytes) -> bool:
        """Ask the harness whether a supplied key is well formed."""
        response = self.invoke(
            {
                "operation": "ml-kem-key-check",
                "parameterSet": parameter_set,
                "keyType": key_type,
                "key": key.hex().upper(),
            }
        )
        return _verdict(response)


class SubprocessMlDsaProvider(HarnessClient):
    """ML-DSA operations performed by an external harness."""

    def verify(
        self,
        *,
        parameter_set: str,
        public_key: bytes,
        message: bytes,
        signature: bytes,
        context: bytes,
        signature_interface: str = "external",
    ) -> bool:
        """Ask the harness for its verification verdict."""
        response = self.invoke(
            {
                "operation": "ml-dsa-verify",
                "parameterSet": parameter_set,
                "pk": public_key.hex().upper(),
                "message": message.hex().upper(),
                "signature": signature.hex().upper(),
                "context": context.hex().upper(),
                "signatureInterface": signature_interface,
            }
        )
        return _verdict(response)


__all__ = [
    "ML_DSA_PARAMETER_SETS",
    "ML_KEM_PARAMETER_SETS",
    "MlDsaProvider",
    "MlKemProvider",
    "SubprocessMlDsaProvider",
    "SubprocessMlKemProvider",
]
