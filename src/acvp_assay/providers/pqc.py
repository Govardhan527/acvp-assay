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

from acvp_assay.models import ProviderMetadata
from acvp_assay.providers.subprocess_harness import HarnessClient, decode_hex

ML_KEM_PARAMETER_SETS = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")
ML_DSA_PARAMETER_SETS = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")


@runtime_checkable
class MlKemProvider(Protocol):
    """Replaceable ML-KEM boundary."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def generate_key(self, *, parameter_set: str, d: bytes, z: bytes) -> tuple[bytes, bytes]:
        """Generate a key pair from ACVP's two seeds, returning ``(ek, dk)``.

        FIPS 203 KeyGen takes ``d`` and ``z``, and ACVP supplies both, so the
        key pair is a function of the vector and compares exactly. An API that
        generates its own randomness cannot answer these cases at all.
        """
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

    def generate_key(self, *, parameter_set: str, seed: bytes) -> tuple[bytes, bytes]:
        """Generate a key pair from ACVP's 32-byte seed, returning ``(pk, sk)``.

        FIPS 204 KeyGen_internal takes exactly this seed, so both halves of the
        answer are fixed by the vector. An API whose only key generator draws
        its own randomness cannot express the case, which is ``interface_lacks``
        rather than a missing implementation.
        """
        ...

    def sign(
        self,
        *,
        parameter_set: str,
        secret_key: bytes,
        message: bytes,
        context: bytes | None,
        rnd: bytes | None,
        signature_interface: str,
        pre_hash: str,
        hash_alg: str | None,
        external_mu: bool,
    ) -> bytes:
        """Sign one ACVP case exactly as its group describes it.

        Four group parameters change the answer and none can be inferred from
        the signature: ``rnd`` is ``None`` for a deterministic case, where FIPS
        204 requires 32 zero bytes, and the 32 bytes ACVP chose otherwise;
        ``signature_interface`` decides whether the message carries the
        ``00 || len(ctx) || ctx`` prefix or none at all; ``pre_hash`` replaces
        the message with a digest under ``hash_alg`` and the prefix byte with
        ``01``; and ``external_mu`` means ``message`` is already the 64-byte
        ``mu``, which has absorbed the public key.
        """
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
        from acvp_assay.providers.subprocess_harness import HarnessProtocolError

        raise HarnessProtocolError(f"harness response is missing a boolean {field!r}")
    return value


class SubprocessMlKemProvider(HarnessClient):
    """ML-KEM operations performed by an external harness."""

    def generate_key(self, *, parameter_set: str, d: bytes, z: bytes) -> tuple[bytes, bytes]:
        """Generate a key pair from ACVP's ``d`` and ``z``."""
        response = self.invoke(
            {
                "operation": "ml-kem-keygen",
                "parameterSet": parameter_set,
                "d": d.hex().upper(),
                "z": z.hex().upper(),
            }
        )
        return decode_hex(response, "ek"), decode_hex(response, "dk")

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

    def generate_key(self, *, parameter_set: str, seed: bytes) -> tuple[bytes, bytes]:
        """Generate a key pair from ACVP's 32-byte seed."""
        response = self.invoke(
            {
                "operation": "ml-dsa-keygen",
                "parameterSet": parameter_set,
                "seed": seed.hex().upper(),
            }
        )
        return decode_hex(response, "pk"), decode_hex(response, "sk")

    def sign(
        self,
        *,
        parameter_set: str,
        secret_key: bytes,
        message: bytes,
        context: bytes | None,
        rnd: bytes | None,
        signature_interface: str,
        pre_hash: str,
        hash_alg: str | None,
        external_mu: bool,
    ) -> bytes:
        """Ask the harness to sign, sending every parameter its group fixes.

        A field ACVP does not send is not sent on: the internal interface
        carries no ``context`` and a deterministic group carries no ``rnd``, so
        a harness sees the same shape the vector had. ``deterministic`` travels
        as its own flag rather than being inferred from a missing ``rnd``,
        because the two readings of an absent field -- "use zeros" and "choose
        your own" -- produce different signatures and only one is right.
        """
        request: dict[str, object] = {
            "operation": "ml-dsa-sign",
            "parameterSet": parameter_set,
            "sk": secret_key.hex().upper(),
            "signatureInterface": signature_interface,
            "preHash": pre_hash,
            "externalMu": external_mu,
            "deterministic": rnd is None,
        }
        request["mu" if external_mu else "message"] = message.hex().upper()
        if context is not None:
            request["context"] = context.hex().upper()
        if rnd is not None:
            request["rnd"] = rnd.hex().upper()
        if hash_alg is not None:
            request["hashAlg"] = hash_alg
        return decode_hex(self.invoke(request), "signature")

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
