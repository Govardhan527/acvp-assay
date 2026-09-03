"""ECDSA provider boundary and its ``cryptography``-backed implementation."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

import cryptography
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from acvp_assay.models import ProviderMetadata
from acvp_assay.providers.subprocess_harness import (
    HarnessClient,
    HarnessProtocolError,
    decode_hex,
)

#: ACVP curve name to the ``cryptography`` curve implementing it. Binary (B-)
#: and Koblitz (K-) curves are deliberately absent: OpenSSL does not offer them
#: here, and reporting those groups UNSUPPORTED is honest.
CURVES: dict[str, type[ec.EllipticCurve]] = {
    "P-224": ec.SECP224R1,
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}

HASHES: dict[str, type[hashes.HashAlgorithm]] = {
    "SHA2-224": hashes.SHA224,
    "SHA2-256": hashes.SHA256,
    "SHA2-384": hashes.SHA384,
    "SHA2-512": hashes.SHA512,
    "SHA2-512/224": hashes.SHA512_224,
    "SHA2-512/256": hashes.SHA512_256,
    "SHA3-224": hashes.SHA3_224,
    "SHA3-256": hashes.SHA3_256,
    "SHA3-384": hashes.SHA3_384,
    "SHA3-512": hashes.SHA3_512,
}


@dataclass(frozen=True, slots=True)
class GroupSignatures:
    """Signatures over several messages, all under one key pair.

    ACVP reports ``qx``/``qy`` once per sigGen *group*, so every case in that
    group must be signed with the same key. Calling ``sign`` per case generates
    a fresh key each time, which cannot be reported in that shape.
    """

    qx: bytes
    qy: bytes
    signatures: tuple[tuple[bytes, bytes], ...]


@dataclass(frozen=True, slots=True)
class GeneratedSignature:
    """One signature and the public key the implementation generated for it."""

    qx: bytes
    qy: bytes
    r: bytes
    s: bytes


@runtime_checkable
class EcdsaProvider(Protocol):
    """Replaceable ECDSA boundary."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def supports(self, *, curve: str, hash_algorithm: str) -> bool:
        """Whether this implementation offers the curve and hash.

        Capability belongs to the implementation. Deciding it from what
        ``cryptography`` happens to expose would wrongly declare an HSM's
        binary curves unsupported.
        """
        ...

    def sign(self, *, curve: str, hash_algorithm: str, message: bytes) -> GeneratedSignature:
        """Generate a key pair, sign, and return the signature with its public key."""
        ...

    def sign_group(
        self, *, curve: str, hash_algorithm: str, messages: Sequence[bytes]
    ) -> GroupSignatures:
        """Sign a whole group under one key pair.

        Separate from ``sign`` because ACVP reports the public key once per
        group: a submission needs every case in the group signed under the key
        it reports, which per-case signing cannot express.
        """
        ...

    def verify(
        self,
        *,
        curve: str,
        hash_algorithm: str,
        message: bytes,
        qx: bytes,
        qy: bytes,
        r: bytes,
        s: bytes,
    ) -> bool:
        """Report whether the signature verifies. A malformed key is a false verdict."""
        ...


def _curve(name: str) -> ec.EllipticCurve:
    if name not in CURVES:
        raise ValueError(f"unsupported curve {name!r}")
    return CURVES[name]()


def _hash(name: str) -> hashes.HashAlgorithm:
    if name not in HASHES:
        raise ValueError(f"unsupported hash algorithm {name!r}")
    return HASHES[name]()


def _field_bytes(value: int, curve: ec.EllipticCurve) -> bytes:
    return value.to_bytes((curve.key_size + 7) // 8, "big")


class CryptographyEcdsaProvider:
    """ECDSA operations backed by cryptography's OpenSSL binding."""

    def metadata(self) -> ProviderMetadata:
        """Identify both the Python binding and OpenSSL backend versions."""
        return ProviderMetadata(
            name="cryptography-ecdsa",
            library_name="cryptography",
            library_version=cryptography.__version__,
            backend_name="OpenSSL",
            backend_version=backend.openssl_version_text(),
        )

    def supports(self, *, curve: str, hash_algorithm: str) -> bool:
        """Report what this OpenSSL build actually offers."""
        return curve in CURVES and hash_algorithm in HASHES

    def sign(self, *, curve: str, hash_algorithm: str, message: bytes) -> GeneratedSignature:
        """Generate a fresh key pair and sign, as an ACVP sigGen case requires.

        ACVP sigGen supplies only a message: the implementation under test
        provides its own key, which is why the expected ``qx``/``qy``/``r``/``s``
        in a vector file belong to NIST's implementation and are not
        comparable to ours.
        """
        curve_instance = _curve(curve)
        algorithm = _hash(hash_algorithm)
        private_key = ec.generate_private_key(curve_instance)
        signature = private_key.sign(message, ec.ECDSA(algorithm))
        r, s = utils.decode_dss_signature(signature)
        numbers = private_key.public_key().public_numbers()
        return GeneratedSignature(
            qx=_field_bytes(numbers.x, curve_instance),
            qy=_field_bytes(numbers.y, curve_instance),
            r=_field_bytes(r, curve_instance),
            s=_field_bytes(s, curve_instance),
        )

    def sign_group(
        self, *, curve: str, hash_algorithm: str, messages: Sequence[bytes]
    ) -> GroupSignatures:
        """Sign every message in a group under one freshly generated key.

        This is what a submission needs: ACVP reports the public key once per
        group, so a fresh key per case would be unreportable.
        """
        curve_instance = _curve(curve)
        algorithm = _hash(hash_algorithm)
        private_key = ec.generate_private_key(curve_instance)
        numbers = private_key.public_key().public_numbers()
        signatures: list[tuple[bytes, bytes]] = []
        for message in messages:
            r, s = utils.decode_dss_signature(private_key.sign(message, ec.ECDSA(algorithm)))
            signatures.append((_field_bytes(r, curve_instance), _field_bytes(s, curve_instance)))
        return GroupSignatures(
            qx=_field_bytes(numbers.x, curve_instance),
            qy=_field_bytes(numbers.y, curve_instance),
            signatures=tuple(signatures),
        )

    def verify(
        self,
        *,
        curve: str,
        hash_algorithm: str,
        message: bytes,
        qx: bytes,
        qy: bytes,
        r: bytes,
        s: bytes,
    ) -> bool:
        """Verify a signature, treating an off-curve public key as a false verdict.

        ACVP sigVer sets deliberately include invalid points and out-of-range
        scalars. Those must produce a *verdict* of false, not an error: the
        implementation is being asked whether it correctly rejects them.
        """
        curve_instance = _curve(curve)
        algorithm = _hash(hash_algorithm)
        try:
            public_key = ec.EllipticCurvePublicNumbers(
                int.from_bytes(qx, "big"),
                int.from_bytes(qy, "big"),
                curve_instance,
            ).public_key()
            signature = utils.encode_dss_signature(
                int.from_bytes(r, "big"), int.from_bytes(s, "big")
            )
        except ValueError:
            return False
        try:
            public_key.verify(signature, message, ec.ECDSA(algorithm))
        except InvalidSignature:
            return False
        return True


class SubprocessEcdsaProvider(HarnessClient):
    """ECDSA operations performed by an external harness."""

    def supports(self, *, curve: str, hash_algorithm: str) -> bool:
        """Assume capability; the harness declines per case with ``unsupported``."""
        return True

    def sign(self, *, curve: str, hash_algorithm: str, message: bytes) -> GeneratedSignature:
        """Ask the harness to generate a key pair and sign."""
        response = self.invoke(
            {
                "operation": "ecdsa-sign",
                "curve": curve,
                "hashAlg": hash_algorithm,
                "message": message.hex().upper(),
            }
        )
        return GeneratedSignature(
            qx=decode_hex(response, "qx"),
            qy=decode_hex(response, "qy"),
            r=decode_hex(response, "r"),
            s=decode_hex(response, "s"),
        )

    def sign_group(
        self, *, curve: str, hash_algorithm: str, messages: Sequence[bytes]
    ) -> GroupSignatures:
        """Ask the harness to sign a whole group under one key it generates."""
        response = self.invoke(
            {
                "operation": "ecdsa-sign-group",
                "curve": curve,
                "hashAlg": hash_algorithm,
                "messages": [message.hex().upper() for message in messages],
            }
        )
        signatures = response.get("signatures")
        if not isinstance(signatures, list):
            raise HarnessProtocolError("harness returned no 'signatures' array")
        if len(signatures) != len(messages):
            raise HarnessProtocolError(
                f"harness returned {len(signatures)} signatures for {len(messages)} messages"
            )
        decoded: list[tuple[bytes, bytes]] = []
        for index, value in enumerate(signatures):
            if not isinstance(value, dict):
                raise HarnessProtocolError(f"harness returned a non-object signature at {index}")
            decoded.append((decode_hex(value, "r"), decode_hex(value, "s")))
        return GroupSignatures(
            qx=decode_hex(response, "qx"),
            qy=decode_hex(response, "qy"),
            signatures=tuple(decoded),
        )

    def verify(
        self,
        *,
        curve: str,
        hash_algorithm: str,
        message: bytes,
        qx: bytes,
        qy: bytes,
        r: bytes,
        s: bytes,
    ) -> bool:
        """Ask the harness for its verification verdict."""
        response = self.invoke(
            {
                "operation": "ecdsa-verify",
                "curve": curve,
                "hashAlg": hash_algorithm,
                "message": message.hex().upper(),
                "qx": qx.hex().upper(),
                "qy": qy.hex().upper(),
                "r": r.hex().upper(),
                "s": s.hex().upper(),
            }
        )
        verdict = response.get("testPassed")
        if not isinstance(verdict, bool):
            raise HarnessProtocolError("harness response is missing a boolean 'testPassed'")
        return verdict


__all__ = [
    "CURVES",
    "HASHES",
    "CryptographyEcdsaProvider",
    "EcdsaProvider",
    "GeneratedSignature",
    "GroupSignatures",
    "SubprocessEcdsaProvider",
]
