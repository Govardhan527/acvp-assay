"""KAS-ECC-SSC: the shared-secret half of elliptic-curve key agreement.

SP 800-56A rev3 splits key agreement into computing a shared secret Z and then
running it through a KDF. The ``-SSC`` registration covers only the first half,
which is what most modules validate today because the derivation is validated
separately as KDA.

Two shapes arrive, and they differ in a way that matters:

``VAL``
    The vector supplies the implementation's own private key, both public keys,
    and a candidate Z. The answer is a verdict -- does Z follow from those
    inputs -- and ACVP supplies wrong ones deliberately, so rejecting is a
    correct answer rather than a failure.

``AFT``
    The vector supplies only the peer's public key. The implementation
    generates its own ephemeral key pair and reports it alongside Z. Nothing
    about that is reproducible: a fresh key gives a different Z every run, so
    it cannot be compared with the value NIST recorded from its own run. The
    ACVP server can still check it, because it holds the peer private key and
    can recompute Z from the public key reported back to it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.asymmetric import ec

from acvp_assay.models import ProviderMetadata
from acvp_assay.providers.subprocess_harness import HarnessClient, decode_hex

#: ACVP's ``domainParameterGenerationMode`` to the curve implementing it.
#: Binary and Koblitz curves are absent for the same reason as in ECDSA:
#: OpenSSL does not offer them here, and declaring them is honest.
CURVES: dict[str, type[ec.EllipticCurve]] = {
    "P-224": ec.SECP224R1,
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}

#: Only the unified ephemeral scheme is answered. The static and MQV schemes
#: carry extra key pairs and a different case shape.
EPHEMERAL_UNIFIED = "ephemeralUnified"


@dataclass(frozen=True, slots=True)
class SharedSecret:
    """A computed Z, with the public key the implementation used to reach it."""

    x: bytes
    y: bytes
    z: bytes


def coordinate_length(curve: str) -> int:
    """Bytes in one affine coordinate of the named curve."""
    return (CURVES[curve]().key_size + 7) // 8


class KasEccProvider(Protocol):
    """Replaceable KAS-ECC-SSC boundary."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def supports(self, *, curve: str) -> bool:
        """Whether this implementation offers the curve.

        Capability belongs to the implementation, as everywhere else here: an
        HSM's binary curves are not unsupported merely because this binding
        lacks them.
        """
        ...

    def shared_secret(
        self, *, curve: str, peer_x: bytes, peer_y: bytes, private_key: bytes | None
    ) -> SharedSecret:
        """Compute Z against the peer's public key.

        ``private_key`` is supplied for VAL cases and ``None`` for AFT, where
        the implementation generates an ephemeral pair and reports it.
        """
        ...


class CryptographyKasEcc:
    """OpenSSL-backed KAS-ECC-SSC through the ``cryptography`` package."""

    def metadata(self) -> ProviderMetadata:
        """Record the binding and the OpenSSL behind it."""
        return ProviderMetadata(
            name="cryptography-kas-ecc",
            library_name="cryptography",
            library_version=cryptography.__version__,
            backend_name="OpenSSL",
            backend_version=backend.openssl_version_text(),
        )

    def supports(self, *, curve: str) -> bool:
        """Whether OpenSSL offers this curve here."""
        return curve in CURVES

    def shared_secret(
        self, *, curve: str, peer_x: bytes, peer_y: bytes, private_key: bytes | None
    ) -> SharedSecret:
        """Derive Z, generating an ephemeral key pair when none is supplied."""
        instance = CURVES[curve]()
        peer = ec.EllipticCurvePublicNumbers(
            int.from_bytes(peer_x, "big"), int.from_bytes(peer_y, "big"), instance
        ).public_key()
        private = (
            ec.generate_private_key(instance)
            if private_key is None
            else ec.derive_private_key(int.from_bytes(private_key, "big"), instance)
        )
        numbers = private.public_key().public_numbers()
        width = coordinate_length(curve)
        return SharedSecret(
            x=numbers.x.to_bytes(width, "big"),
            y=numbers.y.to_bytes(width, "big"),
            z=private.exchange(ec.ECDH(), peer),
        )


class SubprocessKasEcc(HarnessClient):
    """KAS-ECC-SSC performed by an external harness."""

    def supports(self, *, curve: str) -> bool:
        """Assume capability; the harness declines per case with ``unsupported``."""
        del curve
        return True

    def shared_secret(
        self, *, curve: str, peer_x: bytes, peer_y: bytes, private_key: bytes | None
    ) -> SharedSecret:
        """Ask the harness for Z and the public key it used."""
        request: dict[str, object] = {
            "operation": "kas-ecc-ssc",
            "curve": curve,
            "serverX": peer_x.hex().upper(),
            "serverY": peer_y.hex().upper(),
        }
        if private_key is not None:
            request["privateKey"] = private_key.hex().upper()
        response = self.invoke(request)
        return SharedSecret(
            x=decode_hex(response, "iutX"),
            y=decode_hex(response, "iutY"),
            z=decode_hex(response, "z"),
        )


__all__ = [
    "CURVES",
    "EPHEMERAL_UNIFIED",
    "CryptographyKasEcc",
    "KasEccProvider",
    "SharedSecret",
    "SubprocessKasEcc",
    "coordinate_length",
]
