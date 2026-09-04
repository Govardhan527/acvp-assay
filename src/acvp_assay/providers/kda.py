"""KDA: the key-derivation half of SP 800-56C.

Key agreement produces a shared secret Z; SP 800-56C turns it into keying
material. ACVP validates the two separately, which is why ``KAS-ECC-SSC``
carries only the secret and this carries only the derivation -- a module that
does both validates both, and most that do TLS do.

The HKDF mode is extract-then-expand, RFC 5869: the salt keys an HMAC over Z to
give a pseudorandom key, which is then expanded against ``fixedInfo`` to the
requested length. What ACVP adds is that ``fixedInfo`` is *assembled* from the
two parties' contributions according to a pattern the group declares, so the
derivation cannot be checked without building that string exactly right.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from acvp_assay.models import ProviderMetadata
from acvp_assay.providers.subprocess_harness import HarnessClient, decode_hex

ALGORITHM = "KDA"
HKDF_MODE = "HKDF"

#: ACVP's ``hmacAlg`` to the hash keying it.
HMAC_HASHES: dict[str, type[hashes.HashAlgorithm]] = {
    "SHA2-224": hashes.SHA224,
    "SHA2-256": hashes.SHA256,
    "SHA2-384": hashes.SHA384,
    "SHA2-512": hashes.SHA512,
    "SHA2-512/224": hashes.SHA512_224,
    "SHA2-512/256": hashes.SHA512_256,
}

#: The only ``fixedInfoPattern`` answered. Others exist -- patterns can name a
#: literal, an algorithm id, a label -- and each assembles a different string,
#: so guessing at one would produce a derivation that is wrong everywhere
#: rather than merely unsupported.
UPARTY_VPARTY = "uPartyInfo||vPartyInfo"

CONCATENATION = "concatenation"


@dataclass(frozen=True, slots=True)
class PartyInfo:
    """One party's contribution to ``fixedInfo``."""

    party_id: bytes
    ephemeral_data: bytes | None = None

    def encoded(self) -> bytes:
        """The party's bytes, identifier first."""
        return self.party_id + (self.ephemeral_data or b"")


def fixed_info(pattern: str, party_u: PartyInfo, party_v: PartyInfo) -> bytes:
    """Assemble ``fixedInfo`` for a pattern this runner builds.

    Raises for any other pattern rather than returning a sentinel: callers
    already decline an unrecognised pattern before deriving, so an optional
    return only created a branch nothing could reach -- and a silent fallback
    here would produce keying material that is wrong on every case.
    """
    if pattern != UPARTY_VPARTY:
        raise ValueError(f"fixedInfoPattern {pattern!r} is not assembled by this runner")
    return party_u.encoded() + party_v.encoded()


class KdaProvider(Protocol):
    """Replaceable SP 800-56C derivation boundary."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def derive(
        self, *, hmac_alg: str, salt: bytes, shared_secret: bytes, info: bytes, output_bytes: int
    ) -> bytes:
        """Derive keying material from a shared secret."""
        ...


class CryptographyKda:
    """OpenSSL-backed HKDF through the ``cryptography`` package."""

    def metadata(self) -> ProviderMetadata:
        """Record the binding and the OpenSSL behind it."""
        return ProviderMetadata(
            name="cryptography-kda",
            library_name="cryptography",
            library_version=cryptography.__version__,
            backend_name="OpenSSL",
            backend_version=backend.openssl_version_text(),
        )

    def derive(
        self, *, hmac_alg: str, salt: bytes, shared_secret: bytes, info: bytes, output_bytes: int
    ) -> bytes:
        """Extract with the salt, then expand against the fixed info."""
        algorithm = HMAC_HASHES.get(hmac_alg)
        if algorithm is None:
            raise ValueError(f"unsupported hmacAlg {hmac_alg!r}")
        return HKDF(algorithm=algorithm(), length=output_bytes, salt=salt, info=info).derive(
            shared_secret
        )


class SubprocessKda(HarnessClient):
    """SP 800-56C derivation performed by an external harness."""

    def derive(
        self, *, hmac_alg: str, salt: bytes, shared_secret: bytes, info: bytes, output_bytes: int
    ) -> bytes:
        """Ask the harness to derive.

        ``fixedInfo`` is sent already assembled. Putting the pattern on the
        wire would make every harness reimplement the same string-building and
        get it wrong in the same places; sending the bytes keeps the question
        to "derive this", which is what the implementation is being tested on.
        """
        return decode_hex(
            self.invoke(
                {
                    "operation": "kda-hkdf",
                    "hmacAlg": hmac_alg,
                    "salt": salt.hex().upper(),
                    "z": shared_secret.hex().upper(),
                    "fixedInfo": info.hex().upper(),
                    "l": output_bytes * 8,
                }
            ),
            "dkm",
        )


__all__ = [
    "ALGORITHM",
    "CONCATENATION",
    "HKDF_MODE",
    "HMAC_HASHES",
    "UPARTY_VPARTY",
    "CryptographyKda",
    "KdaProvider",
    "PartyInfo",
    "SubprocessKda",
    "fixed_info",
]
