"""KAS-FFC-SSC (SP 800-56Ar3): the shared secret, over finite fields.

The sibling of ``KAS-ECC-SSC``, and deliberately built on the same split. Only
the group differs: where the ECC variant names a curve, this one names a safe
prime group -- and it names it with exactly the strings ``safePrimes`` uses, so
the domain parameters come from one table rather than two. That is why the two
families were built together: 278 of the 322 certificates carrying safePrimes
also carry KAS-FFC-SSC.

The offline/live split settled for the ECC variant applies unchanged:

* **VAL** supplies both private keys' worth of material and a claimed ``z``.
  Recomputing it here is a complete check.
* **AFT** has the implementation generate an ephemeral key, so ``z`` differs on
  every run and nothing offline can compare it. Only the server, which holds the
  peer private key, can verify what comes back.
"""

from __future__ import annotations

import platform
import secrets
from typing import Protocol, runtime_checkable

from acvp_assay.models import ProviderMetadata
from acvp_assay.providers.digest import ssl_version_text
from acvp_assay.providers.safe_primes import GENERATOR, SAFE_PRIME_GROUPS
from acvp_assay.providers.subprocess_harness import HarnessClient, decode_hex

ALGORITHM = "KAS-FFC-SSC"

#: The one scheme this implements. dhEphem is both parties ephemeral, which is
#: what makes the AFT case unverifiable offline.
DH_EPHEM = "dhEphem"


def supported_groups() -> tuple[str, ...]:
    """The domain parameter sets this provider can work in."""
    return tuple(SAFE_PRIME_GROUPS)


@runtime_checkable
class KasFfcProvider(Protocol):
    """Replaceable boundary for finite-field shared-secret computation."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def supports(self, *, group: str) -> bool:
        """Whether the named domain parameter set is available."""
        ...

    def shared_secret(self, *, group: str, private_key: bytes, peer_public: bytes) -> bytes:
        """Compute z from our private key and the peer's public key."""
        ...

    def generate(self, *, group: str) -> tuple[bytes, bytes]:
        """Generate an ephemeral key pair, returning ``(private, public)``."""
        ...


class PythonKasFfc:
    """Finite-field Diffie-Hellman by modular exponentiation."""

    def metadata(self) -> ProviderMetadata:
        """Identify the interpreter and the OpenSSL build behind it."""
        return ProviderMetadata(
            name="python-kas-ffc-ssc",
            library_name="python",
            library_version=platform.python_version(),
            backend_name="OpenSSL",
            backend_version=ssl_version_text(),
        )

    def supports(self, *, group: str) -> bool:
        """Whether the named domain parameter set is available."""
        return group in SAFE_PRIME_GROUPS

    def _size(self, group: str) -> int:
        return (SAFE_PRIME_GROUPS[group].bit_length() + 7) // 8

    def shared_secret(self, *, group: str, private_key: bytes, peer_public: bytes) -> bytes:
        """Compute z from our private key and the peer's public key.

        z is left-padded to the modulus length. ACVP compares the bytes, so a
        short secret that dropped its leading zeros is a wrong answer even
        though the integer is right.
        """
        prime = SAFE_PRIME_GROUPS[group]
        public = int.from_bytes(peer_public, "big")
        if not 1 < public < prime - 1:
            raise ValueError("peer public key is outside the usable range")
        secret = pow(public, int.from_bytes(private_key, "big"), prime)
        return secret.to_bytes(self._size(group), "big")

    def generate(self, *, group: str) -> tuple[bytes, bytes]:
        """Generate an ephemeral key pair, returning ``(private, public)``."""
        prime = SAFE_PRIME_GROUPS[group]
        # In [1, q-1], q = (p-1)/2 -- see PythonSafePrimes.key_gen for why a
        # larger x still produces a valid public key and so cannot be caught
        # by any check this side of the server.
        private = secrets.randbelow((prime - 1) // 2 - 1) + 1
        size = self._size(group)
        return (
            private.to_bytes(size, "big"),
            pow(GENERATOR, private, prime).to_bytes(size, "big"),
        )


class SubprocessKasFfc(HarnessClient):
    """Finite-field shared-secret computation performed by an external harness."""

    def supports(self, *, group: str) -> bool:
        """A harness decides its own groups, so nothing is refused here."""
        return True

    def shared_secret(self, *, group: str, private_key: bytes, peer_public: bytes) -> bytes:
        """Ask the harness to compute z."""
        response = self.invoke(
            {
                "operation": "kas-ffc-ssc",
                "domainParameterGenerationMode": group,
                "privateKey": private_key.hex().upper(),
                "peerPublic": peer_public.hex().upper(),
            }
        )
        return decode_hex(response, "z")

    def generate(self, *, group: str) -> tuple[bytes, bytes]:
        """Ask the harness for an ephemeral key pair."""
        response = self.invoke(
            {"operation": "kas-ffc-keygen", "domainParameterGenerationMode": group}
        )
        return decode_hex(response, "privateKey"), decode_hex(response, "publicKey")


__all__ = [
    "ALGORITHM",
    "DH_EPHEM",
    "KasFfcProvider",
    "PythonKasFfc",
    "SubprocessKasFfc",
    "supported_groups",
]
