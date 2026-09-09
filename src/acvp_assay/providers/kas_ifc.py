"""KAS-IFC-SSC and KTS-IFC (SP 800-56Br2): key agreement and transport over RSA.

The integer-factorisation siblings of the ECC and FFC families, and grouped
with KTS-IFC because certificates group them: of the 214 active FIPS 140-3
modules validating KTS-IFC, 114 also validate KAS-IFC-SSC.

**These behave differently from the ECC and FFC variants in a way that matters
to what an offline run means.** There, an AFT case has the implementation
generate an ephemeral key, so nothing local can check it. Here most cases hand
the implementation *its own RSA private key*, so the answer is deterministic and
fully checkable offline. Only the cases where the implementation originates
fresh secret material -- KAS1 initiator, KAS2's own contribution, and KTS-IFC as
initiator -- remain server-only.

The rules below were each reproduced from the live server's answers before this
was written:

* **KAS1** carries one secret. The responder recovers it with RSADP; the
  initiator chooses it and sends ``C = Z^e mod n``.
* **KAS2** carries two, and ``Z`` is the initiator's own contribution
  **concatenated with** the one it recovers -- ``iutZ || RSADP(serverC)`` -- not
  combined or hashed.
* **KTS-IFC** transports keying material under RSA-OAEP rather than deriving a
  shared secret, so the responder simply decrypts.
"""

from __future__ import annotations

import platform
import secrets
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from acvp_assay.models import ProviderMetadata
from acvp_assay.providers.digest import ssl_version_text
from acvp_assay.providers.subprocess_harness import HarnessClient, decode_hex

KAS_IFC = "KAS-IFC-SSC"
KTS_IFC = "KTS-IFC"

KAS1 = "KAS1"
KAS2 = "KAS2"
SCHEMES: tuple[str, ...] = (KAS1, KAS2)

#: The OAEP hashes ACVP names, mapped to their `cryptography` objects.
OAEP_HASHES: dict[str, hashes.HashAlgorithm] = {
    "SHA2-224": hashes.SHA224(),
    "SHA2-256": hashes.SHA256(),
    "SHA2-384": hashes.SHA384(),
    "SHA2-512": hashes.SHA512(),
}


@dataclass(frozen=True, slots=True)
class RsaKey:
    """An RSA private key exactly as an ACVP case supplies it."""

    n: int
    e: int
    d: int
    p: int
    q: int

    @property
    def size(self) -> int:
        """The modulus length in bytes, which every output is padded to."""
        return (self.n.bit_length() + 7) // 8

    def private_key(self) -> rsa.RSAPrivateKey:
        """Rebuild the key object, deriving the CRT values ACVP omits."""
        return rsa.RSAPrivateNumbers(
            p=self.p,
            q=self.q,
            d=self.d,
            dmp1=rsa.rsa_crt_dmp1(self.d, self.p),
            dmq1=rsa.rsa_crt_dmq1(self.d, self.q),
            iqmp=rsa.rsa_crt_iqmp(self.p, self.q),
            public_numbers=rsa.RSAPublicNumbers(e=self.e, n=self.n),
        ).private_key()


@runtime_checkable
class KasIfcProvider(Protocol):
    """Replaceable boundary for the IFC key-agreement and transport families."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def recover(self, *, key: RsaKey, ciphertext: bytes) -> bytes:
        """RSADP: recover the secret the peer sent, padded to the modulus."""
        ...

    def originate(self, *, peer_n: int, peer_e: int) -> tuple[bytes, bytes]:
        """Choose a secret and encrypt it to the peer, returning ``(z, c)``."""
        ...

    def oaep_decrypt(self, *, key: RsaKey, ciphertext: bytes, hash_alg: str) -> bytes:
        """Recover transported keying material under RSA-OAEP."""
        ...

    def oaep_encrypt(
        self, *, peer_n: int, peer_e: int, hash_alg: str, length_bytes: int
    ) -> tuple[bytes, bytes]:
        """Generate keying material and transport it, returning ``(dkm, c)``."""
        ...


class CryptographyKasIfc:
    """The IFC primitives over `cryptography`, with the raw operations by hand.

    RSADP and RSAEP have no padding, and no library exposes them directly --
    for good reason, since unpadded RSA is a footgun everywhere except here,
    where the specification calls for exactly that.
    """

    def metadata(self) -> ProviderMetadata:
        """Identify the library and the OpenSSL build behind it."""
        return ProviderMetadata(
            name="cryptography-kas-ifc",
            library_name="cryptography",
            library_version=platform.python_version(),
            backend_name="OpenSSL",
            backend_version=ssl_version_text(),
        )

    def recover(self, *, key: RsaKey, ciphertext: bytes) -> bytes:
        """RSADP: recover the secret the peer sent, padded to the modulus."""
        value = int.from_bytes(ciphertext, "big")
        if not 0 <= value < key.n:
            raise ValueError("ciphertext is not a residue modulo n")
        return pow(value, key.d, key.n).to_bytes(key.size, "big")

    def originate(self, *, peer_n: int, peer_e: int) -> tuple[bytes, bytes]:
        """Choose a secret and encrypt it to the peer, returning ``(z, c)``.

        SP 800-56Br2 puts Z in [1, n-1]; drawing the full modulus width and
        reducing would bias it, so it is drawn below n directly.
        """
        size = (peer_n.bit_length() + 7) // 8
        z = secrets.randbelow(peer_n - 2) + 1
        c = pow(z, peer_e, peer_n)
        return z.to_bytes(size, "big"), c.to_bytes(size, "big")

    def _oaep(self, hash_alg: str) -> padding.OAEP:
        if hash_alg not in OAEP_HASHES:
            raise ValueError(f"unsupported OAEP hash {hash_alg!r}")
        algorithm = OAEP_HASHES[hash_alg]
        return padding.OAEP(mgf=padding.MGF1(algorithm=algorithm), algorithm=algorithm, label=None)

    def oaep_decrypt(self, *, key: RsaKey, ciphertext: bytes, hash_alg: str) -> bytes:
        """Recover transported keying material under RSA-OAEP."""
        return key.private_key().decrypt(ciphertext, self._oaep(hash_alg))

    def oaep_encrypt(
        self, *, peer_n: int, peer_e: int, hash_alg: str, length_bytes: int
    ) -> tuple[bytes, bytes]:
        """Generate keying material and transport it, returning ``(dkm, c)``."""
        dkm = secrets.token_bytes(length_bytes)
        public = rsa.RSAPublicNumbers(e=peer_e, n=peer_n).public_key()
        return dkm, public.encrypt(dkm, self._oaep(hash_alg))


class SubprocessKasIfc(HarnessClient):
    """The IFC families performed by an external harness."""

    def _hex(self, value: int) -> str:
        """An integer as hex with an even digit count.

        ``format(65537, "X")`` is ``"10001"`` -- five digits -- and
        ``bytes.fromhex`` refuses odd-length input, so a harness would crash on
        the commonest public exponent there is. ACVP itself always sends an even
        number of digits.
        """
        text = format(value, "X")
        return text if len(text) % 2 == 0 else "0" + text

    def _key_fields(self, key: RsaKey) -> dict[str, object]:
        return {
            "iutN": self._hex(key.n),
            "iutE": self._hex(key.e),
            "iutD": self._hex(key.d),
            "iutP": self._hex(key.p),
            "iutQ": self._hex(key.q),
        }

    def recover(self, *, key: RsaKey, ciphertext: bytes) -> bytes:
        """Ask the harness to run RSADP."""
        request: dict[str, object] = {
            "operation": "kas-ifc-recover",
            "serverC": ciphertext.hex().upper(),
        }
        request.update(self._key_fields(key))
        return decode_hex(self.invoke(request), "z")

    def originate(self, *, peer_n: int, peer_e: int) -> tuple[bytes, bytes]:
        """Ask the harness to choose a secret and encrypt it."""
        response = self.invoke(
            {
                "operation": "kas-ifc-originate",
                "serverN": self._hex(peer_n),
                "serverE": self._hex(peer_e),
            }
        )
        return decode_hex(response, "z"), decode_hex(response, "c")

    def oaep_decrypt(self, *, key: RsaKey, ciphertext: bytes, hash_alg: str) -> bytes:
        """Ask the harness to OAEP-decrypt transported keying material."""
        request: dict[str, object] = {
            "operation": "kts-ifc-decrypt",
            "serverC": ciphertext.hex().upper(),
            "hashAlg": hash_alg,
        }
        request.update(self._key_fields(key))
        return decode_hex(self.invoke(request), "dkm")

    def oaep_encrypt(
        self, *, peer_n: int, peer_e: int, hash_alg: str, length_bytes: int
    ) -> tuple[bytes, bytes]:
        """Ask the harness to generate keying material and transport it."""
        response = self.invoke(
            {
                "operation": "kts-ifc-encrypt",
                "serverN": self._hex(peer_n),
                "serverE": self._hex(peer_e),
                "hashAlg": hash_alg,
                "keyLen": length_bytes * 8,
            }
        )
        return decode_hex(response, "dkm"), decode_hex(response, "c")


__all__ = [
    "KAS1",
    "KAS2",
    "KAS_IFC",
    "KTS_IFC",
    "OAEP_HASHES",
    "SCHEMES",
    "CryptographyKasIfc",
    "KasIfcProvider",
    "RsaKey",
    "SubprocessKasIfc",
]
