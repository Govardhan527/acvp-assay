"""safePrimes (SP 800-56A): key generation and verification over named groups.

The vector set names its group -- ``MODP-2048``, ``ffdhe3072`` -- and never
sends the domain parameters, so every implementation has to carry them. The six
below are the RFC 3526 (MODP) and RFC 7919 (FFDHE) primes, and the generator is
2 for all of them.

They were not transcribed. Each was computed from the formula in its RFC --
RFC 3526 ``p = 2^n - 2^(n-64) - 1 + 2^64 * (floor(2^(n-130) * pi) + offset)``
and RFC 7919 the same shape over *e* -- and then checked against the live
server's own ``keyVer`` answers, where all 60 verdicts across all six groups
agreed, 42 true and 18 false. A wrong prime would have failed every case in its
group rather than some of them, which is the useful shape of that check.

What ACVP asks for splits the same way key agreement does:

* **keyVer** supplies ``x`` and ``y`` and asks whether they are a pair. That is
  fully checkable here.
* **keyGen** supplies nothing but a group and asks the implementation to
  generate. The value is fresh every run, so nothing offline can compare it;
  only the server, which recomputes ``g^x mod p``, can say whether it is right.
"""

from __future__ import annotations

import secrets
from typing import Protocol, runtime_checkable

from acvp_assay.models import ProviderMetadata
from acvp_assay.providers.digest import ssl_version_text
from acvp_assay.providers.subprocess_harness import HarnessClient, decode_hex

ALGORITHM = "safePrimes"

#: Every safe-prime group ACVP names, mapped to its prime. The generator is 2
#: throughout, which is what makes these groups usable without sending g.
GENERATOR = 2

SAFE_PRIME_GROUPS: dict[str, int] = {
    "MODP-2048": int(
        ""
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
        16,
    ),
    "MODP-3072": int(
        ""
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
        "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
        "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
        "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
        16,
    ),
    "MODP-4096": int(
        ""
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
        "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
        "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
        "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
        "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8"
        "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
        "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
        "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
        16,
    ),
    "ffdhe2048": int(
        ""
        "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695"
        "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A"
        "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
        "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A"
        "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4"
        "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
        "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005"
        "C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF",
        16,
    ),
    "ffdhe3072": int(
        ""
        "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695"
        "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A"
        "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
        "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A"
        "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4"
        "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
        "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005"
        "C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035B"
        "BC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
        "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF"
        "5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E"
        "0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF",
        16,
    ),
    "ffdhe4096": int(
        ""
        "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695"
        "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A"
        "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
        "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A"
        "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4"
        "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
        "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005"
        "C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035B"
        "BC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C"
        "AEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF"
        "5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E"
        "0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB"
        "7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A"
        "7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038"
        "092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF"
        "8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6AFFFFFFFFFFFFFFFF",
        16,
    ),
}


def group_names() -> tuple[str, ...]:
    """The groups this provider knows, in the spelling ACVP uses."""
    return tuple(SAFE_PRIME_GROUPS)


@runtime_checkable
class SafePrimesProvider(Protocol):
    """Replaceable boundary for safe-prime key generation and verification."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def key_gen(self, *, group: str) -> tuple[bytes, bytes]:
        """Generate a key pair for the named group, returning ``(x, y)``."""
        ...

    def key_ver(self, *, group: str, x: bytes, y: bytes) -> bool:
        """Report whether ``y`` is the public key matching private ``x``."""
        ...


def _to_bytes(value: int, prime: int) -> bytes:
    return value.to_bytes((prime.bit_length() + 7) // 8, "big")


class PythonSafePrimes:
    """Modular exponentiation over the named groups.

    No library exposes these groups directly, and the operation is one modexp,
    so it is done here rather than pulled through a key-exchange API that would
    have to be talked out of doing its own parameter generation.
    """

    def metadata(self) -> ProviderMetadata:
        """Identify the interpreter and the OpenSSL build behind it."""
        import platform

        return ProviderMetadata(
            name="python-safe-primes",
            library_name="python",
            library_version=platform.python_version(),
            backend_name="OpenSSL",
            backend_version=ssl_version_text(),
        )

    def key_gen(self, *, group: str) -> tuple[bytes, bytes]:
        """Generate a key pair for the named group, returning ``(x, y)``."""
        prime = SAFE_PRIME_GROUPS[group]
        # x must be in [1, q-1] where q = (p-1)/2, not [1, p-2]. The generator
        # 2 has order q, so an out-of-range x still yields a perfectly valid y:
        # g^x == g^(x mod q). A self-check therefore cannot see the error --
        # key_ver on our own key_gen passes either way -- and the first session
        # to say so was NIST's, which rejected 766220's keyGen set outright.
        subgroup_order = (prime - 1) // 2
        x = secrets.randbelow(subgroup_order - 1) + 1
        return _to_bytes(x, prime), _to_bytes(pow(GENERATOR, x, prime), prime)

    def key_ver(self, *, group: str, x: bytes, y: bytes) -> bool:
        """Report whether ``y`` is the public key matching private ``x``."""
        prime = SAFE_PRIME_GROUPS[group]
        public = int.from_bytes(y, "big")
        # Range first. These vectors happen never to exercise it -- all 18 of
        # the server's failing cases are a y that simply is not g^x -- but a
        # verifier that skips it accepts 1 and p-1, which are valid-looking and
        # useless.
        if not 1 < public < prime - 1:
            return False
        return pow(GENERATOR, int.from_bytes(x, "big"), prime) == public


class SubprocessSafePrimes(HarnessClient):
    """Safe-prime key operations performed by an external harness."""

    def key_gen(self, *, group: str) -> tuple[bytes, bytes]:
        """Ask the harness to generate a key pair."""
        response = self.invoke({"operation": "safe-primes-keygen", "safePrimeGroup": group})
        return decode_hex(response, "x"), decode_hex(response, "y")

    def key_ver(self, *, group: str, x: bytes, y: bytes) -> bool:
        """Ask the harness whether the pair is valid."""
        response = self.invoke(
            {
                "operation": "safe-primes-keyver",
                "safePrimeGroup": group,
                "x": x.hex().upper(),
                "y": y.hex().upper(),
            }
        )
        verdict = response.get("testPassed")
        if not isinstance(verdict, bool):
            raise ValueError("harness did not return a boolean testPassed")
        return verdict


__all__ = [
    "ALGORITHM",
    "GENERATOR",
    "SAFE_PRIME_GROUPS",
    "PythonSafePrimes",
    "SafePrimesProvider",
    "SubprocessSafePrimes",
    "group_names",
]
