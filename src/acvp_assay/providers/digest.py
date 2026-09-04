"""Hash and MAC provider boundaries, and their hashlib-backed implementations."""

from __future__ import annotations

import hashlib
import hmac
import platform
import sys
from collections.abc import Callable, Sequence
from typing import Protocol, runtime_checkable

from acvp_assay.models import ProviderMetadata
from acvp_assay.providers.subprocess_harness import (
    HarnessClient,
    HarnessProtocolError,
    decode_hex,
)

MCT_OUTER_ITERATIONS = 100
MCT_INNER_ITERATIONS = 1000

#: ACVP algorithm name to the hashlib constructor name behind it.
HASHLIB_ALGORITHMS = {
    "SHA-1": "sha1",
    "SHA2-224": "sha224",
    "SHA2-256": "sha256",
    "SHA2-384": "sha384",
    "SHA2-512": "sha512",
    "SHA2-512/224": "sha512_224",
    "SHA2-512/256": "sha512_256",
    "SHA3-224": "sha3_224",
    "SHA3-256": "sha3_256",
    "SHA3-384": "sha3_384",
    "SHA3-512": "sha3_512",
}

#: SHA-3 chains its Monte Carlo test differently from SHA-1 and SHA-2, so the
#: family a name belongs to decides which chain runs.
SHA3_ALGORITHMS = frozenset(name for name in HASHLIB_ALGORITHMS if name.startswith("SHA3-"))

#: The extendable-output functions, mapped to their constructors. Unlike
#: everything in HASHLIB_ALGORITHMS these have no fixed digest length: the
#: caller asks for as many bytes as it wants, and FIPS 202 is explicit that
#: they are *not* approved as hash functions, only for the uses NIST names.
#:
#: The constructors are held rather than the hashlib names because
#: ``hashlib.new`` is typed as returning a fixed-length hash, whose ``digest``
#: takes no argument -- so going through it would not typecheck, and would
#: hide the very thing that makes an XOF different.
XOF_ALGORITHMS = {
    "SHAKE-128": hashlib.shake_128,
    "SHAKE-256": hashlib.shake_256,
}


@runtime_checkable
class HashProvider(Protocol):
    """Replaceable message-digest boundary."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def digest(self, message: bytes) -> bytes:
        """Hash one complete message."""
        ...

    def digest_mct(self, seed: bytes, *, alternate: bool) -> list[bytes]:
        """Run the ACVP Monte Carlo chain and return one digest per outer iteration."""
        ...


@runtime_checkable
class MacProvider(Protocol):
    """Replaceable keyed-MAC boundary."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def mac(self, *, key: bytes, message: bytes, mac_length_bits: int) -> bytes:
        """Compute a MAC and truncate it to the requested length."""
        ...


class XofProvider(Protocol):
    """Replaceable extendable-output-function boundary.

    Separate from ``HashProvider`` because the output length is an input here.
    A fixed-length interface cannot express it, and squeezing SHAKE into one
    would mean either a fake digest size or a lie about what was asked for.
    """

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def squeeze(self, *, algorithm: str, message: bytes, output_bytes: int) -> bytes:
        """Absorb the message and squeeze out exactly ``output_bytes``."""
        ...


def monte_carlo_sha3(
    seed: bytes,
    digest: Callable[[bytes], bytes],
    *,
    alternate: bool,
) -> list[bytes]:
    """Run the ACVP SHA-3 Monte Carlo chain, returning the 100 outer digests.

    SHA-3 chains a single digest rather than three::

        For j = 0 to 99
            MD[0] = SEED
            For i = 1 to 1000
                MSG = MD[i-1]
                MD[i] = SHA3(MSG)
            Output MD[1000]; SEED = MD[1000]

    Reusing the SHA-2 chain here would be silently wrong on every case: the
    two families share a test type name and nothing else.
    """
    seed_length = len(seed)
    outputs: list[bytes] = []
    for _ in range(MCT_OUTER_ITERATIONS):
        current = seed
        for _ in range(MCT_INNER_ITERATIONS):
            message = current
            if alternate:
                message = message[:seed_length].ljust(seed_length, b"\x00")
            current = digest(message)
        outputs.append(current)
        seed = current
    return outputs


def monte_carlo(
    seed: bytes,
    digest: Callable[[bytes], bytes],
    *,
    alternate: bool,
) -> list[bytes]:
    """Run the ACVP SHA-1/SHA-2 Monte Carlo chain, returning the 100 outer digests.

    Standard::

        for j in 0..99:
            A = B = C = SEED
            for i in 0..999:
                MD = SHA(A || B || C); A, B, C = B, C, MD
            output MD; SEED = MD

    The ``alternate`` variant exists for implementations that cannot accept a
    message three digests wide: every inner message is truncated or
    zero-padded to the length of the *original* seed. That length is captured
    once, before the loop, so later iterations pad up to it even though the
    seed has by then shrunk to one digest.
    """
    seed_length = len(seed)
    outputs: list[bytes] = []
    for _ in range(MCT_OUTER_ITERATIONS):
        a, b, c = seed, seed, seed
        for _ in range(MCT_INNER_ITERATIONS):
            message = a + b + c
            if alternate:
                message = message[:seed_length].ljust(seed_length, b"\x00")
            current = digest(message)
            a, b, c = b, c, current
        outputs.append(c)
        seed = c
    return outputs


def _python_metadata(name: str) -> ProviderMetadata:
    return ProviderMetadata(
        name=name,
        library_name="hashlib",
        library_version=platform.python_version(),
        backend_name="OpenSSL",
        backend_version=ssl_version_text(),
    )


def ssl_version_text() -> str:
    """Report the OpenSSL build backing hashlib, or the interpreter if unknown."""
    try:
        import ssl
    except ImportError:  # pragma: no cover - ssl is present in supported builds
        return f"Python {sys.version.split()[0]}"
    return ssl.OPENSSL_VERSION


class HashlibHashProvider:
    """Message digests computed by Python's hashlib."""

    def __init__(self, algorithm: str) -> None:
        if algorithm not in HASHLIB_ALGORITHMS:
            raise ValueError(f"unsupported hash algorithm {algorithm!r}")
        self._algorithm = algorithm
        self._constructor = HASHLIB_ALGORITHMS[algorithm]

    def metadata(self) -> ProviderMetadata:
        """Identify hashlib and the OpenSSL build behind it."""
        return _python_metadata(f"hashlib-{self._algorithm.lower().replace('/', '-')}")

    def digest(self, message: bytes) -> bytes:
        """Hash one complete message."""
        return hashlib.new(self._constructor, message).digest()

    def digest_mct(self, seed: bytes, *, alternate: bool) -> list[bytes]:
        """Run the Monte Carlo chain this algorithm's family calls for."""
        chain = monte_carlo_sha3 if self._algorithm in SHA3_ALGORITHMS else monte_carlo
        return chain(seed, self.digest, alternate=alternate)


class HashlibMacProvider:
    """HMAC computed by Python's hmac module over hashlib."""

    def __init__(self, algorithm: str) -> None:
        underlying = algorithm.removeprefix("HMAC-")
        if underlying not in HASHLIB_ALGORITHMS:
            raise ValueError(f"unsupported MAC algorithm {algorithm!r}")
        self._algorithm = algorithm
        self._constructor = HASHLIB_ALGORITHMS[underlying]

    def metadata(self) -> ProviderMetadata:
        """Identify hashlib and the OpenSSL build behind it."""
        return _python_metadata(f"hashlib-{self._algorithm.lower().replace('/', '-')}")

    def mac(self, *, key: bytes, message: bytes, mac_length_bits: int) -> bytes:
        """Compute the MAC and truncate it to the requested bit length."""
        if mac_length_bits <= 0 or mac_length_bits % 8 != 0:
            raise ValueError("macLen must be a positive multiple of 8")
        full = hmac.new(key, message, self._constructor).digest()
        length = mac_length_bits // 8
        if length > len(full):
            raise ValueError("macLen exceeds the underlying digest length")
        return full[:length]


__all__ = [
    "HASHLIB_ALGORITHMS",
    "SHA3_ALGORITHMS",
    "XOF_ALGORITHMS",
    "XofProvider",
    "MCT_INNER_ITERATIONS",
    "MCT_OUTER_ITERATIONS",
    "HashProvider",
    "HashlibHashProvider",
    "HashlibMacProvider",
    "HashlibXofProvider",
    "MacProvider",
    "SubprocessHashProvider",
    "SubprocessMacProvider",
    "SubprocessXofProvider",
    "monte_carlo",
    "monte_carlo_sha3",
    "ssl_version_text",
]


class HashlibXofProvider:
    """SHAKE through Python's ``hashlib``."""

    def metadata(self) -> ProviderMetadata:
        """Record the interpreter and the OpenSSL hashlib is built against."""
        return _python_metadata("hashlib-shake")

    def squeeze(self, *, algorithm: str, message: bytes, output_bytes: int) -> bytes:
        """Squeeze ``output_bytes`` from the named XOF."""
        constructor = XOF_ALGORITHMS.get(algorithm)
        if constructor is None:
            raise ValueError(f"unsupported extendable-output function {algorithm!r}")
        return constructor(message).digest(output_bytes)


class SubprocessXofProvider(HarnessClient):
    """SHAKE performed by an external harness."""

    def squeeze(self, *, algorithm: str, message: bytes, output_bytes: int) -> bytes:
        """Ask the harness for exactly this many bytes.

        ``outLen`` is sent in bits, matching ACVP, so a harness reading the
        request does not have to know this runner's internal units.
        """
        return decode_hex(
            self.invoke(
                {
                    "operation": "xof",
                    "algorithm": algorithm,
                    "message": message.hex().upper(),
                    "outLen": output_bytes * 8,
                }
            ),
            "md",
        )


class SubprocessHashProvider(HarnessClient):
    """Message digests computed by an external harness.

    The Monte Carlo chain is delegated whole rather than driven case by case:
    at 100,000 inner iterations, one process spawn per hash would take hours.
    Running the chain is what a real implementation under test does anyway.
    """

    def __init__(self, algorithm: str, command: Sequence[str], **kwargs: float) -> None:
        super().__init__(command, **kwargs)
        self._algorithm = algorithm

    def digest(self, message: bytes) -> bytes:
        """Hash one complete message through the harness."""
        response = self.invoke(
            {
                "operation": "digest",
                "algorithm": self._algorithm,
                "message": message.hex().upper(),
            }
        )
        return decode_hex(response, "md")

    def digest_mct(self, seed: bytes, *, alternate: bool) -> list[bytes]:
        """Ask the harness to run the whole Monte Carlo chain and return its outputs."""
        response = self.invoke(
            {
                "operation": "digest-mct",
                "algorithm": self._algorithm,
                "seed": seed.hex().upper(),
                "alternate": alternate,
            }
        )
        values = response.get("md")
        if not isinstance(values, list):
            raise HarnessProtocolError("harness returned no 'md' array for the Monte Carlo chain")
        digests: list[bytes] = []
        for index, value in enumerate(values):
            if not isinstance(value, str):
                raise HarnessProtocolError(f"harness returned a non-string md at index {index}")
            try:
                digests.append(bytes.fromhex(value))
            except ValueError:
                raise HarnessProtocolError(
                    f"harness returned invalid hex md at index {index}"
                ) from None
        return digests


class SubprocessMacProvider(HarnessClient):
    """Keyed MACs computed by an external harness."""

    def __init__(self, algorithm: str, command: Sequence[str], **kwargs: float) -> None:
        super().__init__(command, **kwargs)
        self._algorithm = algorithm

    def mac(self, *, key: bytes, message: bytes, mac_length_bits: int) -> bytes:
        """Compute a MAC through the harness, truncated to the requested length."""
        response = self.invoke(
            {
                "operation": "mac",
                "algorithm": self._algorithm,
                "key": key.hex().upper(),
                "message": message.hex().upper(),
                "macLen": mac_length_bits,
            }
        )
        return decode_hex(response, "mac")
