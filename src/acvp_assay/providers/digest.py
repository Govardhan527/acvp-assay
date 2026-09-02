"""Hash and MAC provider boundaries, and their hashlib-backed implementations."""

from __future__ import annotations

import hashlib
import hmac
import platform
import sys
from collections.abc import Callable
from typing import Protocol, runtime_checkable

from acvp_assay.models import ProviderMetadata

MCT_OUTER_ITERATIONS = 100
MCT_INNER_ITERATIONS = 1000

#: ACVP algorithm name to the hashlib constructor name behind it.
HASHLIB_ALGORITHMS = {
    "SHA2-224": "sha224",
    "SHA2-256": "sha256",
    "SHA2-384": "sha384",
    "SHA2-512": "sha512",
    "SHA2-512/224": "sha512_224",
    "SHA2-512/256": "sha512_256",
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


def monte_carlo(
    seed: bytes,
    digest: Callable[[bytes], bytes],
    *,
    alternate: bool,
) -> list[bytes]:
    """Run the ACVP SHA Monte Carlo chain, returning the 100 outer digests.

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
        """Run the Monte Carlo chain using this algorithm."""
        return monte_carlo(seed, self.digest, alternate=alternate)


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
    "MCT_INNER_ITERATIONS",
    "MCT_OUTER_ITERATIONS",
    "HashProvider",
    "HashlibHashProvider",
    "HashlibMacProvider",
    "MacProvider",
    "monte_carlo",
    "ssl_version_text",
]
