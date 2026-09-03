"""Hash_DRBG and HMAC_DRBG (SP 800-90A).

These complete the DRBG trio beside `ctr_drbg`. All three are state machines
with the same lifecycle -- instantiate, optionally reseed, generate twice -- so
they present the same boundary, and the two ``ctrDRBG``-specific options are
accepted and ignored here rather than splitting the runner into three paths.

The two mechanisms differ sharply inside. HMAC_DRBG keeps a key and a value and
advances both through an update routine. Hash_DRBG keeps a seed-length value
``V`` and a constant ``C``, and folds the reseed counter into ``V`` on every
generation, which is the part an implementation is most likely to omit.

Both were written from NIST's own generator -- ``DrbgHash.cs`` and
``DrbgHmac.cs`` in usnistgov/ACVP-Server -- rather than from the prose, and
then checked against the live server.
"""

from __future__ import annotations

import hashlib
import hmac

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend

from acvp_assay.models import ProviderMetadata
from acvp_assay.providers.digest import HASHLIB_ALGORITHMS

#: SP 800-90A seed lengths, in bits. The wider hashes get the wider seed.
SEED_LENGTH_BITS: dict[str, int] = {
    "SHA-1": 440,
    "SHA2-224": 440,
    "SHA2-256": 440,
    "SHA2-512/224": 440,
    "SHA2-512/256": 440,
    "SHA2-384": 888,
    "SHA2-512": 888,
}


def _digest_name(mode: str) -> str:
    """The hashlib constructor name for an ACVP DRBG ``mode``."""
    name = HASHLIB_ALGORITHMS.get(mode)
    if name is None or mode not in SEED_LENGTH_BITS:
        raise ValueError(f"unsupported DRBG mode {mode!r}")
    return name


def _metadata(name: str) -> ProviderMetadata:
    return ProviderMetadata(
        name=name,
        library_name="cryptography",
        library_version=cryptography.__version__,
        backend_name="OpenSSL",
        backend_version=backend.openssl_version_text(),
    )


class HmacDrbg:
    """HMAC_DRBG: a key and a value, both advanced by one update routine."""

    def __init__(self) -> None:
        """Create an uninstantiated DRBG."""
        self._digest = ""
        self._key = b""
        self._v = b""

    def metadata(self) -> ProviderMetadata:
        """Identify the binding and backend behind this DRBG."""
        return _metadata("hmac-drbg")

    def _hmac(self, key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, self._digest).digest()

    def _update(self, provided: bytes) -> None:
        """Advance Key and V, twice when there is data to fold in.

        The second pass is skipped for empty input, which is what makes a
        generation with no additional input differ from one with it.
        """
        self._key = self._hmac(self._key, self._v + b"\x00" + provided)
        self._v = self._hmac(self._key, self._v)
        if not provided:
            return
        self._key = self._hmac(self._key, self._v + b"\x01" + provided)
        self._v = self._hmac(self._key, self._v)

    def instantiate(
        self,
        *,
        mode: str,
        entropy: bytes,
        nonce: bytes,
        personalization: bytes,
        derivation_function: bool = False,
        counter_field_bits: int = 0,
    ) -> None:
        """Seed a fresh instance. The two ctrDRBG options do not apply here."""
        del derivation_function, counter_field_bits
        self._digest = _digest_name(mode)
        length = hashlib.new(self._digest).digest_size
        self._key = b"\x00" * length
        self._v = b"\x01" * length
        self._update(entropy + nonce + personalization)

    def reseed(self, *, entropy: bytes, additional_input: bytes) -> None:
        """Fold fresh entropy and any additional input into the state."""
        self._update(entropy + additional_input)

    def generate(self, *, byte_count: int, additional_input: bytes) -> bytes:
        """Produce output, updating the state before and after."""
        if additional_input:
            self._update(additional_input)
        output = b""
        while len(output) < byte_count:
            self._v = self._hmac(self._key, self._v)
            output += self._v
        # Run unconditionally: with no additional input this is still one pass
        # of the update routine, and skipping it desynchronises every later
        # generation.
        self._update(additional_input)
        return output[:byte_count]


class HashDrbg:
    """Hash_DRBG: a seed-length value V, a constant C, and a reseed counter."""

    def __init__(self) -> None:
        """Create an uninstantiated DRBG."""
        self._digest = ""
        self._seed_bytes = 0
        self._v = b""
        self._c = b""
        self._reseed_counter = 0

    def metadata(self) -> ProviderMetadata:
        """Identify the binding and backend behind this DRBG."""
        return _metadata("hash-drbg")

    def _hash(self, data: bytes) -> bytes:
        return hashlib.new(self._digest, data).digest()

    def _add(self, *values: bytes) -> bytes:
        """Sum values as big-endian integers, modulo the seed length."""
        total = sum(int.from_bytes(value, "big") for value in values)
        return (total % (1 << (self._seed_bytes * 8))).to_bytes(self._seed_bytes, "big")

    def _hash_df(self, data: bytes, byte_count: int) -> bytes:
        """The derivation function: counter and length prefixed to the input."""
        output = b""
        counter = 1
        while len(output) < byte_count:
            output += self._hash(bytes([counter]) + (byte_count * 8).to_bytes(4, "big") + data)
            counter += 1
        return output[:byte_count]

    def _reseed_state(self, seed_material: bytes) -> None:
        """Derive V and C from seed material, as instantiate and reseed both do."""
        self._v = self._hash_df(seed_material, self._seed_bytes)
        self._c = self._hash_df(b"\x00" + self._v, self._seed_bytes)
        self._reseed_counter = 1

    def instantiate(
        self,
        *,
        mode: str,
        entropy: bytes,
        nonce: bytes,
        personalization: bytes,
        derivation_function: bool = False,
        counter_field_bits: int = 0,
    ) -> None:
        """Seed a fresh instance. The two ctrDRBG options do not apply here."""
        del derivation_function, counter_field_bits
        self._digest = _digest_name(mode)
        self._seed_bytes = SEED_LENGTH_BITS[mode] // 8
        self._reseed_state(entropy + nonce + personalization)

    def reseed(self, *, entropy: bytes, additional_input: bytes) -> None:
        """Reseed from the current V, fresh entropy and any additional input."""
        self._reseed_state(b"\x01" + self._v + entropy + additional_input)

    def _hash_gen(self, byte_count: int) -> bytes:
        """Produce output by hashing V, incrementing it between blocks."""
        data = self._v
        output = b""
        while len(output) < byte_count:
            output += self._hash(data)
            data = self._add(data, b"\x01")
        return output[:byte_count]

    def generate(self, *, byte_count: int, additional_input: bytes) -> bytes:
        """Produce output, then fold H, C and the reseed counter back into V."""
        if additional_input:
            w = self._hash(b"\x02" + self._v + additional_input)
            self._v = self._add(self._v, w)
        output = self._hash_gen(byte_count)
        h = self._hash(b"\x03" + self._v)
        # The reseed counter is part of the sum: an implementation that folds
        # only H and C stays correct for exactly one generation.
        self._v = self._add(self._v, h, self._c, self._reseed_counter.to_bytes(4, "big"))
        self._reseed_counter += 1
        return output


__all__ = ["SEED_LENGTH_BITS", "HashDrbg", "HmacDrbg"]
