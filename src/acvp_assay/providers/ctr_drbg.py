"""CTR_DRBG (SP 800-90A) — the one algorithm nearly every FIPS module contains.

Unlike everything else behind a provider here, a DRBG is a *state machine*
rather than a one-shot transform. A case instantiates it, optionally reseeds
it, and generates twice; only the second generation is compared. That shape is
why this needed a new provider rather than another method on an existing one.

Three-key TDES is deliberately absent. SP 800-131A disallowed it for this use
after 2023, and the upstream vectors still carry TDES groups, so those cases
are reported UNSUPPORTED rather than answered with a deprecated primitive.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from acvp_assay.models import ProviderMetadata

#: Key and block length in bytes for each supported ``mode``.
BLOCK_CIPHERS: dict[str, tuple[int, int]] = {
    "AES-128": (16, 16),
    "AES-192": (24, 16),
    "AES-256": (32, 16),
}

_DF_KEY = bytes(range(32))


@runtime_checkable
class CtrDrbgProvider(Protocol):
    """Replaceable boundary for one CTR_DRBG instance's lifetime."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def instantiate(
        self,
        *,
        mode: str,
        derivation_function: bool,
        counter_field_bits: int,
        entropy: bytes,
        nonce: bytes,
        personalization: bytes,
    ) -> None:
        """Seed a fresh instance. Must be called before reseed or generate."""
        ...

    def reseed(self, *, entropy: bytes, additional_input: bytes) -> None:
        """Fold fresh entropy into the working state."""
        ...

    def generate(self, *, byte_count: int, additional_input: bytes) -> bytes:
        """Produce output, updating the state afterwards as the standard requires."""
        ...


class CryptographyCtrDrbg:
    """CTR_DRBG over an AES block cipher from cryptography's OpenSSL binding.

    One object is one DRBG instance: ``instantiate`` resets it, so a caller
    runs one test case per object.
    """

    def __init__(self) -> None:
        """Create an uninstantiated DRBG."""
        self._key = b""
        self._v = b""
        self._key_length = 0
        self._block_length = 0
        self._seed_length = 0
        self._counter_bits = 0
        self._derivation_function = False

    def metadata(self) -> ProviderMetadata:
        """Identify both the Python binding and the OpenSSL backend."""
        return ProviderMetadata(
            name="cryptography-ctr-drbg",
            library_name="cryptography",
            library_version=cryptography.__version__,
            backend_name="OpenSSL",
            backend_version=backend.openssl_version_text(),
        )

    def _encrypt(self, key: bytes, block: bytes) -> bytes:
        """Encrypt one block. ECB is the raw block-cipher call the standard specifies."""
        encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305
        return encryptor.update(block) + encryptor.finalize()

    def _increment(self) -> None:
        """Add one to V, touching only the rightmost ``counterFieldLen`` bits.

        The whole block increments in the original SP 800-90A. The r1 revision
        allows a narrower counter field, leaving the leading bits fixed, so
        this is a mask-and-wrap rather than a plain integer add.
        """
        value = int.from_bytes(self._v, "big")
        counter_mask = (1 << self._counter_bits) - 1
        fixed = value & ~counter_mask
        counter = (value + 1) & counter_mask
        self._v = (fixed | counter).to_bytes(self._block_length, "big")

    def _bcc(self, key: bytes, data: bytes) -> bytes:
        """CBC-MAC over whole blocks, as the derivation function's inner step."""
        chaining = b"\x00" * self._block_length
        for offset in range(0, len(data), self._block_length):
            block = data[offset : offset + self._block_length]
            chaining = self._encrypt(
                key, bytes(a ^ b for a, b in zip(chaining, block, strict=True))
            )
        return chaining

    def _derive(self, data: bytes, byte_count: int) -> bytes:
        """Block_Cipher_df: condense arbitrary input to exactly ``byte_count`` bytes."""
        prefix = len(data).to_bytes(4, "big") + byte_count.to_bytes(4, "big")
        block = prefix + data + b"\x80"
        remainder = len(block) % self._block_length
        if remainder:
            block += b"\x00" * (self._block_length - remainder)

        key = _DF_KEY[: self._key_length]
        temp = b""
        counter = 0
        while len(temp) < self._key_length + self._block_length:
            iv = counter.to_bytes(4, "big") + b"\x00" * (self._block_length - 4)
            temp += self._bcc(key, iv + block)
            counter += 1

        derived_key = temp[: self._key_length]
        chunk = temp[self._key_length : self._key_length + self._block_length]
        output = b""
        while len(output) < byte_count:
            chunk = self._encrypt(derived_key, chunk)
            output += chunk
        return output[:byte_count]

    def _update(self, provided: bytes) -> None:
        """CTR_DRBG_Update: refresh Key and V from exactly one seed length of input."""
        temp = b""
        while len(temp) < self._seed_length:
            self._increment()
            temp += self._encrypt(self._key, self._v)
        mixed = bytes(a ^ b for a, b in zip(temp[: self._seed_length], provided, strict=True))
        self._key = mixed[: self._key_length]
        self._v = mixed[self._key_length :]

    def _fit(self, data: bytes) -> bytes:
        """Pad or truncate to one seed length, for the no-derivation-function path."""
        return data.ljust(self._seed_length, b"\x00")[: self._seed_length]

    def _seed_material(self, entropy: bytes, extra: bytes) -> bytes:
        """Combine entropy with additional input, by whichever route is configured."""
        if self._derivation_function:
            return self._derive(entropy + extra, self._seed_length)
        return bytes(a ^ b for a, b in zip(self._fit(entropy), self._fit(extra), strict=True))

    def instantiate(
        self,
        *,
        mode: str,
        derivation_function: bool,
        counter_field_bits: int,
        entropy: bytes,
        nonce: bytes,
        personalization: bytes,
    ) -> None:
        """Seed a fresh instance from entropy, nonce and personalization string."""
        try:
            self._key_length, self._block_length = BLOCK_CIPHERS[mode]
        except KeyError as error:
            raise ValueError(f"unsupported CTR_DRBG mode {mode!r}") from error
        self._seed_length = self._key_length + self._block_length
        self._counter_bits = counter_field_bits or self._block_length * 8
        self._derivation_function = derivation_function
        self._key = b"\x00" * self._key_length
        self._v = b"\x00" * self._block_length

        material = (
            self._derive(entropy + nonce + personalization, self._seed_length)
            if derivation_function
            else self._seed_material(entropy, personalization)
        )
        self._update(material)

    def reseed(self, *, entropy: bytes, additional_input: bytes) -> None:
        """Fold fresh entropy and any additional input back into the state."""
        self._update(self._seed_material(entropy, additional_input))

    def generate(self, *, byte_count: int, additional_input: bytes) -> bytes:
        """Produce ``byte_count`` bytes, then update the state as the standard requires.

        The trailing update is what stops the output being a plain counter-mode
        keystream: without it, a caller who learns the state can read backwards.
        """
        if additional_input:
            prepared = (
                self._derive(additional_input, self._seed_length)
                if self._derivation_function
                else self._fit(additional_input)
            )
            self._update(prepared)
        else:
            prepared = b"\x00" * self._seed_length

        output = b""
        while len(output) < byte_count:
            self._increment()
            output += self._encrypt(self._key, self._v)
        self._update(prepared)
        return output[:byte_count]


__all__ = ["BLOCK_CIPHERS", "CryptographyCtrDrbg", "CtrDrbgProvider"]
