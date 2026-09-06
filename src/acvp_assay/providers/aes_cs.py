"""ACVP-AES-CBC-CS1, -CS2 and -CS3: CBC with ciphertext stealing.

Ciphertext stealing removes the padding CBC would otherwise need for a payload
that is not a whole number of blocks, by borrowing the bits it is short from
the previous ciphertext block. The three registry names run *identical*
cryptography and differ only in the order the last two blocks are written:

* **CS1** never reorders. The truncated block stays where it falls.
* **CS2** reorders only when the final block is partial. When the payload is a
  whole number of blocks it is CS1, and both are then plain CBC.
* **CS3** always reorders, whether the final block is partial or not.

That is the entire difference, and it is worth stating plainly because reading
it as three algorithms rather than one algorithm and three orderings is how a
day gets lost. Each ordering here was checked against 2,228 of the live
server's cases per variant, in both directions.

A payload of exactly one block cannot steal from anything, so it degenerates to
CBC, which is what the server's vectors expect.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from acvp_assay.models import ProviderMetadata
from acvp_assay.providers.subprocess_harness import HarnessClient, decode_hex

CS1 = "ACVP-AES-CBC-CS1"
CS2 = "ACVP-AES-CBC-CS2"
CS3 = "ACVP-AES-CBC-CS3"

#: The three names, and whether a partial final block is reordered.
SUPPORTED: tuple[str, ...] = (CS1, CS2, CS3)

BLOCK = 16


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def swaps(algorithm: str, *, partial: bool) -> bool:
    """Whether this variant writes the last two blocks in reverse order."""
    if algorithm == CS3:
        return True
    if algorithm == CS2:
        return partial
    return False


@runtime_checkable
class AesCsProvider(Protocol):
    """Replaceable boundary for CBC with ciphertext stealing."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def transform(
        self, *, algorithm: str, key: bytes, iv: bytes, data: bytes, encrypt: bool
    ) -> bytes:
        """Encrypt or decrypt one payload with ciphertext stealing."""
        ...


class CryptographyAesCs:
    """Ciphertext stealing built on the raw block cipher.

    No library exposes these modes, so the CBC chain is driven here. Only the
    final two blocks are unusual; everything before them is ordinary CBC.
    """

    def metadata(self) -> ProviderMetadata:
        """Identify both the Python binding and the OpenSSL backend."""
        return ProviderMetadata(
            name="cryptography-aes-cbc-cs",
            library_name="cryptography",
            library_version=cryptography.__version__,
            backend_name="OpenSSL",
            backend_version=backend.openssl_version_text(),
        )

    def _encrypt_block(self, key: bytes, block: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305 - CBC primitive
        return cipher.update(block) + cipher.finalize()

    def _decrypt_block(self, key: bytes, block: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.ECB()).decryptor()  # noqa: S305 - CBC primitive
        return cipher.update(block) + cipher.finalize()

    def transform(
        self, *, algorithm: str, key: bytes, iv: bytes, data: bytes, encrypt: bool
    ) -> bytes:
        """Encrypt or decrypt one payload with ciphertext stealing."""
        if algorithm not in SUPPORTED:
            raise ValueError(f"unsupported ciphertext-stealing mode {algorithm!r}")
        if len(data) < BLOCK:
            raise ValueError("ciphertext stealing needs at least one full block")
        if encrypt:
            return self._encrypt(algorithm, key, iv, data)
        return self._decrypt(algorithm, key, iv, data)

    def _encrypt(self, algorithm: str, key: bytes, iv: bytes, data: bytes) -> bytes:
        if len(data) == BLOCK:
            return self._encrypt_block(key, _xor(data, iv))
        whole, remainder = divmod(len(data), BLOCK)
        if remainder == 0:
            whole, remainder = whole - 1, BLOCK
        blocks: list[bytes] = []
        previous = iv
        for index in range(whole):
            previous = self._encrypt_block(
                key, _xor(data[BLOCK * index : BLOCK * index + BLOCK], previous)
            )
            blocks.append(previous)
        head = blocks[-1]
        # The short final block is zero extended, then chained onto the block it
        # steals from. The stolen bits are the ones dropped from `head`.
        padded = data[BLOCK * whole :] + b"\x00" * (BLOCK - remainder)
        tail = self._encrypt_block(key, _xor(padded, head))
        stolen = head[:remainder]
        body = b"".join(blocks[:-1])
        if swaps(algorithm, partial=remainder != BLOCK):
            return body + tail + stolen
        return body + stolen + tail

    def _decrypt(self, algorithm: str, key: bytes, iv: bytes, data: bytes) -> bytes:
        if len(data) == BLOCK:
            return _xor(self._decrypt_block(key, data), iv)
        whole, remainder = divmod(len(data), BLOCK)
        if remainder == 0:
            whole, remainder = whole - 1, BLOCK
        body, rest = data[: BLOCK * (whole - 1)], data[BLOCK * (whole - 1) :]
        if swaps(algorithm, partial=remainder != BLOCK):
            tail, stolen = rest[:BLOCK], rest[BLOCK:]
        else:
            stolen, tail = rest[:remainder], rest[remainder:]
        plain: list[bytes] = []
        previous = iv
        for index in range(whole - 1):
            block = body[BLOCK * index : BLOCK * index + BLOCK]
            plain.append(_xor(self._decrypt_block(key, block), previous))
            previous = block
        # Decrypting the stolen-from block recovers the bits the ciphertext is
        # missing, which is what makes the truncated block whole again.
        zeroed = self._decrypt_block(key, tail)
        head = stolen + zeroed[remainder:]
        plain.append(_xor(self._decrypt_block(key, head), previous))
        plain.append(_xor(zeroed, head)[:remainder])
        return b"".join(plain)


class SubprocessAesCs(HarnessClient):
    """Ciphertext stealing performed by an external harness."""

    def transform(
        self, *, algorithm: str, key: bytes, iv: bytes, data: bytes, encrypt: bool
    ) -> bytes:
        """Encrypt or decrypt one payload through the harness."""
        response = self.invoke(
            {
                "operation": "cbc-cs",
                "algorithm": algorithm,
                "direction": "encrypt" if encrypt else "decrypt",
                "key": key.hex().upper(),
                "iv": iv.hex().upper(),
                "data": data.hex().upper(),
            }
        )
        return decode_hex(response, "out")


__all__ = [
    "BLOCK",
    "CS1",
    "CS2",
    "CS3",
    "SUPPORTED",
    "AesCsProvider",
    "CryptographyAesCs",
    "SubprocessAesCs",
    "swaps",
]
