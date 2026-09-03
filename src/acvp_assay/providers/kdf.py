"""SP 800-108 key derivation: counter, feedback and double-pipeline modes.

The three modes differ only in what they feed the PRF on each iteration, so
they share one provider. What makes this family awkward is not the modes but
the placement rules around them: the iteration counter can sit before the fixed
data, after it, before the feedback value, nowhere at all, or *inside* the
fixed data at a bit offset that need not fall on a byte boundary.

Requested output lengths are likewise in bits rather than bytes, and the
upstream set asks for lengths such as 331 and 1003, so the final byte carries
padding bits that must be cleared. An implementation that returns whole bytes
disagrees with NIST on roughly one case in eight.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

from acvp_assay.models import ProviderMetadata
from acvp_assay.providers.subprocess_harness import HarnessClient, decode_hex

#: ACVP ``macMode`` to the hashlib name backing its HMAC.
HMAC_MODES: dict[str, str] = {
    "HMAC-SHA-1": "sha1",
    "HMAC-SHA2-224": "sha224",
    "HMAC-SHA2-256": "sha256",
    "HMAC-SHA2-384": "sha384",
    "HMAC-SHA2-512": "sha512",
    "HMAC-SHA2-512/224": "sha512_224",
    "HMAC-SHA2-512/256": "sha512_256",
    "HMAC-SHA3-224": "sha3_224",
    "HMAC-SHA3-256": "sha3_256",
    "HMAC-SHA3-384": "sha3_384",
    "HMAC-SHA3-512": "sha3_512",
}

#: ACVP ``macMode`` to the AES key length its CMAC requires, in bytes.
CMAC_MODES: dict[str, int] = {"CMAC-AES128": 16, "CMAC-AES192": 24, "CMAC-AES256": 32}

COUNTER = "counter"
FEEDBACK = "feedback"
DOUBLE_PIPELINE = "double pipeline iteration"
KDF_MODES = (COUNTER, FEEDBACK, DOUBLE_PIPELINE)

BEFORE_FIXED = "before fixed data"
AFTER_FIXED = "after fixed data"
MIDDLE_FIXED = "middle fixed data"
BEFORE_ITERATOR = "before iterator"
NO_COUNTER = "none"
COUNTER_LOCATIONS = (BEFORE_FIXED, AFTER_FIXED, MIDDLE_FIXED, BEFORE_ITERATOR, NO_COUNTER)


@dataclass(frozen=True, slots=True)
class KdfRequest:
    """One derivation. Grouped into an object because SP 800-108 has this many knobs."""

    mac_mode: str
    kdf_mode: str
    counter_location: str
    counter_bits: int
    key_in: bytes
    fixed_data: bytes
    output_bits: int
    iv: bytes = b""
    break_location: int = 0


@runtime_checkable
class KdfProvider(Protocol):
    """Replaceable boundary for SP 800-108 derivation."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def derive(self, request: KdfRequest) -> bytes:
        """Derive keying material. Raises ValueError for a request it cannot honour."""
        ...


def _mask_to_bits(data: bytes, bit_count: int) -> bytes:
    """Truncate to ``bit_count`` bits, clearing any padding bits in the last byte."""
    length = -(-bit_count // 8)
    truncated = bytearray(data[:length])
    used = bit_count % 8
    if used:
        truncated[-1] &= (0xFF << (8 - used)) & 0xFF
    return bytes(truncated)


def _splice(fixed_data: bytes, counter: int, counter_bits: int, break_location: int) -> bytes:
    """Insert the counter into the fixed data at a bit offset.

    ``breakLocation`` counts bits, not bytes, and the upstream set uses offsets
    such as 51 and 105, so this cannot be done by slicing the byte string.
    """
    total_bits = len(fixed_data) * 8
    whole = int.from_bytes(fixed_data, "big")
    tail_bits = total_bits - break_location
    head = whole >> tail_bits
    tail = whole & ((1 << tail_bits) - 1)
    joined = (head << (counter_bits + tail_bits)) | (counter << tail_bits) | tail
    return joined.to_bytes((total_bits + counter_bits) // 8, "big")


class CryptographyKdf:
    """SP 800-108 over HMAC and CMAC-AES from cryptography and hashlib."""

    def metadata(self) -> ProviderMetadata:
        """Identify both the Python binding and the OpenSSL backend."""
        return ProviderMetadata(
            name="cryptography-kdf-sp800-108",
            library_name="cryptography",
            library_version=cryptography.__version__,
            backend_name="OpenSSL",
            backend_version=backend.openssl_version_text(),
        )

    def _prf(self, mac_mode: str, key: bytes, data: bytes) -> bytes:
        """Apply the group's pseudorandom function."""
        digest_name = HMAC_MODES.get(mac_mode)
        if digest_name is not None:
            return hmac.new(key, data, digest_name).digest()
        expected_length = CMAC_MODES.get(mac_mode)
        if expected_length is None:
            raise ValueError(f"unsupported macMode {mac_mode!r}")
        if len(key) != expected_length:
            raise ValueError(f"{mac_mode} needs a {expected_length}-byte key")
        context = cmac.CMAC(algorithms.AES(key))
        context.update(data)
        return context.finalize()

    def _counter(self, iteration: int, counter_bits: int) -> bytes:
        """Encode the iteration counter, or nothing when the mode omits it."""
        return iteration.to_bytes(counter_bits // 8, "big") if counter_bits else b""

    def _place(self, request: KdfRequest, iteration: int, iterator: bytes, counter: bytes) -> bytes:
        """Assemble one PRF input from the iterator, fixed data and counter."""
        if request.counter_location == BEFORE_ITERATOR:
            return counter + iterator + request.fixed_data
        if request.counter_location == BEFORE_FIXED:
            return iterator + counter + request.fixed_data
        if request.counter_location == AFTER_FIXED:
            return iterator + request.fixed_data + counter
        if request.counter_location == MIDDLE_FIXED:
            return iterator + _splice(
                request.fixed_data, iteration, request.counter_bits, request.break_location
            )
        return iterator + request.fixed_data

    def derive(self, request: KdfRequest) -> bytes:
        """Derive ``output_bits`` bits of keying material."""
        if request.kdf_mode not in KDF_MODES:
            raise ValueError(f"unsupported kdfMode {request.kdf_mode!r}")
        if request.counter_location not in COUNTER_LOCATIONS:
            raise ValueError(f"unsupported counterLocation {request.counter_location!r}")
        if request.output_bits <= 0:
            raise ValueError("keyOutLength must be positive")

        prf_bits = len(self._prf(request.mac_mode, request.key_in, b"")) * 8
        iterations = -(-request.output_bits // prf_bits)

        derived = b""
        feedback = request.iv
        pipeline = request.fixed_data
        for iteration in range(1, iterations + 1):
            counter = self._counter(iteration, request.counter_bits)
            if request.kdf_mode == COUNTER:
                block = self._place(request, iteration, b"", counter)
                derived += self._prf(request.mac_mode, request.key_in, block)
            elif request.kdf_mode == FEEDBACK:
                block = self._place(request, iteration, feedback, counter)
                feedback = self._prf(request.mac_mode, request.key_in, block)
                derived += feedback
            else:
                pipeline = self._prf(request.mac_mode, request.key_in, pipeline)
                block = self._place(request, iteration, pipeline, counter)
                derived += self._prf(request.mac_mode, request.key_in, block)
        return _mask_to_bits(derived, request.output_bits)


def supported_mac_modes() -> tuple[str, ...]:
    """Every ``macMode`` this provider implements."""
    return (*HMAC_MODES, *CMAC_MODES)


__all__ = [
    "AFTER_FIXED",
    "BEFORE_FIXED",
    "BEFORE_ITERATOR",
    "CMAC_MODES",
    "COUNTER",
    "COUNTER_LOCATIONS",
    "DOUBLE_PIPELINE",
    "FEEDBACK",
    "HMAC_MODES",
    "KDF_MODES",
    "MIDDLE_FIXED",
    "NO_COUNTER",
    "CryptographyKdf",
    "KdfProvider",
    "KdfRequest",
    "supported_mac_modes",
]


class SubprocessKdfProvider(HarnessClient):
    """SP 800-108 derivation performed by an external harness.

    One request per case. ``fixedData`` travels *in* rather than being chosen
    by the harness: the offline runner derives against the fixed data NIST
    recorded, so that the two can be compared at all. A harness free to choose
    its own would produce a different key every run and nothing to check it
    against.
    """

    def derive(self, request: KdfRequest) -> bytes:
        """Derive keying material through the harness."""
        return decode_hex(
            self.invoke(
                {
                    "operation": "kdf-108",
                    "kdfMode": request.kdf_mode,
                    "macMode": request.mac_mode,
                    "counterLocation": request.counter_location,
                    "counterLength": request.counter_bits,
                    "keyOutLength": request.output_bits,
                    "keyIn": request.key_in.hex().upper(),
                    "fixedData": request.fixed_data.hex().upper(),
                    "iv": request.iv.hex().upper(),
                    "breakLocation": request.break_location,
                }
            ),
            "keyOut",
        )
