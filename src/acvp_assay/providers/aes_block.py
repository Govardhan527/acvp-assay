"""AES-CBC, AES-CTR, AES-OFB and AES-CFB128: the chaining modes.

These are the modes that carry state between blocks, which is what separates
them from ECB and from the authenticated modes. They are grouped because their
Monte Carlo tests are one algorithm: CBC, OFB and CFB128 share the specification's
pseudocode exactly, differing only in which primitive is called.

CTR has no Monte Carlo test at all. ACVP gives it a ``CTR`` test type, but the
implementation under test processes those as ordinary functional tests -- the
counter behaviour is checked server-side by back-computing the IVs. So a CTR
group needs no chain, and inventing one would answer a question nobody asked.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, cast, runtime_checkable

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from acvp_assay.models import ProviderMetadata
from acvp_assay.providers.aes_modes import (
    MCT_INNER_ITERATIONS,
    MCT_OUTER_ITERATIONS,
    key_shuffle,
)
from acvp_assay.providers.subprocess_harness import (
    HarnessClient,
    decode_hex,
    decode_mct_quads,
)

#: CFB and OFB move to `decrepit` in cryptography 49 and warn before that, so
#: these follow the move where it exists rather than pinning to one side of it.
_CFB: Callable[[bytes], modes.Mode]
_OFB: Callable[[bytes], modes.Mode]
_CFB8: Callable[[bytes], modes.Mode]
try:  # pragma: no cover - which branch runs depends on the installed version
    from cryptography.hazmat.decrepit.ciphers.modes import CFB as _decrepit_cfb
    from cryptography.hazmat.decrepit.ciphers.modes import CFB8 as _decrepit_cfb8
    from cryptography.hazmat.decrepit.ciphers.modes import OFB as _decrepit_ofb

    _CFB, _OFB, _CFB8 = _decrepit_cfb, _decrepit_ofb, _decrepit_cfb8
except ImportError:  # pragma: no cover - older cryptography has no `decrepit`
    _CFB, _OFB, _CFB8 = modes.CFB, modes.OFB, modes.CFB8

CBC = "ACVP-AES-CBC"
CTR = "ACVP-AES-CTR"
OFB = "ACVP-AES-OFB"
CFB128 = "ACVP-AES-CFB128"
CFB8 = "ACVP-AES-CFB8"
CFB1 = "ACVP-AES-CFB1"

#: Modes this provider implements, and whether they define a Monte Carlo test.
CHAINING_MODES: dict[str, bool] = {
    CBC: True,
    OFB: True,
    CFB128: True,
    CFB8: True,
    CFB1: True,
    CTR: False,
}

#: CFB modes whose feedback advances by less than a block, and by how many bits.
#: CFB128 is deliberately absent: its segment *is* the block, which is what lets
#: it share the whole-block chain with CBC and OFB. These two cannot.
SEGMENT_BITS: dict[str, int] = {CFB8: 8, CFB1: 1}

#: The AES block, in bits. A segment chain feeds back a whole block's worth of
#: segments, so this also fixes how far back the plaintext feed reaches.
BLOCK_BITS = 128

#: One outer Monte Carlo iteration: the key, IV and input in force, and the output.
McQuad = tuple[bytes, bytes, bytes, bytes]


def _to_bits(data: bytes, count: int) -> list[int]:
    """The first ``count`` bits of ``data``, most significant bit first."""
    return [(data[index // 8] >> (7 - index % 8)) & 1 for index in range(count)]


def _from_bits(values: list[int]) -> bytes:
    """Pack bits most significant first, zero padding the final byte.

    ACVP carries a bit string as hex, so a one-bit payload of 1 travels as
    ``80`` rather than ``01``. Packing the other way round produces answers that
    are right about the cipher and wrong about the encoding.
    """
    packed = bytearray((len(values) + 7) // 8)
    for index, bit in enumerate(values):
        if bit:
            packed[index // 8] |= 1 << (7 - index % 8)
    return bytes(packed)


def _mode_for(algorithm: str, iv: bytes) -> modes.Mode:
    """Build the cryptography mode object for one ACVP algorithm name.

    CFB and OFB moved to ``cryptography.hazmat.decrepit`` and leave
    ``primitives.ciphers.modes`` in version 49. ACVP still tests both, so this
    follows the move where it exists and falls back where it does not, rather
    than pinning the package to one side of that change.
    """
    if algorithm == CBC:
        return modes.CBC(iv)
    if algorithm == OFB:
        return _OFB(iv)
    if algorithm == CFB128:
        return _CFB(iv)
    if algorithm == CFB8:
        return _CFB8(iv)
    if algorithm == CTR:
        return modes.CTR(iv)
    raise ValueError(f"unsupported chaining mode {algorithm!r}")


@runtime_checkable
class AesBlockProvider(Protocol):
    """Replaceable boundary for the AES chaining modes."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def transform(
        self,
        *,
        algorithm: str,
        key: bytes,
        iv: bytes,
        data: bytes,
        encrypt: bool,
        payload_bits: int | None = None,
    ) -> bytes:
        """Encrypt or decrypt in the named chaining mode.

        ``payload_bits`` is the payload length in bits, and is required only by
        CFB1, whose payload is not a whole number of bytes.
        """
        ...

    def monte_carlo(
        self,
        *,
        algorithm: str,
        key: bytes,
        iv: bytes,
        data: bytes,
        encrypt: bool,
        payload_bits: int | None = None,
    ) -> list[McQuad]:
        """Run the chaining-mode Monte Carlo chain, one quad per outer iteration."""
        ...


class CryptographyAesBlockProvider:
    """AES chaining modes backed by cryptography's OpenSSL binding."""

    def metadata(self) -> ProviderMetadata:
        """Identify both the Python binding and the OpenSSL backend."""
        return ProviderMetadata(
            name="cryptography-aes-block",
            library_name="cryptography",
            library_version=cryptography.__version__,
            backend_name="OpenSSL",
            backend_version=backend.openssl_version_text(),
        )

    def transform(
        self,
        *,
        algorithm: str,
        key: bytes,
        iv: bytes,
        data: bytes,
        encrypt: bool,
        payload_bits: int | None = None,
    ) -> bytes:
        """Encrypt or decrypt one payload in the named mode."""
        if algorithm == CFB1:
            return self._cfb1(
                key=key,
                iv=iv,
                data=data,
                encrypt=encrypt,
                count=len(data) * 8 if payload_bits is None else payload_bits,
            )
        # Cipher is generic over its mode, and an unnarrowed `Mode` resolves to
        # the AEAD overload of encryptor()/decryptor(). None of these four modes
        # is authenticated; CTR carries a nonce rather than an IV but exposes the
        # same construction, and neither attribute is read here.
        mode = cast(modes.ModeWithInitializationVector, _mode_for(algorithm, iv))
        cipher = Cipher(algorithms.AES(key), mode)
        operation = cipher.encryptor() if encrypt else cipher.decryptor()
        return operation.update(data) + operation.finalize()

    def _cfb1(self, *, key: bytes, iv: bytes, data: bytes, encrypt: bool, count: int) -> bytes:
        """AES-CFB1 one bit at a time.

        No library offers CFB1 -- ``cryptography`` stops at CFB8 -- so the shift
        register is driven here. Each step encrypts the register, takes its most
        significant bit as the keystream, and shifts the *ciphertext* bit in at
        the bottom: the output bit when encrypting, the input bit when
        decrypting. That asymmetry is the same one the whole-block chains have,
        and getting it backwards produces a decrypt that disagrees from the
        first bit.
        """
        register = _to_bits(iv, BLOCK_BITS)
        source = _to_bits(data, count)
        produced: list[int] = []
        for bit in source:
            keystream = (self._block(key, _from_bits(register))[0] >> 7) & 1
            output = keystream ^ bit
            produced.append(output)
            register = register[1:] + [output if encrypt else bit]
        return _from_bits(produced)

    def _block(self, key: bytes, block: bytes) -> bytes:
        """One raw AES block encryption, the primitive every CFB mode calls."""
        cipher = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        return cipher.update(block) + cipher.finalize()

    def _segment_monte_carlo(
        self, *, algorithm: str, key: bytes, iv: bytes, data: bytes, encrypt: bool
    ) -> list[McQuad]:
        """The Monte Carlo chain for CFB8 and CFB1.

        This is a different algorithm from the whole-block chain, not a
        parameterisation of it. A segment mode feeds back one segment per step,
        so a block's worth of feedback takes ``BLOCK_BITS // segment`` steps, and
        the plaintext for step ``j`` comes from the IV while the register still
        holds it and from the output ``span`` steps back once it does not::

            input[0]      = the case's input
            input[j + 1]  = IV segment j          for j < span
            input[j + 1]  = output[j - span]      for j >= span

        The key is then XORed with the last ``len(key)`` bytes of output rather
        than with whole blocks, the next IV is the last ``span`` segments, and
        the next input is the segment before those. Every rule here was checked
        against the 100 outer iterations the live server returns, in both
        directions; none of it was taken from prose.
        """
        segment = SEGMENT_BITS[algorithm]
        span = BLOCK_BITS // segment
        results: list[McQuad] = []
        for _ in range(MCT_OUTER_ITERATIONS):
            register = _to_bits(iv, BLOCK_BITS)
            iv_segments = [
                register[index * segment : (index + 1) * segment] for index in range(span)
            ]
            fed = _to_bits(data, segment)
            produced: list[list[int]] = []
            for step in range(MCT_INNER_ITERATIONS):
                keystream = _to_bits(self._block(key, _from_bits(register)), segment)
                output = [a ^ b for a, b in zip(keystream, fed, strict=True)]
                produced.append(output)
                register = register[segment:] + (output if encrypt else fed)
                fed = iv_segments[step] if step < span else produced[step - span]
            stream = [bit for chunk in produced for bit in chunk]
            results.append((key, iv, data, _from_bits(produced[-1])))
            # The key takes the last keyLen bits of output, which is more than
            # one block once the key is 192 or 256 bits; the IV takes the last
            # block's worth regardless.
            material = _from_bits(stream[-len(key) * 8 :])
            key = bytes(a ^ b for a, b in zip(key, material, strict=True))
            data = _from_bits(produced[-span - 1])
            iv = _from_bits(stream[-BLOCK_BITS:])
        return results

    def _advance_iv(
        self,
        algorithm: str,
        *,
        key: bytes,
        iv: bytes,
        fed: bytes,
        produced: bytes,
        encrypt: bool,
    ) -> bytes:
        """Advance the cipher's IV exactly as a stateful implementation would.

        This is the whole difficulty of these chains, and the specification's
        pseudocode hides it: it writes the inner loop as a cipher that
        "continues" from the previous call without saying what continuing does
        to the IV. Each mode answers differently. Each answer below was taken
        from NIST's own generator -- ``MonteCarloAesCbc.cs`` and its siblings in
        usnistgov/ACVP-Server, where the encrypt and decrypt routines are
        structurally identical and the asymmetry lives entirely inside the
        cipher object -- and then confirmed against the live server's arrays.

        * CBC and CFB128 **encrypting**: the IV becomes the ciphertext just
          produced.
        * CBC and CFB128 **decrypting**: the IV becomes the ciphertext just
          *consumed*. Input, not output. This asymmetry is why a chain written
          by mirroring the encrypt pseudocode runs to completion and disagrees
          with NIST from the very first block.
        * OFB in **either** direction: the IV becomes the raw keystream block,
          which is neither the input nor the output, because OFB's feedback
          never touches the data.
        """
        if algorithm == OFB:
            # The keystream block is the bare block-cipher output over the IV.
            return self.transform(
                algorithm=CBC, key=key, iv=b"\x00" * len(iv), data=iv, encrypt=True
            )
        return produced if encrypt else fed

    def monte_carlo(
        self,
        *,
        algorithm: str,
        key: bytes,
        iv: bytes,
        data: bytes,
        encrypt: bool,
        payload_bits: int | None = None,
    ) -> list[McQuad]:
        """Run the CBC, OFB or CFB128 Monte Carlo chain.

        The payload chain is shared by all three modes and both directions::

            payload[0] = the case's input
            payload[1] = IV
            payload[j] = output[j - 2]   for j >= 2

        Only the IV advance differs between them; see :meth:`_advance_iv`.
        """
        if not CHAINING_MODES.get(algorithm, False):
            raise ValueError(f"{algorithm} has no Monte Carlo test")
        if algorithm in SEGMENT_BITS:
            return self._segment_monte_carlo(
                algorithm=algorithm, key=key, iv=iv, data=data, encrypt=encrypt
            )

        results: list[McQuad] = []
        for _ in range(MCT_OUTER_ITERATIONS):
            first_input = data
            feedback = iv
            payload = data
            previous = b""
            carried = b""
            for iteration in range(MCT_INNER_ITERATIONS):
                produced = self.transform(
                    algorithm=algorithm, key=key, iv=feedback, data=payload, encrypt=encrypt
                )
                feedback = self._advance_iv(
                    algorithm,
                    key=key,
                    iv=feedback,
                    fed=payload,
                    produced=produced,
                    encrypt=encrypt,
                )
                if iteration == 0:
                    previous = iv
                carried = previous
                payload = previous
                previous = produced
            results.append((key, iv, first_input, previous))
            key = key_shuffle(key, previous, carried)
            iv = previous
            data = carried
        return results


__all__ = [
    "BLOCK_BITS",
    "CBC",
    "CFB1",
    "CFB8",
    "CFB128",
    "CHAINING_MODES",
    "CTR",
    "OFB",
    "SEGMENT_BITS",
    "AesBlockProvider",
    "CryptographyAesBlockProvider",
    "McQuad",
]


class SubprocessAesBlockProvider(HarnessClient):
    """AES chaining modes performed by an external harness.

    The Monte Carlo chain is delegated whole. Driving its 100 x 1000 inner
    iterations across the wire would be 100,000 exchanges per case, and running
    the chain is what a real implementation under test does anyway. Each outer
    iteration comes back as the key and IV in force, the input, and the output
    -- the four values ACVP records, and the two (last and previous output) the
    key shuffle needs.
    """

    def transform(
        self,
        *,
        algorithm: str,
        key: bytes,
        iv: bytes,
        data: bytes,
        encrypt: bool,
        payload_bits: int | None = None,
    ) -> bytes:
        """Encrypt or decrypt one payload through the harness."""
        request: dict[str, object] = {
            "operation": "block-transform",
            "algorithm": algorithm,
            "direction": "encrypt" if encrypt else "decrypt",
            "key": key.hex().upper(),
            "iv": iv.hex().upper(),
            "data": data.hex().upper(),
        }
        if payload_bits is not None:
            # Sent only for CFB1, whose payload is not a whole number of bytes.
            # Adding it unconditionally would change every existing harness's
            # input for modes where the byte count already says everything.
            request["payloadLen"] = payload_bits
        response = self.invoke(request)
        return decode_hex(response, "out")

    def monte_carlo(
        self,
        *,
        algorithm: str,
        key: bytes,
        iv: bytes,
        data: bytes,
        encrypt: bool,
        payload_bits: int | None = None,
    ) -> list[McQuad]:
        """Ask the harness to run the whole Monte Carlo chain."""
        if not CHAINING_MODES.get(algorithm, False):
            raise ValueError(f"{algorithm} has no Monte Carlo test")
        request: dict[str, object] = {
            "operation": "block-mct",
            "algorithm": algorithm,
            "direction": "encrypt" if encrypt else "decrypt",
            "key": key.hex().upper(),
            "iv": iv.hex().upper(),
            "data": data.hex().upper(),
        }
        if payload_bits is not None:
            request["payloadLen"] = payload_bits
        response = self.invoke(request)
        return decode_mct_quads(response)
