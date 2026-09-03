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

#: CFB and OFB move to `decrepit` in cryptography 49 and warn before that, so
#: these follow the move where it exists rather than pinning to one side of it.
_CFB: Callable[[bytes], modes.Mode]
_OFB: Callable[[bytes], modes.Mode]
try:  # pragma: no cover - which branch runs depends on the installed version
    from cryptography.hazmat.decrepit.ciphers.modes import CFB as _decrepit_cfb
    from cryptography.hazmat.decrepit.ciphers.modes import OFB as _decrepit_ofb

    _CFB, _OFB = _decrepit_cfb, _decrepit_ofb
except ImportError:  # pragma: no cover - older cryptography has no `decrepit`
    _CFB, _OFB = modes.CFB, modes.OFB

CBC = "ACVP-AES-CBC"
CTR = "ACVP-AES-CTR"
OFB = "ACVP-AES-OFB"
CFB128 = "ACVP-AES-CFB128"

#: Modes this provider implements, and whether they define a Monte Carlo test.
CHAINING_MODES: dict[str, bool] = {CBC: True, OFB: True, CFB128: True, CTR: False}

#: One outer Monte Carlo iteration: the key, IV and input in force, and the output.
McQuad = tuple[bytes, bytes, bytes, bytes]


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
        self, *, algorithm: str, key: bytes, iv: bytes, data: bytes, encrypt: bool
    ) -> bytes:
        """Encrypt or decrypt in the named chaining mode."""
        ...

    def monte_carlo(
        self, *, algorithm: str, key: bytes, iv: bytes, data: bytes, encrypt: bool
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
        self, *, algorithm: str, key: bytes, iv: bytes, data: bytes, encrypt: bool
    ) -> bytes:
        """Encrypt or decrypt one payload in the named mode."""
        # Cipher is generic over its mode, and an unnarrowed `Mode` resolves to
        # the AEAD overload of encryptor()/decryptor(). None of these four modes
        # is authenticated; CTR carries a nonce rather than an IV but exposes the
        # same construction, and neither attribute is read here.
        mode = cast(modes.ModeWithInitializationVector, _mode_for(algorithm, iv))
        cipher = Cipher(algorithms.AES(key), mode)
        operation = cipher.encryptor() if encrypt else cipher.decryptor()
        return operation.update(data) + operation.finalize()

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
        self, *, algorithm: str, key: bytes, iv: bytes, data: bytes, encrypt: bool
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
    "CBC",
    "CFB128",
    "CHAINING_MODES",
    "CTR",
    "OFB",
    "AesBlockProvider",
    "CryptographyAesBlockProvider",
    "McQuad",
]
