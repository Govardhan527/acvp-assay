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

from typing import Protocol, cast, runtime_checkable

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:  # pragma: no cover - which branch runs depends on the installed version
    # CFB and OFB move here in cryptography 49 and warn before that.
    from cryptography.hazmat.decrepit.ciphers.modes import CFB as _CFB
    from cryptography.hazmat.decrepit.ciphers.modes import OFB as _OFB
except ImportError:  # pragma: no cover - older cryptography has no `decrepit`
    _CFB = modes.CFB
    _OFB = modes.OFB

from acvp_assay.models import ProviderMetadata
from acvp_assay.providers.aes_modes import (
    MCT_INNER_ITERATIONS,
    MCT_OUTER_ITERATIONS,
    key_shuffle,
)

CBC = "ACVP-AES-CBC"
CTR = "ACVP-AES-CTR"
OFB = "ACVP-AES-OFB"
CFB128 = "ACVP-AES-CFB128"

#: Modes this provider implements, and whether they define a Monte Carlo test.
CHAINING_MODES: dict[str, bool] = {CBC: True, OFB: True, CFB128: True, CTR: False}

#: Directions whose Monte Carlo chain is *verified* against NIST's own answers.
#:
#: The specification says the decrypt chain is the encrypt pseudocode with PT
#: and CT swapped. Taken literally that is what this provider implements, and
#: for CBC and CFB128 encryption it reproduces the live server's arrays exactly,
#: field for field. Decryption does not, and OFB does not in either direction.
#: An exhaustive search over 36 plausible feedback rules found nothing that
#: does, so the real chain is something this runner has not established.
#:
#: Rather than ship a chain that runs to completion and quietly disagrees,
#: the unverified combinations are declared. See docs/limitations.md.
VERIFIED_MONTE_CARLO: dict[str, frozenset[str]] = {
    CBC: frozenset({"encrypt"}),
    CFB128: frozenset({"encrypt"}),
    OFB: frozenset(),
    CTR: frozenset(),
}


def monte_carlo_is_verified(algorithm: str, *, encrypt: bool) -> bool:
    """Whether this runner can answer the Monte Carlo chain for this direction."""
    return ("encrypt" if encrypt else "decrypt") in VERIFIED_MONTE_CARLO.get(algorithm, frozenset())


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

    def monte_carlo(
        self, *, algorithm: str, key: bytes, iv: bytes, data: bytes, encrypt: bool
    ) -> list[McQuad]:
        """Run the shared CBC/OFB/CFB128 Monte Carlo chain.

        The specification writes the inner loop as a stateful cipher that
        continues from the previous call. For a one-block operation that is the
        same as restarting with the previous output block as the IV, which is
        what this does::

            For j = 0 to 999
                If j = 0: CT[j] = ENC(Key, IV, PT[j]);      PT[j+1] = IV
                Else:     CT[j] = ENC(Key, CT[j-1], PT[j]); PT[j+1] = CT[j-1]

        The feedback value and the next input are the same value, which is why
        one variable serves both below.
        """
        if not CHAINING_MODES.get(algorithm, False):
            raise ValueError(f"{algorithm} has no Monte Carlo test")
        if not monte_carlo_is_verified(algorithm, encrypt=encrypt):
            direction = "encrypt" if encrypt else "decrypt"
            raise ValueError(
                f"the {algorithm} {direction} Monte Carlo chain is not verified against "
                "NIST's answers; this runner declines rather than guess"
            )

        results: list[McQuad] = []
        for _ in range(MCT_OUTER_ITERATIONS):
            first_input = data
            feedback = iv
            previous = b""
            current = b""
            block = data
            for _ in range(MCT_INNER_ITERATIONS):
                produced = self.transform(
                    algorithm=algorithm, key=key, iv=feedback, data=block, encrypt=encrypt
                )
                # The next input and the next feedback are both the value this
                # iteration chained from, so they advance together.
                block, feedback = feedback, produced
                previous, current = current, produced
            results.append((key, iv, first_input, current))
            key = key_shuffle(key, current, previous)
            iv = current
            data = previous
        return results


__all__ = [
    "CBC",
    "CFB128",
    "CHAINING_MODES",
    "VERIFIED_MONTE_CARLO",
    "CTR",
    "OFB",
    "AesBlockProvider",
    "CryptographyAesBlockProvider",
    "McQuad",
    "monte_carlo_is_verified",
]
