"""RSA signature generation and verification, and the two raw primitives.

The two halves of this module are deliberately different in kind.

``sign_group`` and ``verify`` go through ``cryptography``, because a padded RSA
signature is a real construction with a real security contract and this project
does not reimplement those.

``signature_primitive`` and ``decryption_primitive`` are bare modular
exponentiation, and are computed directly. That is not a shortcut: those ACVP
modes exist precisely to exercise the unpadded operation, including inputs a
padded API would refuse. Routing them through a library that enforces padding
would test the wrong thing, or nothing.

Both primitives carry a range check whose bounds differ, which is easy to get
backwards. They were taken from NIST's own generator in usnistgov/ACVP-Server:
``OracleObserverRsaSignaturePrimitive_v2_0CaseGrain`` draws valid messages with
``GetRandomBigInteger(N - 1)``, so a message is in range when ``m < n``; the
decryption grain draws ``GetRandomBigInteger(1, N - 1)``, so a ciphertext is in
range only when ``1 < c < n - 1``. Both were then confirmed against every case
of the pinned upstream sets, with no disagreement.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

import cryptography
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from acvp_assay.models import ProviderMetadata
from acvp_assay.providers.subprocess_harness import (
    HarnessClient,
    HarnessProtocolError,
    decode_hex,
)

MGF1 = "mgf1"
PKCS1V15 = "pkcs1v1.5"
PSS = "pss"
SIGNATURE_TYPES = (PKCS1V15, PSS)

#: ACVP ``hashAlg`` to the cryptography hash it names. SHAKE is absent on
#: purpose: FIPS 186-5 admits it for PSS, and this binding has no PSS over an
#: extendable-output function, so those groups are declared rather than guessed.
HASHES: dict[str, type[hashes.HashAlgorithm]] = {
    "SHA-1": hashes.SHA1,
    "SHA2-224": hashes.SHA224,
    "SHA2-256": hashes.SHA256,
    "SHA2-384": hashes.SHA384,
    "SHA2-512": hashes.SHA512,
    "SHA2-512/224": hashes.SHA512_224,
    "SHA2-512/256": hashes.SHA512_256,
    "SHA3-224": hashes.SHA3_224,
    "SHA3-256": hashes.SHA3_256,
    "SHA3-384": hashes.SHA3_384,
    "SHA3-512": hashes.SHA3_512,
}


@dataclass(frozen=True, slots=True)
class RsaGroupSignatures:
    """Signatures over several messages, all under one key pair.

    ACVP reports ``n`` and ``e`` once per sigGen *group*, so every case in that
    group must be signed with the same key -- the same constraint ECDSA sigGen
    has, for the same reason.
    """

    n: bytes
    e: bytes
    signatures: tuple[bytes, ...]


@runtime_checkable
class RsaProvider(Protocol):
    """Replaceable boundary for RSA signatures and raw primitives."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def supports(self, *, signature_type: str, hash_algorithm: str, mask_function: str) -> bool:
        """Report whether this build can sign and verify with these choices."""
        ...

    def sign_group(
        self,
        *,
        signature_type: str,
        hash_algorithm: str,
        mask_function: str,
        modulo: int,
        salt_length: int,
        messages: Sequence[bytes],
    ) -> RsaGroupSignatures:
        """Sign every message in a group under one freshly generated key."""
        ...

    def verify(
        self,
        *,
        signature_type: str,
        hash_algorithm: str,
        mask_function: str,
        salt_length: int,
        n: int,
        e: int,
        message: bytes,
        signature: bytes,
    ) -> bool:
        """Report whether a signature verifies. A rejection is an answer, not an error."""
        ...

    def signature_primitive(self, *, n: int, d: int, message: int) -> int | None:
        """Raw RSA over a message, or None when it is out of range."""
        ...

    def signature_primitive_crt(
        self, *, n: int, p: int, q: int, dmp1: int, dmq1: int, iqmp: int, message: int
    ) -> int | None:
        """Raw RSA by the Chinese remainder theorem, for ``keyMode: crt`` cases."""
        ...

    def decryption_primitive(self, *, n: int, d: int, ciphertext: int) -> int | None:
        """Raw RSA over a ciphertext, or None when it is out of range."""
        ...


def _padding(
    signature_type: str, hash_algorithm: str, salt_length: int
) -> padding.AsymmetricPadding:
    """Build the padding an ACVP group describes."""
    if signature_type == PKCS1V15:
        return padding.PKCS1v15()
    if signature_type != PSS:
        raise ValueError(f"unsupported sigType {signature_type!r}")
    return padding.PSS(mgf=padding.MGF1(HASHES[hash_algorithm]()), salt_length=salt_length)


def _int_bytes(value: int, byte_length: int) -> bytes:
    return value.to_bytes(byte_length, "big")


class CryptographyRsaProvider:
    """RSA backed by cryptography, with the raw primitives computed directly."""

    def metadata(self) -> ProviderMetadata:
        """Identify both the Python binding and the OpenSSL backend."""
        return ProviderMetadata(
            name="cryptography-rsa",
            library_name="cryptography",
            library_version=cryptography.__version__,
            backend_name="OpenSSL",
            backend_version=backend.openssl_version_text(),
        )

    def supports(self, *, signature_type: str, hash_algorithm: str, mask_function: str) -> bool:
        """Report what this build actually offers.

        The mask function matters and is easy to overlook: FIPS 186-5 allows
        PSS to use SHAKE as its MGF, which ACVP signals with ``maskFunction``
        rather than through ``hashAlg``. This binding has only MGF1, so a
        SHAKE-masked group is declared even when its hash is one we support.
        """
        if signature_type not in SIGNATURE_TYPES or hash_algorithm not in HASHES:
            return False
        return signature_type != PSS or mask_function in (MGF1, "")

    def sign_group(
        self,
        *,
        signature_type: str,
        hash_algorithm: str,
        mask_function: str,
        modulo: int,
        salt_length: int,
        messages: Sequence[bytes],
    ) -> RsaGroupSignatures:
        """Generate one key of the group's modulus and sign every message with it."""
        del mask_function  # gated by supports(); MGF1 is the only mask here
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=modulo)
        numbers = private_key.public_key().public_numbers()
        scheme = _padding(signature_type, hash_algorithm, salt_length)
        algorithm = HASHES[hash_algorithm]()
        byte_length = modulo // 8
        return RsaGroupSignatures(
            n=_int_bytes(numbers.n, byte_length),
            e=_int_bytes(numbers.e, (numbers.e.bit_length() + 7) // 8),
            signatures=tuple(private_key.sign(message, scheme, algorithm) for message in messages),
        )

    def verify(
        self,
        *,
        signature_type: str,
        hash_algorithm: str,
        mask_function: str,
        salt_length: int,
        n: int,
        e: int,
        message: bytes,
        signature: bytes,
    ) -> bool:
        """Verify against a public key the vector supplies.

        ACVP builds deliberately invalid signatures into sigVer groups, so a
        rejection here is the correct answer rather than a failure.
        """
        del mask_function  # gated by supports(); MGF1 is the only mask here
        public_key = rsa.RSAPublicNumbers(e=e, n=n).public_key()
        try:
            public_key.verify(
                signature,
                message,
                _padding(signature_type, hash_algorithm, salt_length),
                HASHES[hash_algorithm](),
            )
        except (InvalidSignature, ValueError):
            return False
        return True

    def signature_primitive(self, *, n: int, d: int, message: int) -> int | None:
        """Raw RSA over a message, or None when the message is out of range.

        In range means ``message < n``: the generator draws valid messages from
        ``[0, n)``, so zero and one are both legitimate here.
        """
        if not 0 <= message < n:
            return None
        return pow(message, d, n)

    def signature_primitive_crt(
        self, *, n: int, p: int, q: int, dmp1: int, dmq1: int, iqmp: int, message: int
    ) -> int | None:
        """Raw RSA by the Chinese remainder theorem, for ``keyMode: crt`` cases.

        Half the upstream signaturePrimitive groups never supply ``d`` at all,
        only the CRT parameters derived from it, so a runner that reads ``d``
        alone answers nothing for them.
        """
        if not 0 <= message < n:
            return None
        m1 = pow(message, dmp1, p)
        m2 = pow(message, dmq1, q)
        return (m2 + q * (iqmp * (m1 - m2) % p)) % n

    def decryption_primitive(self, *, n: int, d: int, ciphertext: int) -> int | None:
        """Raw RSA over a ciphertext, or None when it is out of range.

        SP 800-56B excludes the endpoints, so in range means ``1 < c < n - 1``.
        The bounds differ from the signature primitive's, and swapping them
        silently mislabels the cases ACVP includes precisely to catch that.
        """
        if not 1 < ciphertext < n - 1:
            return None
        return pow(ciphertext, d, n)


__all__ = [
    "HASHES",
    "PKCS1V15",
    "PSS",
    "SIGNATURE_TYPES",
    "CryptographyRsaProvider",
    "RsaGroupSignatures",
    "RsaProvider",
    "SubprocessRsaProvider",
]


def _hex_int(value: int) -> str:
    """Render an integer as even-length uppercase hex, as the wire uses."""
    digits = f"{value:X}"
    return digits.zfill(len(digits) + len(digits) % 2)


def _optional_int(response: Mapping[str, object], key: str) -> int | None:
    """Read a primitive's answer: a value, or None when it declared the input out of range.

    ``testPassed: false`` is how a harness says "out of range". The two
    primitives use different bounds and ACVP includes cases on both sides of
    each, so this has to be an answer rather than an error.
    """
    if response.get("testPassed") is False:
        return None
    return int.from_bytes(decode_hex(response, key), "big")


class SubprocessRsaProvider(HarnessClient):
    """RSA signatures and raw primitives performed by an external harness.

    A whole sigGen group is signed in one exchange. ACVP reports the public key
    once per group, so every case in it must share a key -- asking case by case
    would either force the harness to cache one or produce a document that
    cannot be expressed.
    """

    def supports(self, *, signature_type: str, hash_algorithm: str, mask_function: str) -> bool:
        """Assume capability; the harness declines per case with ``unsupported``.

        The mask function is still sent with every request. Deciding here that
        a harness cannot do SHAKE would be this runner's assumption, not the
        implementation's, and the whole point of the boundary is that capability
        is the implementation's to declare.
        """
        del signature_type, hash_algorithm, mask_function
        return True

    def sign_group(
        self,
        *,
        signature_type: str,
        hash_algorithm: str,
        mask_function: str,
        modulo: int,
        salt_length: int,
        messages: Sequence[bytes],
    ) -> RsaGroupSignatures:
        """Ask the harness to sign a whole group under one key it generates."""
        response = self.invoke(
            {
                "operation": "rsa-sign-group",
                "sigType": signature_type,
                "hashAlg": hash_algorithm,
                "maskFunction": mask_function,
                "modulo": modulo,
                "saltLen": salt_length,
                "messages": [message.hex().upper() for message in messages],
            }
        )
        signatures = response.get("signatures")
        if not isinstance(signatures, list):
            raise HarnessProtocolError("harness returned no 'signatures' array")
        if len(signatures) != len(messages):
            raise HarnessProtocolError(
                f"harness returned {len(signatures)} signatures for {len(messages)} messages"
            )
        decoded: list[bytes] = []
        for index, value in enumerate(signatures):
            if not isinstance(value, str):
                raise HarnessProtocolError(f"harness returned a non-string signature at {index}")
            try:
                decoded.append(bytes.fromhex(value))
            except ValueError:
                raise HarnessProtocolError(
                    f"harness returned invalid hex signature at {index}"
                ) from None
        return RsaGroupSignatures(
            n=decode_hex(response, "n"), e=decode_hex(response, "e"), signatures=tuple(decoded)
        )

    def verify(
        self,
        *,
        signature_type: str,
        hash_algorithm: str,
        mask_function: str,
        salt_length: int,
        n: int,
        e: int,
        message: bytes,
        signature: bytes,
    ) -> bool:
        """Ask the harness for its verification verdict."""
        response = self.invoke(
            {
                "operation": "rsa-verify",
                "sigType": signature_type,
                "hashAlg": hash_algorithm,
                "maskFunction": mask_function,
                "saltLen": salt_length,
                "n": _hex_int(n),
                "e": _hex_int(e),
                "message": message.hex().upper(),
                "signature": signature.hex().upper(),
            }
        )
        verdict = response.get("testPassed")
        if not isinstance(verdict, bool):
            raise HarnessProtocolError("harness returned no boolean 'testPassed'")
        return verdict

    def signature_primitive(self, *, n: int, d: int, message: int) -> int | None:
        """Raw RSA over a message, through the harness."""
        return _optional_int(
            self.invoke(
                {
                    "operation": "rsa-primitive-sign",
                    "n": _hex_int(n),
                    "d": _hex_int(d),
                    "message": _hex_int(message),
                }
            ),
            "signature",
        )

    def signature_primitive_crt(
        self, *, n: int, p: int, q: int, dmp1: int, dmq1: int, iqmp: int, message: int
    ) -> int | None:
        """Raw RSA by the Chinese remainder theorem, through the harness."""
        return _optional_int(
            self.invoke(
                {
                    "operation": "rsa-primitive-sign",
                    "n": _hex_int(n),
                    "p": _hex_int(p),
                    "q": _hex_int(q),
                    "dmp1": _hex_int(dmp1),
                    "dmq1": _hex_int(dmq1),
                    "iqmp": _hex_int(iqmp),
                    "message": _hex_int(message),
                }
            ),
            "signature",
        )

    def decryption_primitive(self, *, n: int, d: int, ciphertext: int) -> int | None:
        """Raw RSA over a ciphertext, through the harness."""
        return _optional_int(
            self.invoke(
                {
                    "operation": "rsa-primitive-decrypt",
                    "n": _hex_int(n),
                    "d": _hex_int(d),
                    "ct": _hex_int(ciphertext),
                }
            ),
            "pt",
        )
