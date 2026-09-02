#!/usr/bin/env python3
"""Reference harness for acvp-assay's subprocess provider.

Covers AES-GCM, SHA-2 (including the Monte Carlo chain), HMAC, and ECDSA.

This is a worked example of the wire contract, not part of the package: it
imports nothing from ``acvp_assay``, which is the point — a harness is an
independent program and can be written in any language.

Run it with::

    acvp-assay run fixtures/aes-gcm-valid-encrypt/prompt.json \\
        --provider-command "python3 examples/reference_harness.py"

Contract: read one JSON request on stdin, write one JSON response on stdout,
exit 0. Report a rejected authentication tag as
``{"error": "authentication failed"}`` — that is a correct outcome for many
decrypt vectors, not a crash. Write diagnostics to stderr, never to stdout, and
never print key material.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from typing import Any

import cryptography
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HASHLIB = {
    "SHA2-224": "sha224",
    "SHA2-256": "sha256",
    "SHA2-384": "sha384",
    "SHA2-512": "sha512",
    "SHA2-512/224": "sha512_224",
    "SHA2-512/256": "sha512_256",
}

CURVES = {
    "P-224": ec.SECP224R1,
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}

HASHES = {
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


def metadata() -> dict[str, str]:
    """Identify this implementation so results can be attributed to it."""
    return {
        "name": "reference-harness",
        "libraryName": "cryptography",
        "libraryVersion": cryptography.__version__,
        "backendName": "OpenSSL",
        "backendVersion": backend.openssl_version_text(),
    }


def encrypt(request: dict[str, Any]) -> dict[str, str]:
    """Encrypt and return the ciphertext and the requested tag prefix."""
    key = bytes.fromhex(request["key"])
    iv = bytes.fromhex(request["iv"])
    aad = bytes.fromhex(request["aad"])
    plaintext = bytes.fromhex(request["pt"])
    tag_bytes = int(request["tagLen"]) // 8

    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return {
        "ct": ciphertext.hex().upper(),
        "tag": encryptor.tag[:tag_bytes].hex().upper(),
    }


def decrypt(request: dict[str, Any]) -> dict[str, str]:
    """Authenticate and decrypt, or report the rejection as an expected outcome."""
    key = bytes.fromhex(request["key"])
    iv = bytes.fromhex(request["iv"])
    aad = bytes.fromhex(request["aad"])
    ciphertext = bytes.fromhex(request["ct"])
    tag = bytes.fromhex(request["tag"])

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag, min_tag_length=len(tag)),
    ).decryptor()
    decryptor.authenticate_additional_data(aad)
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        return {"error": "authentication failed"}
    return {"pt": plaintext.hex().upper()}


def digest(request: dict[str, Any]) -> dict[str, str]:
    """Hash one message."""
    name = HASHLIB.get(request["algorithm"])
    if name is None:
        return {"error": "unsupported"}
    return {"md": hashlib.new(name, bytes.fromhex(request["message"])).digest().hex().upper()}


def digest_mct(request: dict[str, Any]) -> dict[str, Any]:
    """Run the whole ACVP Monte Carlo chain and return one digest per outer iteration.

    The chain is run here rather than driven case by case by the caller: at
    100,000 inner iterations, a round trip per hash would take hours. The
    ``alternate`` variant truncates or zero-pads every message to the length of
    the *original* seed, captured once before the loop.
    """
    name = HASHLIB.get(request["algorithm"])
    if name is None:
        return {"error": "unsupported"}
    seed = bytes.fromhex(request["seed"])
    alternate = bool(request.get("alternate"))
    width = len(seed)
    outputs: list[str] = []
    for _ in range(100):
        a = b = c = seed
        for _ in range(1000):
            message = a + b + c
            if alternate:
                message = message[:width].ljust(width, b"\x00")
            current = hashlib.new(name, message).digest()
            a, b, c = b, c, current
        outputs.append(c.hex().upper())
        seed = c
    return {"md": outputs}


def mac(request: dict[str, Any]) -> dict[str, str]:
    """Compute an HMAC truncated to the requested bit length."""
    name = HASHLIB.get(str(request["algorithm"]).removeprefix("HMAC-"))
    if name is None:
        return {"error": "unsupported"}
    full = hmac.new(bytes.fromhex(request["key"]), bytes.fromhex(request["message"]), name).digest()
    length = int(request["macLen"]) // 8
    if length > len(full):
        return {"error": "unsupported"}
    return {"mac": full[:length].hex().upper()}


def _ecdsa_parameters(request: dict[str, Any]) -> tuple[Any, Any] | None:
    curve = CURVES.get(request["curve"])
    algorithm = HASHES.get(request["hashAlg"])
    if curve is None or algorithm is None:
        return None
    return curve(), algorithm()


def ecdsa_sign(request: dict[str, Any]) -> dict[str, str]:
    """Generate a key pair and sign, returning the public key with the signature."""
    parameters = _ecdsa_parameters(request)
    if parameters is None:
        return {"error": "unsupported"}
    curve, algorithm = parameters
    key = ec.generate_private_key(curve)
    signature = key.sign(bytes.fromhex(request["message"]), ec.ECDSA(algorithm))
    r, s = utils.decode_dss_signature(signature)
    numbers = key.public_key().public_numbers()
    size = (curve.key_size + 7) // 8
    return {
        "qx": numbers.x.to_bytes(size, "big").hex().upper(),
        "qy": numbers.y.to_bytes(size, "big").hex().upper(),
        "r": r.to_bytes(size, "big").hex().upper(),
        "s": s.to_bytes(size, "big").hex().upper(),
    }


def ecdsa_verify(request: dict[str, Any]) -> dict[str, Any]:
    """Report a verification verdict. An off-curve key is a false verdict, not an error."""
    parameters = _ecdsa_parameters(request)
    if parameters is None:
        return {"error": "unsupported"}
    curve, algorithm = parameters
    try:
        public_key = ec.EllipticCurvePublicNumbers(
            int(request["qx"], 16), int(request["qy"], 16), curve
        ).public_key()
        signature = utils.encode_dss_signature(int(request["r"], 16), int(request["s"], 16))
    except ValueError:
        return {"testPassed": False}
    try:
        public_key.verify(signature, bytes.fromhex(request["message"]), ec.ECDSA(algorithm))
    except InvalidSignature:
        return {"testPassed": False}
    return {"testPassed": True}


HANDLERS = {
    "metadata": lambda _: metadata(),
    "encrypt": encrypt,
    "decrypt": decrypt,
    "digest": digest,
    "digest-mct": digest_mct,
    "mac": mac,
    "ecdsa-sign": ecdsa_sign,
    "ecdsa-verify": ecdsa_verify,
}


def main() -> int:
    """Handle exactly one request from stdin."""
    request = json.loads(sys.stdin.read())
    operation = request.get("operation")

    handler = HANDLERS.get(operation)
    if handler is None:
        json.dump({"error": f"unsupported operation {operation!r}"}, sys.stdout)
        return 0

    json.dump(handler(request), sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
