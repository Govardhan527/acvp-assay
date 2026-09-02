#!/usr/bin/env python3
"""Reference AES-GCM harness for acvp-runner's subprocess provider.

This is a worked example of the wire contract, not part of the package: it
imports nothing from ``acvp_runner``, which is the point — a harness is an
independent program and can be written in any language.

Run it with::

    acvp-runner run fixtures/aes-gcm-valid-encrypt/prompt.json \\
        --provider-command "python3 examples/reference_harness.py"

Contract: read one JSON request on stdin, write one JSON response on stdout,
exit 0. Report a rejected authentication tag as
``{"error": "authentication failed"}`` — that is a correct outcome for many
decrypt vectors, not a crash. Write diagnostics to stderr, never to stdout, and
never print key material.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import cryptography
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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


def main() -> int:
    """Handle exactly one request from stdin."""
    request = json.loads(sys.stdin.read())
    operation = request.get("operation")

    handlers = {"metadata": lambda _: metadata(), "encrypt": encrypt, "decrypt": decrypt}
    handler = handlers.get(operation)
    if handler is None:
        json.dump({"error": f"unsupported operation {operation!r}"}, sys.stdout)
        return 0

    json.dump(handler(request), sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
