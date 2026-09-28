#!/usr/bin/env python3
"""Reference ML-KEM / ML-DSA harness for acvp-assay's subprocess provider.

This exists to prove the PQC path end to end and to demonstrate it, **not** as
an implementation anyone should validate or ship. It is backed by
``kyber-py`` and ``dilithium-py``, which are pure-Python educational
implementations: they are not constant-time and make no side-channel claims.
Their value here is that they already pass NIST's own ACVP known-answer tests,
which makes them a trustworthy *reference* for checking that this runner
parses, routes, and compares PQC vectors correctly.

A real engagement points ``--provider-command`` at the customer's
implementation instead — OpenSSL 3.5+, liboqs, an HSM, or their own module.

Install the references (development only, never a runtime dependency)::

    pip install kyber-py dilithium-py

Then::

    acvp-assay run vectors/ML-KEM-encapDecap-FIPS203/prompt.json \\
        --provider-command "python3 examples/pqc_reference_harness.py"
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from typing import Any

from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

ML_KEM = {
    "ML-KEM-512": ML_KEM_512,
    "ML-KEM-768": ML_KEM_768,
    "ML-KEM-1024": ML_KEM_1024,
}

ML_DSA = {
    "ML-DSA-44": ML_DSA_44,
    "ML-DSA-65": ML_DSA_65,
    "ML-DSA-87": ML_DSA_87,
}


def metadata() -> dict[str, Any]:
    """Identify the reference implementations behind this harness.

    ``buildId`` is the SHA-256 of this file, which is the whole of the harness.
    ``build`` says where it ran; for pure Python the interpreter is the toolchain,
    and there are no flags to report.
    """
    with open(__file__, "rb") as source:
        build = hashlib.sha256(source.read()).hexdigest()
    return {
        "name": "pqc-reference-harness",
        "libraryName": "kyber-py + dilithium-py",
        "libraryVersion": "reference",
        "backendName": "pure-python",
        "backendVersion": "not-constant-time",
        "buildId": f"sha256:{build}",
        "build": {
            "compiler": f"CPython {platform.python_version()}",
            "cpu": platform.machine(),
            "os": f"{platform.system()} {platform.release()}",
        },
    }


#: The DER-encoded OID of each hash, and the digest length HashML-DSA fixes for it.
#: FIPS 204 Algorithm 4 puts this OID into the signed prefix, so the same digest
#: under two different names is two different signatures. The two XOFs have fixed
#: lengths here rather than a caller's choice: 256 bits for SHAKE-128, 512 for
#: SHAKE-256.
PRE_HASH = {
    "SHA2-224": ("0609608648016503040204", "sha224", 28),
    "SHA2-256": ("0609608648016503040201", "sha256", 32),
    "SHA2-384": ("0609608648016503040202", "sha384", 48),
    "SHA2-512": ("0609608648016503040203", "sha512", 64),
    "SHA2-512/224": ("0609608648016503040205", "sha512_224", 28),
    "SHA2-512/256": ("0609608648016503040206", "sha512_256", 32),
    "SHA3-224": ("0609608648016503040207", "sha3_224", 28),
    "SHA3-256": ("0609608648016503040208", "sha3_256", 32),
    "SHA3-384": ("0609608648016503040209", "sha3_384", 48),
    "SHA3-512": ("060960864801650304020A", "sha3_512", 64),
    "SHAKE-128": ("060960864801650304020B", "shake_128", 32),
    "SHAKE-256": ("060960864801650304020C", "shake_256", 64),
}


def ml_kem_keygen(request: dict[str, Any]) -> dict[str, str]:
    """Generate an ML-KEM key pair from ACVP's two seeds.

    FIPS 203 KeyGen takes ``d`` and ``z``; the public ``keygen`` invents both,
    so only the internal entry point can answer these cases.
    """
    kem = ML_KEM[request["parameterSet"]]
    encapsulation, decapsulation = kem._keygen_internal(
        bytes.fromhex(request["d"]), bytes.fromhex(request["z"])
    )
    return {"ek": encapsulation.hex().upper(), "dk": decapsulation.hex().upper()}


def ml_dsa_keygen(request: dict[str, Any]) -> dict[str, str]:
    """Generate an ML-DSA key pair from ACVP's 32-byte seed."""
    dsa = ML_DSA[request["parameterSet"]]
    public, secret = dsa._keygen_internal(bytes.fromhex(request["seed"]))
    return {"pk": public.hex().upper(), "sk": secret.hex().upper()}


def ml_dsa_sign(request: dict[str, Any]) -> dict[str, str]:
    """Sign one ACVP case with exactly the randomness and prefix its group fixes.

    The message that actually gets signed is built here rather than by the
    library's own ``sign``, because ACVP asks for combinations its public API
    does not offer: the internal interface with no prefix at all, a supplied
    ``rnd``, a precomputed ``mu``, and HashML-DSA's OID-carrying prefix.
    """
    dsa = ML_DSA[request["parameterSet"]]
    secret = bytes.fromhex(request["sk"])
    rnd = bytes.fromhex(request["rnd"]) if "rnd" in request else bytes(32)
    if request.get("externalMu"):
        signature = dsa._sign_internal(secret, bytes.fromhex(request["mu"]), rnd, external_mu=True)
        return {"signature": signature.hex().upper()}

    message = bytes.fromhex(request["message"])
    if request.get("signatureInterface") == "internal":
        return {"signature": dsa._sign_internal(secret, message, rnd).hex().upper()}

    signature = dsa._sign_internal(secret, signed_message(request, message), rnd)
    return {"signature": signature.hex().upper()}


def signed_message(request: dict[str, Any], message: bytes) -> bytes:
    """Build what the external interface actually signs: the prefix, then the message.

    Pure ML-DSA signs ``00 || len(ctx) || ctx || M``. HashML-DSA signs
    ``01 || len(ctx) || ctx || OID || PH(M)``, so the same digest under two
    different hash names is two different signatures.
    """
    context = bytes.fromhex(request.get("context", ""))
    if request.get("preHash") != "preHash":
        return bytes([0, len(context)]) + context + message
    oid, algorithm, length = PRE_HASH[request["hashAlg"]]
    digest = hashlib.new(algorithm)
    digest.update(message)
    hashed = (
        digest.digest(length)  # type: ignore[call-arg]
        if algorithm.startswith("shake")
        else digest.digest()
    )
    return bytes([1, len(context)]) + context + bytes.fromhex(oid) + hashed


def encapsulate(request: dict[str, Any]) -> dict[str, str]:
    """Encapsulate using ACVP's supplied randomness, so the output is comparable.

    ``_encaps_internal`` is the deterministic entry point; the public
    ``encaps`` generates its own ``m``. Note it returns ``(K, c)``, the
    reverse of ACVP's field order.
    """
    kem = ML_KEM[request["parameterSet"]]
    shared, ciphertext = kem._encaps_internal(
        bytes.fromhex(request["ek"]), bytes.fromhex(request["m"])
    )
    return {"c": ciphertext.hex().upper(), "k": shared.hex().upper()}


def decapsulate(request: dict[str, Any]) -> dict[str, str]:
    """Decapsulate and return the shared secret."""
    kem = ML_KEM[request["parameterSet"]]
    shared = kem.decaps(bytes.fromhex(request["dk"]), bytes.fromhex(request["c"]))
    return {"k": shared.hex().upper()}


def key_check(request: dict[str, Any]) -> dict[str, bool]:
    """Report whether a supplied key is well formed.

    ACVP's key-check groups deliberately include malformed keys: rejecting
    them is the correct answer, so a failure here is a verdict, not an error.
    """
    kem = ML_KEM[request["parameterSet"]]
    key = bytes.fromhex(request["key"])
    try:
        if request["keyType"] == "ek":
            kem._encaps_internal(key, bytes(32))
        else:
            kem.decaps(key, bytes(kem.du * kem.k * 32 + kem.dv * 32))
    except (ValueError, TypeError, IndexError):
        return {"testPassed": False}
    return {"testPassed": True}


def ml_dsa_verify(request: dict[str, Any]) -> dict[str, Any]:
    """Report the verification verdict for an ML-DSA signature.

    The signature interface matters: ML-DSA's *internal* interface omits the
    domain separator and context prefix the *external* one applies, so an
    internal signature checked externally is rejected even when valid.

    ``dilithium-py`` signs with an external ``mu`` and offers no way to *verify*
    with one, so those cases are declined as ``interface_lacks`` rather than
    answered with a verdict this harness cannot reach. That is the honest code:
    the library computes exactly this internally, and its API has nowhere to
    hand the value in.
    """
    dsa = ML_DSA[request["parameterSet"]]
    public_key = bytes.fromhex(request["pk"])
    signature = bytes.fromhex(request["signature"])
    if request.get("externalMu"):
        return {
            "error": "unsupported",
            "declineReason": "interface_lacks",
            "detail": "dilithium-py verifies from a message, never from a supplied mu",
        }
    message = bytes.fromhex(request["message"])
    try:
        if request.get("signatureInterface") == "internal":
            verdict = dsa._verify_internal(public_key, message, signature)
        else:
            verdict = dsa._verify_internal(public_key, signed_message(request, message), signature)
    except (ValueError, TypeError, IndexError):
        return {"testPassed": False}
    return {"testPassed": bool(verdict)}


HANDLERS = {
    "metadata": lambda _: metadata(),
    "ml-kem-keygen": ml_kem_keygen,
    "ml-kem-encapsulate": encapsulate,
    "ml-kem-decapsulate": decapsulate,
    "ml-kem-key-check": key_check,
    "ml-dsa-keygen": ml_dsa_keygen,
    "ml-dsa-sign": ml_dsa_sign,
    "ml-dsa-verify": ml_dsa_verify,
}


def main() -> int:
    """Answer requests until stdin closes.

    One JSON request per line in, one JSON response per line out, with the
    process kept alive for the whole run. See `reference_harness.py` for why
    that matters.
    """
    for line in sys.stdin:
        if not line.strip():
            continue
        request = json.loads(line)
        handler = HANDLERS.get(request.get("operation"))
        response = (
            {"error": f"unsupported operation {request.get('operation')!r}"}
            if handler is None
            else handler(request)
        )
        print(json.dumps(response), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
