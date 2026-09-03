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

import json
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


def metadata() -> dict[str, str]:
    """Identify the reference implementations behind this harness."""
    return {
        "name": "pqc-reference-harness",
        "libraryName": "kyber-py + dilithium-py",
        "libraryVersion": "reference",
        "backendName": "pure-python",
        "backendVersion": "not-constant-time",
    }


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


def ml_dsa_verify(request: dict[str, Any]) -> dict[str, bool]:
    """Report the verification verdict for an ML-DSA signature.

    The signature interface matters: ML-DSA's *internal* interface omits the
    domain separator and context prefix the *external* one applies, so an
    internal signature checked externally is rejected even when valid.
    """
    dsa = ML_DSA[request["parameterSet"]]
    public_key = bytes.fromhex(request["pk"])
    message = bytes.fromhex(request["message"])
    signature = bytes.fromhex(request["signature"])
    try:
        if request.get("signatureInterface") == "internal":
            verdict = dsa._verify_internal(public_key, message, signature)
        else:
            verdict = dsa.verify(
                public_key, message, signature, bytes.fromhex(request.get("context", ""))
            )
    except (ValueError, TypeError, IndexError):
        return {"testPassed": False}
    return {"testPassed": bool(verdict)}


HANDLERS = {
    "metadata": lambda _: metadata(),
    "ml-kem-encapsulate": encapsulate,
    "ml-kem-decapsulate": decapsulate,
    "ml-kem-key-check": key_check,
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
