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
from cryptography.hazmat.primitives import cmac as cmac_mod
from cryptography.hazmat.primitives import hashes, keywrap
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:  # pragma: no cover - CFB and OFB move to `decrepit` in cryptography 49
    from cryptography.hazmat.decrepit.ciphers.modes import CFB as _CFB
    from cryptography.hazmat.decrepit.ciphers.modes import OFB as _OFB
except ImportError:  # pragma: no cover
    _CFB, _OFB = modes.CFB, modes.OFB

HASHLIB = {
    "SHA-1": "sha1",
    "SHA2-224": "sha224",
    "SHA2-256": "sha256",
    "SHA2-384": "sha384",
    "SHA2-512": "sha512",
    "SHA2-512/224": "sha512_224",
    "SHA2-512/256": "sha512_256",
    "SHA3-224": "sha3_224",
    "SHA3-256": "sha3_256",
    "SHA3-384": "sha3_384",
    "SHA3-512": "sha3_512",
}

#: SHA-3 chains its Monte Carlo test differently from SHA-1 and SHA-2. The two
#: families share the "MCT" test type name and nothing else, so a harness that
#: runs one chain for both fails every SHA-3 Monte Carlo case while looking
#: structurally correct.
SHA3 = frozenset(name for name in HASHLIB if name.startswith("SHA3-"))

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
    sha3 = request["algorithm"] in SHA3
    outputs: list[str] = []
    for _ in range(100):
        a = b = c = seed
        for _ in range(1000):
            # SHA-3 hashes the previous digest alone; SHA-1 and SHA-2 hash
            # three concatenated.
            message = c if sha3 else a + b + c
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


def ecdsa_sign_group(request: dict[str, Any]) -> dict[str, Any]:
    """Sign every message in a group under one freshly generated key.

    Same rule as RSA sigGen: ACVP reports qx/qy once per group, so a key per
    case could not be reported. In sigGen the key belongs to the implementation
    under test, which is why it is generated here rather than supplied.
    """
    parameters = _ecdsa_parameters(request)
    if parameters is None:
        return {"error": "unsupported"}
    curve, algorithm = parameters
    key = ec.generate_private_key(curve)
    numbers = key.public_key().public_numbers()
    size = (curve.key_size + 7) // 8
    signatures: list[dict[str, str]] = []
    for message in request["messages"]:
        r, s = utils.decode_dss_signature(key.sign(bytes.fromhex(message), ec.ECDSA(algorithm)))
        signatures.append(
            {
                "r": r.to_bytes(size, "big").hex().upper(),
                "s": s.to_bytes(size, "big").hex().upper(),
            }
        )
    return {
        "qx": numbers.x.to_bytes(size, "big").hex().upper(),
        "qy": numbers.y.to_bytes(size, "big").hex().upper(),
        "signatures": signatures,
    }


def xts_transform(request: dict[str, Any]) -> dict[str, Any]:
    """AES-XTS over one payload, split into data units.

    The key is two AES keys concatenated, the tweak is already 16 bytes by the
    time it arrives, and a payload longer than the data unit is several units
    with the tweak incremented -- as a little-endian integer -- once per unit.
    """
    key = bytes.fromhex(request["key"])
    tweak = bytes.fromhex(request["tweak"])
    data = bytes.fromhex(request["data"])
    encrypt = request["direction"] == "encrypt"
    unit = request["dataUnitLen"] // 8
    width = min(unit, len(data)) or len(data)
    base = int.from_bytes(tweak, "little")
    out = bytearray()
    for index, start in enumerate(range(0, len(data), width)):
        mode = modes.XTS(((base + index) % (1 << 128)).to_bytes(16, "little"))
        cipher = Cipher(algorithms.AES(key), mode)
        operation = cipher.encryptor() if encrypt else cipher.decryptor()
        out += operation.update(data[start : start + width]) + operation.finalize()
    return {"out": bytes(out).hex().upper()}


def kas_ecc_ssc(request: dict[str, Any]) -> dict[str, Any]:
    """Compute an ECDH shared secret, generating a key pair when none is given.

    A VAL case supplies ``privateKey`` and the answer is deterministic. An AFT
    case supplies only the peer's public key, so the implementation generates
    its own ephemeral pair -- which is why an AFT case can only be judged by
    the ACVP server, which holds the peer private key.
    """
    curve = CURVES.get(request["curve"])
    if curve is None:
        return {"error": "unsupported"}
    instance = curve()
    peer = ec.EllipticCurvePublicNumbers(
        int(request["serverX"], 16), int(request["serverY"], 16), instance
    ).public_key()
    supplied = request.get("privateKey")
    key = (
        ec.generate_private_key(instance)
        if supplied is None
        else ec.derive_private_key(int(supplied, 16), instance)
    )
    numbers = key.public_key().public_numbers()
    size = (instance.key_size + 7) // 8
    return {
        "iutX": numbers.x.to_bytes(size, "big").hex().upper(),
        "iutY": numbers.y.to_bytes(size, "big").hex().upper(),
        "z": key.exchange(ec.ECDH(), peer).hex().upper(),
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


BLOCK_MODES = {
    "ACVP-AES-ECB": lambda _iv: modes.ECB(),  # noqa: S305 - ACVP tests ECB directly
    "ACVP-AES-CBC": modes.CBC,
    "ACVP-AES-CTR": modes.CTR,
    "ACVP-AES-OFB": _OFB,
    "ACVP-AES-CFB128": _CFB,
}

#: How the cipher's IV advances between Monte Carlo iterations. The
#: specification writes the inner loop as a cipher that "continues" from the
#: previous call without saying what that does to the IV, and each mode answers
#: differently -- see docs/harness-protocol.md.
MCT_INNER = 1000
MCT_OUTER = 100


def _block(algorithm: str, key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    """One transform in the named mode."""
    builder = BLOCK_MODES[algorithm]
    cipher = Cipher(algorithms.AES(key), builder(iv))
    operation = cipher.encryptor() if encrypt else cipher.decryptor()
    return operation.update(data) + operation.finalize()


def _next_iv(
    algorithm: str, key: bytes, iv: bytes, fed: bytes, produced: bytes, encrypt: bool
) -> bytes:
    """Advance the IV as a stateful implementation of this mode would."""
    if algorithm == "ACVP-AES-ECB":
        return b""
    if algorithm == "ACVP-AES-OFB":
        # OFB feeds back the raw keystream, which is neither input nor output.
        return _block("ACVP-AES-ECB", key, b"", iv, True)
    return produced if encrypt else fed


def _shuffle(key: bytes, last: bytes, previous: bytes) -> bytes:
    """The shared AES Monte Carlo key shuffle; wider keys reach further back."""
    if len(key) == 16:
        feed = last
    elif len(key) == 24:
        feed = previous[-8:] + last
    else:
        feed = previous + last
    return bytes(a ^ b for a, b in zip(key, feed, strict=True))


def block_transform(request: dict[str, Any]) -> dict[str, str]:
    """Encrypt or decrypt one payload in an AES block or chaining mode."""
    algorithm = request["algorithm"]
    if algorithm not in BLOCK_MODES:
        return {"error": "unsupported"}
    produced = _block(
        algorithm,
        bytes.fromhex(request["key"]),
        bytes.fromhex(request["iv"]),
        bytes.fromhex(request["data"]),
        request["direction"] == "encrypt",
    )
    return {"out": produced.hex().upper()}


def block_mct(request: dict[str, Any]) -> dict[str, Any]:
    """Run the whole AES Monte Carlo chain and return every outer iteration.

    Delegated rather than driven case by case: 100 x 1000 iterations would be
    100,000 exchanges over the wire, and running the chain is what a real
    implementation under test does anyway.
    """
    algorithm = request["algorithm"]
    if algorithm not in BLOCK_MODES or algorithm == "ACVP-AES-CTR":
        return {"error": "unsupported"}
    encrypt = request["direction"] == "encrypt"
    key = bytes.fromhex(request["key"])
    iv = bytes.fromhex(request["iv"])
    data = bytes.fromhex(request["data"])

    results: list[dict[str, str]] = []
    for _ in range(MCT_OUTER):
        first_input, feedback, payload = data, iv, data
        previous = carried = b""
        for iteration in range(MCT_INNER):
            produced = _block(algorithm, key, feedback, payload, encrypt)
            feedback = _next_iv(algorithm, key, feedback, payload, produced, encrypt)
            if iteration == 0:
                previous = iv if algorithm != "ACVP-AES-ECB" else produced
            if algorithm == "ACVP-AES-ECB":
                carried, previous, payload = previous, produced, produced
            else:
                carried, payload, previous = previous, previous, produced
        results.append(
            {
                "key": key.hex().upper(),
                "iv": iv.hex().upper(),
                "in": first_input.hex().upper(),
                "out": previous.hex().upper(),
            }
        )
        key = _shuffle(key, previous, carried)
        iv = previous if algorithm != "ACVP-AES-ECB" else b""
        data = previous if algorithm == "ACVP-AES-ECB" else carried
    return {"resultsArray": results}


def cmac(request: dict[str, Any]) -> dict[str, str]:
    """Compute a CMAC truncated to the requested bit length."""
    context = cmac_mod.CMAC(algorithms.AES(bytes.fromhex(request["key"])))
    context.update(bytes.fromhex(request["message"]))
    return {"mac": context.finalize()[: request["macLen"] // 8].hex().upper()}


def gmac(request: dict[str, Any]) -> dict[str, str]:
    """Authenticate AAD with no payload, returning the requested tag prefix."""
    encryptor = Cipher(
        algorithms.AES(bytes.fromhex(request["key"])),
        modes.GCM(bytes.fromhex(request["iv"])),
    ).encryptor()
    encryptor.authenticate_additional_data(bytes.fromhex(request["aad"]))
    encryptor.finalize()
    return {"tag": encryptor.tag[: request["tagLen"] // 8].hex().upper()}


def key_wrap(request: dict[str, Any]) -> dict[str, str]:
    """Wrap or unwrap key material.

    A rejected unwrapping is reported as an authentication failure, not a
    crash: half of each upstream unwrap set is a deliberately corrupt wrapping
    where refusing it is the correct answer.
    """
    key = bytes.fromhex(request["key"])
    data = bytes.fromhex(request["data"])
    padded = bool(request["padded"])
    try:
        if request["direction"] == "wrap":
            produced = (
                keywrap.aes_key_wrap_with_padding(key, data)
                if padded
                else keywrap.aes_key_wrap(key, data)
            )
        else:
            produced = (
                keywrap.aes_key_unwrap_with_padding(key, data)
                if padded
                else keywrap.aes_key_unwrap(key, data)
            )
    except (keywrap.InvalidUnwrap, InvalidSignature):
        return {"error": "authentication failed"}
    return {"out": produced.hex().upper()}


RSA_HASHES = {
    "SHA-1": hashes.SHA1,
    "SHA2-224": hashes.SHA224,
    "SHA2-256": hashes.SHA256,
    "SHA2-384": hashes.SHA384,
    "SHA2-512": hashes.SHA512,
    "SHA3-256": hashes.SHA3_256,
    "SHA3-384": hashes.SHA3_384,
    "SHA3-512": hashes.SHA3_512,
}


def _rsa_padding(request: dict[str, Any]) -> Any:
    """Build the padding an ACVP RSA group describes, or None if unsupported.

    `maskFunction` is a field of its own: FIPS 186-5 lets PSS use SHAKE as its
    mask generation function, which is not the same question as `hashAlg`.
    """
    algorithm = RSA_HASHES.get(request["hashAlg"])
    if algorithm is None:
        return None
    if request["sigType"] == "pkcs1v1.5":
        return padding.PKCS1v15()
    if request["sigType"] != "pss":
        return None
    if request.get("maskFunction", "mgf1") not in ("mgf1", ""):
        return None
    return padding.PSS(mgf=padding.MGF1(algorithm()), salt_length=request["saltLen"])


def rsa_sign_group(request: dict[str, Any]) -> dict[str, Any]:
    """Sign every message in a group under one freshly generated key.

    ACVP reports the public key once per group, so a key per case could not be
    reported at all. Generating it here is the point: in sigGen the key belongs
    to the implementation under test, not to the vector.
    """
    scheme = _rsa_padding(request)
    algorithm = RSA_HASHES.get(request["hashAlg"])
    if scheme is None or algorithm is None:
        return {"error": "unsupported"}
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=request["modulo"])
    numbers = private_key.public_key().public_numbers()
    return {
        "n": f"{numbers.n:X}".zfill(request["modulo"] // 4),
        "e": f"{numbers.e:X}".zfill(6),
        "signatures": [
            private_key.sign(bytes.fromhex(message), scheme, algorithm()).hex().upper()
            for message in request["messages"]
        ],
    }


def rsa_verify(request: dict[str, Any]) -> dict[str, Any]:
    """Report whether a signature verifies. A rejection is an answer."""
    scheme = _rsa_padding(request)
    algorithm = RSA_HASHES.get(request["hashAlg"])
    if scheme is None or algorithm is None:
        return {"error": "unsupported"}
    public_key = rsa.RSAPublicNumbers(e=int(request["e"], 16), n=int(request["n"], 16)).public_key()
    try:
        public_key.verify(
            bytes.fromhex(request["signature"]),
            bytes.fromhex(request["message"]),
            scheme,
            algorithm(),
        )
    except (InvalidSignature, ValueError):
        return {"testPassed": False}
    return {"testPassed": True}


def rsa_primitive_sign(request: dict[str, Any]) -> dict[str, Any]:
    """Raw RSA over a message: valid when 0 <= m < n.

    Bare modular exponentiation on purpose. This ACVP mode exists to exercise
    the unpadded operation, including inputs a padded API would refuse.
    """
    n = int(request["n"], 16)
    message = int(request["message"], 16)
    if not 0 <= message < n:
        return {"testPassed": False}
    if "d" in request:
        signature = pow(message, int(request["d"], 16), n)
    else:
        p, q = int(request["p"], 16), int(request["q"], 16)
        m1 = pow(message, int(request["dmp1"], 16), p)
        m2 = pow(message, int(request["dmq1"], 16), q)
        signature = (m2 + q * (int(request["iqmp"], 16) * (m1 - m2) % p)) % n
    width = (n.bit_length() + 7) // 8 * 2
    return {"testPassed": True, "signature": f"{signature:X}".zfill(width)}


def rsa_primitive_decrypt(request: dict[str, Any]) -> dict[str, Any]:
    """Raw RSA over a ciphertext: valid only when 1 < c < n-1.

    Stricter than the signature primitive, and deliberately so -- SP 800-56B
    excludes the endpoints. ACVP includes cases on both sides to catch an
    implementation that shares one rule between the two.
    """
    n = int(request["n"], 16)
    ciphertext = int(request["ct"], 16)
    if not 1 < ciphertext < n - 1:
        return {"testPassed": False}
    width = (n.bit_length() + 7) // 8 * 2
    return {
        "testPassed": True,
        "pt": f"{pow(ciphertext, int(request['d'], 16), n):X}".zfill(width),
    }


#: Every PRF SP 800-108 admits that this harness can compute. CMAC-TDES is
#: absent on purpose: disallowed for this use since 2023.
HMAC_FOR_KDF = {f"HMAC-{name}": digest for name, digest in HASHLIB.items()}
CMAC_KEY_BYTES = {"CMAC-AES128": 16, "CMAC-AES192": 24, "CMAC-AES256": 32}


def kdf_108(request: dict[str, Any]) -> dict[str, Any]:
    """Derive keying material with SP 800-108.

    `fixedData` arrives as input rather than being chosen here: the runner
    compares against the fixed data NIST recorded, and a harness free to choose
    its own would produce a different key every run with nothing to check it
    against.
    """
    prf = request["macMode"]
    if prf in HMAC_FOR_KDF:
        outlen = hashlib.new(HMAC_FOR_KDF[prf]).digest_size
    elif prf in CMAC_KEY_BYTES:
        outlen = 16
    else:
        return {"error": "unsupported"}

    def mac(data: bytes) -> bytes:
        key = bytes.fromhex(request["keyIn"])
        if prf in HMAC_FOR_KDF:
            return hmac.new(key, data, HMAC_FOR_KDF[prf]).digest()
        context = cmac_mod.CMAC(algorithms.AES(key))
        context.update(data)
        return context.finalize()

    fixed = bytes.fromhex(request["fixedData"])
    counter_bytes = request["counterLength"] // 8
    bits = request["keyOutLength"]
    iterations = -(-bits // (outlen * 8))

    def place(index: int, iterator: bytes) -> bytes:
        counter = index.to_bytes(counter_bytes, "big") if counter_bytes else b""
        location = request["counterLocation"]
        if location == "before iterator":
            return counter + iterator + fixed
        if location == "before fixed data":
            return iterator + counter + fixed
        if location == "after fixed data":
            return iterator + fixed + counter
        if location == "middle fixed data":
            # A *bit* offset, so the counter splices mid-byte.
            total = len(fixed) * 8
            tail_bits = total - request["breakLocation"]
            whole = int.from_bytes(fixed, "big")
            joined = (
                ((whole >> tail_bits) << (counter_bytes * 8 + tail_bits))
                | (index << tail_bits)
                | (whole & ((1 << tail_bits) - 1))
            )
            return iterator + joined.to_bytes((total + counter_bytes * 8) // 8, "big")
        return iterator + fixed

    derived = b""
    feedback = bytes.fromhex(request["iv"])
    pipeline = fixed
    for index in range(1, iterations + 1):
        if request["kdfMode"] == "counter":
            derived += mac(place(index, b""))
        elif request["kdfMode"] == "feedback":
            feedback = mac(place(index, feedback))
            derived += feedback
        else:
            pipeline = mac(pipeline)
            derived += mac(place(index, pipeline))

    length = -(-bits // 8)
    out = bytearray(derived[:length])
    if bits % 8:
        out[-1] &= (0xFF << (8 - bits % 8)) & 0xFF
    return {"keyOut": bytes(out).hex().upper()}


DRBG_SEED_BITS = {
    "SHA-1": 440,
    "SHA2-224": 440,
    "SHA2-256": 440,
    "SHA2-512/224": 440,
    "SHA2-512/256": 440,
    "SHA2-384": 888,
    "SHA2-512": 888,
}
DRBG_AES = {"AES-128": 16, "AES-192": 24, "AES-256": 32}


class _HmacDrbg:
    """HMAC_DRBG: a key and a value, both advanced by one update routine."""

    def __init__(self, mode: str) -> None:
        self.digest = HASHLIB[mode]
        size = hashlib.new(self.digest).digest_size
        self.key, self.v = b"\x00" * size, b"\x01" * size

    def _mac(self, key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, self.digest).digest()

    def _update(self, provided: bytes) -> None:
        self.key = self._mac(self.key, self.v + b"\x00" + provided)
        self.v = self._mac(self.key, self.v)
        if not provided:
            return
        self.key = self._mac(self.key, self.v + b"\x01" + provided)
        self.v = self._mac(self.key, self.v)

    def instantiate(self, entropy: bytes, nonce: bytes, perso: bytes) -> None:
        self._update(entropy + nonce + perso)

    def reseed(self, entropy: bytes, extra: bytes) -> None:
        self._update(entropy + extra)

    def generate(self, count: int, extra: bytes) -> bytes:
        if extra:
            self._update(extra)
        out = b""
        while len(out) < count:
            self.v = self._mac(self.key, self.v)
            out += self.v
        # Runs even with no additional input: skipping it desynchronises every
        # later generation.
        self._update(extra)
        return out[:count]


class _HashDrbg:
    """Hash_DRBG: a seed-length V, a constant C, and a reseed counter."""

    def __init__(self, mode: str) -> None:
        self.digest = HASHLIB[mode]
        self.width = DRBG_SEED_BITS[mode] // 8
        self.v = self.c = b""
        self.counter = 1

    def _hash(self, data: bytes) -> bytes:
        return hashlib.new(self.digest, data).digest()

    def _add(self, *values: bytes) -> bytes:
        total = sum(int.from_bytes(value, "big") for value in values)
        return (total % (1 << (self.width * 8))).to_bytes(self.width, "big")

    def _df(self, data: bytes) -> bytes:
        out, counter = b"", 1
        while len(out) < self.width:
            out += self._hash(bytes([counter]) + (self.width * 8).to_bytes(4, "big") + data)
            counter += 1
        return out[: self.width]

    def _seed(self, material: bytes) -> None:
        self.v = self._df(material)
        self.c = self._df(b"\x00" + self.v)
        self.counter = 1

    def instantiate(self, entropy: bytes, nonce: bytes, perso: bytes) -> None:
        self._seed(entropy + nonce + perso)

    def reseed(self, entropy: bytes, extra: bytes) -> None:
        self._seed(b"\x01" + self.v + entropy + extra)

    def generate(self, count: int, extra: bytes) -> bytes:
        if extra:
            self.v = self._add(self.v, self._hash(b"\x02" + self.v + extra))
        data, out = self.v, b""
        while len(out) < count:
            out += self._hash(data)
            data = self._add(data, b"\x01")
        # The reseed counter is part of the sum: omitting it stays correct for
        # exactly one generation, and every case generates twice.
        self.v = self._add(
            self.v, self._hash(b"\x03" + self.v), self.c, self.counter.to_bytes(4, "big")
        )
        self.counter += 1
        return out[:count]


class _CtrDrbg:
    """CTR_DRBG over AES, with the r1 narrow counter field."""

    def __init__(self, mode: str, derivation_function: bool, counter_bits: int) -> None:
        self.keylen, self.outlen = DRBG_AES[mode], 16
        self.seedlen = self.keylen + self.outlen
        self.df = derivation_function
        self.counter_bits = counter_bits or self.outlen * 8
        self.key, self.v = b"\x00" * self.keylen, b"\x00" * self.outlen

    def _encrypt(self, key: bytes, block: bytes) -> bytes:
        engine = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305
        return engine.update(block) + engine.finalize()

    def _increment(self) -> None:
        value = int.from_bytes(self.v, "big")
        mask = (1 << self.counter_bits) - 1
        self.v = ((value & ~mask) | ((value + 1) & mask)).to_bytes(self.outlen, "big")

    def _bcc(self, key: bytes, data: bytes) -> bytes:
        chain = b"\x00" * self.outlen
        for offset in range(0, len(data), self.outlen):
            block = data[offset : offset + self.outlen]
            chain = self._encrypt(key, bytes(a ^ b for a, b in zip(chain, block, strict=True)))
        return chain

    def _derive(self, data: bytes, count: int) -> bytes:
        block = len(data).to_bytes(4, "big") + count.to_bytes(4, "big") + data + b"\x80"
        if len(block) % self.outlen:
            block += b"\x00" * (self.outlen - len(block) % self.outlen)
        key, temp, index = bytes(range(32))[: self.keylen], b"", 0
        while len(temp) < self.keylen + self.outlen:
            iv = index.to_bytes(4, "big") + b"\x00" * (self.outlen - 4)
            temp += self._bcc(key, iv + block)
            index += 1
        derived, chunk, out = temp[: self.keylen], temp[self.keylen : self.seedlen], b""
        while len(out) < count:
            chunk = self._encrypt(derived, chunk)
            out += chunk
        return out[:count]

    def _update(self, provided: bytes) -> None:
        temp = b""
        while len(temp) < self.seedlen:
            self._increment()
            temp += self._encrypt(self.key, self.v)
        mixed = bytes(a ^ b for a, b in zip(temp[: self.seedlen], provided, strict=True))
        self.key, self.v = mixed[: self.keylen], mixed[self.keylen :]

    def _fit(self, data: bytes) -> bytes:
        return data.ljust(self.seedlen, b"\x00")[: self.seedlen]

    def _material(self, entropy: bytes, extra: bytes) -> bytes:
        if self.df:
            return self._derive(entropy + extra, self.seedlen)
        return bytes(a ^ b for a, b in zip(self._fit(entropy), self._fit(extra), strict=True))

    def instantiate(self, entropy: bytes, nonce: bytes, perso: bytes) -> None:
        material = (
            self._derive(entropy + nonce + perso, self.seedlen)
            if self.df
            else self._material(entropy, perso)
        )
        self._update(material)

    def reseed(self, entropy: bytes, extra: bytes) -> None:
        self._update(self._material(entropy, extra))

    def generate(self, count: int, extra: bytes) -> bytes:
        if extra:
            prepared = self._derive(extra, self.seedlen) if self.df else self._fit(extra)
            self._update(prepared)
        else:
            prepared = b"\x00" * self.seedlen
        out = b""
        while len(out) < count:
            self._increment()
            out += self._encrypt(self.key, self.v)
        self._update(prepared)
        return out[:count]


def drbg(request: dict[str, Any]) -> dict[str, Any]:
    """Run a whole DRBG case and return the bits of the final generation.

    The entire case arrives in one request -- seed material plus the ordered
    `otherInput` steps -- rather than as a conversation. A DRBG is a state
    machine, and keeping the state on this side means the two sides agree about
    an answer rather than about a sequence of calls.

    Two details are silently wrong if you get them wrong. Prediction resistance
    turns a generation carrying entropy into a reseed *then* a generation, with
    the additional input consumed by the reseed. And every case generates twice
    while only the second output is compared: returning the first would pass a
    DRBG that never updates its state.
    """
    mechanism, mode = request["mechanism"], request["mode"]
    if mechanism == "ctrDRBG":
        if mode not in DRBG_AES:
            return {"error": "unsupported"}
        engine: Any = _CtrDrbg(mode, request["derFunc"], request["counterFieldLen"])
    elif mode not in DRBG_SEED_BITS:
        return {"error": "unsupported"}
    elif mechanism == "hashDRBG":
        engine = _HashDrbg(mode)
    elif mechanism == "hmacDRBG":
        engine = _HmacDrbg(mode)
    else:
        return {"error": "unsupported"}

    engine.instantiate(
        bytes.fromhex(request["entropyInput"]),
        bytes.fromhex(request["nonce"]),
        bytes.fromhex(request["persoString"]),
    )
    count = request["returnedBitsLen"] // 8
    produced = b""
    for step in request["otherInput"]:
        extra = bytes.fromhex(step["additionalInput"])
        entropy = bytes.fromhex(step.get("entropyInput", ""))
        if step["intendedUse"] == "reSeed":
            engine.reseed(entropy, extra)
        elif entropy:
            engine.reseed(entropy, extra)
            produced = engine.generate(count, b"")
        else:
            produced = engine.generate(count, extra)
    return {"returnedBits": produced.hex().upper()}


HANDLERS = {
    "drbg": drbg,
    "kdf-108": kdf_108,
    "rsa-sign-group": rsa_sign_group,
    "rsa-verify": rsa_verify,
    "rsa-primitive-sign": rsa_primitive_sign,
    "rsa-primitive-decrypt": rsa_primitive_decrypt,
    "block-transform": block_transform,
    "block-mct": block_mct,
    "cmac": cmac,
    "gmac": gmac,
    "key-wrap": key_wrap,
    "metadata": lambda _: metadata(),
    "encrypt": encrypt,
    "decrypt": decrypt,
    "digest": digest,
    "digest-mct": digest_mct,
    "mac": mac,
    "ecdsa-sign": ecdsa_sign,
    "ecdsa-sign-group": ecdsa_sign_group,
    "kas-ecc-ssc": kas_ecc_ssc,
    "xts-transform": xts_transform,
    "ecdsa-verify": ecdsa_verify,
}


def main() -> int:
    """Answer requests until stdin closes.

    One JSON request per line in, one JSON response per line out. The process
    is started once and kept alive for the whole run, so any expensive setup --
    opening a PKCS#11 session, attaching to a serial port, logging in to a
    device -- happens once here rather than once per case.

    ``flush=True`` is not optional: a harness that buffers its stdout looks to
    the runner exactly like one that has hung.
    """
    for line in sys.stdin:
        if not line.strip():
            continue
        request = json.loads(line)
        operation = request.get("operation")
        handler = HANDLERS.get(operation)
        response = (
            {"error": f"unsupported operation {operation!r}"}
            if handler is None
            else handler(request)
        )
        print(json.dumps(response), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
