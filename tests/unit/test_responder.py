"""Response construction for submission to a live ACVTS server.

The shapes asserted here are the ones NIST accepted: session 765339 on the Demo
server was answered from this code path and returned ``"passed": true``. The
value of these tests is that they pin the *document shape* -- a submission that
is subtly malformed is scored as wrong answers, not rejected as malformed, so
there is no second chance to notice.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest

from acvp_assay.responder import (
    FIXED_DATA_BYTES,
    ResponseError,
    build_response,
    supported_response_algorithms,
)


def write_prompt(tmp_path: Path, document: dict[str, object]) -> Path:
    """Write a prompt document and return its path."""
    path = tmp_path / "prompt.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_an_aft_group_answers_with_a_digest_per_case(tmp_path: Path) -> None:
    """Each AFT case carries an ``md`` and nothing else."""
    message = b"acvp"
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 4032018,
            "algorithm": "SHA2-256",
            "revision": "1.0",
            "isSample": True,
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "tests": [
                        {"tcId": 1, "msg": message.hex(), "len": len(message) * 8},
                        {"tcId": 2, "msg": "", "len": 0},
                    ],
                }
            ],
        },
    )

    response = build_response(prompt)

    assert response["vsId"] == 4032018
    assert response["algorithm"] == "SHA2-256"
    assert response["revision"] == "1.0"
    group = response["testGroups"][0]  # type: ignore[index]
    assert group["tgId"] == 1
    assert group["tests"][0] == {
        "tcId": 1,
        "md": hashlib.sha256(message).hexdigest().upper(),
    }
    assert group["tests"][1]["md"] == hashlib.sha256(b"").hexdigest().upper()


def test_a_monte_carlo_group_answers_with_the_whole_chain(tmp_path: Path) -> None:
    """An MCT case needs all 100 digests, not just the final one.

    The offline runner compares the whole chain but reports only its last
    value; a submission built from that report would be rejected as 99 missing
    answers, which is why responses are built from the provider directly.
    """
    seed = bytes(range(32))
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "SHA2-256",
            "revision": "1.0",
            "isSample": True,
            "testGroups": [
                {
                    "tgId": 2,
                    "testType": "MCT",
                    "mctVersion": "standard",
                    "tests": [{"tcId": 513, "msg": seed.hex(), "len": len(seed) * 8}],
                }
            ],
        },
    )

    response = build_response(prompt)

    case = response["testGroups"][0]["tests"][0]  # type: ignore[index]
    assert set(case) == {"tcId", "resultsArray"}
    assert len(case["resultsArray"]) == 100
    assert all(set(entry) == {"md"} for entry in case["resultsArray"])
    assert all(len(entry["md"]) == 64 for entry in case["resultsArray"])


def test_a_large_data_test_is_refused_rather_than_half_answered(tmp_path: Path) -> None:
    """An LDT group must stop the submission, not silently omit cases."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "SHA2-256",
            "revision": "1.0",
            "isSample": True,
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "LDT",
                    "tests": [
                        {
                            "tcId": 1,
                            "largeMsg": {
                                "content": "AB",
                                "contentLength": 8,
                                "fullLength": 8589934592,
                                "expansionTechnique": "repeating",
                            },
                        }
                    ],
                }
            ],
        },
    )

    with pytest.raises(ResponseError, match="large data test"):
        build_response(prompt)


def test_an_unknown_mct_version_is_refused(tmp_path: Path) -> None:
    """Guessing a Monte Carlo chain would produce confidently wrong answers."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "SHA2-256",
            "revision": "1.0",
            "isSample": True,
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "MCT",
                    "mctVersion": "spiral",
                    "tests": [{"tcId": 1, "msg": "00", "len": 8}],
                }
            ],
        },
    )

    with pytest.raises(ResponseError, match="mctVersion"):
        build_response(prompt)


def test_an_algorithm_without_a_builder_is_refused(tmp_path: Path) -> None:
    """Silence would be scored as wrong answers, so this raises instead."""
    prompt = write_prompt(
        tmp_path,
        {"vsId": 1, "algorithm": "ACVP-AES-CBC", "revision": "1.0", "testGroups": []},
    )

    with pytest.raises(ResponseError, match="no response builder"):
        build_response(prompt)


def test_supported_algorithms_are_reported() -> None:
    """Callers need to know what can be submitted before registering for it."""
    supported = supported_response_algorithms()

    assert "SHA2-256" in supported
    assert "SHA2-512" in supported
    assert "HMAC-SHA2-256" in supported
    assert "ACVP-AES-ECB" in supported
    assert "ctrDRBG" in supported
    assert "KDF" in supported
    assert "ECDSA" in supported


def test_hmac_answers_with_a_truncated_mac(tmp_path: Path) -> None:
    """The group's macLen governs how much of the MAC is reported."""
    key, message = bytes(range(32)), b"acvp"
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "HMAC-SHA2-256",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "keyLen": 256,
                    "msgLen": 32,
                    "macLen": 96,
                    "tests": [{"tcId": 1, "key": key.hex(), "msg": message.hex()}],
                }
            ],
        },
    )

    case = build_response(prompt)["testGroups"][0]["tests"][0]  # type: ignore[index]

    expected = hmac.new(key, message, hashlib.sha256).hexdigest().upper()
    assert case == {"tcId": 1, "mac": expected[: 96 // 4]}


def test_aes_ecb_monte_carlo_answers_with_key_input_and_output(tmp_path: Path) -> None:
    """Each AES Monte Carlo iteration reports three values, unlike SHA-2's one."""
    key = "000102030405060708090A0B0C0D0E0F"
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ACVP-AES-ECB",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "MCT",
                    "direction": "encrypt",
                    "keyLen": 128,
                    "tests": [{"tcId": 1, "key": key, "pt": "00112233445566778899AABBCCDDEEFF"}],
                }
            ],
        },
    )

    case = build_response(prompt)["testGroups"][0]["tests"][0]  # type: ignore[index]

    assert len(case["resultsArray"]) == 100
    assert set(case["resultsArray"][0]) == {"key", "pt", "ct"}


def test_a_corrupt_wrapping_answers_false_rather_than_erroring(tmp_path: Path) -> None:
    """Half of each upstream unwrap group is deliberately invalid."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ACVP-AES-KW",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "direction": "decrypt",
                    "kwCipher": "cipher",
                    "keyLen": 128,
                    "tests": [
                        {"tcId": 1, "key": "000102030405060708090A0B0C0D0E0F", "ct": "00" * 40}
                    ],
                }
            ],
        },
    )

    case = build_response(prompt)["testGroups"][0]["tests"][0]  # type: ignore[index]

    assert case == {"tcId": 1, "testPassed": False}


def test_the_inverse_key_wrap_is_refused(tmp_path: Path) -> None:
    """Answering a construction this runner does not implement would be a guess."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ACVP-AES-KW",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "direction": "encrypt",
                    "kwCipher": "inverse",
                    "keyLen": 128,
                    "tests": [
                        {"tcId": 1, "key": "000102030405060708090A0B0C0D0E0F", "pt": "00" * 32}
                    ],
                }
            ],
        },
    )

    with pytest.raises(ResponseError, match="kwCipher"):
        build_response(prompt)


def test_kdf_reports_the_fixed_data_it_chose(tmp_path: Path) -> None:
    """SP 800-108 leaves fixedData to the implementation, so it must be reported.

    The server checks that keyOut follows from the fixedData submitted, so an
    answer without it cannot be scored.
    """
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "KDF",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "kdfMode": "counter",
                    "counterLocation": "middle fixed data",
                    "macMode": "HMAC-SHA2-256",
                    "counterLength": 8,
                    "keyOutLength": 256,
                    "tests": [{"tcId": 1, "keyIn": bytes(range(32)).hex()}],
                }
            ],
        },
    )

    case = build_response(prompt)["testGroups"][0]["tests"][0]  # type: ignore[index]

    assert set(case) == {"tcId", "fixedData", "breakLocation", "keyOut"}
    assert len(bytes.fromhex(case["fixedData"])) == FIXED_DATA_BYTES
    # Strictly inside the fixed data: 0 or the full width would be
    # indistinguishable from "before" and "after".
    assert 0 < case["breakLocation"] < FIXED_DATA_BYTES * 8
    assert len(bytes.fromhex(case["keyOut"])) == 32


def test_ecdsa_siggen_reports_one_public_key_per_group(tmp_path: Path) -> None:
    """ACVP reports the key at group level, so every case must share it."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ECDSA",
            "mode": "sigGen",
            "revision": "FIPS186-5",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "curve": "P-256",
                    "hashAlg": "SHA2-256",
                    "tests": [
                        {"tcId": 1, "message": b"one".hex()},
                        {"tcId": 2, "message": b"two".hex()},
                    ],
                }
            ],
        },
    )

    group = build_response(prompt)["testGroups"][0]  # type: ignore[index]

    assert set(group) == {"tgId", "qx", "qy", "tests"}
    assert all(set(case) == {"tcId", "r", "s"} for case in group["tests"])


def test_ctr_drbg_refuses_tdes(tmp_path: Path) -> None:
    """Three-key TDES has been disallowed for this use since 2023."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ctrDRBG",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "mode": "TDES",
                    "derFunc": True,
                    "predResistance": False,
                    "returnedBitsLen": 128,
                    "tests": [
                        {
                            "tcId": 1,
                            "entropyInput": "00" * 29,
                            "nonce": "",
                            "persoString": "",
                            "otherInput": [
                                {"intendedUse": "generate", "additionalInput": ""},
                                {"intendedUse": "generate", "additionalInput": ""},
                            ],
                        }
                    ],
                }
            ],
        },
    )

    with pytest.raises(ResponseError, match="TDES"):
        build_response(prompt)


def test_aes_gcm_encrypt_answers_with_ciphertext_and_tag(tmp_path: Path) -> None:
    """An encrypt case reports both halves of the AEAD output."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ACVP-AES-GCM",
            "revision": "1.0",
            "isSample": True,
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "direction": "encrypt",
                    "ivGen": "external",
                    "ivGenMode": "8.2.1",
                    "keyLen": 128,
                    "ivLen": 96,
                    "payloadLen": 128,
                    "aadLen": 0,
                    "tagLen": 128,
                    "tests": [
                        {
                            "tcId": 1,
                            "key": "000102030405060708090A0B0C0D0E0F",
                            "iv": "101112131415161718191A1B",
                            "pt": "00112233445566778899AABBCCDDEEFF",
                            "aad": "",
                        }
                    ],
                }
            ],
        },
    )

    case = build_response(prompt)["testGroups"][0]["tests"][0]  # type: ignore[index]

    assert set(case) == {"tcId", "ct", "tag"}
    assert len(bytes.fromhex(case["tag"])) == 16


def test_aes_gcm_rejecting_a_forged_tag_answers_false(tmp_path: Path) -> None:
    """ACVP builds deliberate authentication failures into decrypt groups."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ACVP-AES-GCM",
            "revision": "1.0",
            "isSample": True,
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "direction": "decrypt",
                    "ivGen": "external",
                    "ivGenMode": "8.2.1",
                    "keyLen": 128,
                    "ivLen": 96,
                    "payloadLen": 128,
                    "aadLen": 0,
                    "tagLen": 128,
                    "tests": [
                        {
                            "tcId": 1,
                            "key": "000102030405060708090A0B0C0D0E0F",
                            "iv": "101112131415161718191A1B",
                            "ct": "00112233445566778899AABBCCDDEEFF",
                            "aad": "",
                            "tag": "00" * 16,
                        }
                    ],
                }
            ],
        },
    )

    case = build_response(prompt)["testGroups"][0]["tests"][0]  # type: ignore[index]

    assert case == {"tcId": 1, "testPassed": False}


def test_aes_gcm_internal_iv_generation_is_refused(tmp_path: Path) -> None:
    """This runner does not generate IVs, and guessing would fail every case."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ACVP-AES-GCM",
            "revision": "1.0",
            "isSample": True,
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "direction": "encrypt",
                    "ivGen": "internal",
                    "ivGenMode": "8.2.2",
                    "keyLen": 128,
                    "ivLen": 96,
                    "payloadLen": 128,
                    "aadLen": 0,
                    "tagLen": 128,
                    "tests": [
                        {
                            "tcId": 1,
                            "key": "000102030405060708090A0B0C0D0E0F",
                            "iv": "101112131415161718191A1B",
                            "pt": "00112233445566778899AABBCCDDEEFF",
                            "aad": "",
                        }
                    ],
                }
            ],
        },
    )

    with pytest.raises(ResponseError, match="generate the IV"):
        build_response(prompt)


def test_cmac_verification_answers_with_a_verdict(tmp_path: Path) -> None:
    """A ver group answers testPassed, not a MAC."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "CMAC-AES",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "direction": "ver",
                    "keyLen": 128,
                    "macLen": 128,
                    "tests": [
                        {
                            "tcId": 1,
                            "key": "000102030405060708090A0B0C0D0E0F",
                            "message": "00",
                            "mac": "00" * 16,
                        }
                    ],
                }
            ],
        },
    )

    case = build_response(prompt)["testGroups"][0]["tests"][0]  # type: ignore[index]

    assert case == {"tcId": 1, "testPassed": False}


def test_gmac_verification_answers_with_a_verdict(tmp_path: Path) -> None:
    """A decrypt GMAC group judges the tag it was given."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ACVP-AES-GMAC",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "direction": "decrypt",
                    "keyLen": 128,
                    "ivLen": 96,
                    "tagLen": 128,
                    "tests": [
                        {
                            "tcId": 1,
                            "key": "000102030405060708090A0B0C0D0E0F",
                            "iv": "101112131415161718191A1B",
                            "aad": "AABB",
                            "tag": "00" * 16,
                        }
                    ],
                }
            ],
        },
    )

    case = build_response(prompt)["testGroups"][0]["tests"][0]  # type: ignore[index]

    assert case == {"tcId": 1, "testPassed": False}


def test_ecdsa_sigver_answers_with_a_verdict(tmp_path: Path) -> None:
    """sigVer is verdict-only: the signature supplied may be deliberately invalid."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ECDSA",
            "mode": "sigVer",
            "revision": "FIPS186-5",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "curve": "P-256",
                    "hashAlg": "SHA2-256",
                    "tests": [
                        {
                            "tcId": 1,
                            "message": b"acvp".hex(),
                            "qx": "01" * 32,
                            "qy": "02" * 32,
                            "r": "03" * 32,
                            "s": "04" * 32,
                        }
                    ],
                }
            ],
        },
    )

    case = build_response(prompt)["testGroups"][0]["tests"][0]  # type: ignore[index]

    assert case == {"tcId": 1, "testPassed": False}


def test_an_unavailable_curve_is_refused(tmp_path: Path) -> None:
    """Answering a curve this build lacks would fail every case in the group."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ECDSA",
            "mode": "sigGen",
            "revision": "FIPS186-5",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "curve": "B-233",
                    "hashAlg": "SHA2-256",
                    "tests": [{"tcId": 1, "message": b"acvp".hex()}],
                }
            ],
        },
    )

    with pytest.raises(ResponseError, match="does not offer|B-233"):
        build_response(prompt)


def test_ctr_drbg_answers_with_the_returned_bits(tmp_path: Path) -> None:
    """The compared value is the second generation's output."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ctrDRBG",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "mode": "AES-128",
                    "derFunc": True,
                    "predResistance": False,
                    "returnedBitsLen": 256,
                    "counterFieldLen": 128,
                    "tests": [
                        {
                            "tcId": 1,
                            "entropyInput": bytes(range(32)).hex(),
                            "nonce": "",
                            "persoString": "",
                            "otherInput": [
                                {"intendedUse": "generate", "additionalInput": ""},
                                {"intendedUse": "generate", "additionalInput": ""},
                            ],
                        }
                    ],
                }
            ],
        },
    )

    case = build_response(prompt)["testGroups"][0]["tests"][0]  # type: ignore[index]

    assert set(case) == {"tcId", "returnedBits"}
    assert len(bytes.fromhex(case["returnedBits"])) == 32


def test_aes_gcm_successful_decryption_answers_with_plaintext(tmp_path: Path) -> None:
    """A genuine decrypt reports the recovered plaintext alongside the verdict."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key, iv, plaintext = bytes(range(16)), bytes(range(12)), b"sixteen  bytes!!"
    sealed = AESGCM(key).encrypt(iv, plaintext, b"")
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ACVP-AES-GCM",
            "revision": "1.0",
            "isSample": True,
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "direction": "decrypt",
                    "ivGen": "external",
                    "ivGenMode": "8.2.1",
                    "keyLen": 128,
                    "ivLen": 96,
                    "payloadLen": 128,
                    "aadLen": 0,
                    "tagLen": 128,
                    "tests": [
                        {
                            "tcId": 1,
                            "key": key.hex(),
                            "iv": iv.hex(),
                            "ct": sealed[:-16].hex(),
                            "aad": "",
                            "tag": sealed[-16:].hex(),
                        }
                    ],
                }
            ],
        },
    )

    case = build_response(prompt)["testGroups"][0]["tests"][0]  # type: ignore[index]

    assert case == {"tcId": 1, "testPassed": True, "pt": plaintext.hex().upper()}


def test_aes_ecb_decrypt_answers_with_plaintext(tmp_path: Path) -> None:
    """The reported field name follows the group's direction."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ACVP-AES-ECB",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "direction": "decrypt",
                    "keyLen": 128,
                    "tests": [
                        {
                            "tcId": 1,
                            "key": "000102030405060708090A0B0C0D0E0F",
                            "ct": "69C4E0D86A7B0430D8CDB78070B4C55A",
                        }
                    ],
                }
            ],
        },
    )

    case = build_response(prompt)["testGroups"][0]["tests"][0]  # type: ignore[index]

    assert case == {"tcId": 1, "pt": "00112233445566778899AABBCCDDEEFF"}


def test_cmac_generation_answers_with_a_mac(tmp_path: Path) -> None:
    """A gen group reports the MAC it computed."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "CMAC-AES",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "direction": "gen",
                    "keyLen": 128,
                    "macLen": 128,
                    "tests": [
                        {"tcId": 1, "key": "000102030405060708090A0B0C0D0E0F", "message": "00"}
                    ],
                }
            ],
        },
    )

    case = build_response(prompt)["testGroups"][0]["tests"][0]  # type: ignore[index]

    assert set(case) == {"tcId", "mac"}
    assert len(bytes.fromhex(case["mac"])) == 16


def test_gmac_generation_answers_with_a_tag(tmp_path: Path) -> None:
    """An encrypt GMAC group reports the tag."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ACVP-AES-GMAC",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "direction": "encrypt",
                    "keyLen": 128,
                    "ivLen": 96,
                    "tagLen": 128,
                    "tests": [
                        {
                            "tcId": 1,
                            "key": "000102030405060708090A0B0C0D0E0F",
                            "iv": "101112131415161718191A1B",
                            "aad": "AABB",
                        }
                    ],
                }
            ],
        },
    )

    case = build_response(prompt)["testGroups"][0]["tests"][0]  # type: ignore[index]

    assert set(case) == {"tcId", "tag"}


def test_a_successful_key_wrap_answers_with_ciphertext(tmp_path: Path) -> None:
    """Wrapping reports ct; only unwrapping carries a verdict."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ACVP-AES-KW",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "direction": "encrypt",
                    "kwCipher": "cipher",
                    "keyLen": 128,
                    "tests": [
                        {
                            "tcId": 1,
                            "key": "000102030405060708090A0B0C0D0E0F",
                            "pt": bytes(range(32)).hex(),
                        }
                    ],
                }
            ],
        },
    )

    case = build_response(prompt)["testGroups"][0]["tests"][0]  # type: ignore[index]

    assert set(case) == {"tcId", "ct"}


def test_a_valid_unwrap_answers_true_with_the_plaintext(tmp_path: Path) -> None:
    """A genuine wrapping is accepted and its payload reported."""
    from cryptography.hazmat.primitives import keywrap

    key, payload = bytes(range(16)), bytes(range(32))
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ACVP-AES-KW",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "direction": "decrypt",
                    "kwCipher": "cipher",
                    "keyLen": 128,
                    "tests": [
                        {
                            "tcId": 1,
                            "key": key.hex(),
                            "ct": keywrap.aes_key_wrap(key, payload).hex(),
                        }
                    ],
                }
            ],
        },
    )

    case = build_response(prompt)["testGroups"][0]["tests"][0]  # type: ignore[index]

    assert case == {"tcId": 1, "testPassed": True, "pt": payload.hex().upper()}


def test_ctr_drbg_with_prediction_resistance_and_reseed(tmp_path: Path) -> None:
    """Both reseed paths must be driven, not just the plain generate."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ctrDRBG",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "mode": "AES-128",
                    "derFunc": True,
                    "predResistance": True,
                    "returnedBitsLen": 128,
                    "counterFieldLen": 128,
                    "tests": [
                        {
                            "tcId": 1,
                            "entropyInput": bytes(range(32)).hex(),
                            "nonce": "",
                            "persoString": "",
                            "otherInput": [
                                {
                                    "intendedUse": "reSeed",
                                    "additionalInput": "AA" * 32,
                                    "entropyInput": "BB" * 32,
                                },
                                {
                                    "intendedUse": "generate",
                                    "additionalInput": "CC" * 32,
                                    "entropyInput": "DD" * 32,
                                },
                                {
                                    "intendedUse": "generate",
                                    "additionalInput": "EE" * 32,
                                    "entropyInput": "FF" * 32,
                                },
                            ],
                        }
                    ],
                }
            ],
        },
    )

    case = build_response(prompt)["testGroups"][0]["tests"][0]  # type: ignore[index]

    assert len(bytes.fromhex(case["returnedBits"])) == 16


def test_ctr_drbg_without_a_generation_is_refused(tmp_path: Path) -> None:
    """A sequence of reseeds alone produces nothing to submit."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ctrDRBG",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "mode": "AES-128",
                    "derFunc": True,
                    "predResistance": False,
                    "returnedBitsLen": 128,
                    "tests": [
                        {
                            "tcId": 1,
                            "entropyInput": bytes(range(32)).hex(),
                            "nonce": "",
                            "persoString": "",
                            "otherInput": [
                                {
                                    "intendedUse": "reSeed",
                                    "additionalInput": "",
                                    "entropyInput": "BB" * 32,
                                }
                            ],
                        }
                    ],
                }
            ],
        },
    )

    with pytest.raises(ResponseError, match="no generation"):
        build_response(prompt)


def test_kdf_refuses_a_mac_mode_it_cannot_compute(tmp_path: Path) -> None:
    """CMAC-TDES appears upstream and is not implemented here."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "KDF",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "kdfMode": "counter",
                    "counterLocation": "after fixed data",
                    "macMode": "CMAC-TDES",
                    "counterLength": 8,
                    "keyOutLength": 128,
                    "tests": [{"tcId": 1, "keyIn": bytes(range(21)).hex()}],
                }
            ],
        },
    )

    with pytest.raises(ResponseError, match="macMode"):
        build_response(prompt)


def test_an_ecdsa_component_test_is_refused(tmp_path: Path) -> None:
    """Component tests skip the hash step and are not answered here."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ECDSA",
            "mode": "sigGen",
            "revision": "FIPS186-5",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "curve": "P-256",
                    "hashAlg": "SHA2-256",
                    "componentTest": True,
                    "tests": [{"tcId": 1, "message": b"acvp".hex()}],
                }
            ],
        },
    )

    with pytest.raises(ResponseError, match="component test"):
        build_response(prompt)


def test_kdf_without_a_middle_counter_omits_break_location(tmp_path: Path) -> None:
    """breakLocation is meaningful only when the counter sits inside the fixed data."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "KDF",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "kdfMode": "counter",
                    "counterLocation": "after fixed data",
                    "macMode": "HMAC-SHA2-256",
                    "counterLength": 8,
                    "keyOutLength": 256,
                    "tests": [{"tcId": 1, "keyIn": bytes(range(32)).hex()}],
                }
            ],
        },
    )

    case = build_response(prompt)["testGroups"][0]["tests"][0]  # type: ignore[index]

    assert set(case) == {"tcId", "fixedData", "keyOut"}
