"""Tests for ECDSA: the verdict-only and produce-and-verify result shapes."""

from __future__ import annotations

import json
from typing import Any

import pytest

from acvp_runner.algorithms import ecdsa
from acvp_runner.models import ResultStatus
from acvp_runner.parser import AcvpValidationError
from acvp_runner.providers.ecdsa import CryptographyEcdsaProvider

CURVE = "P-256"
HASH = "SHA2-256"
MESSAGE = b"acvp message"


def provider() -> CryptographyEcdsaProvider:
    """Return the OpenSSL-backed ECDSA provider."""
    return CryptographyEcdsaProvider()


def sig_ver_documents(
    *, valid: bool, expected_verdict: bool
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build a sigVer prompt/expected pair around a real signature."""
    produced = provider().sign(curve=CURVE, hash_algorithm=HASH, message=MESSAGE)
    r = produced.r if valid else bytes([produced.r[0] ^ 0x01]) + produced.r[1:]
    prompt = {
        "vsId": 1,
        "algorithm": "ECDSA",
        "revision": "FIPS186-5",
        "mode": "sigVer",
        "testGroups": [
            {
                "tgId": 1,
                "curve": CURVE,
                "hashAlg": HASH,
                "tests": [
                    {
                        "tcId": 1,
                        "message": MESSAGE.hex().upper(),
                        "qx": produced.qx.hex().upper(),
                        "qy": produced.qy.hex().upper(),
                        "r": r.hex().upper(),
                        "s": produced.s.hex().upper(),
                    }
                ],
            }
        ],
    }
    expected = {
        "vsId": 1,
        "testGroups": [{"tgId": 1, "tests": [{"tcId": 1, "testPassed": expected_verdict}]}],
    }
    return prompt, expected


def run(prompt: dict[str, Any], expected: dict[str, Any]) -> list[Any]:
    """Run an in-memory ECDSA prompt/expected pair."""
    return ecdsa.run_vector_set(
        ecdsa.parse_vector_set(prompt),
        ecdsa.parse_expected_results(expected),
        provider(),
    )


# --- provider --------------------------------------------------------------


def test_sign_then_verify_round_trips() -> None:
    """A freshly generated signature verifies under its own public key."""
    produced = provider().sign(curve=CURVE, hash_algorithm=HASH, message=MESSAGE)

    assert provider().verify(
        curve=CURVE,
        hash_algorithm=HASH,
        message=MESSAGE,
        qx=produced.qx,
        qy=produced.qy,
        r=produced.r,
        s=produced.s,
    )


def test_off_curve_public_key_is_a_false_verdict_not_an_error() -> None:
    """ACVP includes invalid points; rejecting them is the correct answer.

    Treating a malformed key as an exception would turn a conforming
    implementation's correct rejection into an error.
    """
    assert not provider().verify(
        curve=CURVE,
        hash_algorithm=HASH,
        message=MESSAGE,
        qx=b"\x01" * 32,
        qy=b"\x02" * 32,
        r=b"\x03" * 32,
        s=b"\x04" * 32,
    )


@pytest.mark.parametrize(
    ("curve", "hash_algorithm", "match"),
    [("B-233", HASH, "unsupported curve"), (CURVE, "SHAKE-128", "unsupported hash")],
)
def test_unsupported_parameters_are_rejected(curve: str, hash_algorithm: str, match: str) -> None:
    """Curves and hashes OpenSSL does not offer here fail loudly."""
    with pytest.raises(ValueError, match=match):
        provider().sign(curve=curve, hash_algorithm=hash_algorithm, message=MESSAGE)


def test_provider_metadata_identifies_openssl() -> None:
    """Reports attribute ECDSA results to cryptography and its OpenSSL build."""
    metadata = provider().metadata()

    assert metadata.name == "cryptography-ecdsa"
    assert metadata.backend_name == "OpenSSL"


# --- sigVer: verdict-only --------------------------------------------------


@pytest.mark.parametrize("valid", [True, False])
def test_correct_verdict_passes(valid: bool) -> None:
    """Agreeing with ACVP's verdict passes, for valid and invalid signatures alike."""
    prompt, expected = sig_ver_documents(valid=valid, expected_verdict=valid)

    results = run(prompt, expected)

    assert results[0].status is ResultStatus.PASS
    assert results[0].expected is not None
    assert results[0].expected.as_document() == {"testPassed": valid}


def test_accepting_an_invalid_signature_fails_loudly() -> None:
    """Claiming a signature ACVP calls invalid is valid is a security failure."""
    prompt, expected = sig_ver_documents(valid=True, expected_verdict=False)

    results = run(prompt, expected)

    assert results[0].status is ResultStatus.FAIL
    assert results[0].diagnostic == "accepted a signature ACVP declares invalid"


def test_rejecting_a_valid_signature_fails() -> None:
    """Rejecting a signature ACVP calls valid is a correctness failure."""
    prompt, expected = sig_ver_documents(valid=False, expected_verdict=True)

    results = run(prompt, expected)

    assert results[0].status is ResultStatus.FAIL
    assert results[0].diagnostic == "rejected a signature ACVP declares valid"


def test_sig_ver_without_expected_verdict_is_unsupported() -> None:
    """A case with no recorded verdict has nothing to be judged against."""
    prompt, _ = sig_ver_documents(valid=True, expected_verdict=True)

    results = run(prompt, {"vsId": 1, "testGroups": []})

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert results[0].diagnostic == "no expected verdict recorded"


def test_sig_ver_missing_signature_fields_is_unsupported() -> None:
    """A sigVer case must carry the key and signature it is judged on."""
    prompt, expected = sig_ver_documents(valid=True, expected_verdict=True)
    del prompt["testGroups"][0]["tests"][0]["s"]

    results = run(prompt, expected)

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "missing a key or signature" in (results[0].diagnostic or "")


# --- sigGen: produce-and-verify --------------------------------------------


def test_sig_gen_verifies_its_own_signature() -> None:
    """sigGen passes by self-verification, since NIST's r/s are not reproducible."""
    prompt = {
        "vsId": 1,
        "algorithm": "ECDSA",
        "revision": "FIPS186-5",
        "mode": "sigGen",
        "testGroups": [
            {
                "tgId": 1,
                "curve": CURVE,
                "hashAlg": HASH,
                "tests": [{"tcId": 1, "message": MESSAGE.hex().upper()}],
            }
        ],
    }

    results = run(prompt, {"vsId": 1, "testGroups": []})

    assert results[0].status is ResultStatus.PASS
    assert results[0].diagnostic == "signature verified under the generated public key"
    assert results[0].expected is None, "NIST's own signature must not be treated as comparable"
    assert results[0].actual is not None
    assert set(results[0].actual.as_document()) == {"qx", "qy", "r", "s"}


def test_expected_results_discard_non_comparable_signature_fields() -> None:
    """Parsing keeps only verdicts; NIST's qx/qy/r/s are deliberately dropped."""
    expected = ecdsa.parse_expected_results(
        {
            "vsId": 1,
            "testGroups": [
                {"tgId": 1, "qx": "AA", "qy": "BB", "tests": [{"tcId": 1, "r": "CC", "s": "DD"}]}
            ],
        }
    )

    assert expected.verdicts == {}


# --- groups the runner declines --------------------------------------------


@pytest.mark.parametrize(
    ("mutation", "fragment"),
    [
        ({"curve": "B-233"}, "is not supported"),
        ({"hashAlg": "SHAKE-128"}, "is not supported"),
        ({"componentTest": True}, "component-only"),
    ],
)
def test_declined_groups_are_unsupported(mutation: dict[str, Any], fragment: str) -> None:
    """Groups outside this provider's reach are declared, never approximated."""
    prompt, expected = sig_ver_documents(valid=True, expected_verdict=True)
    prompt["testGroups"][0].update(mutation)

    results = run(prompt, expected)

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert fragment in (results[0].diagnostic or "")


@pytest.mark.parametrize(
    ("mutation", "path"),
    [({"algorithm": "RSA"}, "$.algorithm"), ({"mode": "keyGen"}, "$.mode")],
)
def test_parse_rejects_contracts_outside_scope(mutation: dict[str, str], path: str) -> None:
    """An algorithm or mode this module does not implement is refused at parse time."""
    prompt, _ = sig_ver_documents(valid=True, expected_verdict=True)
    prompt.update(mutation)

    with pytest.raises(AcvpValidationError) as captured:
        ecdsa.parse_vector_set(prompt)

    assert captured.value.path == path


def test_load_from_files(tmp_path: Any) -> None:
    """The file entry points parse prompt and expected documents."""
    prompt, expected = sig_ver_documents(valid=True, expected_verdict=True)
    (tmp_path / "prompt.json").write_text(json.dumps(prompt), encoding="utf-8")
    (tmp_path / "expectedResults.json").write_text(json.dumps(expected), encoding="utf-8")

    vector_set = ecdsa.load_vector_set(tmp_path / "prompt.json")
    loaded = ecdsa.load_expected_results(tmp_path / "expectedResults.json")

    assert vector_set.mode == "sigVer"
    assert loaded.verdicts == {(1, 1): True}
