"""Tests for AES-ECB, GMAC, CMAC and key wrapping."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acvp_assay.algorithms import aes_modes
from acvp_assay.models import ResultStatus
from acvp_assay.parser import AcvpValidationError
from acvp_assay.providers.aes_modes import (
    MCT_OUTER_ITERATIONS,
    AesModeProvider,
    CryptographyAesModeProvider,
    _shuffle,
)

KEY128 = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
BLOCK = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
# FIPS 197 known answer: AES-128-ECB of the above block under the above key.
FIPS197_CT = bytes.fromhex("69C4E0D86A7B0430D8CDB78070B4C55A")


def provider() -> CryptographyAesModeProvider:
    """Return the OpenSSL-backed AES mode provider."""
    return CryptographyAesModeProvider()


def documents(
    algorithm: str,
    group: dict[str, Any],
    cases: list[dict[str, Any]],
    expected_cases: list[dict[str, Any]],
) -> tuple[Any, Any]:
    """Build a one-group prompt/expected pair."""
    prompt = {
        "vsId": 1,
        "algorithm": algorithm,
        "revision": "1.0",
        "testGroups": [{"tgId": 1, "testType": "AFT", **group, "tests": cases}],
    }
    expected = {"vsId": 1, "testGroups": [{"tgId": 1, "tests": expected_cases}]}
    return prompt, expected


def run(algorithm: str, group: dict[str, Any], cases: list[Any], expected: list[Any]) -> Any:
    """Parse and execute a synthetic vector set."""
    prompt, expected_document = documents(algorithm, group, cases, expected)
    return aes_modes.run_vector_set(
        aes_modes.parse_vector_set(prompt),
        aes_modes.parse_expected_results(expected_document),
        provider(),
    )


# --- provider --------------------------------------------------------------


def test_ecb_matches_the_fips197_known_answer() -> None:
    """AES-128-ECB agrees with the published FIPS 197 vector, both directions."""
    encrypted = provider().ecb(key=KEY128, data=BLOCK, encrypt=True)

    assert encrypted == FIPS197_CT
    assert provider().ecb(key=KEY128, data=FIPS197_CT, encrypt=False) == BLOCK


def test_monte_carlo_returns_key_input_and_output_per_iteration() -> None:
    """AES MCT reports three values per round, unlike SHA's single digest.

    The key is shuffled between outer iterations, so a run that only checked
    the output would miss a wrong key schedule entirely.
    """
    chain = provider().ecb_monte_carlo(key=KEY128, data=BLOCK, encrypt=True)

    assert len(chain) == MCT_OUTER_ITERATIONS
    assert chain[0][0] == KEY128, "first iteration uses the supplied key"
    assert chain[0][1] == BLOCK
    assert len({entry[0] for entry in chain}) == MCT_OUTER_ITERATIONS, "key changes every round"


@pytest.mark.parametrize("key_length", [16, 24, 32])
def test_key_shuffle_preserves_key_length(key_length: int) -> None:
    """Each key size draws the right amount of feedback material.

    128 uses the final block alone; 192 and 256 reach back into the previous
    block because one 128-bit output cannot refresh a wider key.
    """
    key = bytes(range(key_length))
    shuffled = _shuffle(key, b"\x11" * 16, b"\x22" * 16)

    assert len(shuffled) == key_length
    assert shuffled != key


def test_cmac_truncates_and_rejects_bad_lengths() -> None:
    """CMAC honours macLen, and refuses lengths it cannot produce."""
    full = provider().cmac(key=KEY128, message=b"abc", mac_length_bits=128)
    short = provider().cmac(key=KEY128, message=b"abc", mac_length_bits=64)

    assert len(full) == 16
    assert short == full[:8]
    with pytest.raises(ValueError, match="positive multiple of 8"):
        provider().cmac(key=KEY128, message=b"abc", mac_length_bits=12)
    with pytest.raises(ValueError, match="exceeds"):
        provider().cmac(key=KEY128, message=b"abc", mac_length_bits=256)


def test_gmac_authenticates_aad_with_no_payload() -> None:
    """GMAC is GCM with an empty payload; the tag covers the AAD alone."""
    iv = bytes.fromhex("101112131415161718191A1B")
    tag = provider().gmac(key=KEY128, iv=iv, aad=b"context", tag_length_bits=128)

    assert len(tag) == 16
    assert provider().gmac(key=KEY128, iv=iv, aad=b"other", tag_length_bits=128) != tag
    with pytest.raises(ValueError, match="positive multiple of 8"):
        provider().gmac(key=KEY128, iv=iv, aad=b"", tag_length_bits=0)


@pytest.mark.parametrize("padded", [False, True])
def test_key_wrap_round_trips_and_rejects_tampering(padded: bool) -> None:
    """Wrapping round-trips, and a corrupted wrapping is refused."""
    payload = bytes(range(32))
    wrapped = provider().key_wrap(key=KEY128, data=payload, padded=padded, wrap=True)

    assert provider().key_wrap(key=KEY128, data=wrapped, padded=padded, wrap=False) == payload

    corrupted = bytes([wrapped[0] ^ 0xFF]) + wrapped[1:]
    with pytest.raises(ValueError, match="unwrapping failed"):
        provider().key_wrap(key=KEY128, data=corrupted, padded=padded, wrap=False)


def test_provider_satisfies_the_protocol_and_identifies_itself() -> None:
    """The protocol is structural and the report attributes results to OpenSSL."""
    instance = provider()

    assert isinstance(instance, AesModeProvider)
    assert instance.metadata().name == "cryptography-aes-modes"
    assert instance.metadata().backend_name == "OpenSSL"


# --- ECB -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("direction", "field", "value", "expected_field", "expected_value"),
    [
        ("encrypt", "pt", BLOCK, "ct", FIPS197_CT),
        ("decrypt", "ct", FIPS197_CT, "pt", BLOCK),
    ],
)
def test_ecb_both_directions_pass(
    direction: str, field: str, value: bytes, expected_field: str, expected_value: bytes
) -> None:
    """Encrypt and decrypt groups each compare their own output field."""
    results = run(
        aes_modes.ECB,
        {"direction": direction, "keyLen": 128},
        [{"tcId": 1, "key": KEY128.hex(), field: value.hex()}],
        [{"tcId": 1, expected_field: expected_value.hex()}],
    )

    assert results[0].status is ResultStatus.PASS


def test_ecb_mismatch_names_the_field() -> None:
    """A wrong ciphertext fails with the ACVP field name."""
    results = run(
        aes_modes.ECB,
        {"direction": "encrypt", "keyLen": 128},
        [{"tcId": 1, "key": KEY128.hex(), "pt": BLOCK.hex()}],
        [{"tcId": 1, "ct": "00" * 16}],
    )

    assert results[0].status is ResultStatus.FAIL
    assert results[0].diagnostic == "ct mismatch"


def test_ecb_monte_carlo_group_passes_and_reports_the_count() -> None:
    """An MCT group compares key, input and output across all 100 rounds."""
    chain = provider().ecb_monte_carlo(key=KEY128, data=BLOCK, encrypt=True)
    results = run(
        aes_modes.ECB,
        {"direction": "encrypt", "keyLen": 128, "testType": "MCT"},
        [{"tcId": 1, "key": KEY128.hex(), "pt": BLOCK.hex()}],
        [
            {
                "tcId": 1,
                "resultsArray": [
                    {"key": k.hex(), "pt": p.hex(), "ct": c.hex()} for k, p, c in chain
                ],
            }
        ],
    )

    assert results[0].status is ResultStatus.PASS
    assert results[0].diagnostic == "100 Monte Carlo iterations matched"


def test_ecb_monte_carlo_mismatch_names_the_iteration_and_field() -> None:
    """A diverging chain reports where and in which field it diverged."""
    chain = provider().ecb_monte_carlo(key=KEY128, data=BLOCK, encrypt=True)
    array = [{"key": k.hex(), "pt": p.hex(), "ct": c.hex()} for k, p, c in chain]
    array[5]["ct"] = "00" * 16
    results = run(
        aes_modes.ECB,
        {"direction": "encrypt", "keyLen": 128, "testType": "MCT"},
        [{"tcId": 1, "key": KEY128.hex(), "pt": BLOCK.hex()}],
        [{"tcId": 1, "resultsArray": array}],
    )

    assert results[0].status is ResultStatus.FAIL
    assert results[0].diagnostic == "ct mismatch at Monte Carlo iteration 5"


def test_ecb_monte_carlo_length_mismatch_fails() -> None:
    """A chain of the wrong length fails rather than comparing partially."""
    results = run(
        aes_modes.ECB,
        {"direction": "encrypt", "keyLen": 128, "testType": "MCT"},
        [{"tcId": 1, "key": KEY128.hex(), "pt": BLOCK.hex()}],
        [{"tcId": 1, "resultsArray": [{"ct": "00" * 16}]}],
    )

    assert results[0].status is ResultStatus.FAIL
    assert "expected 1 Monte Carlo iterations, got 100" in (results[0].diagnostic or "")


def test_mct_without_results_array_is_unsupported() -> None:
    """An MCT case needs its expected chain."""
    results = run(
        aes_modes.ECB,
        {"direction": "encrypt", "keyLen": 128, "testType": "MCT"},
        [{"tcId": 1, "key": KEY128.hex(), "pt": BLOCK.hex()}],
        [{"tcId": 1, "ct": "00" * 16}],
    )

    assert results[0].status is ResultStatus.UNSUPPORTED


# --- CMAC ------------------------------------------------------------------


def test_cmac_generation_and_verification() -> None:
    """gen compares the MAC; ver compares a verdict."""
    mac = provider().cmac(key=KEY128, message=b"\x01\x02", mac_length_bits=64)
    generated = run(
        aes_modes.CMAC,
        {"direction": "gen", "keyLen": 128, "macLen": 64},
        [{"tcId": 1, "key": KEY128.hex(), "message": "0102"}],
        [{"tcId": 1, "mac": mac.hex()}],
    )
    verified = run(
        aes_modes.CMAC,
        {"direction": "ver", "keyLen": 128, "macLen": 64},
        [{"tcId": 1, "key": KEY128.hex(), "message": "0102", "mac": mac.hex()}],
        [{"tcId": 1, "testPassed": True}],
    )

    assert generated[0].status is ResultStatus.PASS
    assert verified[0].status is ResultStatus.PASS


def test_cmac_verification_rejects_a_forged_mac() -> None:
    """A wrong MAC that ACVP marks invalid must be rejected, and that is a pass."""
    results = run(
        aes_modes.CMAC,
        {"direction": "ver", "keyLen": 128, "macLen": 64},
        [{"tcId": 1, "key": KEY128.hex(), "message": "0102", "mac": "00" * 8}],
        [{"tcId": 1, "testPassed": False}],
    )

    assert results[0].status is ResultStatus.PASS


def test_cmac_accepting_a_forged_mac_is_a_failure() -> None:
    """Claiming a forged MAC is valid is a loud failure."""
    mac = provider().cmac(key=KEY128, message=b"\x01\x02", mac_length_bits=64)
    results = run(
        aes_modes.CMAC,
        {"direction": "ver", "keyLen": 128, "macLen": 64},
        [{"tcId": 1, "key": KEY128.hex(), "message": "0102", "mac": mac.hex()}],
        [{"tcId": 1, "testPassed": False}],
    )

    assert results[0].status is ResultStatus.FAIL
    assert "accepted a MAC" in (results[0].diagnostic or "")


# --- GMAC ------------------------------------------------------------------


def test_gmac_generation_and_verification() -> None:
    """encrypt compares the tag; decrypt compares a verdict."""
    iv = bytes.fromhex("101112131415161718191A1B")
    tag = provider().gmac(key=KEY128, iv=iv, aad=b"\xaa\xbb", tag_length_bits=128)
    group = {"direction": "encrypt", "keyLen": 128, "ivLen": 96, "tagLen": 128}
    generated = run(
        aes_modes.GMAC,
        group,
        [{"tcId": 1, "key": KEY128.hex(), "iv": iv.hex(), "aad": "aabb"}],
        [{"tcId": 1, "tag": tag.hex()}],
    )
    verified = run(
        aes_modes.GMAC,
        {**group, "direction": "decrypt"},
        [{"tcId": 1, "key": KEY128.hex(), "iv": iv.hex(), "aad": "aabb", "tag": tag.hex()}],
        [{"tcId": 1, "testPassed": True}],
    )

    assert generated[0].status is ResultStatus.PASS
    assert verified[0].status is ResultStatus.PASS


# --- key wrap --------------------------------------------------------------


@pytest.mark.parametrize("algorithm", [aes_modes.KW, aes_modes.KWP])
def test_key_wrap_both_directions(algorithm: str) -> None:
    """Wrapping compares ciphertext; unwrapping compares plaintext."""
    payload = bytes(range(32))
    wrapped = provider().key_wrap(
        key=KEY128, data=payload, padded=algorithm == aes_modes.KWP, wrap=True
    )
    group = {"direction": "encrypt", "keyLen": 128, "kwCipher": "cipher"}
    forward = run(
        algorithm,
        group,
        [{"tcId": 1, "key": KEY128.hex(), "pt": payload.hex()}],
        [{"tcId": 1, "ct": wrapped.hex()}],
    )
    backward = run(
        algorithm,
        {**group, "direction": "decrypt"},
        [{"tcId": 1, "key": KEY128.hex(), "ct": wrapped.hex()}],
        [{"tcId": 1, "pt": payload.hex()}],
    )

    assert forward[0].status is ResultStatus.PASS
    assert backward[0].status is ResultStatus.PASS


def test_rejected_unwrap_is_a_pass_when_acvp_expects_rejection() -> None:
    """A deliberately corrupted wrapping must be refused, and that is correct."""
    results = run(
        aes_modes.KW,
        {"direction": "decrypt", "keyLen": 128, "kwCipher": "cipher"},
        [{"tcId": 1, "key": KEY128.hex(), "ct": "00" * 40}],
        [{"tcId": 1, "testPassed": False}],
    )

    assert results[0].status is ResultStatus.PASS


def test_inverse_kw_cipher_is_declared_unsupported() -> None:
    """The inverse construction is declared rather than approximated.

    It reverses which AES direction performs the wrap; guessing would produce
    wrong verdicts on half of NIST's upstream KW groups.
    """
    results = run(
        aes_modes.KW,
        {"direction": "encrypt", "keyLen": 128, "kwCipher": "inverse"},
        [{"tcId": 1, "key": KEY128.hex(), "pt": (bytes(range(32))).hex()}],
        [{"tcId": 1, "ct": "00" * 40}],
    )

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "inverse" in (results[0].diagnostic or "")


# --- parsing and declined cases -------------------------------------------


def test_unsupported_algorithm_is_rejected() -> None:
    """Only the five families this module implements are accepted."""
    prompt, _ = documents("ACVP-AES-CBC", {"direction": "encrypt"}, [], [])

    with pytest.raises(AcvpValidationError, match="unsupported algorithm"):
        aes_modes.parse_vector_set(prompt)


@pytest.mark.parametrize(
    ("algorithm", "group", "case", "expected"),
    [
        (
            aes_modes.ECB,
            {"direction": "encrypt", "keyLen": 128},
            {"key": KEY128.hex(), "pt": BLOCK.hex()},
            {},
        ),
        (
            aes_modes.CMAC,
            {"direction": "gen", "keyLen": 128, "macLen": 64},
            {"key": KEY128.hex(), "message": "01"},
            {},
        ),
        (
            aes_modes.GMAC,
            {"direction": "encrypt", "keyLen": 128, "tagLen": 128},
            {"key": KEY128.hex(), "iv": "101112131415161718191A1B"},
            {},
        ),
    ],
)
def test_missing_expected_value_is_unsupported(
    algorithm: str, group: dict[str, Any], case: dict[str, Any], expected: dict[str, Any]
) -> None:
    """A case with nothing recorded to compare against is declared, not passed."""
    results = run(algorithm, group, [{"tcId": 1, **case}], [{"tcId": 1, **expected}])

    assert results[0].status is ResultStatus.UNSUPPORTED


def test_case_absent_from_expected_results_is_unsupported() -> None:
    """A case with no expected entry at all is declared."""
    results = run(
        aes_modes.ECB,
        {"direction": "encrypt", "keyLen": 128},
        [{"tcId": 1, "key": KEY128.hex(), "pt": BLOCK.hex()}],
        [],
    )

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert results[0].diagnostic == "no expected result recorded"


def test_verdict_only_cmac_without_a_verdict_is_unsupported() -> None:
    """A ver group needs a boolean to be judged against."""
    results = run(
        aes_modes.CMAC,
        {"direction": "ver", "keyLen": 128, "macLen": 64},
        [{"tcId": 1, "key": KEY128.hex(), "message": "01", "mac": "00" * 8}],
        [{"tcId": 1, "mac": "00" * 8}],
    )

    assert results[0].status is ResultStatus.UNSUPPORTED


def test_load_from_files(tmp_path: Path) -> None:
    """The file entry points parse prompt and expected documents."""
    prompt, expected = documents(
        aes_modes.ECB,
        {"direction": "encrypt", "keyLen": 128},
        [{"tcId": 1, "key": KEY128.hex(), "pt": BLOCK.hex()}],
        [{"tcId": 1, "ct": FIPS197_CT.hex()}],
    )
    (tmp_path / "prompt.json").write_text(json.dumps(prompt), encoding="utf-8")
    (tmp_path / "expectedResults.json").write_text(json.dumps(expected), encoding="utf-8")

    assert aes_modes.load_vector_set(tmp_path / "prompt.json").algorithm == aes_modes.ECB
    assert aes_modes.load_expected_results(tmp_path / "expectedResults.json").vs_id == 1


def test_gmac_verification_rejects_a_forged_tag() -> None:
    """A tag ACVP declares invalid must be rejected, and that is a pass."""
    iv = bytes.fromhex("101112131415161718191A1B")
    results = run(
        aes_modes.GMAC,
        {"direction": "decrypt", "keyLen": 128, "ivLen": 96, "tagLen": 128},
        [{"tcId": 1, "key": KEY128.hex(), "iv": iv.hex(), "aad": "aabb", "tag": "00" * 16}],
        [{"tcId": 1, "testPassed": False}],
    )

    assert results[0].status is ResultStatus.PASS


def test_gmac_without_a_verdict_is_unsupported() -> None:
    """A decrypt group needs a boolean to judge against."""
    iv = bytes.fromhex("101112131415161718191A1B")
    results = run(
        aes_modes.GMAC,
        {"direction": "decrypt", "keyLen": 128, "ivLen": 96, "tagLen": 128},
        [{"tcId": 1, "key": KEY128.hex(), "iv": iv.hex(), "aad": "aabb", "tag": "00" * 16}],
        [{"tcId": 1, "tag": "00" * 16}],
    )

    assert results[0].status is ResultStatus.UNSUPPORTED


def test_successful_unwrap_where_acvp_expects_rejection_is_a_failure() -> None:
    """Accepting a wrapping ACVP declares invalid is a loud failure."""
    payload = bytes(range(32))
    wrapped = provider().key_wrap(key=KEY128, data=payload, padded=False, wrap=True)
    results = run(
        aes_modes.KW,
        {"direction": "decrypt", "keyLen": 128, "kwCipher": "cipher"},
        [{"tcId": 1, "key": KEY128.hex(), "ct": wrapped.hex()}],
        [{"tcId": 1, "testPassed": False}],
    )

    assert results[0].status is ResultStatus.FAIL
    assert "accepted a wrapping" in (results[0].diagnostic or "")


def test_failed_unwrap_without_a_verdict_is_unsupported() -> None:
    """A rejected unwrap with nothing recorded to compare is declared."""
    results = run(
        aes_modes.KW,
        {"direction": "decrypt", "keyLen": 128, "kwCipher": "cipher"},
        [{"tcId": 1, "key": KEY128.hex(), "ct": "00" * 40}],
        [{"tcId": 1, "pt": "00" * 32}],
    )

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "unwrapping failed" in (results[0].diagnostic or "")


def test_key_wrap_missing_expected_value_is_unsupported() -> None:
    """A wrap case with no expected ciphertext is declared."""
    results = run(
        aes_modes.KW,
        {"direction": "encrypt", "keyLen": 128, "kwCipher": "cipher"},
        [{"tcId": 1, "key": KEY128.hex(), "pt": (bytes(range(32))).hex()}],
        [{"tcId": 1}],
    )

    assert results[0].status is ResultStatus.UNSUPPORTED
