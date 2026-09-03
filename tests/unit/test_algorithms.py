"""Tests for SHA-2 / HMAC vector handling and algorithm dispatch."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acvp_assay.algorithms import (
    UnsupportedAlgorithmError,
    hmac_mac,
    peek_algorithm,
    run_vector_file,
    sha2,
    supported_algorithms,
)
from acvp_assay.models import ResultStatus
from acvp_assay.parser import AcvpValidationError
from acvp_assay.providers.digest import HashlibHashProvider, HashlibMacProvider

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
SHA2 = FIXTURES / "sha2-256-known-answers"
HMAC = FIXTURES / "hmac-sha2-256-known-answers"


def sha2_prompt() -> dict[str, Any]:
    """Return a mutable copy of the SHA-2 fixture prompt."""
    document: dict[str, Any] = json.loads((SHA2 / "prompt.json").read_text())
    return document


def run_sha2(prompt: dict[str, Any], expected: dict[str, Any]) -> list[Any]:
    """Run an in-memory SHA-2 prompt/expected pair."""
    return sha2.run_vector_set(
        sha2.parse_vector_set(prompt),
        sha2.parse_expected_results(expected),
        HashlibHashProvider("SHA2-256"),
    )


# --- SHA-2 -----------------------------------------------------------------


def test_sha2_fixture_passes_against_published_digests() -> None:
    """Both FIPS 180-4 known answers pass, including the zero-length case."""
    results = sha2.run_vector_set(
        sha2.load_vector_set(SHA2 / "prompt.json"),
        sha2.load_expected_results(SHA2 / "expectedResults.json"),
        HashlibHashProvider("SHA2-256"),
    )

    assert [r.status for r in results] == [ResultStatus.PASS, ResultStatus.PASS]


def test_declared_bit_length_trims_a_padded_message() -> None:
    """ACVP pads a zero-length message; the declared ``len`` is authoritative."""
    vector_set = sha2.load_vector_set(SHA2 / "prompt.json")
    zero_length = vector_set.test_groups[0].tests[1]

    assert zero_length.length_bits == 0
    assert zero_length.message == b""


def test_sha2_digest_mismatch_is_a_failure() -> None:
    """A wrong digest fails with a field-named diagnostic."""
    expected = json.loads((SHA2 / "expectedResults.json").read_text())
    expected["testGroups"][0]["tests"][0]["md"] = "00" * 32

    results = run_sha2(sha2_prompt(), expected)

    assert results[0].status is ResultStatus.FAIL
    assert results[0].diagnostic == "md mismatch"


def test_large_data_tests_are_unsupported_not_approximated() -> None:
    """LDT groups expand to gigabytes and are declared, never guessed."""
    prompt = sha2_prompt()
    prompt["testGroups"] = [
        {
            "tgId": 9,
            "testType": "LDT",
            "tests": [
                {
                    "tcId": 1,
                    "largeMsg": {
                        "content": "AABB",
                        "contentLength": 16,
                        "fullLength": 8589934592,
                        "expansionTechnique": "repeating",
                    },
                }
            ],
        }
    ]
    expected = {
        "vsId": 900010,
        "algorithm": "SHA2-256",
        "revision": "1.0",
        "testGroups": [{"tgId": 9, "tests": [{"tcId": 1, "md": "00" * 32}]}],
    }

    results = run_sha2(prompt, expected)

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "large data tests" in (results[0].diagnostic or "")


def test_bit_oriented_messages_are_unsupported() -> None:
    """A non-byte-aligned message length is declared rather than mishandled."""
    prompt = sha2_prompt()
    prompt["testGroups"][0]["tests"] = [{"tcId": 1, "len": 5, "msg": "F8"}]
    expected = {
        "vsId": 900010,
        "algorithm": "SHA2-256",
        "revision": "1.0",
        "testGroups": [{"tgId": 1, "tests": [{"tcId": 1, "md": "00" * 32}]}],
    }

    results = run_sha2(prompt, expected)

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "bit-oriented" in (results[0].diagnostic or "")


def test_monte_carlo_group_compares_the_whole_results_array() -> None:
    """An MCT case is one verdict over one hundred chained digests."""
    seed = bytes(range(64))
    digests = HashlibHashProvider("SHA2-256").digest_mct(seed, alternate=True)
    prompt = sha2_prompt()
    prompt["testGroups"] = [
        {
            "tgId": 2,
            "testType": "MCT",
            "mctVersion": "alternate",
            "tests": [{"tcId": 1, "len": len(seed) * 8, "msg": seed.hex().upper()}],
        }
    ]
    expected = {
        "vsId": 900010,
        "algorithm": "SHA2-256",
        "revision": "1.0",
        "testGroups": [
            {
                "tgId": 2,
                "tests": [{"tcId": 1, "resultsArray": [{"md": d.hex().upper()} for d in digests]}],
            }
        ],
    }

    results = run_sha2(prompt, expected)

    assert results[0].status is ResultStatus.PASS
    assert results[0].diagnostic == "100 Monte Carlo iterations matched"


def test_monte_carlo_mismatch_names_the_iteration() -> None:
    """A diverging chain reports where it first diverged."""
    seed = bytes(range(64))
    digests = HashlibHashProvider("SHA2-256").digest_mct(seed, alternate=True)
    array = [{"md": d.hex().upper()} for d in digests]
    array[7] = {"md": "00" * 32}
    prompt = sha2_prompt()
    prompt["testGroups"] = [
        {
            "tgId": 2,
            "testType": "MCT",
            "mctVersion": "alternate",
            "tests": [{"tcId": 1, "len": len(seed) * 8, "msg": seed.hex().upper()}],
        }
    ]
    expected = {
        "vsId": 900010,
        "algorithm": "SHA2-256",
        "revision": "1.0",
        "testGroups": [{"tgId": 2, "tests": [{"tcId": 1, "resultsArray": array}]}],
    }

    results = run_sha2(prompt, expected)

    assert results[0].status is ResultStatus.FAIL
    assert results[0].diagnostic == "md mismatch at Monte Carlo iteration 7"


def test_unknown_mct_version_is_unsupported() -> None:
    """An unrecognised mctVersion is declared, not assumed to be standard."""
    prompt = sha2_prompt()
    prompt["testGroups"] = [
        {
            "tgId": 2,
            "testType": "MCT",
            "mctVersion": "future",
            "tests": [{"tcId": 1, "len": 16, "msg": "AABB"}],
        }
    ]
    expected = {
        "vsId": 900010,
        "algorithm": "SHA2-256",
        "revision": "1.0",
        "testGroups": [{"tgId": 2, "tests": [{"tcId": 1, "resultsArray": [{"md": "00" * 32}]}]}],
    }

    results = run_sha2(prompt, expected)

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "mctVersion 'future'" in (results[0].diagnostic or "")


def test_mct_without_results_array_is_unsupported() -> None:
    """An MCT case needs its expected chain to be comparable."""
    prompt = sha2_prompt()
    prompt["testGroups"] = [
        {
            "tgId": 2,
            "testType": "MCT",
            "mctVersion": "alternate",
            "tests": [{"tcId": 1, "len": 16, "msg": "AABB"}],
        }
    ]
    expected = {
        "vsId": 900010,
        "algorithm": "SHA2-256",
        "revision": "1.0",
        "testGroups": [{"tgId": 2, "tests": [{"tcId": 1, "md": "00" * 32}]}],
    }

    results = run_sha2(prompt, expected)

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "resultsArray" in (results[0].diagnostic or "")


def test_mct_length_mismatch_is_a_failure() -> None:
    """A chain of the wrong length fails rather than comparing partially."""
    prompt = sha2_prompt()
    seed = bytes(range(32))
    prompt["testGroups"] = [
        {
            "tgId": 2,
            "testType": "MCT",
            "mctVersion": "alternate",
            "tests": [{"tcId": 1, "len": 256, "msg": seed.hex().upper()}],
        }
    ]
    expected = {
        "vsId": 900010,
        "algorithm": "SHA2-256",
        "revision": "1.0",
        "testGroups": [{"tgId": 2, "tests": [{"tcId": 1, "resultsArray": [{"md": "00" * 32}]}]}],
    }

    results = run_sha2(prompt, expected)

    assert results[0].status is ResultStatus.FAIL
    assert "expected 1 Monte Carlo digests, got 100" in (results[0].diagnostic or "")


def test_case_without_expected_result_is_unsupported() -> None:
    """A case with nothing to compare against is declared, not silently passed."""
    results = run_sha2(
        sha2_prompt(),
        {"vsId": 900010, "algorithm": "SHA2-256", "revision": "1.0", "testGroups": []},
    )

    assert {r.status for r in results} == {ResultStatus.UNSUPPORTED}


@pytest.mark.parametrize(
    ("mutation", "path"),
    [
        ({"algorithm": "MD5"}, "$.algorithm"),
        ({"revision": "2.0"}, "$.revision"),
    ],
)
def test_sha2_rejects_contracts_outside_its_scope(mutation: dict[str, str], path: str) -> None:
    """Unsupported algorithm or revision is refused at parse time."""
    prompt = sha2_prompt() | mutation

    with pytest.raises(AcvpValidationError) as captured:
        sha2.parse_vector_set(prompt)

    assert captured.value.path == path


def test_sha2_rejects_an_unknown_test_type() -> None:
    """A test type outside AFT/MCT/LDT is refused rather than guessed."""
    prompt = sha2_prompt()
    prompt["testGroups"][0]["testType"] = "VOT"

    with pytest.raises(AcvpValidationError, match="unsupported test type"):
        sha2.parse_vector_set(prompt)


def test_aft_case_without_a_digest_is_unsupported() -> None:
    """An expected entry that records no ``md`` leaves nothing to compare."""
    expected = {
        "vsId": 900010,
        "algorithm": "SHA2-256",
        "revision": "1.0",
        "testGroups": [{"tgId": 1, "tests": [{"tcId": 1}, {"tcId": 2}]}],
    }

    results = run_sha2(sha2_prompt(), expected)

    assert {r.status for r in results} == {ResultStatus.UNSUPPORTED}
    assert results[0].diagnostic == "no expected digest recorded"


def test_digest_and_mac_results_serialize_with_acvp_field_names() -> None:
    """Reports render digests as ``md`` and MACs as ``mac``, in uppercase hex."""
    from acvp_assay.reporter import build_report

    sha_results, sha_metadata = run_vector_file(SHA2 / "prompt.json", SHA2 / "expectedResults.json")
    mac_results, _ = run_vector_file(HMAC / "prompt.json", HMAC / "expectedResults.json")

    sha_cases = build_report(sha_results, sha_metadata)["cases"]
    mac_cases = build_report(mac_results, sha_metadata)["cases"]
    assert isinstance(sha_cases, list)
    assert isinstance(mac_cases, list)

    assert sha_cases[0]["expected"] == {
        "md": "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
    }
    assert mac_cases[1]["actual"] == {"mac": "B0344C61D8DB38535CA8"}


# --- HMAC ------------------------------------------------------------------


def test_hmac_fixture_passes_including_truncation() -> None:
    """RFC 4231 case 1 passes at full width and truncated to 80 bits."""
    results = hmac_mac.run_vector_set(
        hmac_mac.load_vector_set(HMAC / "prompt.json"),
        hmac_mac.load_expected_results(HMAC / "expectedResults.json"),
        HashlibMacProvider("HMAC-SHA2-256"),
    )

    assert [r.status for r in results] == [ResultStatus.PASS, ResultStatus.PASS]


def test_hmac_mismatch_is_a_failure() -> None:
    """A wrong MAC fails with a field-named diagnostic."""
    expected = json.loads((HMAC / "expectedResults.json").read_text())
    expected["testGroups"][0]["tests"][0]["mac"] = "00" * 32

    results = hmac_mac.run_vector_set(
        hmac_mac.load_vector_set(HMAC / "prompt.json"),
        hmac_mac.parse_expected_results(expected),
        HashlibMacProvider("HMAC-SHA2-256"),
    )

    assert results[0].status is ResultStatus.FAIL
    assert results[0].diagnostic == "mac mismatch"


def test_hmac_case_without_expected_result_is_unsupported() -> None:
    """An HMAC case with no recorded MAC is declared, not passed."""
    results = hmac_mac.run_vector_set(
        hmac_mac.load_vector_set(HMAC / "prompt.json"),
        hmac_mac.parse_expected_results(
            {"vsId": 900011, "algorithm": "HMAC-SHA2-256", "revision": "1.0", "testGroups": []}
        ),
        HashlibMacProvider("HMAC-SHA2-256"),
    )

    assert {r.status for r in results} == {ResultStatus.UNSUPPORTED}


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        ({"algorithm": "HMAC-MD5"}, "unsupported algorithm"),
        ({"revision": "2.0"}, "unsupported revision"),
    ],
)
def test_hmac_rejects_contracts_outside_its_scope(mutation: dict[str, str], match: str) -> None:
    """Unsupported algorithm or revision is refused at parse time."""
    prompt = json.loads((HMAC / "prompt.json").read_text()) | mutation

    with pytest.raises(AcvpValidationError, match=match):
        hmac_mac.parse_vector_set(prompt)


def test_hmac_rejects_a_non_aft_test_type() -> None:
    """HMAC sets are AFT-only; anything else is refused."""
    prompt = json.loads((HMAC / "prompt.json").read_text())
    prompt["testGroups"][0]["testType"] = "MCT"

    with pytest.raises(AcvpValidationError, match="unsupported test type"):
        hmac_mac.parse_vector_set(prompt)


# --- dispatch --------------------------------------------------------------


def test_supported_algorithms_lists_every_family() -> None:
    """The advertised list covers AES-GCM, the SHA-2 variants, and their HMACs."""
    names = supported_algorithms()

    assert "ACVP-AES-GCM" in names
    assert "SHA2-256" in names
    assert "HMAC-SHA2-512/256" in names
    assert names == sorted(names)


@pytest.mark.parametrize(
    ("directory", "expected_algorithm"),
    [
        ("aes-gcm-valid-encrypt", "ACVP-AES-GCM"),
        ("sha2-256-known-answers", "SHA2-256"),
        ("hmac-sha2-256-known-answers", "HMAC-SHA2-256"),
        ("ecdsa-p256-sigver", "ECDSA"),
    ],
)
def test_dispatch_runs_each_family_from_its_vector_file(
    directory: str, expected_algorithm: str
) -> None:
    """One entry point routes each algorithm to the right parser and runner."""
    prompt = FIXTURES / directory / "prompt.json"

    assert peek_algorithm(prompt)[0] == expected_algorithm

    results, metadata = run_vector_file(prompt, prompt.parent / "expectedResults.json")

    assert results
    assert all(r.status is ResultStatus.PASS for r in results)
    assert metadata.name


def test_dispatch_rejects_an_unimplemented_algorithm(tmp_path: Path) -> None:
    """An unknown algorithm names what this runner does implement."""
    prompt = tmp_path / "prompt.json"
    prompt.write_text(
        json.dumps({"vsId": 1, "algorithm": "ACVP-AES-CBC", "revision": "1.0"}),
        encoding="utf-8",
    )

    with pytest.raises(UnsupportedAlgorithmError, match="SHA2-256"):
        run_vector_file(prompt, tmp_path / "expectedResults.json")


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("not json", "invalid JSON"),
        ("[]", "expected an object"),
        ('{"vsId": 1}', "missing algorithm or revision"),
    ],
)
def test_peek_algorithm_reports_malformed_files(tmp_path: Path, content: str, message: str) -> None:
    """Dispatch fails with a bounded diagnostic before any algorithm is chosen."""
    prompt = tmp_path / "prompt.json"
    prompt.write_text(content, encoding="utf-8")

    with pytest.raises(AcvpValidationError, match=message):
        peek_algorithm(prompt)


def test_aes_mode_families_are_dispatched_and_refuse_a_harness(tmp_path: Path) -> None:
    """The five AES mode families route to their runner and decline --provider-command."""
    from acvp_assay.algorithms import aes_modes

    key = "000102030405060708090A0B0C0D0E0F"
    prompt = {
        "vsId": 1,
        "algorithm": aes_modes.ECB,
        "revision": "1.0",
        "testGroups": [
            {
                "tgId": 1,
                "testType": "AFT",
                "direction": "encrypt",
                "keyLen": 128,
                "tests": [{"tcId": 1, "key": key, "pt": "00112233445566778899AABBCCDDEEFF"}],
            }
        ],
    }
    expected = {
        "vsId": 1,
        "testGroups": [
            {"tgId": 1, "tests": [{"tcId": 1, "ct": "69C4E0D86A7B0430D8CDB78070B4C55A"}]}
        ],
    }
    (tmp_path / "prompt.json").write_text(json.dumps(prompt), encoding="utf-8")
    (tmp_path / "expectedResults.json").write_text(json.dumps(expected), encoding="utf-8")

    results, metadata = run_vector_file(tmp_path / "prompt.json", tmp_path / "expectedResults.json")

    assert metadata.name == "cryptography-aes-modes"
    assert results[0].status is ResultStatus.PASS
    assert "ACVP-AES-ECB" in supported_algorithms()

    with pytest.raises(UnsupportedAlgorithmError, match="AES mode families"):
        run_vector_file(
            tmp_path / "prompt.json",
            tmp_path / "expectedResults.json",
            provider_command="python3 h.py",
        )


def test_ctr_drbg_is_dispatched_and_refuses_a_harness(tmp_path: Path) -> None:
    """ctrDRBG routes to its runner, and declines --provider-command.

    The known answer is NIST's own, from tgId 13 / tcId 181 of the pinned
    ctrDRBG-SP800-90Ar1 set.
    """
    group = {
        "tgId": 13,
        "testType": "AFT",
        "derFunc": True,
        "predResistance": False,
        "mode": "AES-128",
        "returnedBitsLen": 256,
        "counterFieldLen": 128,
        "tests": [
            {
                "tcId": 181,
                "entropyInput": (
                    "7E1D87DBE3C6F31556D9B448AF56F037C5742BAA57A6AF0B208B32C02E714B90"
                ),
                "nonce": "8444A76CCC181B71DBDB362B2E5EC07AB6570A05515F9BCD8FF832D428BD3191",
                "persoString": ("26232C1AB9B6E1555B52EF291A690F9B0B518755ADE1C7F805F14C6D78C62891"),
                "otherInput": [
                    {
                        "intendedUse": "reSeed",
                        "additionalInput": (
                            "3151EE933DB69C6E07BA99FC7D6699074CF4AA02F6AA53C9B341BFB418A0C682"
                        ),
                        "entropyInput": (
                            "757C3540F4757708DCAB50C7EF6268AD4EE1CF5859D07D6791E209B4BE791A58"
                        ),
                    },
                    {
                        "intendedUse": "generate",
                        "additionalInput": (
                            "DA1F030818A9990BE878FFCFA6EC28825EDAB5A67326AF27EE9AC92F92D75A01"
                        ),
                        "entropyInput": "",
                    },
                    {
                        "intendedUse": "generate",
                        "additionalInput": (
                            "24E6811F9586EEE10162AB016BBB58C1B86146734D5577FF3D1D62D2A7F57802"
                        ),
                        "entropyInput": "",
                    },
                ],
            }
        ],
    }
    prompt = {
        "vsId": 1,
        "algorithm": "ctrDRBG",
        "revision": "SP800-90Ar1",
        "testGroups": [group],
    }
    expected = {
        "vsId": 1,
        "testGroups": [
            {
                "tgId": 13,
                "tests": [
                    {
                        "tcId": 181,
                        "returnedBits": (
                            "F67D256063A2483D4425FB71D68725EB3AFF060B3BF7918052534FEBC3B98DDF"
                        ),
                    }
                ],
            }
        ],
    }
    (tmp_path / "prompt.json").write_text(json.dumps(prompt), encoding="utf-8")
    (tmp_path / "expectedResults.json").write_text(json.dumps(expected), encoding="utf-8")

    results, metadata = run_vector_file(tmp_path / "prompt.json", tmp_path / "expectedResults.json")

    assert metadata.name == "cryptography-ctr-drbg"
    assert [r.status for r in results] == [ResultStatus.PASS]
    assert "ctrDRBG" in supported_algorithms()

    with pytest.raises(UnsupportedAlgorithmError, match="ctrDRBG"):
        run_vector_file(
            tmp_path / "prompt.json",
            tmp_path / "expectedResults.json",
            provider_command="python3 h.py",
        )


def test_kdf_is_dispatched_and_refuses_a_harness(tmp_path: Path) -> None:
    """KDF SP 800-108 routes to its runner, and declines --provider-command.

    The known answer is NIST's own, from the pinned KDF-1.0 set: counter mode,
    CMAC-AES128, the counter after the fixed data.
    """
    prompt = {
        "vsId": 1,
        "algorithm": "KDF",
        "revision": "1.0",
        "testGroups": [
            {
                "tgId": 1,
                "testType": "AFT",
                "kdfMode": "counter",
                "counterLocation": "after fixed data",
                "macMode": "CMAC-AES128",
                "counterLength": 8,
                "keyOutLength": 8,
                "tests": [{"tcId": 1, "keyIn": "C5FE792532A5088D296AD6622CCD5B42"}],
            }
        ],
    }
    expected = {
        "vsId": 1,
        "testGroups": [
            {
                "tgId": 1,
                "tests": [
                    {
                        "tcId": 1,
                        "fixedData": "31BF13E5997BABDB4602F3226F45D523",
                        "keyOut": "38",
                    }
                ],
            }
        ],
    }
    (tmp_path / "prompt.json").write_text(json.dumps(prompt), encoding="utf-8")
    (tmp_path / "expectedResults.json").write_text(json.dumps(expected), encoding="utf-8")

    results, metadata = run_vector_file(tmp_path / "prompt.json", tmp_path / "expectedResults.json")

    assert metadata.name == "cryptography-kdf-sp800-108"
    assert [r.status for r in results] == [ResultStatus.PASS]
    assert "KDF" in supported_algorithms()

    with pytest.raises(UnsupportedAlgorithmError, match="KDF SP 800-108"):
        run_vector_file(
            tmp_path / "prompt.json",
            tmp_path / "expectedResults.json",
            provider_command="python3 h.py",
        )
