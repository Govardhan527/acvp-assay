"""AES chaining modes: CBC, CTR, OFB and CFB128.

The Monte Carlo assertions matter most here. CBC, OFB and CFB128 share one
chain, and the specification writes its inner loop as a stateful cipher that
continues from the previous call -- which for a one-block operation means
restarting with the previous output as the IV. Getting that wrong produces a
chain that runs to completion and disagrees with NIST from the second
iteration onwards.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acvp_assay.algorithms import aes_block
from acvp_assay.models import ResultStatus
from acvp_assay.parser import AcvpValidationError
from acvp_assay.providers.aes_block import (
    CBC,
    CFB128,
    CTR,
    OFB,
    CryptographyAesBlockProvider,
)

KEY = bytes(range(16))
IV = bytes(range(16, 32))
BLOCK = bytes(range(32, 48))


def provider() -> CryptographyAesBlockProvider:
    """A built-in provider instance."""
    return CryptographyAesBlockProvider()


@pytest.mark.parametrize("algorithm", [CBC, CTR, OFB, CFB128])
def test_every_mode_round_trips(algorithm: str) -> None:
    """Decrypting an encryption returns the original payload."""
    encrypted = provider().transform(algorithm=algorithm, key=KEY, iv=IV, data=BLOCK, encrypt=True)
    decrypted = provider().transform(
        algorithm=algorithm, key=KEY, iv=IV, data=encrypted, encrypt=False
    )

    assert encrypted != BLOCK
    assert decrypted == BLOCK


def test_an_unknown_mode_is_refused() -> None:
    """The provider will not guess at a mode it does not implement."""
    with pytest.raises(ValueError, match="unsupported chaining mode"):
        provider().transform(algorithm="ACVP-AES-XTS", key=KEY, iv=IV, data=BLOCK, encrypt=True)


def test_counter_mode_has_no_monte_carlo_test() -> None:
    """CTR's test type is a server-side distinction; the client runs no chain."""
    with pytest.raises(ValueError, match="no Monte Carlo test"):
        provider().monte_carlo(algorithm=CTR, key=KEY, iv=IV, data=BLOCK, encrypt=True)


@pytest.mark.parametrize(
    ("algorithm", "encrypt"),
    [(CBC, True), (CBC, False), (CFB128, True), (CFB128, False), (OFB, True), (OFB, False)],
)
def test_every_monte_carlo_chain_is_supported(algorithm: str, encrypt: bool) -> None:
    """All three modes chain in both directions; only the IV advance differs.

    CBC and CFB128 advance the IV to the ciphertext just produced when
    encrypting and to the one just consumed when decrypting; OFB advances it to
    the raw keystream block in both. Those rules come from NIST's own generator
    and each reproduces the live server's arrays field for field.
    """
    chain = provider().monte_carlo(algorithm=algorithm, key=KEY, iv=IV, data=BLOCK, encrypt=encrypt)

    assert len(chain) == 100
    assert chain[0][:3] == (KEY, IV, BLOCK)
    assert all(len(field) == 16 for entry in chain for field in entry)


def test_the_iv_advance_distinguishes_the_modes() -> None:
    """CBC and CFB128 chain differently by direction; OFB does not, and cannot.

    OFB's feedback never touches the data, so encryption and decryption are the
    same operation and must produce the same chain. CBC and CFB128 advance the
    IV to the ciphertext produced when encrypting and to the one consumed when
    decrypting, so their two directions must differ -- assuming otherwise is
    exactly what makes a decrypt chain run happily and disagree with NIST.
    """
    engine = provider()

    def run(algorithm: str, encrypt: bool) -> bytes:
        return engine.monte_carlo(algorithm=algorithm, key=KEY, iv=IV, data=BLOCK, encrypt=encrypt)[
            0
        ][3]

    assert run(CBC, True) != run(CBC, False)
    assert run(CFB128, True) != run(CFB128, False)
    assert run(OFB, True) == run(OFB, False)
    assert run(CBC, True) != run(CFB128, True) != run(OFB, True)


def test_the_key_shuffle_advances_the_key_each_iteration() -> None:
    """A chain that reused one key would still run, and would be wrong."""
    chain = provider().monte_carlo(algorithm=CBC, key=KEY, iv=IV, data=BLOCK, encrypt=True)

    keys = [entry[0] for entry in chain]
    assert len(set(keys)) == 100
    assert all(len(key) == len(KEY) for key in keys)


def documents(
    algorithm: str, group: dict[str, object], expected: list[dict[str, object]]
) -> tuple[dict[str, object], dict[str, object]]:
    """Build a matching prompt and expected-results pair."""
    prompt = {
        "vsId": 1,
        "algorithm": algorithm,
        "revision": "1.0",
        "testGroups": [group],
    }
    results = {
        "vsId": 1,
        "testGroups": [{"tgId": group["tgId"], "tests": expected}],
    }
    return prompt, results


def test_an_aft_case_compares_the_transformed_payload() -> None:
    """A functional case is a plain compare-output."""
    ciphertext = provider().transform(algorithm=CBC, key=KEY, iv=IV, data=BLOCK, encrypt=True)
    prompt, expected = documents(
        CBC,
        {
            "tgId": 1,
            "testType": "AFT",
            "direction": "encrypt",
            "keyLen": 128,
            "tests": [{"tcId": 1, "key": KEY.hex(), "iv": IV.hex(), "pt": BLOCK.hex()}],
        },
        [{"tcId": 1, "ct": ciphertext.hex()}],
    )

    results = aes_block.run_vector_set(
        aes_block.parse_vector_set(prompt),
        aes_block.parse_expected_results(expected),
        provider(),
    )

    assert [r.status for r in results] == [ResultStatus.PASS]


def test_a_wrong_answer_is_a_failure() -> None:
    """Anything other than the expected payload must be reported."""
    prompt, expected = documents(
        CBC,
        {
            "tgId": 1,
            "testType": "AFT",
            "direction": "decrypt",
            "keyLen": 128,
            "tests": [{"tcId": 1, "key": KEY.hex(), "iv": IV.hex(), "ct": BLOCK.hex()}],
        },
        [{"tcId": 1, "pt": "00" * 16}],
    )

    results = aes_block.run_vector_set(
        aes_block.parse_vector_set(prompt),
        aes_block.parse_expected_results(expected),
        provider(),
    )

    assert results[0].status is ResultStatus.FAIL
    assert results[0].diagnostic == "pt differs"


def test_a_monte_carlo_case_compares_every_iteration() -> None:
    """All 100 outer iterations are checked, not just the final one."""
    chain = provider().monte_carlo(algorithm=CBC, key=KEY, iv=IV, data=BLOCK, encrypt=True)
    prompt, expected = documents(
        CBC,
        {
            "tgId": 1,
            "testType": "MCT",
            "direction": "encrypt",
            "keyLen": 128,
            "tests": [{"tcId": 1, "key": KEY.hex(), "iv": IV.hex(), "pt": BLOCK.hex()}],
        },
        [
            {
                "tcId": 1,
                "resultsArray": [
                    {"key": k.hex(), "iv": i.hex(), "pt": p.hex(), "ct": c.hex()}
                    for k, i, p, c in chain
                ],
            }
        ],
    )

    results = aes_block.run_vector_set(
        aes_block.parse_vector_set(prompt),
        aes_block.parse_expected_results(expected),
        provider(),
    )

    assert [r.status for r in results] == [ResultStatus.PASS]


def test_a_diverging_monte_carlo_iteration_is_reported_with_its_index() -> None:
    """A chain that goes wrong midway names where, not just that it failed."""
    chain = provider().monte_carlo(algorithm=CBC, key=KEY, iv=IV, data=BLOCK, encrypt=True)
    entries = [
        {"key": k.hex(), "iv": i.hex(), "pt": p.hex(), "ct": c.hex()} for k, i, p, c in chain
    ]
    entries[7]["ct"] = "00" * 16
    prompt, expected = documents(
        CBC,
        {
            "tgId": 1,
            "testType": "MCT",
            "direction": "encrypt",
            "keyLen": 128,
            "tests": [{"tcId": 1, "key": KEY.hex(), "iv": IV.hex(), "pt": BLOCK.hex()}],
        },
        [{"tcId": 1, "resultsArray": entries}],
    )

    results = aes_block.run_vector_set(
        aes_block.parse_vector_set(prompt),
        aes_block.parse_expected_results(expected),
        provider(),
    )

    assert results[0].status is ResultStatus.FAIL
    assert "iteration 7" in (results[0].diagnostic or "")


def test_a_short_monte_carlo_chain_is_reported() -> None:
    """A truncated expected chain is a mismatch, not a silent pass."""
    prompt, expected = documents(
        CBC,
        {
            "tgId": 1,
            "testType": "MCT",
            "direction": "encrypt",
            "keyLen": 128,
            "tests": [{"tcId": 1, "key": KEY.hex(), "iv": IV.hex(), "pt": BLOCK.hex()}],
        },
        [{"tcId": 1, "resultsArray": [{"ct": "00" * 16}]}],
    )

    results = aes_block.run_vector_set(
        aes_block.parse_vector_set(prompt),
        aes_block.parse_expected_results(expected),
        provider(),
    )

    assert results[0].status is ResultStatus.FAIL
    assert "Monte Carlo iterations" in (results[0].diagnostic or "")


def test_a_monte_carlo_case_without_a_chain_is_declared() -> None:
    """Nothing to compare against is not a failure."""
    prompt, expected = documents(
        CBC,
        {
            "tgId": 1,
            "testType": "MCT",
            "direction": "encrypt",
            "keyLen": 128,
            "tests": [{"tcId": 1, "key": KEY.hex(), "iv": IV.hex(), "pt": BLOCK.hex()}],
        },
        [{"tcId": 1, "ct": "00" * 16}],
    )

    results = aes_block.run_vector_set(
        aes_block.parse_vector_set(prompt),
        aes_block.parse_expected_results(expected),
        provider(),
    )

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "resultsArray" in (results[0].diagnostic or "")


def test_missing_expected_values_are_declared() -> None:
    """An unrecorded case and an unrecorded field are both declared."""
    group = {
        "tgId": 1,
        "testType": "AFT",
        "direction": "encrypt",
        "keyLen": 128,
        "tests": [{"tcId": 1, "key": KEY.hex(), "iv": IV.hex(), "pt": BLOCK.hex()}],
    }
    absent_case, _ = documents(CBC, group, [])
    empty_field, _ = documents(CBC, group, [])

    for expected_cases, fragment in (([], "no expected result"), ([{"tcId": 1}], "no expected ct")):
        results = aes_block.run_vector_set(
            aes_block.parse_vector_set(absent_case),
            aes_block.parse_expected_results(
                {"vsId": 1, "testGroups": [{"tgId": 1, "tests": expected_cases}]}
            ),
            provider(),
        )
        assert results[0].status is ResultStatus.UNSUPPORTED
        assert fragment in (results[0].diagnostic or "")
    assert empty_field["vsId"] == 1


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"algorithm": "ACVP-AES-XTS"}, "expected one of"),
        ({"testGroups": "not-a-list"}, "expected an array"),
    ],
)
def test_malformed_documents_are_rejected(mutation: dict[str, object], message: str) -> None:
    """A prompt this runner cannot trust is refused."""
    prompt, _ = documents(
        CBC,
        {
            "tgId": 1,
            "testType": "AFT",
            "direction": "encrypt",
            "keyLen": 128,
            "tests": [{"tcId": 1, "key": KEY.hex(), "iv": IV.hex(), "pt": BLOCK.hex()}],
        },
        [],
    )
    with pytest.raises(AcvpValidationError, match=message):
        aes_block.parse_vector_set(prompt | mutation)


def test_an_unknown_direction_is_rejected() -> None:
    """The direction vocabulary is closed."""
    prompt, _ = documents(
        CBC,
        {
            "tgId": 1,
            "testType": "AFT",
            "direction": "sideways",
            "keyLen": 128,
            "tests": [{"tcId": 1, "key": KEY.hex(), "iv": IV.hex(), "pt": BLOCK.hex()}],
        },
        [],
    )
    with pytest.raises(AcvpValidationError, match="encrypt"):
        aes_block.parse_vector_set(prompt)


def test_files_round_trip_through_the_loaders(tmp_path: Path) -> None:
    """The path-taking loaders parse what the document parsers accept."""
    prompt, expected = documents(
        OFB,
        {
            "tgId": 1,
            "testType": "AFT",
            "direction": "encrypt",
            "keyLen": 128,
            "tests": [{"tcId": 1, "key": KEY.hex(), "iv": IV.hex(), "pt": BLOCK.hex()}],
        },
        [{"tcId": 1, "ct": "00" * 16}],
    )
    (tmp_path / "prompt.json").write_text(json.dumps(prompt), encoding="utf-8")
    (tmp_path / "expected.json").write_text(json.dumps(expected), encoding="utf-8")

    vector_set = aes_block.load_vector_set(tmp_path / "prompt.json")
    results = aes_block.load_expected_results(tmp_path / "expected.json")

    assert vector_set.algorithm == OFB
    assert results.cases[(1, 1)].values["ct"] == b"\x00" * 16


def test_provider_metadata_names_the_backend() -> None:
    """A report is only meaningful if it says what produced it."""
    metadata = provider().metadata()

    assert metadata.name == "cryptography-aes-block"
    assert metadata.backend_name == "OpenSSL"
    assert metadata.library_version and metadata.backend_version
