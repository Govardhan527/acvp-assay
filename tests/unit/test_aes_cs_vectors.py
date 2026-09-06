"""Parsing and execution for the ciphertext-stealing vector sets.

The provider's arithmetic is covered in ``test_aes_cs.py``. What is covered
here is everything around it: that ACVP's ids survive parsing, that a wrong
answer is reported as FAIL rather than swallowed, and that a harness declining
a case produces UNSUPPORTED rather than an error.

The vectors are generated here rather than copied from NIST, so nothing in this
file redistributes anything.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acvp_assay.algorithms import aes_cs
from acvp_assay.models import ResultStatus
from acvp_assay.parser import AcvpValidationError
from acvp_assay.providers.aes_cs import CS1, CS3, CryptographyAesCs, SubprocessAesCs
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

KEY = bytes(range(16))
IV = bytes(range(16, 32))
PLAINTEXT = bytes(range(40))


def _ciphertext(algorithm: str) -> bytes:
    return CryptographyAesCs().transform(
        algorithm=algorithm, key=KEY, iv=IV, data=PLAINTEXT, encrypt=True
    )


def _prompt(algorithm: str = CS1) -> dict[str, Any]:
    return {
        "vsId": 42,
        "algorithm": algorithm,
        "revision": "1.0",
        "testGroups": [
            {
                "tgId": 7,
                "testType": "AFT",
                "direction": "encrypt",
                "tests": [
                    {
                        "tcId": 3,
                        "key": KEY.hex().upper(),
                        "iv": IV.hex().upper(),
                        "pt": PLAINTEXT.hex().upper(),
                        "payloadLen": len(PLAINTEXT) * 8,
                    }
                ],
            }
        ],
    }


def _expected(algorithm: str = CS1, ciphertext: bytes | None = None) -> dict[str, Any]:
    value = _ciphertext(algorithm) if ciphertext is None else ciphertext
    return {
        "vsId": 42,
        "testGroups": [{"tgId": 7, "tests": [{"tcId": 3, "ct": value.hex().upper()}]}],
    }


def test_parsing_preserves_every_acvp_identifier() -> None:
    vector_set = aes_cs.parse_vector_set(_prompt())
    assert vector_set.vs_id == 42
    assert vector_set.algorithm == CS1
    assert vector_set.revision == "1.0"
    group = vector_set.test_groups[0]
    assert (group.tg_id, group.direction) == (7, "encrypt")
    assert group.tests[0].tc_id == 3
    assert group.tests[0].payload_bits == len(PLAINTEXT) * 8


def test_a_decrypt_group_reads_its_payload_from_ct() -> None:
    prompt = _prompt()
    group = prompt["testGroups"][0]
    group["direction"] = "decrypt"
    group["tests"][0]["ct"] = group["tests"][0].pop("pt")
    parsed = aes_cs.parse_vector_set(prompt)
    assert parsed.test_groups[0].tests[0].data == PLAINTEXT


def test_an_unrelated_algorithm_is_refused() -> None:
    prompt = _prompt()
    prompt["algorithm"] = "ACVP-AES-CBC"
    with pytest.raises(AcvpValidationError):
        aes_cs.parse_vector_set(prompt)


def test_an_unknown_direction_is_refused() -> None:
    prompt = _prompt()
    prompt["testGroups"][0]["direction"] = "sideways"
    with pytest.raises(AcvpValidationError):
        aes_cs.parse_vector_set(prompt)


def test_a_correct_answer_passes() -> None:
    results = aes_cs.run_vector_set(
        aes_cs.parse_vector_set(_prompt()),
        aes_cs.parse_expected_results(_expected()),
        CryptographyAesCs(),
    )
    assert [result.status for result in results] == [ResultStatus.PASS]
    assert results[0].tg_id == 7
    assert results[0].tc_id == 3


def test_a_wrong_answer_fails_rather_than_passing_quietly() -> None:
    """CS3's ordering under a CS1 prompt is the realistic way to be wrong."""
    results = aes_cs.run_vector_set(
        aes_cs.parse_vector_set(_prompt()),
        aes_cs.parse_expected_results(_expected(ciphertext=_ciphertext(CS3))),
        CryptographyAesCs(),
    )
    assert results[0].status is ResultStatus.FAIL
    assert results[0].diagnostic == "ct differs"


def test_a_case_with_no_recorded_answer_is_unsupported() -> None:
    results = aes_cs.run_vector_set(aes_cs.parse_vector_set(_prompt()), {}, CryptographyAesCs())
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_a_harness_declining_a_case_is_unsupported_not_an_error() -> None:
    class Declining(CryptographyAesCs):
        def transform(self, **kwargs: Any) -> bytes:
            raise HarnessUnsupportedError("declined")

    results = aes_cs.run_vector_set(
        aes_cs.parse_vector_set(_prompt()), aes_cs.parse_expected_results(_expected()), Declining()
    )
    assert results[0].status is ResultStatus.UNSUPPORTED
    assert results[0].diagnostic == "the harness declined this case"


def test_the_files_load_from_disk(tmp_path: Path) -> None:
    prompt = tmp_path / "prompt.json"
    expected = tmp_path / "expectedResults.json"
    prompt.write_text(json.dumps(_prompt()), encoding="utf-8")
    expected.write_text(json.dumps(_expected()), encoding="utf-8")
    vector_set = aes_cs.load_vector_set(prompt)
    assert vector_set.vs_id == 42
    assert aes_cs.load_expected_results(expected)[(7, 3)]["ct"] == _ciphertext(CS1)


def test_the_built_in_provider_is_used_unless_a_harness_is_named() -> None:
    assert isinstance(aes_cs.provider_for(None, 1.0), CryptographyAesCs)
    assert isinstance(aes_cs.provider_for("true", 1.0), SubprocessAesCs)
