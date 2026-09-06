"""PBKDF (SP 800-132): the family whose password is not hex.

The derivation itself is `hashlib.pbkdf2_hmac`, so testing the arithmetic would
be testing the standard library. What is worth pinning is everything ACVP
decides: that the password arrives as characters while every other byte string
arrives as hex, that ``keyLen`` counts bits, and that a refused case is reported
rather than guessed at.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from acvp_assay.algorithms import pbkdf as algorithm
from acvp_assay.models import ResultStatus
from acvp_assay.parser import AcvpValidationError
from acvp_assay.providers.pbkdf import (
    ALGORITHM,
    SUPPORTED_HMACS,
    HashlibPbkdf,
    SubprocessPbkdf,
)
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

PASSWORD = "correct horse battery staple"
SALT = bytes(range(16))


def _prompt(hmac_alg: str = "SHA2-256", key_bits: int = 256) -> dict[str, Any]:
    return {
        "vsId": 9,
        "algorithm": ALGORITHM,
        "revision": "1.0",
        "testGroups": [
            {
                "tgId": 2,
                "testType": "AFT",
                "hmacAlg": hmac_alg,
                "tests": [
                    {
                        "tcId": 5,
                        "password": PASSWORD,
                        "salt": SALT.hex().upper(),
                        "iterationCount": 12,
                        "keyLen": key_bits,
                    }
                ],
            }
        ],
    }


def _expected(key: bytes) -> dict[str, Any]:
    return {
        "vsId": 9,
        "testGroups": [{"tgId": 2, "tests": [{"tcId": 5, "derivedKey": key.hex().upper()}]}],
    }


def _reference(hmac_alg: str = "SHA2-256", key_bits: int = 256) -> bytes:
    names = {
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
    return hashlib.pbkdf2_hmac(
        names[hmac_alg], PASSWORD.encode("utf-8"), SALT, 12, dklen=key_bits // 8
    )


@pytest.mark.parametrize("hmac_alg", SUPPORTED_HMACS)
def test_every_approved_hmac_derives(hmac_alg: str) -> None:
    assert HashlibPbkdf().derive(
        hmac_alg=hmac_alg, password=PASSWORD.encode(), salt=SALT, iterations=12, key_bits=256
    ) == _reference(hmac_alg)


def test_key_len_is_counted_in_bits() -> None:
    """256 means 32 bytes. Reading it as bytes would return eight times too much."""
    derived = HashlibPbkdf().derive(
        hmac_alg="SHA2-256", password=PASSWORD.encode(), salt=SALT, iterations=12, key_bits=256
    )
    assert len(derived) == 32


def test_a_key_length_that_is_not_whole_bytes_is_refused() -> None:
    with pytest.raises(ValueError, match="whole number of bytes"):
        HashlibPbkdf().derive(
            hmac_alg="SHA2-256", password=b"x", salt=SALT, iterations=12, key_bits=100
        )


def test_an_unapproved_hmac_is_refused() -> None:
    with pytest.raises(ValueError, match="unsupported hmacAlg"):
        HashlibPbkdf().derive(hmac_alg="MD5", password=b"x", salt=SALT, iterations=12, key_bits=256)


def test_a_zero_iteration_count_is_refused() -> None:
    """PBKDF exists to be expensive; zero iterations is not a derivation."""
    with pytest.raises(ValueError, match="at least 1"):
        HashlibPbkdf().derive(
            hmac_alg="SHA2-256", password=b"x", salt=SALT, iterations=0, key_bits=256
        )


def test_the_password_is_read_as_text_not_hex() -> None:
    """The single most likely misreading of this family.

    ACVP sends the password as characters while every other byte string in a
    vector set is hex. A hex reading fails outright on any password containing a
    letter past 'f' -- and, far worse, silently succeeds on one that happens to
    be hex-shaped, deriving from the wrong bytes.
    """
    parsed = algorithm.parse_vector_set(_prompt())
    assert parsed.test_groups[0].tests[0].password == PASSWORD.encode("utf-8")


def test_a_hex_shaped_password_is_still_read_as_text() -> None:
    prompt = _prompt()
    prompt["testGroups"][0]["tests"][0]["password"] = "abcdef"
    parsed = algorithm.parse_vector_set(prompt)
    assert parsed.test_groups[0].tests[0].password == b"abcdef"
    assert parsed.test_groups[0].tests[0].password != bytes.fromhex("abcdef")


def test_parsing_preserves_every_acvp_identifier() -> None:
    parsed = algorithm.parse_vector_set(_prompt())
    assert (parsed.vs_id, parsed.algorithm, parsed.revision) == (9, ALGORITHM, "1.0")
    group = parsed.test_groups[0]
    assert (group.tg_id, group.hmac_alg) == (2, "SHA2-256")
    case = group.tests[0]
    assert (case.tc_id, case.iterations, case.key_bits, case.salt) == (5, 12, 256, SALT)


def test_an_unrelated_algorithm_is_refused() -> None:
    prompt = _prompt()
    prompt["algorithm"] = "KDF"
    with pytest.raises(AcvpValidationError):
        algorithm.parse_vector_set(prompt)


def test_a_correct_derivation_passes() -> None:
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(_prompt()),
        algorithm.parse_expected_results(_expected(_reference())),
        HashlibPbkdf(),
    )
    assert [r.status for r in results] == [ResultStatus.PASS]
    assert (results[0].tg_id, results[0].tc_id) == (2, 5)


def test_a_wrong_derivation_fails() -> None:
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(_prompt()),
        algorithm.parse_expected_results(_expected(b"\x00" * 32)),
        HashlibPbkdf(),
    )
    assert results[0].status is ResultStatus.FAIL
    assert results[0].diagnostic == "derivedKey differs"


def test_a_case_with_no_recorded_key_is_unsupported() -> None:
    results = algorithm.run_vector_set(algorithm.parse_vector_set(_prompt()), {}, HashlibPbkdf())
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_an_unapproved_group_hmac_is_declined_not_attempted() -> None:
    prompt = _prompt(hmac_alg="MD5")
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(prompt),
        algorithm.parse_expected_results(_expected(b"\x00" * 32)),
        HashlibPbkdf(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED
    assert results[0].diagnostic is not None
    assert "MD5" in results[0].diagnostic


def test_a_harness_declining_a_case_is_unsupported_not_an_error() -> None:
    class Declining(HashlibPbkdf):
        def derive(self, **kwargs: Any) -> bytes:
            raise HarnessUnsupportedError("declined")

    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(_prompt()),
        algorithm.parse_expected_results(_expected(_reference())),
        Declining(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED
    assert results[0].diagnostic == "the harness declined this case"


def test_the_files_load_from_disk(tmp_path: Path) -> None:
    prompt = tmp_path / "prompt.json"
    expected = tmp_path / "expectedResults.json"
    prompt.write_text(json.dumps(_prompt()), encoding="utf-8")
    expected.write_text(json.dumps(_expected(_reference())), encoding="utf-8")
    assert algorithm.load_vector_set(prompt).vs_id == 9
    assert algorithm.load_expected_results(expected)[(2, 5)] == _reference()


def test_the_built_in_provider_is_used_unless_a_harness_is_named() -> None:
    assert isinstance(algorithm.provider_for(None, 1.0), HashlibPbkdf)
    assert isinstance(algorithm.provider_for("true", 1.0), SubprocessPbkdf)


def test_the_provider_identifies_its_backend() -> None:
    metadata = HashlibPbkdf().metadata()
    assert metadata.name == "hashlib-pbkdf"
    assert metadata.library_name == "hashlib"
    assert metadata.library_version


class _RecordingHarness(SubprocessPbkdf):
    def __init__(self) -> None:  # noqa: D107 - deliberately skips the real setup
        self.requests: list[dict[str, object]] = []

    def invoke(self, request: Mapping[str, object]) -> Mapping[str, object]:
        self.requests.append(dict(request))
        return {"derivedKey": "AB" * 32}


def test_the_wire_carries_the_password_as_hex() -> None:
    """ACVP sends text; the wire sends hex.

    Every other value on this protocol is hex, and hex has no character encoding
    for the two sides to disagree about. The runner decodes once so a harness
    never has to know ACVP's convention.
    """
    harness = _RecordingHarness()
    harness.derive(
        hmac_alg="SHA2-256", password=PASSWORD.encode(), salt=SALT, iterations=12, key_bits=256
    )
    request = harness.requests[0]
    assert request["operation"] == "pbkdf"
    assert request["password"] == PASSWORD.encode().hex().upper()
    assert request["keyLen"] == 256
    assert request["iterationCount"] == 12
