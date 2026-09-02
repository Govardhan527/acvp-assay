"""SP 800-108 tests, anchored on cases from NIST's pinned KDF-1.0 vector set.

Between them the five known answers cover all three KDF modes, four of the five
counter placements, the bit-offset splice, and an output length that is not a
whole number of bytes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from acvp_assay.algorithms import kdf
from acvp_assay.models import ResultStatus
from acvp_assay.models import TestCaseResult as CaseResult
from acvp_assay.parser import AcvpValidationError
from acvp_assay.providers.kdf import CryptographyKdf, KdfRequest, supported_mac_modes


@dataclass(frozen=True)
class KnownAnswer:
    """One case from the pinned upstream set, with the answer NIST recorded."""

    kdf_mode: str
    counter_location: str
    mac_mode: str
    output_bits: int
    key_in: str
    fixed_data: str
    key_out: str
    counter_bits: int = 0
    iv: str = ""
    break_location: int | None = None

    def group_fields(self) -> dict[str, object]:
        """Render this record's group-level ACVP fields."""
        fields: dict[str, object] = {
            "kdfMode": self.kdf_mode,
            "counterLocation": self.counter_location,
            "macMode": self.mac_mode,
            "keyOutLength": self.output_bits,
        }
        if self.counter_bits:
            fields["counterLength"] = self.counter_bits
        return fields

    def request(self, **overrides: object) -> KdfRequest:
        """Build the equivalent provider request."""
        return KdfRequest(
            mac_mode=self.mac_mode,
            kdf_mode=self.kdf_mode,
            counter_location=self.counter_location,
            counter_bits=self.counter_bits,
            key_in=bytes.fromhex(self.key_in),
            fixed_data=bytes.fromhex(self.fixed_data),
            output_bits=self.output_bits,
            iv=bytes.fromhex(self.iv),
            break_location=self.break_location or 0,
        )


COUNTER_AFTER = KnownAnswer(
    kdf_mode="counter",
    counter_location="after fixed data",
    mac_mode="CMAC-AES128",
    counter_bits=8,
    output_bits=8,
    key_in="C5FE792532A5088D296AD6622CCD5B42",
    fixed_data="31BF13E5997BABDB4602F3226F45D523",
    key_out="38",
)
COUNTER_MIDDLE = KnownAnswer(
    kdf_mode="counter",
    counter_location="middle fixed data",
    mac_mode="CMAC-AES128",
    counter_bits=8,
    output_bits=8,
    key_in="C003E351F8841C00C76EBC5401D24AE7",
    fixed_data="26B318C77C773D8644CFE44FB67D5262",
    break_location=90,
    key_out="4E",
)
FEEDBACK_BEFORE_ITERATOR = KnownAnswer(
    kdf_mode="feedback",
    counter_location="before iterator",
    mac_mode="CMAC-AES128",
    counter_bits=8,
    output_bits=8,
    key_in="978119AF8A907BD57AB9B5096FF2C67B",
    iv="17DB46704C833A2BD42E5D04B8ABE4F7",
    fixed_data="C899B3EACB31F15C32722107B8F4ECBC",
    key_out="01",
)
DOUBLE_PIPELINE_NO_COUNTER = KnownAnswer(
    kdf_mode="double pipeline iteration",
    counter_location="none",
    mac_mode="CMAC-AES128",
    output_bits=8,
    key_in="75D25192D85945C2768A51C6FBA8149C",
    fixed_data="1549C43A7FFD3B80DE6C09064DB15B9A",
    key_out="90",
)
SUB_BYTE_OUTPUT = KnownAnswer(
    kdf_mode="counter",
    counter_location="before fixed data",
    mac_mode="HMAC-SHA2-256",
    counter_bits=16,
    output_bits=67,
    key_in="EB4870BB0CB04FCEAA966001BC4D54F793B69AD2888A4874DCA5100AA2081933",
    fixed_data="CF91624F816B629CC4FDDC1119B39E00",
    key_out="34E8E9C3CD4008F740",
)

KNOWN_ANSWERS = [
    COUNTER_AFTER,
    COUNTER_MIDDLE,
    FEEDBACK_BEFORE_ITERATOR,
    DOUBLE_PIPELINE_NO_COUNTER,
    SUB_BYTE_OUTPUT,
]


def documents(answer: KnownAnswer) -> tuple[dict[str, object], dict[str, object]]:
    """Build a one-case prompt and its expected results from a known answer."""
    case: dict[str, object] = {"tcId": 1, "keyIn": answer.key_in}
    if answer.iv:
        case["iv"] = answer.iv
    expected_case: dict[str, object] = {
        "tcId": 1,
        "fixedData": answer.fixed_data,
        "keyOut": answer.key_out,
    }
    if answer.break_location is not None:
        expected_case["breakLocation"] = answer.break_location
    prompt: dict[str, object] = {
        "vsId": 1,
        "algorithm": kdf.ALGORITHM,
        "revision": "1.0",
        "testGroups": [{"tgId": 1, "testType": "AFT", **answer.group_fields(), "tests": [case]}],
    }
    expected: dict[str, object] = {
        "vsId": 1,
        "testGroups": [{"tgId": 1, "tests": [expected_case]}],
    }
    return prompt, expected


def run(answer: KnownAnswer) -> list[CaseResult]:
    """Parse and execute one known answer against the built-in provider."""
    prompt, expected = documents(answer)
    return kdf.run_vector_set(
        kdf.parse_vector_set(prompt),
        kdf.parse_expected_results(expected),
        CryptographyKdf(),
    )


@pytest.mark.parametrize(
    "answer", KNOWN_ANSWERS, ids=lambda a: f"{a.kdf_mode}-{a.counter_location}"
)
def test_known_answers_from_the_pinned_nist_set(answer: KnownAnswer) -> None:
    """Every mode and placement agrees with NIST's own answer."""
    assert [r.status for r in run(answer)] == [ResultStatus.PASS]


def test_a_wrong_derivation_is_a_failure() -> None:
    """Anything other than NIST's answer must be reported."""
    results = run(replace(SUB_BYTE_OUTPUT, key_out="00" * 9))

    assert results[0].status is ResultStatus.FAIL
    assert results[0].diagnostic == "derived key differs"


def test_output_shorter_than_a_byte_boundary_has_its_padding_bits_cleared() -> None:
    """67 bits is 9 bytes with 5 padding bits; leaving them set disagrees with NIST."""
    produced = CryptographyKdf().derive(SUB_BYTE_OUTPUT.request())

    assert len(produced) == 9
    assert produced[-1] & 0b0001_1111 == 0
    assert produced.hex().upper() == SUB_BYTE_OUTPUT.key_out


def test_the_counter_splices_into_fixed_data_at_a_bit_offset() -> None:
    """breakLocation 90 is not a byte boundary, so a byte-sliced answer is wrong."""
    provider = CryptographyKdf()
    request = COUNTER_MIDDLE.request()

    assert provider.derive(request).hex().upper() == COUNTER_MIDDLE.key_out
    # The nearest byte boundary must not produce the same answer.
    byte_aligned = provider.derive(replace(request, break_location=88))
    assert byte_aligned.hex().upper() != COUNTER_MIDDLE.key_out


def test_cmac_tdes_is_declared_rather_than_approximated() -> None:
    """CMAC-TDES appears upstream; this provider will not answer it."""
    results = run(replace(COUNTER_AFTER, mac_mode="CMAC-TDES"))

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "CMAC-TDES" in (results[0].diagnostic or "")


def test_a_case_with_no_expected_result_is_declared() -> None:
    """Without fixed data there is nothing to derive from."""
    prompt, expected = documents(COUNTER_AFTER)
    groups = expected["testGroups"]
    assert isinstance(groups, list)
    groups[0]["tests"][0]["tcId"] = 999
    results = kdf.run_vector_set(
        kdf.parse_vector_set(prompt),
        kdf.parse_expected_results(expected),
        CryptographyKdf(),
    )

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "no expected result" in (results[0].diagnostic or "")


def test_a_key_of_the_wrong_length_is_a_provider_error_without_leaking_it() -> None:
    """CMAC-AES256 with a 128-bit key is rejected, and no library text reaches output."""
    results = run(replace(COUNTER_AFTER, mac_mode="CMAC-AES256"))

    assert results[0].status is ResultStatus.ERROR
    assert results[0].diagnostic == "provider error"


def test_the_provider_refuses_requests_it_cannot_honour() -> None:
    """Each refusal is explicit rather than a silently wrong answer."""
    base = SUB_BYTE_OUTPUT.request()
    provider = CryptographyKdf()

    with pytest.raises(ValueError, match="unsupported kdfMode"):
        provider.derive(replace(base, kdf_mode="pipeline"))
    with pytest.raises(ValueError, match="unsupported counterLocation"):
        provider.derive(replace(base, counter_location="sideways"))
    with pytest.raises(ValueError, match="keyOutLength must be positive"):
        provider.derive(replace(base, output_bits=0))
    with pytest.raises(ValueError, match="unsupported macMode"):
        provider.derive(replace(base, mac_mode="CMAC-TDES"))


def test_provider_metadata_names_the_backend() -> None:
    """A report is only meaningful if it says what produced it."""
    metadata = CryptographyKdf().metadata()

    assert metadata.name == "cryptography-kdf-sp800-108"
    assert metadata.library_name == "cryptography"
    assert metadata.backend_name == "OpenSSL"
    assert metadata.library_version and metadata.backend_version


def test_supported_mac_modes_cover_hmac_and_cmac_aes() -> None:
    """Fourteen PRFs, with CMAC-TDES deliberately absent."""
    modes = set(supported_mac_modes())

    assert "HMAC-SHA2-256" in modes
    assert "HMAC-SHA3-512" in modes
    assert "CMAC-AES256" in modes
    assert "CMAC-TDES" not in modes


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"algorithm": "ctrDRBG"}, "expected 'KDF'"),
        ({"testGroups": "not-a-list"}, "expected an array"),
    ],
)
def test_malformed_documents_are_rejected(mutation: dict[str, object], message: str) -> None:
    """A prompt this runner cannot trust is refused, not guessed at."""
    prompt, _ = documents(COUNTER_AFTER)
    with pytest.raises(AcvpValidationError, match=message):
        kdf.parse_vector_set(prompt | mutation)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("kdfMode", "pipeline", "expected one of"),
        ("counterLocation", "sideways", "expected one of"),
        ("keyOutLength", 0, "positive integer"),
        ("counterLength", 7, "multiple of 8"),
        ("counterLength", -8, "multiple of 8"),
    ],
)
def test_malformed_groups_are_rejected(field: str, value: object, message: str) -> None:
    """Group-level parameters are validated before any derivation runs."""
    prompt, _ = documents(COUNTER_AFTER)
    groups = prompt["testGroups"]
    assert isinstance(groups, list)
    groups[0][field] = value
    with pytest.raises(AcvpValidationError, match=message):
        kdf.parse_vector_set(prompt)


def test_a_negative_break_location_is_rejected() -> None:
    """An offset into the fixed data cannot be negative."""
    _, expected = documents(COUNTER_MIDDLE)
    groups = expected["testGroups"]
    assert isinstance(groups, list)
    groups[0]["tests"][0]["breakLocation"] = -1
    with pytest.raises(AcvpValidationError, match="non-negative"):
        kdf.parse_expected_results(expected)


def test_files_round_trip_through_the_loaders(tmp_path: Path) -> None:
    """The path-taking loaders parse what the document parsers accept."""
    prompt, expected = documents(FEEDBACK_BEFORE_ITERATOR)
    (tmp_path / "prompt.json").write_text(json.dumps(prompt), encoding="utf-8")
    (tmp_path / "expected.json").write_text(json.dumps(expected), encoding="utf-8")

    vector_set = kdf.load_vector_set(tmp_path / "prompt.json")
    results = kdf.load_expected_results(tmp_path / "expected.json")

    assert vector_set.groups[0].kdf_mode == "feedback"
    assert vector_set.groups[0].cases[0].iv
    assert results.cases[1].key_out.hex().upper() == "01"
