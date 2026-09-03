"""CTR_DRBG tests, anchored on two cases lifted from NIST's pinned vector set.

Hand-written fixtures cannot check a DRBG: any consistent implementation agrees
with itself. The two known answers below come from
``ctrDRBG-SP800-90Ar1/prompt.json`` at the pinned commit, and between them they
exercise the derivation function both ways, prediction resistance both ways,
both counter field widths, and the explicit reseed path.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acvp_assay.algorithms import ctr_drbg
from acvp_assay.models import ResultStatus
from acvp_assay.models import TestCaseResult as CaseResult
from acvp_assay.parser import AcvpValidationError
from acvp_assay.providers.ctr_drbg import CryptographyCtrDrbg

# tgId 9, tcId 121: derFunc off, prediction resistance on, 64-bit counter field.
NO_DF_PREDICTION_RESISTANCE = {
    "tgId": 9,
    "testType": "AFT",
    "derFunc": False,
    "predResistance": True,
    "mode": "AES-128",
    "returnedBitsLen": 128,
    "counterFieldLen": 64,
    "tests": [
        {
            "tcId": 121,
            "entropyInput": "3E20107EBFB563A749CEAABA42FB735B864E921724DF3937476BA2101D970AFE",
            "nonce": "",
            "persoString": "26C8ACECAC764E3B54171FD53D7D64647237426C4525C236D361234A0BCF4B52",
            "otherInput": [
                {
                    "intendedUse": "generate",
                    "additionalInput": (
                        "403B8B7DBC81D4356D106ED4B5FA53685EBF8A20374ED0D9858165461A0A79D3"
                    ),
                    "entropyInput": (
                        "35EAD342737F71697EFA7BFE328B18AC8AB280CEEB9A6F147DFFFC2DEA522FE9"
                    ),
                },
                {
                    "intendedUse": "generate",
                    "additionalInput": (
                        "D261D1B1D8EBB3044F674C7F5D0AA2767141E216CE1DB40FD1E96A72BAB20E95"
                    ),
                    "entropyInput": (
                        "4E07C5E472E59C69646035D9EF0B20B2DE5DC32C2D5806974643977554186584"
                    ),
                },
            ],
        }
    ],
}
NO_DF_EXPECTED = "A8751C7C439212B293D0AD07ED76F336"

# tgId 13, tcId 181: derivation function on, explicit reseed, full-width counter.
WITH_DF_RESEED = {
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
            "entropyInput": "7E1D87DBE3C6F31556D9B448AF56F037C5742BAA57A6AF0B208B32C02E714B90",
            "nonce": "8444A76CCC181B71DBDB362B2E5EC07AB6570A05515F9BCD8FF832D428BD3191",
            "persoString": "26232C1AB9B6E1555B52EF291A690F9B0B518755ADE1C7F805F14C6D78C62891",
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
WITH_DF_EXPECTED = "F67D256063A2483D4425FB71D68725EB3AFF060B3BF7918052534FEBC3B98DDF"


def prompt(*groups: dict[str, object]) -> dict[str, object]:
    """Wrap groups in a minimal ctrDRBG prompt document."""
    return {
        "vsId": 1,
        "algorithm": ctr_drbg.ALGORITHM,
        "revision": "SP800-90Ar1",
        "testGroups": list(groups),
    }


def expected_for(*pairs: tuple[int, str]) -> dict[str, object]:
    """Wrap case results in a minimal expected-results document."""
    return {
        "vsId": 1,
        "testGroups": [
            {"tgId": 1, "tests": [{"tcId": tc, "returnedBits": bits} for tc, bits in pairs]}
        ],
    }


def run(group: dict[str, object], pairs: tuple[tuple[int, str], ...]) -> list[CaseResult]:
    """Parse and execute one group against the built-in provider."""
    vector_set = ctr_drbg.parse_vector_set(prompt(group))
    expected = ctr_drbg.parse_expected_results(expected_for(*pairs))
    return ctr_drbg.run_vector_set(vector_set, expected, CryptographyCtrDrbg())


def test_known_answer_without_the_derivation_function() -> None:
    """Prediction resistance and a 64-bit counter field, against NIST's own answer."""
    results = run(NO_DF_PREDICTION_RESISTANCE, ((121, NO_DF_EXPECTED),))

    assert [r.status for r in results] == [ResultStatus.PASS]


def test_known_answer_with_the_derivation_function_and_a_reseed() -> None:
    """The derivation function, an explicit reseed, and a full-width counter."""
    results = run(WITH_DF_RESEED, ((181, WITH_DF_EXPECTED),))

    assert [r.status for r in results] == [ResultStatus.PASS]


def test_a_wrong_answer_is_a_failure() -> None:
    """A DRBG producing anything else must be reported, not tolerated."""
    results = run(WITH_DF_RESEED, ((181, "00" * 32),))

    assert results[0].status is ResultStatus.FAIL
    assert results[0].diagnostic == "returned bits differ"


def test_only_the_second_generation_is_compared() -> None:
    """Comparing the first output would pass a DRBG that never updates its state.

    The first generation's output is discarded by the standard's test procedure,
    so it must not be what the runner reports.
    """
    provider = CryptographyCtrDrbg()
    case = WITH_DF_RESEED["tests"][0]  # type: ignore[index]
    provider.instantiate(
        mode="AES-128",
        derivation_function=True,
        counter_field_bits=128,
        entropy=bytes.fromhex(case["entropyInput"]),
        nonce=bytes.fromhex(case["nonce"]),
        personalization=bytes.fromhex(case["persoString"]),
    )
    operations = case["otherInput"]
    provider.reseed(
        entropy=bytes.fromhex(operations[0]["entropyInput"]),
        additional_input=bytes.fromhex(operations[0]["additionalInput"]),
    )
    first = provider.generate(
        byte_count=32, additional_input=bytes.fromhex(operations[1]["additionalInput"])
    )

    assert first.hex().upper() != WITH_DF_EXPECTED


def test_tdes_is_declared_rather_than_approximated() -> None:
    """Three-key TDES was disallowed for this use after 2023."""
    group = dict(WITH_DF_RESEED, mode="TDES")
    results = run(group, ((181, WITH_DF_EXPECTED),))

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "TDES" in (results[0].diagnostic or "")


def test_a_case_with_no_expected_result_is_declared() -> None:
    """Nothing to compare against is not the same as a failure."""
    results = run(WITH_DF_RESEED, ((999, WITH_DF_EXPECTED),))

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "no expected result" in (results[0].diagnostic or "")


def test_a_case_that_never_generates_is_declared() -> None:
    """A sequence of reseeds alone produces nothing to compare."""
    case = dict(WITH_DF_RESEED["tests"][0])  # type: ignore[index]
    case["otherInput"] = [case["otherInput"][0]]
    group = dict(WITH_DF_RESEED, tests=[case])
    results = run(group, ((181, WITH_DF_EXPECTED),))

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "no generation" in (results[0].diagnostic or "")


def test_the_provider_refuses_an_unknown_mode() -> None:
    """The provider will not guess at a block cipher it does not implement."""
    with pytest.raises(ValueError, match="unsupported CTR_DRBG mode"):
        CryptographyCtrDrbg().instantiate(
            mode="Camellia-128",
            derivation_function=True,
            counter_field_bits=128,
            entropy=b"\x00" * 32,
            nonce=b"",
            personalization=b"",
        )


def test_an_absent_counter_field_length_means_the_whole_block() -> None:
    """Revision 1.0 has no counterFieldLen; the counter is then the full block."""
    group = {k: v for k, v in WITH_DF_RESEED.items() if k != "counterFieldLen"}
    results = run(group, ((181, WITH_DF_EXPECTED),))

    assert results[0].status is ResultStatus.PASS


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"algorithm": "ACVP-AES-GCM"}, "expected one of"),
        ({"testGroups": "not-a-list"}, "expected an array"),
    ],
)
def test_malformed_documents_are_rejected(mutation: dict[str, object], message: str) -> None:
    """A prompt this runner cannot trust is refused, not guessed at."""
    document = prompt(WITH_DF_RESEED) | mutation
    with pytest.raises(AcvpValidationError, match=message):
        ctr_drbg.parse_vector_set(document)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("returnedBitsLen", 0, "positive multiple of 8"),
        ("returnedBitsLen", 129, "positive multiple of 8"),
        ("counterFieldLen", -1, "non-negative"),
        ("counterFieldLen", "128", "expected an integer"),
    ],
)
def test_malformed_groups_are_rejected(field: str, value: object, message: str) -> None:
    """Group-level lengths are validated before any DRBG is instantiated."""
    with pytest.raises(AcvpValidationError, match=message):
        ctr_drbg.parse_vector_set(prompt(dict(WITH_DF_RESEED, **{field: value})))


def test_an_unknown_intended_use_is_rejected() -> None:
    """The operation vocabulary is closed: reSeed or generate."""
    case = dict(WITH_DF_RESEED["tests"][0])  # type: ignore[index]
    case["otherInput"] = [dict(case["otherInput"][0], intendedUse="uninstantiate")]
    with pytest.raises(AcvpValidationError, match="expected one of"):
        ctr_drbg.parse_vector_set(prompt(dict(WITH_DF_RESEED, tests=[case])))


def test_provider_metadata_names_the_backend() -> None:
    """A report is only meaningful if it says what produced it."""
    metadata = CryptographyCtrDrbg().metadata()

    assert metadata.name == "cryptography-ctr-drbg"
    assert metadata.library_name == "cryptography"
    assert metadata.backend_name == "OpenSSL"
    assert metadata.library_version and metadata.backend_version


def test_the_derivation_function_handles_input_needing_no_padding() -> None:
    """Block_Cipher_df pads to a block boundary, so the exact-fit case is a branch.

    The 8-byte length prefix plus a 0x80 terminator means an input of 7 bytes
    lands exactly on a 16-byte boundary and must not gain a further block.
    """
    provider = CryptographyCtrDrbg()
    provider.instantiate(
        mode="AES-128",
        derivation_function=True,
        counter_field_bits=128,
        entropy=b"\x01" * 7,
        nonce=b"",
        personalization=b"",
    )

    assert len(provider.generate(byte_count=16, additional_input=b"")) == 16


def test_supported_modes_are_the_aes_family() -> None:
    """TDES is absent by design, and that is worth asserting."""
    assert set(ctr_drbg.supported_modes()) == {"AES-128", "AES-192", "AES-256"}


def test_files_round_trip_through_the_loaders(tmp_path: Path) -> None:
    """The path-taking loaders parse what the document parsers accept."""
    (tmp_path / "prompt.json").write_text(json.dumps(prompt(WITH_DF_RESEED)), encoding="utf-8")
    (tmp_path / "expected.json").write_text(
        json.dumps(expected_for((181, WITH_DF_EXPECTED))), encoding="utf-8"
    )

    vector_set = ctr_drbg.load_vector_set(tmp_path / "prompt.json")
    expected = ctr_drbg.load_expected_results(tmp_path / "expected.json")

    assert vector_set.vs_id == 1
    assert vector_set.revision == "SP800-90Ar1"
    assert expected.returned_bits[181].hex().upper() == WITH_DF_EXPECTED
