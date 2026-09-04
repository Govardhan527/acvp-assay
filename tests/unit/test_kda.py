"""KDA in HKDF mode, anchored on session 765811.

Most of what can go wrong here is not the derivation -- HKDF is well-trodden --
but the assembly of ``fixedInfo``. The group declares a pattern, the case
supplies each party's contribution separately, and a string built even slightly
differently produces keying material that is wrong on every case rather than
some of them. These tests pin that assembly, and pin that an unrecognised
pattern is declined rather than guessed at.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from acvp_assay.algorithms import kda
from acvp_assay.models import ResultStatus
from acvp_assay.providers.kda import (
    UPARTY_VPARTY,
    CryptographyKda,
    PartyInfo,
    fixed_info,
)

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = f"{sys.executable} {ROOT / 'examples/reference_harness.py'}"
LIVE = ROOT / ".acvts/session-765811/4034322"
needs_live = pytest.mark.skipif(
    not (LIVE / "prompt.json").is_file(), reason="fetch session 765811 to run this"
)


def test_fixed_info_is_the_two_parties_concatenated() -> None:
    """Identifier then ephemeral data, U before V."""
    u = PartyInfo(party_id=b"\x01\x02", ephemeral_data=b"\xaa")
    v = PartyInfo(party_id=b"\x03\x04", ephemeral_data=b"\xbb")

    assert fixed_info(UPARTY_VPARTY, u, v) == b"\x01\x02\xaa\x03\x04\xbb"


def test_a_party_without_ephemeral_data_contributes_only_its_identifier() -> None:
    """ephemeralData is optional, and absent is not the same as empty-but-present."""
    u = PartyInfo(party_id=b"\x01\x02")
    v = PartyInfo(party_id=b"\x03\x04", ephemeral_data=b"\xbb")

    assert fixed_info(UPARTY_VPARTY, u, v) == b"\x01\x02\x03\x04\xbb"


def test_an_unrecognised_pattern_refuses_rather_than_improvising() -> None:
    """Guessing at a pattern gives a derivation that is wrong on every case."""
    party = PartyInfo(party_id=b"\x01")

    with pytest.raises(ValueError, match="is not assembled by this runner"):
        fixed_info("literal[0x00]||uPartyInfo", party, party)


def test_the_derivation_is_hkdf() -> None:
    """Extract with the salt, expand against the info -- RFC 5869."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    produced = CryptographyKda().derive(
        hmac_alg="SHA2-256",
        salt=b"\x01" * 32,
        shared_secret=b"\x02" * 32,
        info=b"context",
        output_bytes=64,
    )
    expected = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=b"\x01" * 32, info=b"context"
    ).derive(b"\x02" * 32)

    assert produced == expected


def test_an_unsupported_hash_is_refused() -> None:
    """The provider will not substitute a hash it was not asked for."""
    with pytest.raises(ValueError, match="unsupported hmacAlg"):
        CryptographyKda().derive(
            hmac_alg="SHA3-256", salt=b"", shared_secret=b"z", info=b"", output_bytes=32
        )


@needs_live
@pytest.mark.parametrize("harness", [False, True], ids=["builtin", "harness"])
def test_every_case_nist_generated_passes(harness: bool) -> None:
    """All 300, through the built-in provider and through a harness."""
    results = kda.run_vector_set(
        kda.load_vector_set(LIVE / "prompt.json"),
        kda.load_expected_results(LIVE / "expectedResults.json"),
        kda.provider_for(REFERENCE if harness else None, 300.0),
    )

    assert len(results) == 300
    assert all(r.status is ResultStatus.PASS for r in results)


@needs_live
def test_both_test_types_are_present_and_answered() -> None:
    """AFT compares bytes, VAL compares a verdict. Both must actually run."""
    vector_set = kda.load_vector_set(LIVE / "prompt.json")
    types = {group.test_type for group in vector_set.groups}

    assert types == {kda.AFT, kda.VAL}


@needs_live
def test_the_val_groups_carry_deliberately_wrong_material() -> None:
    """Rejecting wrong keying material is a correct answer, not a failure."""
    expected = kda.load_expected_results(LIVE / "expectedResults.json")
    rejections = [k for k, v in expected.items() if v.test_passed is False]

    assert rejections, "this set should carry cases that must be rejected"

    results = {
        (r.tg_id, r.tc_id): r
        for r in kda.run_vector_set(
            kda.load_vector_set(LIVE / "prompt.json"), expected, CryptographyKda()
        )
    }
    assert all(results[k].status is ResultStatus.PASS for k in rejections)


def prompt_with(tmp_path: Path, configuration: dict[str, object]) -> Path:
    """A one-case KDA prompt, for the decline paths."""
    document = {
        "vsId": 1,
        "algorithm": kda.ALGORITHM,
        "mode": "HKDF",
        "revision": "Sp800-56Cr2",
        "testGroups": [
            {
                "tgId": 1,
                "testType": "AFT",
                "kdfConfiguration": dict(
                    {
                        "kdfType": "hkdf",
                        "l": 256,
                        "saltLen": 256,
                        "saltMethod": "default",
                        "fixedInfoPattern": UPARTY_VPARTY,
                        "fixedInfoEncoding": "concatenation",
                        "hmacAlg": "SHA2-256",
                    },
                    **configuration,
                ),
                "tests": [
                    {
                        "tcId": 1,
                        "kdfParameter": {
                            "kdfType": "hkdf",
                            "salt": "00" * 32,
                            "z": "11" * 32,
                            "l": 256,
                        },
                        "fixedInfoPartyU": {"partyId": "AA" * 16},
                        "fixedInfoPartyV": {"partyId": "BB" * 16},
                    }
                ],
            }
        ],
    }
    path = tmp_path / "prompt.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("configuration", "reason"),
    [
        ({"kdfType": "twoStep"}, "kdfType"),
        ({"hmacAlg": "SHA3-256"}, "hmacAlg"),
        ({"fixedInfoEncoding": "ASN.1"}, "fixedInfoEncoding"),
        ({"fixedInfoPattern": "literal[0xFF]||uPartyInfo"}, "fixedInfoPattern"),
    ],
    ids=["two-step", "unknown-hash", "asn1-encoding", "other-pattern"],
)
def test_a_configuration_this_runner_cannot_answer_is_declined(
    tmp_path: Path, configuration: dict[str, object], reason: str
) -> None:
    """Each decline names the field, because the fix is usually registration."""
    results = kda.run_vector_set(
        kda.load_vector_set(prompt_with(tmp_path, configuration)),
        {(1, 1): kda.KdaExpectation(dkm=b"\x00" * 32, test_passed=None)},
        CryptographyKda(),
    )

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert reason in (results[0].diagnostic or "")


def test_a_case_with_no_recorded_answer_is_declined(tmp_path: Path) -> None:
    """Nothing to compare against is a coverage gap, not a pass."""
    results = kda.run_vector_set(
        kda.load_vector_set(prompt_with(tmp_path, {})), {}, CryptographyKda()
    )

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert "no expected result" in (results[0].diagnostic or "")


def test_a_wrong_derivation_fails(tmp_path: Path) -> None:
    """A mismatch is a failure, and names the field."""
    results = kda.run_vector_set(
        kda.load_vector_set(prompt_with(tmp_path, {})),
        {(1, 1): kda.KdaExpectation(dkm=b"\x00" * 32, test_passed=None)},
        CryptographyKda(),
    )

    assert [r.status for r in results] == [ResultStatus.FAIL]
    assert results[0].diagnostic == "dkm mismatch"


def test_expected_results_must_carry_an_answer(tmp_path: Path) -> None:
    """Neither bytes nor a verdict means the file is unusable."""
    from acvp_assay.parser import AcvpValidationError

    path = tmp_path / "expected.json"
    path.write_text(
        json.dumps({"testGroups": [{"tgId": 1, "tests": [{"tcId": 1}]}]}), encoding="utf-8"
    )

    with pytest.raises(AcvpValidationError, match="dkm or testPassed"):
        kda.load_expected_results(path)


def test_a_harness_declining_a_case_is_a_coverage_gap(tmp_path: Path) -> None:
    """An implementation without HKDF says so; that is not a failure."""
    script = tmp_path / "declines.py"
    script.write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    json.loads(line)\n"
        "    print(json.dumps({'error': 'unsupported'}), flush=True)\n",
        encoding="utf-8",
    )

    results = kda.run_vector_set(
        kda.load_vector_set(prompt_with(tmp_path, {})),
        {(1, 1): kda.KdaExpectation(dkm=b"\x00" * 32, test_passed=None)},
        kda.provider_for(f"{sys.executable} {script}", 60.0),
    )

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert "harness declined" in (results[0].diagnostic or "")


def test_the_builtin_provider_reports_its_backend() -> None:
    """Reports name the library and OpenSSL build that produced them."""
    metadata = kda.metadata_for(kda.provider_for(None, 30.0))

    assert metadata.name == "cryptography-kda"
    assert metadata.backend_version.startswith("OpenSSL")


def val_prompt(tmp_path: Path, case: dict[str, object]) -> Path:
    """A one-case VAL prompt, where the answer is a verdict."""
    document = {
        "vsId": 1,
        "algorithm": kda.ALGORITHM,
        "mode": "HKDF",
        "revision": "Sp800-56Cr2",
        "testGroups": [
            {
                "tgId": 1,
                "testType": "VAL",
                "kdfConfiguration": {
                    "kdfType": "hkdf",
                    "l": 256,
                    "saltLen": 256,
                    "saltMethod": "default",
                    "fixedInfoPattern": UPARTY_VPARTY,
                    "fixedInfoEncoding": "concatenation",
                    "hmacAlg": "SHA2-256",
                },
                "tests": [
                    dict(
                        {
                            "tcId": 1,
                            "kdfParameter": {
                                "kdfType": "hkdf",
                                "salt": "00" * 32,
                                "z": "11" * 32,
                                "l": 256,
                            },
                            "fixedInfoPartyU": {"partyId": "AA" * 16},
                            "fixedInfoPartyV": {"partyId": "BB" * 16},
                        },
                        **case,
                    )
                ],
            }
        ],
    }
    path = tmp_path / "prompt.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def correct_dkm() -> bytes:
    """What the built-in provider derives for the constructed VAL case."""
    return CryptographyKda().derive(
        hmac_alg="SHA2-256",
        salt=bytes(32),
        shared_secret=b"\x11" * 32,
        info=bytes.fromhex("AA" * 16 + "BB" * 16),
        output_bytes=32,
    )


def test_a_val_case_without_a_verdict_is_declined(tmp_path: Path) -> None:
    """A VAL case needs both the candidate material and the recorded answer."""
    prompt = val_prompt(tmp_path, {"dkm": correct_dkm().hex()})

    results = kda.run_vector_set(
        kda.load_vector_set(prompt),
        {(1, 1): kda.KdaExpectation(dkm=None, test_passed=None)},
        CryptographyKda(),
    )

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert "needs a dkm and a verdict" in (results[0].diagnostic or "")


def test_accepting_wrong_material_is_a_failure(tmp_path: Path) -> None:
    """Agreeing with keying material ACVP declares wrong is the worse error."""
    prompt = val_prompt(tmp_path, {"dkm": correct_dkm().hex()})

    results = kda.run_vector_set(
        kda.load_vector_set(prompt),
        {(1, 1): kda.KdaExpectation(dkm=None, test_passed=False)},
        CryptographyKda(),
    )

    assert [r.status for r in results] == [ResultStatus.FAIL]
    assert results[0].diagnostic == "accepted keying material ACVP declares wrong"


def test_rejecting_correct_material_is_a_failure(tmp_path: Path) -> None:
    """And the inverse."""
    prompt = val_prompt(tmp_path, {"dkm": "00" * 32})

    results = kda.run_vector_set(
        kda.load_vector_set(prompt),
        {(1, 1): kda.KdaExpectation(dkm=None, test_passed=True)},
        CryptographyKda(),
    )

    assert [r.status for r in results] == [ResultStatus.FAIL]
    assert results[0].diagnostic == "rejected keying material ACVP declares correct"


def test_an_aft_case_with_only_a_verdict_is_declined(tmp_path: Path) -> None:
    """AFT produces bytes; a bare verdict cannot be compared with them."""
    results = kda.run_vector_set(
        kda.load_vector_set(prompt_with(tmp_path, {})),
        {(1, 1): kda.KdaExpectation(dkm=None, test_passed=True)},
        CryptographyKda(),
    )

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert "no expected dkm" in (results[0].diagnostic or "")
