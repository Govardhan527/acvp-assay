"""KAS-ECC-SSC, anchored on vectors NIST generated for session 765769.

The two test types are not variations on one theme. VAL supplies every input,
including the implementation's own private key, so the answer is a verdict and
is checkable here. AFT supplies only the peer's public key, so the
implementation invents an ephemeral pair and Z differs on every run -- nothing
offline can check that, and saying so is more useful than inventing a
comparison. These tests pin both halves of that split.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from acvp_assay.algorithms import kas_ecc
from acvp_assay.models import ResultStatus
from acvp_assay.providers.kas_ecc import CryptographyKasEcc, coordinate_length

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = f"{sys.executable} {ROOT / 'examples/reference_harness.py'}"


def load_live_set() -> tuple[kas_ecc.KasVectorSet, dict[tuple[int, int], dict[str, object]]]:
    """The prompt and expected results fetched from ACVTS."""
    folder = ROOT / ".acvts/session-765769/4034090"
    return (
        kas_ecc.load_vector_set(folder / "prompt.json"),
        kas_ecc.load_expected_results(folder / "expectedResults.json"),
    )


LIVE = (ROOT / ".acvts/session-765769/4034090/prompt.json").is_file()
needs_live = pytest.mark.skipif(LIVE is False, reason="fetch session 765769 to run this")


def a_real_peer(curve: str) -> tuple[bytes, bytes]:
    """A public point that is actually on the named curve."""
    from cryptography.hazmat.primitives.asymmetric import ec

    from acvp_assay.providers.kas_ecc import CURVES

    numbers = ec.generate_private_key(CURVES[curve]()).public_key().public_numbers()
    width = coordinate_length(curve)
    return numbers.x.to_bytes(width, "big"), numbers.y.to_bytes(width, "big")


@pytest.mark.parametrize("curve", ["P-224", "P-256", "P-384", "P-521"])
def test_the_shared_secret_is_repeatable_and_correctly_sized(curve: str) -> None:
    """Same inputs, same Z -- and the widths are per-curve, easy to get wrong.

    Weak on its own; the live-vector tests below carry the real assurance. What
    this pins is P-521's 66-byte coordinates, which a 64-byte assumption would
    silently truncate.
    """
    provider = CryptographyKasEcc()
    peer_x, peer_y = a_real_peer(curve)
    private = bytes([1] * coordinate_length(curve))

    first = provider.shared_secret(curve=curve, peer_x=peer_x, peer_y=peer_y, private_key=private)
    second = provider.shared_secret(curve=curve, peer_x=peer_x, peer_y=peer_y, private_key=private)

    assert first.z == second.z
    assert len(first.x) == len(first.y) == coordinate_length(curve)
    assert len(first.z) == coordinate_length(curve)


def test_an_absent_private_key_generates_a_fresh_one() -> None:
    """AFT invents a key pair, so two calls must not agree.

    This is exactly why an AFT case cannot be checked offline.
    """
    provider = CryptographyKasEcc()
    peer_x, peer_y = a_real_peer("P-256")

    first = provider.shared_secret(curve="P-256", peer_x=peer_x, peer_y=peer_y, private_key=None)
    second = provider.shared_secret(curve="P-256", peer_x=peer_x, peer_y=peer_y, private_key=None)

    assert first.x != second.x
    assert first.z != second.z


def test_a_peer_point_off_the_curve_is_a_verdict_not_a_crash(tmp_path: Path) -> None:
    """ACVP may supply an unusable public key; rejecting is the answer."""
    document = {
        "vsId": 1,
        "algorithm": kas_ecc.ALGORITHM,
        "revision": kas_ecc.REVISION,
        "testGroups": [
            {
                "tgId": 1,
                "testType": "VAL",
                "domainParameterGenerationMode": "P-256",
                "scheme": kas_ecc.EPHEMERAL_UNIFIED,
                "kasRole": "initiator",
                "tests": [
                    {
                        "tcId": 1,
                        "ephemeralPublicServerX": "00" * 32,
                        "ephemeralPublicServerY": "00" * 32,
                        "ephemeralPrivateIut": "01" * 32,
                        "z": "02" * 32,
                    }
                ],
            }
        ],
    }
    path = tmp_path / "prompt.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    results = kas_ecc.run_vector_set(
        kas_ecc.load_vector_set(path), {(1, 1): {"testPassed": False}}, CryptographyKasEcc()
    )

    assert [r.status for r in results] == [ResultStatus.PASS]


@needs_live
def test_every_val_case_from_nists_own_vectors_passes() -> None:
    """The ten VAL cases NIST generated, judged against its recorded verdicts."""
    vector_set, expected = load_live_set()
    results = kas_ecc.run_vector_set(vector_set, expected, CryptographyKasEcc())

    verdicts = [r for r in results if r.status is not ResultStatus.UNSUPPORTED]
    assert len(verdicts) == 10
    assert all(r.status is ResultStatus.PASS for r in verdicts)


@needs_live
def test_aft_is_declined_with_the_reason_rather_than_guessed_at() -> None:
    """An ephemeral key makes Z unrepeatable, so nothing offline can check it."""
    vector_set, expected = load_live_set()
    results = kas_ecc.run_vector_set(vector_set, expected, CryptographyKasEcc())

    declined = [r for r in results if r.status is ResultStatus.UNSUPPORTED]
    assert len(declined) == 10
    assert all("ephemeral" in (r.diagnostic or "") for r in declined)


@needs_live
def test_the_harness_path_agrees_with_the_builtin() -> None:
    """A vendor's implementation reaches this family too."""
    vector_set, expected = load_live_set()
    provider = kas_ecc.provider_for(REFERENCE, 120.0)
    results = kas_ecc.run_vector_set(vector_set, expected, provider)

    verdicts = [r for r in results if r.status is not ResultStatus.UNSUPPORTED]
    assert len(verdicts) == 10
    assert all(r.status is ResultStatus.PASS for r in verdicts)


def test_an_unknown_scheme_is_declined(tmp_path: Path) -> None:
    """Static and MQV schemes carry extra key pairs and a different shape."""
    document = {
        "vsId": 1,
        "algorithm": kas_ecc.ALGORITHM,
        "revision": kas_ecc.REVISION,
        "testGroups": [
            {
                "tgId": 1,
                "testType": "VAL",
                "domainParameterGenerationMode": "P-256",
                "scheme": "fullMQV",
                "kasRole": "initiator",
                "tests": [
                    {
                        "tcId": 1,
                        "ephemeralPublicServerX": "00",
                        "ephemeralPublicServerY": "01",
                    }
                ],
            }
        ],
    }
    path = tmp_path / "prompt.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    results = kas_ecc.run_vector_set(kas_ecc.load_vector_set(path), {}, CryptographyKasEcc())

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert "fullMQV" in (results[0].diagnostic or "")


def test_a_curve_the_provider_lacks_is_declared_not_attempted(tmp_path: Path) -> None:
    """Capability belongs to the implementation, as everywhere else here."""
    document = {
        "vsId": 1,
        "algorithm": kas_ecc.ALGORITHM,
        "revision": kas_ecc.REVISION,
        "testGroups": [
            {
                "tgId": 1,
                "testType": "VAL",
                "domainParameterGenerationMode": "K-233",
                "scheme": kas_ecc.EPHEMERAL_UNIFIED,
                "kasRole": "initiator",
                "tests": [
                    {
                        "tcId": 1,
                        "ephemeralPublicServerX": "00",
                        "ephemeralPublicServerY": "01",
                    }
                ],
            }
        ],
    }
    path = tmp_path / "prompt.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    results = kas_ecc.run_vector_set(kas_ecc.load_vector_set(path), {}, CryptographyKasEcc())

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert "K-233" in (results[0].diagnostic or "")


def prompt_with(tmp_path: Path, group: dict[str, object], case: dict[str, object]) -> Path:
    """A one-case KAS-ECC-SSC prompt, for exercising the decline paths."""
    document = {
        "vsId": 1,
        "algorithm": kas_ecc.ALGORITHM,
        "revision": kas_ecc.REVISION,
        "testGroups": [
            dict(
                {
                    "tgId": 1,
                    "testType": "VAL",
                    "domainParameterGenerationMode": "P-256",
                    "scheme": kas_ecc.EPHEMERAL_UNIFIED,
                    "kasRole": "initiator",
                },
                **group,
                tests=[dict({"tcId": 1}, **case)],
            )
        ],
    }
    path = tmp_path / "prompt.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


PEER = {"ephemeralPublicServerX": "00" * 32, "ephemeralPublicServerY": "01" * 32}


@pytest.mark.parametrize(
    ("group", "case", "expected", "reason"),
    [
        ({"testType": "GDT"}, PEER, {}, "test type"),
        ({}, PEER, {}, "private key and z"),
        (
            {},
            dict(PEER, ephemeralPrivateIut="01" * 32, z="02" * 32),
            {},
            "no expected verdict recorded",
        ),
    ],
    ids=["unknown-test-type", "val-missing-inputs", "no-expected-verdict"],
)
def test_a_case_that_cannot_be_judged_is_declined(
    tmp_path: Path,
    group: dict[str, object],
    case: dict[str, object],
    expected: dict[tuple[int, int], dict[str, object]],
    reason: str,
) -> None:
    """Every path that cannot produce an honest verdict says why."""
    results = kas_ecc.run_vector_set(
        kas_ecc.load_vector_set(prompt_with(tmp_path, group, case)),
        expected,
        CryptographyKasEcc(),
    )

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert reason in (results[0].diagnostic or "")


def test_a_wrong_verdict_fails_and_says_which_way(tmp_path: Path) -> None:
    """Accepting a bad secret and rejecting a good one are different faults."""
    peer_x, peer_y = a_real_peer("P-256")
    prompt = prompt_with(
        tmp_path,
        {},
        {
            "ephemeralPublicServerX": peer_x.hex(),
            "ephemeralPublicServerY": peer_y.hex(),
            "ephemeralPrivateIut": "01" * 32,
            "z": "02" * 32,
        },
    )

    results = kas_ecc.run_vector_set(
        kas_ecc.load_vector_set(prompt), {(1, 1): {"testPassed": True}}, CryptographyKasEcc()
    )

    assert [r.status for r in results] == [ResultStatus.FAIL]
    assert "rejected a shared secret" in (results[0].diagnostic or "")


def test_expected_results_require_a_case_identifier(tmp_path: Path) -> None:
    """A results file without tcId cannot be matched to a case."""
    from acvp_assay.parser import AcvpValidationError

    path = tmp_path / "expected.json"
    path.write_text(
        json.dumps({"testGroups": [{"tgId": 1, "tests": [{"testPassed": True}]}]}),
        encoding="utf-8",
    )

    with pytest.raises(AcvpValidationError, match="tcId"):
        kas_ecc.load_expected_results(path)


def test_the_builtin_provider_reports_its_backend() -> None:
    """Reports name the library and OpenSSL build that produced them."""
    metadata = kas_ecc.metadata_for(kas_ecc.provider_for(None, 30.0))

    assert metadata.name == "cryptography-kas-ecc"
    assert metadata.backend_version.startswith("OpenSSL")
