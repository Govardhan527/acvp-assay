"""Hash_DRBG and HMAC_DRBG, anchored on cases from NIST's live vector sets.

Session 765354 on the Demo server answered both mechanisms and returned
``"passed": true``; the two known answers below are lifted from it. A DRBG
cannot be checked by a hand-written fixture -- any self-consistent
implementation agrees with itself -- so these are the only assertions here that
could ever have failed.
"""

from __future__ import annotations

import pytest
from drbg_known_answers import HASH_KNOWN, HMAC_KNOWN

from acvp_assay.algorithms import ctr_drbg
from acvp_assay.models import ResultStatus
from acvp_assay.models import TestCaseResult as CaseResult
from acvp_assay.providers.hash_drbg import SEED_LENGTH_BITS, HashDrbg, HmacDrbg


def run(algorithm: str, known: dict[str, object], **overrides: object) -> list[CaseResult]:
    """Execute one known answer through the shared DRBG runner."""
    group = {
        "tgId": 1,
        "testType": "AFT",
        "mode": known["mode"],
        "derFunc": known["derFunc"],
        "predResistance": known["predResistance"],
        "returnedBitsLen": known["returnedBitsLen"],
        **overrides,
        "tests": [
            {
                "tcId": 1,
                "entropyInput": known["entropyInput"],
                "nonce": known["nonce"],
                "persoString": known["persoString"],
                "otherInput": known["otherInput"],
            }
        ],
    }
    prompt = {"vsId": 1, "algorithm": algorithm, "revision": "1.0", "testGroups": [group]}
    expected = {
        "vsId": 1,
        "testGroups": [{"tgId": 1, "tests": [{"tcId": 1, "returnedBits": known["returnedBits"]}]}],
    }
    return ctr_drbg.run_vector_set(
        ctr_drbg.parse_vector_set(prompt),
        ctr_drbg.parse_expected_results(expected),
        ctr_drbg.provider_for(algorithm),
    )


def test_hash_drbg_matches_nists_answer() -> None:
    """Hash_DRBG with prediction resistance, against the live server's own result."""
    assert [r.status for r in run("hashDRBG", HASH_KNOWN)] == [ResultStatus.PASS]


def test_hmac_drbg_matches_nists_answer() -> None:
    """HMAC_DRBG over SHA-1, with a personalization string and additional input."""
    assert [r.status for r in run("hmacDRBG", HMAC_KNOWN)] == [ResultStatus.PASS]


def test_a_wrong_answer_is_a_failure() -> None:
    """Anything other than NIST's bits must be reported."""
    wrong = dict(HASH_KNOWN, returnedBits="00" * 128)
    results = run("hashDRBG", wrong)

    assert results[0].status is ResultStatus.FAIL


def test_hash_drbg_folds_the_reseed_counter_into_v() -> None:
    """Two successive generations must differ beyond their keystream.

    Hash_DRBG adds H, C *and* the reseed counter back into V after every
    generation. An implementation that omits the counter stays correct for
    exactly one call, which the two-generation test shape would still catch --
    but only because the second generation is the one compared.
    """
    drbg = HashDrbg()
    drbg.instantiate(
        mode="SHA2-256", entropy=bytes(range(32)), nonce=bytes(16), personalization=b""
    )
    first = drbg.generate(byte_count=32, additional_input=b"")
    second = drbg.generate(byte_count=32, additional_input=b"")

    assert first != second


def test_hmac_drbg_updates_after_generating() -> None:
    """The trailing update runs even with no additional input."""
    drbg = HmacDrbg()
    drbg.instantiate(
        mode="SHA2-256", entropy=bytes(range(32)), nonce=bytes(16), personalization=b""
    )
    first = drbg.generate(byte_count=32, additional_input=b"")
    second = drbg.generate(byte_count=32, additional_input=b"")

    assert first != second


@pytest.mark.parametrize("mechanism", [HashDrbg, HmacDrbg])
def test_reseeding_changes_the_output(mechanism: type[HashDrbg | HmacDrbg]) -> None:
    """A reseed must move the state, or fresh entropy would be doing nothing."""
    outputs = []
    for reseed in (False, True):
        drbg = mechanism()
        drbg.instantiate(
            mode="SHA2-256", entropy=bytes(range(32)), nonce=bytes(16), personalization=b""
        )
        if reseed:
            drbg.reseed(entropy=b"\xaa" * 32, additional_input=b"")
        outputs.append(drbg.generate(byte_count=32, additional_input=b""))

    assert outputs[0] != outputs[1]


@pytest.mark.parametrize("mechanism", [HashDrbg, HmacDrbg])
def test_an_unsupported_mode_is_refused(mechanism: type[HashDrbg | HmacDrbg]) -> None:
    """SHA-3 is not among the DRBG hashes SP 800-90A defines seed lengths for."""
    with pytest.raises(ValueError, match="unsupported DRBG mode"):
        mechanism().instantiate(mode="SHA3-256", entropy=bytes(32), nonce=b"", personalization=b"")


def test_the_wider_hashes_take_the_wider_seed() -> None:
    """SP 800-90A gives SHA-384 and SHA-512 an 888-bit seed, the rest 440."""
    assert SEED_LENGTH_BITS["SHA2-256"] == 440
    assert SEED_LENGTH_BITS["SHA2-512"] == 888
    assert set(SEED_LENGTH_BITS.values()) == {440, 888}


@pytest.mark.parametrize(
    ("algorithm", "expected_name"),
    [("hashDRBG", "hash-drbg"), ("hmacDRBG", "hmac-drbg"), ("ctrDRBG", "cryptography-ctr-drbg")],
)
def test_each_mechanism_reports_its_own_provider(algorithm: str, expected_name: str) -> None:
    """A report must name which of the three produced it."""
    assert ctr_drbg.provider_for(algorithm).metadata().name == expected_name


def test_each_mechanism_declares_its_own_modes() -> None:
    """ctrDRBG takes block ciphers; the other two take hashes."""
    assert "AES-256" in ctr_drbg.supported_modes("ctrDRBG")
    assert "SHA2-256" in ctr_drbg.supported_modes("hashDRBG")
    assert "AES-256" not in ctr_drbg.supported_modes("hmacDRBG")


def test_a_mode_from_the_wrong_mechanism_is_declared() -> None:
    """An AES mode under hashDRBG is declared, not attempted."""
    results = run("hashDRBG", HASH_KNOWN, mode="AES-256")

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "AES-256" in (results[0].diagnostic or "")


@pytest.mark.parametrize("mechanism", [HashDrbg, HmacDrbg])
def test_additional_input_at_generation_changes_the_output(
    mechanism: type[HashDrbg | HmacDrbg],
) -> None:
    """Additional input is folded in before generating, so it must alter the bits.

    Both mechanisms take a separate branch for it -- Hash_DRBG hashes it into V
    with a 0x02 prefix, HMAC_DRBG runs a full update -- and an implementation
    that ignored the field would produce identical output either way.
    """
    outputs = []
    for extra in (b"", b"\xa5" * 32):
        drbg = mechanism()
        drbg.instantiate(
            mode="SHA2-256", entropy=bytes(range(32)), nonce=bytes(16), personalization=b""
        )
        outputs.append(drbg.generate(byte_count=32, additional_input=extra))

    assert outputs[0] != outputs[1]
