"""AES-CCM, anchored on the 4,830 cases NIST generated for session 765788.

The inversion is what these tests are for. Roughly a quarter of the decrypt
cases are deliberate forgeries where *rejecting* the tag is the correct answer,
so a run that reports them as failures tells a vendor their module is broken
when it is behaving exactly as it should -- and a run that stays quiet about an
accepted forgery hides the worst defect a module can have.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from acvp_assay.algorithms import aes_ccm
from acvp_assay.models import ResultStatus
from acvp_assay.providers.aes_ccm import CryptographyAesCcm

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = f"{sys.executable} {ROOT / 'examples/reference_harness.py'}"
LIVE = ROOT / ".acvts/session-765788/4034161"
needs_live = pytest.mark.skipif(
    not (LIVE / "prompt.json").is_file(), reason="fetch session 765788 to run this"
)

KEY = bytes(range(16))
NONCE = bytes(range(13))


def test_the_tag_is_appended_to_the_ciphertext() -> None:
    """CCM reports one value, not a ct/tag pair -- so an empty payload is still output."""
    produced = CryptographyAesCcm().encrypt(
        key=KEY, nonce=NONCE, plaintext=b"", aad=b"", tag_bits=128
    )
    assert len(produced) == 16


@pytest.mark.parametrize("tag_bits", [32, 64, 128])
def test_the_tag_length_belongs_to_the_cipher(tag_bits: int) -> None:
    """Tag length is chosen when the cipher is built, and the output grows with it."""
    produced = CryptographyAesCcm().encrypt(
        key=KEY, nonce=NONCE, plaintext=b"payload", aad=b"", tag_bits=tag_bits
    )
    assert len(produced) == len(b"payload") + tag_bits // 8


def test_a_forged_tag_raises_rather_than_returning_rubbish() -> None:
    """The provider must refuse, so the runner can turn refusal into a verdict."""
    provider = CryptographyAesCcm()
    good = provider.encrypt(key=KEY, nonce=NONCE, plaintext=b"payload", aad=b"", tag_bits=128)
    forged = good[:-1] + bytes([good[-1] ^ 0x01])

    with pytest.raises(InvalidTag):
        provider.decrypt(key=KEY, nonce=NONCE, ciphertext=forged, aad=b"", tag_bits=128)


def test_associated_data_is_authenticated() -> None:
    """Changing the AAD must invalidate the tag."""
    provider = CryptographyAesCcm()
    sealed = provider.encrypt(
        key=KEY, nonce=NONCE, plaintext=b"payload", aad=b"context", tag_bits=128
    )
    assert (
        provider.decrypt(key=KEY, nonce=NONCE, ciphertext=sealed, aad=b"context", tag_bits=128)
        == b"payload"
    )

    with pytest.raises(InvalidTag):
        provider.decrypt(key=KEY, nonce=NONCE, ciphertext=sealed, aad=b"other", tag_bits=128)


@needs_live
@pytest.mark.parametrize("harness", [False, True], ids=["builtin", "harness"])
def test_every_case_nist_generated_passes(harness: bool) -> None:
    """All 4,830, both through the built-in provider and through a harness."""
    vector_set = aes_ccm.load_vector_set(LIVE / "prompt.json")
    expected = aes_ccm.load_expected_results(LIVE / "expectedResults.json")
    provider = aes_ccm.provider_for(REFERENCE if harness else None, 600.0)

    results = aes_ccm.run_vector_set(vector_set, expected, provider)

    assert len(results) == 4830
    assert all(r.status is ResultStatus.PASS for r in results)


@needs_live
def test_the_deliberate_forgeries_are_passes_not_failures() -> None:
    """The inversion, asserted against real vectors.

    If these were scored as failures the summary would report hundreds of
    spurious defects against a conforming implementation.
    """
    vector_set = aes_ccm.load_vector_set(LIVE / "prompt.json")
    expected = aes_ccm.load_expected_results(LIVE / "expectedResults.json")

    forgeries = [key for key, want in expected.items() if want.test_passed is False]
    assert len(forgeries) > 100, "this set should carry deliberate failures"

    results = {
        (r.tg_id, r.tc_id): r
        for r in aes_ccm.run_vector_set(vector_set, expected, CryptographyAesCcm())
    }
    assert all(results[key].status is ResultStatus.PASS for key in forgeries)


def prompt_with(tmp_path: Path, group: dict[str, object], case: dict[str, object]) -> Path:
    """A one-case AES-CCM prompt, for the decline and failure paths."""
    document = {
        "vsId": 1,
        "algorithm": aes_ccm.ALGORITHM,
        "revision": aes_ccm.REVISION,
        "testGroups": [
            dict(
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "direction": "encrypt",
                    "keyLen": 128,
                    "ivLen": 104,
                    "tagLen": 128,
                    "aadLen": 0,
                    "payloadLen": 0,
                },
                **group,
                tests=[dict({"tcId": 1, "key": KEY.hex(), "iv": NONCE.hex()}, **case)],
            )
        ],
    }
    path = tmp_path / "prompt.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_a_tag_length_ccm_does_not_define_is_declined(tmp_path: Path) -> None:
    """CCM admits 32 to 128 in steps of 16, and nothing else."""
    prompt = prompt_with(tmp_path, {"tagLen": 24}, {"pt": ""})

    results = aes_ccm.run_vector_set(aes_ccm.load_vector_set(prompt), {}, CryptographyAesCcm())

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert "tagLen 24" in (results[0].diagnostic or "")


def test_accepting_a_forgery_is_a_loud_failure(tmp_path: Path) -> None:
    """The other half of the inversion, and the worse half.

    A module that accepts a tag ACVP declares invalid must never be reported
    as passing.
    """
    sealed = CryptographyAesCcm().encrypt(
        key=KEY, nonce=NONCE, plaintext=b"", aad=b"", tag_bits=128
    )
    prompt = prompt_with(tmp_path, {"direction": "decrypt"}, {"ct": sealed.hex(), "aad": ""})

    results = aes_ccm.run_vector_set(
        aes_ccm.load_vector_set(prompt),
        {(1, 1): aes_ccm.CcmExpectation(payload=None, test_passed=False)},
        CryptographyAesCcm(),
    )

    assert [r.status for r in results] == [ResultStatus.FAIL]
    assert results[0].diagnostic == "accepted a tag ACVP declares invalid"


def test_rejecting_a_valid_tag_is_a_failure(tmp_path: Path) -> None:
    """And the inverse: refusing something ACVP says should decrypt."""
    prompt = prompt_with(tmp_path, {"direction": "decrypt"}, {"ct": "00" * 16, "aad": ""})

    results = aes_ccm.run_vector_set(
        aes_ccm.load_vector_set(prompt),
        {(1, 1): aes_ccm.CcmExpectation(payload=b"", test_passed=True)},
        CryptographyAesCcm(),
    )

    assert [r.status for r in results] == [ResultStatus.FAIL]
    assert results[0].diagnostic == "rejected a tag ACVP declares valid"


def test_a_case_with_no_recorded_answer_is_declined(tmp_path: Path) -> None:
    """Nothing to compare against is a coverage gap, not a pass."""
    prompt = prompt_with(tmp_path, {}, {"pt": ""})

    results = aes_ccm.run_vector_set(aes_ccm.load_vector_set(prompt), {}, CryptographyAesCcm())

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert "no expected result" in (results[0].diagnostic or "")


def test_expected_results_must_carry_an_answer(tmp_path: Path) -> None:
    """Neither bytes nor a verdict means the file is unusable."""
    from acvp_assay.parser import AcvpValidationError

    path = tmp_path / "expected.json"
    path.write_text(
        json.dumps({"testGroups": [{"tgId": 1, "tests": [{"tcId": 1}]}]}), encoding="utf-8"
    )

    with pytest.raises(AcvpValidationError, match="ct, pt or testPassed"):
        aes_ccm.load_expected_results(path)


def test_a_harness_declining_a_case_is_a_coverage_gap(tmp_path: Path) -> None:
    """An implementation without CCM says so; that is not a failure."""
    script = tmp_path / "declines.py"
    script.write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    json.loads(line)\n"
        "    print(json.dumps({'error': 'unsupported'}), flush=True)\n",
        encoding="utf-8",
    )
    prompt = prompt_with(tmp_path, {}, {"pt": ""})

    results = aes_ccm.run_vector_set(
        aes_ccm.load_vector_set(prompt),
        {(1, 1): aes_ccm.CcmExpectation(payload=b"\x00" * 16, test_passed=None)},
        aes_ccm.provider_for(f"{sys.executable} {script}", 60.0),
    )

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert "harness declined" in (results[0].diagnostic or "")


def test_the_builtin_provider_reports_its_backend() -> None:
    """Reports name the library and OpenSSL build that produced them."""
    metadata = aes_ccm.metadata_for(aes_ccm.provider_for(None, 30.0))

    assert metadata.name == "cryptography-aes-ccm"
    assert metadata.backend_version.startswith("OpenSSL")


def test_a_decrypt_case_with_no_recorded_plaintext_is_declined(tmp_path: Path) -> None:
    """A verdict of true but no plaintext leaves nothing to compare against."""
    sealed = CryptographyAesCcm().encrypt(
        key=KEY, nonce=NONCE, plaintext=b"", aad=b"", tag_bits=128
    )
    prompt = prompt_with(tmp_path, {"direction": "decrypt"}, {"ct": sealed.hex(), "aad": ""})

    results = aes_ccm.run_vector_set(
        aes_ccm.load_vector_set(prompt),
        {(1, 1): aes_ccm.CcmExpectation(payload=None, test_passed=True)},
        CryptographyAesCcm(),
    )

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert "no expected plaintext" in (results[0].diagnostic or "")


def test_an_encrypt_case_with_only_a_verdict_is_declined(tmp_path: Path) -> None:
    """Encryption produces bytes; a bare verdict cannot be compared with them."""
    prompt = prompt_with(tmp_path, {}, {"pt": ""})

    results = aes_ccm.run_vector_set(
        aes_ccm.load_vector_set(prompt),
        {(1, 1): aes_ccm.CcmExpectation(payload=None, test_passed=True)},
        CryptographyAesCcm(),
    )

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert "no expected ciphertext" in (results[0].diagnostic or "")
