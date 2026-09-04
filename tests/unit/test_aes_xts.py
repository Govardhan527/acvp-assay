"""AES-XTS, anchored on the 480 cases NIST generated for session 765786.

Three things about XTS are easy to get wrong and each fails quietly, so each
has a test that would catch it: the key is two AES keys concatenated, a
sequence-number tweak is little-endian, and a payload longer than the data unit
is several units with the tweak advanced once per unit.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from acvp_assay.algorithms import aes_xts
from acvp_assay.models import ResultStatus
from acvp_assay.providers.aes_xts import CryptographyAesXts, advance, tweak_for

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = f"{sys.executable} {ROOT / 'examples/reference_harness.py'}"
LIVE = ROOT / ".acvts/session-765786/4034143"
needs_live = pytest.mark.skipif(
    not (LIVE / "prompt.json").is_file(), reason="fetch session 765786 to run this"
)


def test_a_sequence_number_tweak_is_little_endian() -> None:
    """Big-endian reproduces half of NIST's cases, which is the trap."""
    assert tweak_for(1) == b"\x01" + bytes(15)
    assert tweak_for(131) == b"\x83" + bytes(15)


def test_the_tweak_advances_once_per_data_unit() -> None:
    """A payload longer than its data unit is several units, not one."""
    assert advance(tweak_for(7), 0) == tweak_for(7)
    assert advance(tweak_for(7), 3) == tweak_for(10)


def test_the_tweak_wraps_rather_than_overflowing() -> None:
    """128 bits is the whole space; one past the top is zero."""
    assert advance((2**128 - 1).to_bytes(16, "little"), 1) == bytes(16)


@pytest.mark.parametrize(("key_bits", "key_bytes"), [(128, 32), (256, 64)])
def test_an_xts_key_is_two_aes_keys(key_bits: int, key_bytes: int) -> None:
    """keyLen 128 means a 32-byte key, which trips length validation."""
    assert aes_xts.KEY_LENGTHS[key_bits] == key_bytes
    produced = CryptographyAesXts().transform(
        key=bytes(range(key_bytes)),
        tweak=tweak_for(1),
        data=bytes(32),
        data_unit_bytes=32,
        encrypt=True,
    )
    assert len(produced) == 32


def test_a_multi_unit_payload_differs_from_one_long_unit() -> None:
    """The distinction the tweak advance exists for.

    Encrypting 64 bytes as two 32-byte units must not equal encrypting it as a
    single 64-byte unit -- if it did, the per-unit tweak would be doing nothing.
    """
    provider = CryptographyAesXts()
    key, tweak, data = bytes(range(32)), tweak_for(1), bytes(64)
    split = provider.transform(key=key, tweak=tweak, data=data, data_unit_bytes=32, encrypt=True)
    whole = provider.transform(key=key, tweak=tweak, data=data, data_unit_bytes=64, encrypt=True)
    assert split != whole


def test_a_short_payload_is_one_unit() -> None:
    """A payload smaller than the data unit is a single short unit."""
    provider = CryptographyAesXts()
    produced = provider.transform(
        key=bytes(range(32)),
        tweak=tweak_for(1),
        data=bytes(16),
        data_unit_bytes=64,
        encrypt=True,
    )
    assert len(produced) == 16


def test_decrypt_reverses_encrypt_across_several_units() -> None:
    """Round trip, which the live vectors also prove but this pins locally."""
    provider = CryptographyAesXts()
    plaintext = bytes(range(96))
    key, tweak = bytes(range(64)), tweak_for(9)
    ciphertext = provider.transform(
        key=key, tweak=tweak, data=plaintext, data_unit_bytes=32, encrypt=True
    )
    recovered = provider.transform(
        key=key, tweak=tweak, data=ciphertext, data_unit_bytes=32, encrypt=False
    )
    assert recovered == plaintext


@needs_live
@pytest.mark.parametrize("command", [None, "reference"])
def test_every_case_nist_generated_passes(command: str | None) -> None:
    """All 480, through the built-in provider and through a harness."""
    vector_set = aes_xts.load_vector_set(LIVE / "prompt.json")
    expected = aes_xts.load_expected_results(LIVE / "expectedResults.json")
    provider = aes_xts.provider_for(None if command is None else REFERENCE, 300.0)

    results = aes_xts.run_vector_set(vector_set, expected, provider)

    assert len(results) == 480
    assert all(r.status is ResultStatus.PASS for r in results)


def prompt_with(tmp_path: Path, group: dict[str, object], case: dict[str, object]) -> Path:
    """A one-case AES-XTS prompt, for the decline paths."""
    document = {
        "vsId": 1,
        "algorithm": aes_xts.ALGORITHM,
        "revision": aes_xts.REVISION,
        "testGroups": [
            dict(
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "direction": "encrypt",
                    "keyLen": 128,
                    "tweakMode": "hex",
                },
                **group,
                tests=[dict({"tcId": 1, "dataUnitLen": 128}, **case)],
            )
        ],
    }
    path = tmp_path / "prompt.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("group", "case", "expected", "reason"),
    [
        (
            {"keyLen": 192},
            {"key": "00" * 48, "pt": "00" * 16, "tweakValue": "00" * 16},
            {(1, 1): b"\x00" * 16},
            "keyLen 192",
        ),
        (
            {},
            {"key": "00" * 16, "pt": "00" * 16, "tweakValue": "00" * 16},
            {(1, 1): b"\x00" * 16},
            "two AES keys concatenated",
        ),
        (
            {"tweakMode": "sequence"},
            {"key": "00" * 32, "pt": "00" * 16},
            {(1, 1): b"\x00" * 16},
            "tweakMode 'sequence'",
        ),
        (
            {},
            {"key": "00" * 32, "pt": "00" * 16, "tweakValue": "00" * 16},
            {},
            "no expected result recorded",
        ),
    ],
    ids=["bad-keylen", "half-length-key", "unknown-tweak-mode", "no-expected"],
)
def test_a_case_that_cannot_be_judged_is_declined(
    tmp_path: Path,
    group: dict[str, object],
    case: dict[str, object],
    expected: dict[tuple[int, int], bytes],
    reason: str,
) -> None:
    """Each decline names what is wrong, since the fix is usually registration."""
    results = aes_xts.run_vector_set(
        aes_xts.load_vector_set(prompt_with(tmp_path, group, case)),
        expected,
        CryptographyAesXts(),
    )

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert reason in (results[0].diagnostic or "")


def test_a_wrong_answer_fails_and_names_the_field(tmp_path: Path) -> None:
    """A mismatch is a failure, not an error."""
    prompt = prompt_with(
        tmp_path, {}, {"key": "00" * 16 + "11" * 16, "pt": "00" * 16, "tweakValue": "00" * 16}
    )

    results = aes_xts.run_vector_set(
        aes_xts.load_vector_set(prompt), {(1, 1): b"\xff" * 16}, CryptographyAesXts()
    )

    assert [r.status for r in results] == [ResultStatus.FAIL]
    assert results[0].diagnostic == "ct mismatch"


def test_expected_results_must_carry_an_output(tmp_path: Path) -> None:
    """A results file with neither ct nor pt cannot be compared against."""
    from acvp_assay.parser import AcvpValidationError

    path = tmp_path / "expected.json"
    path.write_text(
        json.dumps({"testGroups": [{"tgId": 1, "tests": [{"tcId": 1}]}]}), encoding="utf-8"
    )

    with pytest.raises(AcvpValidationError, match="ct or pt"):
        aes_xts.load_expected_results(path)


def test_the_builtin_provider_reports_its_backend() -> None:
    """Reports name the library and OpenSSL build that produced them."""
    metadata = aes_xts.metadata_for(aes_xts.provider_for(None, 30.0))

    assert metadata.name == "cryptography-aes-xts"
    assert metadata.backend_version.startswith("OpenSSL")


def test_duplicated_key_halves_are_an_error_not_a_crash(tmp_path: Path) -> None:
    """XTS forbids the two halves being equal, and the provider says so.

    The run must survive it with a bounded diagnostic that carries none of the
    library's own message, which can quote key material.
    """
    prompt = prompt_with(tmp_path, {}, {"key": "00" * 32, "pt": "00" * 16, "tweakValue": "00" * 16})

    results = aes_xts.run_vector_set(
        aes_xts.load_vector_set(prompt), {(1, 1): b"\x00" * 16}, CryptographyAesXts()
    )

    assert [r.status for r in results] == [ResultStatus.ERROR]
    assert results[0].diagnostic == "provider error"


def test_a_harness_declining_a_case_is_a_coverage_gap(tmp_path: Path) -> None:
    """An implementation that lacks XTS says so; that is not a failure."""
    script = tmp_path / "declines.py"
    script.write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    json.loads(line)\n"
        "    print(json.dumps({'error': 'unsupported'}), flush=True)\n",
        encoding="utf-8",
    )
    prompt = prompt_with(
        tmp_path, {}, {"key": "00" * 16 + "11" * 16, "pt": "00" * 16, "tweakValue": "00" * 16}
    )

    results = aes_xts.run_vector_set(
        aes_xts.load_vector_set(prompt),
        {(1, 1): b"\x00" * 16},
        aes_xts.provider_for(f"{sys.executable} {script}", 60.0),
    )

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert "harness declined" in (results[0].diagnostic or "")
