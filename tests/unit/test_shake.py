"""SHAKE-128 and SHAKE-256, anchored on session 765794.

What separates an XOF from a hash is that the output length is an *input*, so
these tests are mostly about that: the same message squeezed to a different
length is a different answer, and a fixed-length interface cannot express it.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from acvp_assay.algorithms import shake
from acvp_assay.models import ResultStatus
from acvp_assay.providers.digest import XOF_ALGORITHMS, HashlibXofProvider

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = f"{sys.executable} {ROOT / 'examples/reference_harness.py'}"
LIVE = ROOT / ".acvts/session-765794"
needs_live = pytest.mark.skipif(
    not (LIVE / "4034179/prompt.json").is_file(), reason="fetch session 765794 to run this"
)


def test_both_xofs_are_offered() -> None:
    """FIPS 202 defines two, and both are registrable names."""
    assert set(XOF_ALGORITHMS) == {"SHAKE-128", "SHAKE-256"}
    assert set(shake.SUPPORTED) == {"SHAKE-128", "SHAKE-256"}


@pytest.mark.parametrize("algorithm", ["SHAKE-128", "SHAKE-256"])
def test_the_output_is_exactly_the_requested_length(algorithm: str) -> None:
    """Any length, not a fixed digest size. That is the whole point."""
    provider = HashlibXofProvider()
    for length in (2, 16, 32, 137, 512):
        assert (
            len(provider.squeeze(algorithm=algorithm, message=b"abc", output_bytes=length))
            == length
        )


def test_a_longer_squeeze_extends_a_shorter_one() -> None:
    """An XOF is one stream, so a short output prefixes a longer one.

    Anything that rehashed per length rather than squeezing would fail this.
    """
    provider = HashlibXofProvider()
    short = provider.squeeze(algorithm="SHAKE-128", message=b"abc", output_bytes=16)
    long = provider.squeeze(algorithm="SHAKE-128", message=b"abc", output_bytes=64)
    assert long.startswith(short)


def test_the_two_xofs_differ_on_the_same_input() -> None:
    """SHAKE-128 and SHAKE-256 have different capacities, so different output."""
    provider = HashlibXofProvider()
    one_two_eight = provider.squeeze(algorithm="SHAKE-128", message=b"abc", output_bytes=32)
    two_five_six = provider.squeeze(algorithm="SHAKE-256", message=b"abc", output_bytes=32)
    assert one_two_eight != two_five_six


def test_it_matches_the_reference_implementation() -> None:
    """FIPS 202's own answer for SHAKE-128 of 'abc'."""
    produced = HashlibXofProvider().squeeze(algorithm="SHAKE-128", message=b"abc", output_bytes=32)
    assert produced == hashlib.shake_128(b"abc").digest(32)


def test_an_unknown_xof_is_refused() -> None:
    """The provider will not guess at a function it does not implement."""
    with pytest.raises(ValueError, match="unsupported extendable-output function"):
        HashlibXofProvider().squeeze(algorithm="SHAKE-512", message=b"", output_bytes=8)


@needs_live
@pytest.mark.parametrize(
    ("vector_set", "count"), [("4034179", 270), ("4034180", 238)], ids=["shake-128", "shake-256"]
)
@pytest.mark.parametrize("harness", [False, True], ids=["builtin", "harness"])
def test_every_case_nist_generated_passes(vector_set: str, count: int, harness: bool) -> None:
    """All of them, through the built-in provider and through a harness."""
    folder = LIVE / vector_set
    results = shake.run_vector_set(
        shake.load_vector_set(folder / "prompt.json"),
        shake.load_expected_results(folder / "expectedResults.json"),
        shake.provider_for(REFERENCE if harness else None, 300.0),
    )

    assert len(results) == count
    assert all(r.status is ResultStatus.PASS for r in results)


def prompt_with(tmp_path: Path, group: dict[str, object], case: dict[str, object]) -> Path:
    """A one-case SHAKE prompt, for the decline paths."""
    document = {
        "vsId": 1,
        "algorithm": "SHAKE-128",
        "revision": shake.REVISION,
        "testGroups": [
            dict(
                {"tgId": 1, "testType": "AFT"},
                **group,
                tests=[dict({"tcId": 1, "msg": "616263", "len": 24, "outLen": 256}, **case)],
            )
        ],
    }
    path = tmp_path / "prompt.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_a_monte_carlo_group_is_declined_with_the_remedy(tmp_path: Path) -> None:
    """The SHAKE MCT chain is not implemented, and says so rather than guessing.

    Implementing a chain with no vectors to check it against would be a guess,
    and a wrong chain fails every case of a group that looks supported.
    """
    prompt = prompt_with(tmp_path, {"testType": "MCT"}, {})

    results = shake.run_vector_set(
        shake.load_vector_set(prompt), {(1, 1): b""}, HashlibXofProvider()
    )

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert "register only AFT" in (results[0].diagnostic or "")


def test_an_output_length_that_is_not_whole_bytes_is_declined(tmp_path: Path) -> None:
    """ACVP permits bit-granular outLen; this runner squeezes whole bytes."""
    prompt = prompt_with(tmp_path, {}, {"outLen": 12})

    results = shake.run_vector_set(
        shake.load_vector_set(prompt), {(1, 1): b""}, HashlibXofProvider()
    )

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert "whole number of bytes" in (results[0].diagnostic or "")


def test_a_case_with_no_recorded_answer_is_declined(tmp_path: Path) -> None:
    """Nothing to compare against is a coverage gap, not a pass."""
    results = shake.run_vector_set(
        shake.load_vector_set(prompt_with(tmp_path, {}, {})), {}, HashlibXofProvider()
    )

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert "no expected result" in (results[0].diagnostic or "")


def test_a_wrong_answer_fails(tmp_path: Path) -> None:
    """A mismatch is a failure, and names the field."""
    results = shake.run_vector_set(
        shake.load_vector_set(prompt_with(tmp_path, {}, {})),
        {(1, 1): b"\x00" * 32},
        HashlibXofProvider(),
    )

    assert [r.status for r in results] == [ResultStatus.FAIL]
    assert results[0].diagnostic == "md mismatch"


def test_a_bit_granular_message_length_is_rejected_at_parse(tmp_path: Path) -> None:
    """This set carries whole-byte messages; anything else is unparsed, not guessed."""
    from acvp_assay.parser import AcvpValidationError

    prompt = prompt_with(tmp_path, {}, {"len": 20})

    with pytest.raises(AcvpValidationError, match="whole bytes"):
        shake.load_vector_set(prompt)


def test_a_harness_declining_a_case_is_a_coverage_gap(tmp_path: Path) -> None:
    """An implementation without SHAKE says so; that is not a failure."""
    script = tmp_path / "declines.py"
    script.write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    json.loads(line)\n"
        "    print(json.dumps({'error': 'unsupported'}), flush=True)\n",
        encoding="utf-8",
    )

    results = shake.run_vector_set(
        shake.load_vector_set(prompt_with(tmp_path, {}, {})),
        {(1, 1): b"\x00" * 32},
        shake.provider_for(f"{sys.executable} {script}", 60.0),
    )

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert "harness declined" in (results[0].diagnostic or "")


def test_the_builtin_provider_reports_its_backend() -> None:
    """Reports name what produced them."""
    metadata = shake.metadata_for(shake.provider_for(None, 30.0))

    assert metadata.name == "hashlib-shake"


def test_a_set_naming_an_algorithm_that_is_not_an_xof_is_declined(tmp_path: Path) -> None:
    """The vector set names the algorithm, and it has to be one we squeeze."""
    document = {
        "vsId": 1,
        "algorithm": "SHA3-256",
        "revision": shake.REVISION,
        "testGroups": [
            {
                "tgId": 1,
                "testType": "AFT",
                "tests": [{"tcId": 1, "msg": "616263", "len": 24, "outLen": 256}],
            }
        ],
    }
    path = tmp_path / "prompt.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    results = shake.run_vector_set(shake.load_vector_set(path), {(1, 1): b""}, HashlibXofProvider())

    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED]
    assert "not an XOF" in (results[0].diagnostic or "")
