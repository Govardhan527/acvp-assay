"""Answering a live session from a vendor's implementation rather than our own.

The offline runner and the responder differ in what a declined case means. The
runner reports UNSUPPORTED and carries on, because a coverage gap is a fact
worth recording. The responder cannot: ACVP scores a missing case as a wrong
answer, so a document that is short a case records a failure the implementation
never earned. These tests pin that asymmetry, and pin that capability decisions
belong to the implementation once one is supplied.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import cast

import pytest
from drbg_known_answers import HASH_KNOWN, HMAC_KNOWN

from acvp_assay.responder import (
    Harness,
    ResponseError,
    build_response,
    supported_response_algorithms,
)

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = f"{sys.executable} {ROOT / 'examples/reference_harness.py'}"


def write_prompt(tmp_path: Path, document: dict[str, object]) -> Path:
    """Write a prompt document and return its path."""
    path = tmp_path / "prompt.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def declining_harness(tmp_path: Path) -> Harness:
    """A harness that answers every request with ``unsupported``.

    This is what a real implementation sends for a parameter set it does not
    offer -- distinct from a harness that crashes, which is a protocol error.
    """
    script = tmp_path / "declines.py"
    script.write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    json.loads(line)\n"
        "    print(json.dumps({'error': 'unsupported'}), flush=True)\n",
        encoding="utf-8",
    )
    return Harness(f"{sys.executable} {script}")


def sha2_prompt(tmp_path: Path) -> Path:
    """A one-case SHA2-256 AFT prompt."""
    return write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "SHA2-256",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "tests": [{"tcId": 1, "msg": b"ACVP".hex(), "len": 32}],
                }
            ],
        },
    )


def test_the_harness_answers_exactly_as_the_builtin_does(tmp_path: Path) -> None:
    """Same document either way: the server is told what was computed, not how."""
    prompt = sha2_prompt(tmp_path)

    builtin = build_response(prompt)
    through_harness = build_response(prompt, harness=Harness(REFERENCE))

    assert through_harness == builtin


def test_a_declined_case_refuses_the_whole_document(tmp_path: Path) -> None:
    """One case the harness will not answer stops the submission."""
    with pytest.raises(ResponseError, match="scored as wrong answers"):
        build_response(sha2_prompt(tmp_path), harness=declining_harness(tmp_path))


def test_the_refusal_names_the_operation_the_harness_declined(tmp_path: Path) -> None:
    """A vendor needs to know which operation to implement or de-register."""
    with pytest.raises(ResponseError, match="'digest'"):
        build_response(sha2_prompt(tmp_path), harness=declining_harness(tmp_path))


def test_capability_belongs_to_the_implementation(tmp_path: Path) -> None:
    """A mode the built-in lacks is offered to the harness rather than refused.

    Two-key TDES is the case that matters: the built-in provider does not
    implement it, but a vendor's product may, and refusing on our own behalf
    would make their submission impossible.
    """
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ctrDRBG",
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "derFunc": True,
                    "predResistance": False,
                    "mode": "TDES",
                    "returnedBitsLen": 64,
                    "counterFieldLen": 64,
                    "tests": [
                        {
                            "tcId": 1,
                            "entropyInput": "00" * 32,
                            "nonce": "11" * 32,
                            "persoString": "",
                            "otherInput": [
                                {
                                    "intendedUse": "generate",
                                    "additionalInput": "",
                                    "entropyInput": "",
                                },
                                {
                                    "intendedUse": "generate",
                                    "additionalInput": "",
                                    "entropyInput": "",
                                },
                            ],
                        }
                    ],
                }
            ],
        },
    )

    with pytest.raises(ResponseError, match="built-in provider does not implement"):
        build_response(prompt)

    # With a harness the refusal comes from the implementation instead, which
    # is the whole point -- here the reference harness declines TDES itself.
    with pytest.raises(ResponseError, match="the harness declined"):
        build_response(prompt, harness=Harness(REFERENCE))


def test_the_harness_subprocesses_are_closed_when_the_document_is_built(
    tmp_path: Path,
) -> None:
    """A live session answers many vector sets; leaked processes would accumulate."""
    harness = Harness(REFERENCE)
    build_response(sha2_prompt(tmp_path), harness=harness)

    assert harness._clients == []


def test_the_harness_is_closed_even_when_a_case_is_declined(tmp_path: Path) -> None:
    """Refusing the document must not leak the process that refused it."""
    harness = declining_harness(tmp_path)
    with pytest.raises(ResponseError):
        build_response(sha2_prompt(tmp_path), harness=harness)

    assert harness._clients == []


def test_ecdsa_siggen_signs_a_group_under_one_key(tmp_path: Path) -> None:
    """ACVP reports qx/qy once per group, so every case shares the key.

    Per-case signing would generate a fresh key each time and could not be
    reported in the shape ACVP asks for, so the harness signs the whole group
    in one exchange.
    """
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ECDSA",
            "mode": "sigGen",
            "revision": "FIPS186-5",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "curve": "P-256",
                    "hashAlg": "SHA2-256",
                    "tests": [
                        {"tcId": 1, "message": "00" * 32},
                        {"tcId": 2, "message": "11" * 32},
                    ],
                }
            ],
        },
    )

    group = build_response(prompt, harness=Harness(REFERENCE))["testGroups"][0]  # type: ignore[index]

    assert set(group) == {"tgId", "qx", "qy", "tests"}
    assert len(group["tests"]) == 2
    assert {case["tcId"] for case in group["tests"]} == {1, 2}
    assert all(set(case) == {"tcId", "r", "s"} for case in group["tests"])


@pytest.mark.parametrize(
    ("algorithm", "known"),
    [("hashDRBG", HASH_KNOWN), ("hmacDRBG", HMAC_KNOWN)],
)
def test_the_other_drbg_mechanisms_answer_with_nists_own_bits(
    tmp_path: Path, algorithm: str, known: dict[str, object]
) -> None:
    """Hash_DRBG and HMAC_DRBG reach the responder, not just ctrDRBG.

    The expected bits are NIST's, from the session that answered both
    mechanisms: a DRBG cannot be checked against a hand-written fixture,
    because any self-consistent implementation agrees with itself.
    """
    case = dict(known)
    expected = case.pop("returnedBits")
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": algorithm,
            "revision": "1.0",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "mode": case.pop("mode"),
                    "derFunc": case.pop("derFunc"),
                    "predResistance": case.pop("predResistance"),
                    "returnedBitsLen": case.pop("returnedBitsLen"),
                    "counterFieldLen": 0,
                    "tests": [{"tcId": 1, **case}],
                }
            ],
        },
    )

    answer = build_response(prompt)["testGroups"][0]["tests"][0]  # type: ignore[index]

    assert answer == {"tcId": 1, "returnedBits": expected}


PQC_HARNESS = f"{sys.executable} {ROOT / 'examples/pqc_reference_harness.py'}"


def test_pqc_refuses_without_a_harness(tmp_path: Path) -> None:
    """There is no built-in ML-KEM, so a submission cannot be invented.

    Every other family can answer from the built-in providers. PQC cannot, and
    saying so plainly is better than emitting a document nobody computed --
    ACVP would score the missing cases as wrong answers.
    """
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ML-KEM",
            "mode": "encapDecap",
            "revision": "FIPS203",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "parameterSet": "ML-KEM-768",
                    "function": "encapsulation",
                    "tests": [{"tcId": 1, "ek": "00", "m": "11"}],
                }
            ],
        },
    )

    with pytest.raises(ResponseError, match="no built-in provider"):
        build_response(prompt)


def test_ml_dsa_answers_with_a_verdict_per_case(tmp_path: Path) -> None:
    """sigVer is verdict-only: ACVP supplies signatures that may be invalid."""
    source = json.loads(
        (ROOT / "vectors/ML-DSA-sigVer-FIPS204/prompt.json").read_text(encoding="utf-8")
    )
    groups = [
        group
        for group in source["testGroups"]
        if group.get("preHash", "pure") == "pure" and not group.get("externalMu")
    ][:1]
    prompt = write_prompt(tmp_path, dict(source, testGroups=groups))

    answered = build_response(prompt, harness=Harness(PQC_HARNESS, timeout_seconds=300.0))

    cases = answered["testGroups"][0]["tests"]  # type: ignore[index]
    assert cases
    assert all(set(case) == {"tcId", "testPassed"} for case in cases)
    assert all(isinstance(case["testPassed"], bool) for case in cases)


def test_ml_dsa_refuses_a_prehash_group(tmp_path: Path) -> None:
    """A capability the runner cannot answer stops the document, not the case.

    preHash groups are refused rather than answered wrongly; the fix is to
    register only 'pure', which the message says.
    """
    source = json.loads(
        (ROOT / "vectors/ML-DSA-sigVer-FIPS204/prompt.json").read_text(encoding="utf-8")
    )
    groups = [group for group in source["testGroups"] if group.get("preHash") == "preHash"][:1]
    prompt = write_prompt(tmp_path, dict(source, testGroups=groups))

    with pytest.raises(ResponseError, match="preHash"):
        build_response(prompt, harness=Harness(PQC_HARNESS, timeout_seconds=300.0))


def test_every_runnable_algorithm_can_now_be_submitted() -> None:
    """The two lists finally agree, which is the point of the PQC builders."""
    from acvp_assay.algorithms import supported_algorithms

    assert set(supported_algorithms()) == set(supported_response_algorithms())


def cases_of(response: dict[str, object]) -> list[dict[str, object]]:
    """Every case across every group of a response document."""
    groups = cast("list[dict[str, object]]", response["testGroups"])
    return [case for group in groups for case in cast("list[dict[str, object]]", group["tests"])]


def ml_kem_prompt(tmp_path: Path, *functions: str) -> Path:
    """The pinned ML-KEM set, narrowed to the named functions."""
    source = json.loads(
        (ROOT / "vectors/ML-KEM-encapDecap-FIPS203/prompt.json").read_text(encoding="utf-8")
    )
    groups = [group for group in source["testGroups"] if group["function"] in functions]
    assert groups, functions  # noqa: S101 - the pinned set is expected to carry these
    return write_prompt(tmp_path, dict(source, testGroups=groups[:2]))


def test_ml_kem_encapsulation_answers_with_ciphertext_and_shared_secret(
    tmp_path: Path,
) -> None:
    """Encapsulation produces both values ACVP scores."""
    prompt = ml_kem_prompt(tmp_path, "encapsulation")

    answered = build_response(prompt, harness=Harness(PQC_HARNESS, timeout_seconds=300.0))

    cases = cases_of(answered)
    assert cases
    assert all(set(case) == {"tcId", "c", "k"} for case in cases)


def test_ml_kem_decapsulation_answers_with_the_shared_secret(tmp_path: Path) -> None:
    """Decapsulation reports only k -- the ciphertext was supplied."""
    prompt = ml_kem_prompt(tmp_path, "decapsulation")

    answered = build_response(prompt, harness=Harness(PQC_HARNESS, timeout_seconds=300.0))

    cases = cases_of(answered)
    assert cases
    assert all(set(case) == {"tcId", "k"} for case in cases)


def test_ml_kem_key_checks_answer_with_a_verdict(tmp_path: Path) -> None:
    """ACVP supplies deliberately malformed keys; rejecting one is the answer."""
    prompt = ml_kem_prompt(tmp_path, "encapsulationKeyCheck", "decapsulationKeyCheck")

    answered = build_response(prompt, harness=Harness(PQC_HARNESS, timeout_seconds=300.0))

    cases = cases_of(answered)
    assert cases
    assert all(set(case) == {"tcId", "testPassed"} for case in cases)
    assert not all(case["testPassed"] for case in cases), "a key check set with no rejection"


def test_ml_kem_refuses_an_unknown_parameter_set(tmp_path: Path) -> None:
    """A parameter set outside FIPS 203 is refused rather than guessed at."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "ML-KEM",
            "mode": "encapDecap",
            "revision": "FIPS203",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "parameterSet": "ML-KEM-1536",
                    "function": "encapsulation",
                    "tests": [{"tcId": 1, "ek": "00", "m": "11"}],
                }
            ],
        },
    )

    with pytest.raises(ResponseError, match="ML-KEM-1536"):
        build_response(prompt, harness=Harness(PQC_HARNESS, timeout_seconds=60.0))


def pqc_prompt(tmp_path: Path, algorithm: str, mode: str, group: dict[str, object]) -> Path:
    """A one-group PQC prompt, for exercising the refusal paths."""
    revision = "FIPS203" if algorithm == "ML-KEM" else "FIPS204"
    return write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": algorithm,
            "mode": mode,
            "revision": revision,
            "testGroups": [dict({"tgId": 1, "testType": "AFT"}, **group)],
        },
    )


@pytest.mark.parametrize(
    ("group", "expected"),
    [
        (
            {
                "parameterSet": "ML-KEM-768",
                "function": "encapsulation",
                "tests": [{"tcId": 1, "ek": "00"}],
            },
            "missing ek or m",
        ),
        (
            {
                "parameterSet": "ML-KEM-768",
                "function": "decapsulation",
                "tests": [{"tcId": 1, "dk": "00"}],
            },
            "missing dk or c",
        ),
        (
            {
                "parameterSet": "ML-KEM-768",
                "function": "encapsulationKeyCheck",
                "tests": [{"tcId": 1}],
            },
            "missing ek",
        ),
        (
            {
                "parameterSet": "ML-KEM-768",
                "function": "keyGen",
                "tests": [{"tcId": 1, "ek": "00"}],
            },
            "does not answer",
        ),
    ],
    ids=["encap-missing", "decap-missing", "keycheck-missing", "unknown-function"],
)
def test_ml_kem_refuses_a_case_it_cannot_answer_faithfully(
    tmp_path: Path, group: dict[str, object], expected: str
) -> None:
    """A malformed or unanswerable case stops the document rather than guessing.

    Emitting a case computed from absent input would be scored as a wrong
    answer, which is worse than sending nothing.
    """
    prompt = pqc_prompt(tmp_path, "ML-KEM", "encapDecap", group)

    with pytest.raises(ResponseError, match=expected):
        build_response(prompt, harness=Harness(PQC_HARNESS, timeout_seconds=60.0))


@pytest.mark.parametrize(
    ("group", "expected"),
    [
        (
            {"parameterSet": "ML-DSA-99", "tests": [{"tcId": 1}]},
            "ML-DSA-99",
        ),
        (
            {"parameterSet": "ML-DSA-65", "externalMu": True, "tests": [{"tcId": 1}]},
            "externalMu",
        ),
        (
            {"parameterSet": "ML-DSA-65", "tests": [{"tcId": 1, "pk": "00"}]},
            "missing message, signature",
        ),
    ],
    ids=["unknown-parameter-set", "external-mu", "missing-fields"],
)
def test_ml_dsa_refuses_a_group_it_cannot_answer_faithfully(
    tmp_path: Path, group: dict[str, object], expected: str
) -> None:
    """Same rule for ML-DSA: refuse the document, and say what to register instead."""
    prompt = pqc_prompt(tmp_path, "ML-DSA", "sigVer", group)

    with pytest.raises(ResponseError, match=expected):
        build_response(prompt, harness=Harness(PQC_HARNESS, timeout_seconds=60.0))
