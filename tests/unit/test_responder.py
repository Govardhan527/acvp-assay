"""Response construction for submission to a live ACVTS server.

The shapes asserted here are the ones NIST accepted: session 765339 on the Demo
server was answered from this code path and returned ``"passed": true``. The
value of these tests is that they pin the *document shape* -- a submission that
is subtly malformed is scored as wrong answers, not rejected as malformed, so
there is no second chance to notice.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from acvp_assay.responder import (
    UnsupportedResponseError,
    build_response,
    supported_response_algorithms,
)


def write_prompt(tmp_path: Path, document: dict[str, object]) -> Path:
    """Write a prompt document and return its path."""
    path = tmp_path / "prompt.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_an_aft_group_answers_with_a_digest_per_case(tmp_path: Path) -> None:
    """Each AFT case carries an ``md`` and nothing else."""
    message = b"acvp"
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 4032018,
            "algorithm": "SHA2-256",
            "revision": "1.0",
            "isSample": True,
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "tests": [
                        {"tcId": 1, "msg": message.hex(), "len": len(message) * 8},
                        {"tcId": 2, "msg": "", "len": 0},
                    ],
                }
            ],
        },
    )

    response = build_response(prompt)

    assert response["vsId"] == 4032018
    assert response["algorithm"] == "SHA2-256"
    assert response["revision"] == "1.0"
    group = response["testGroups"][0]  # type: ignore[index]
    assert group["tgId"] == 1
    assert group["tests"][0] == {
        "tcId": 1,
        "md": hashlib.sha256(message).hexdigest().upper(),
    }
    assert group["tests"][1]["md"] == hashlib.sha256(b"").hexdigest().upper()


def test_a_monte_carlo_group_answers_with_the_whole_chain(tmp_path: Path) -> None:
    """An MCT case needs all 100 digests, not just the final one.

    The offline runner compares the whole chain but reports only its last
    value; a submission built from that report would be rejected as 99 missing
    answers, which is why responses are built from the provider directly.
    """
    seed = bytes(range(32))
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "SHA2-256",
            "revision": "1.0",
            "isSample": True,
            "testGroups": [
                {
                    "tgId": 2,
                    "testType": "MCT",
                    "mctVersion": "standard",
                    "tests": [{"tcId": 513, "msg": seed.hex(), "len": len(seed) * 8}],
                }
            ],
        },
    )

    response = build_response(prompt)

    case = response["testGroups"][0]["tests"][0]  # type: ignore[index]
    assert set(case) == {"tcId", "resultsArray"}
    assert len(case["resultsArray"]) == 100
    assert all(set(entry) == {"md"} for entry in case["resultsArray"])
    assert all(len(entry["md"]) == 64 for entry in case["resultsArray"])


def test_a_large_data_test_is_refused_rather_than_half_answered(tmp_path: Path) -> None:
    """An LDT group must stop the submission, not silently omit cases."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "SHA2-256",
            "revision": "1.0",
            "isSample": True,
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "LDT",
                    "tests": [
                        {
                            "tcId": 1,
                            "largeMsg": {
                                "content": "AB",
                                "contentLength": 8,
                                "fullLength": 8589934592,
                                "expansionTechnique": "repeating",
                            },
                        }
                    ],
                }
            ],
        },
    )

    with pytest.raises(UnsupportedResponseError, match="large data test"):
        build_response(prompt)


def test_an_unknown_mct_version_is_refused(tmp_path: Path) -> None:
    """Guessing a Monte Carlo chain would produce confidently wrong answers."""
    prompt = write_prompt(
        tmp_path,
        {
            "vsId": 1,
            "algorithm": "SHA2-256",
            "revision": "1.0",
            "isSample": True,
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "MCT",
                    "mctVersion": "spiral",
                    "tests": [{"tcId": 1, "msg": "00", "len": 8}],
                }
            ],
        },
    )

    with pytest.raises(UnsupportedResponseError, match="mctVersion"):
        build_response(prompt)


def test_an_algorithm_without_a_builder_is_refused(tmp_path: Path) -> None:
    """Silence would be scored as wrong answers, so this raises instead."""
    prompt = write_prompt(
        tmp_path,
        {"vsId": 1, "algorithm": "ACVP-AES-GCM", "revision": "1.0", "testGroups": []},
    )

    with pytest.raises(UnsupportedResponseError, match="no response builder"):
        build_response(prompt)


def test_supported_algorithms_are_reported() -> None:
    """Callers need to know what can be submitted before registering for it."""
    supported = supported_response_algorithms()

    assert "SHA2-256" in supported
    assert "SHA2-512" in supported
    assert all(name.startswith("SHA2-") for name in supported)
