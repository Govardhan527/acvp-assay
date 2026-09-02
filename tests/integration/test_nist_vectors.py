"""End-to-end run against the pinned upstream NIST AES-GCM vector set.

These vectors are not redistributed with the repository (see
``docs/vector-sources.md``), so the whole module is skipped unless a developer
has run ``python scripts/fetch_vectors.py``. That keeps CI deterministic and
network-free while still exercising real NIST data locally.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors"
PROMPT = VECTORS / "ACVP-AES-GCM-1.0/prompt.json"

pytestmark = pytest.mark.skipif(
    not PROMPT.is_file(),
    reason="pinned NIST vectors absent; run 'python scripts/fetch_vectors.py' to enable",
)


def test_full_nist_vector_set_passes(tmp_path: Path) -> None:
    """All 60 upstream cases pass, including the deliberate-failure cases.

    Groups 3 and 4 contain ten cases NIST marks ``testPassed: false``. A
    correct implementation must reject those tags, so they count as passes;
    scoring them as errors would fail a conforming module.
    """
    output = tmp_path / "result.json"

    completed = subprocess.run(
        [sys.executable, "-m", "acvp_runner", "run", str(PROMPT), "--output", str(output)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["summary"] == {
        "total": 60,
        "passed": 60,
        "failed": 0,
        "errored": 0,
        "skipped": 0,
        "unsupported": 0,
    }

    rejected = [
        case
        for case in report["cases"]
        if case.get("diagnostic") == "authentication rejected as expected"
    ]
    assert len(rejected) == 10


def test_upstream_set_covers_truncated_tags_and_empty_payloads() -> None:
    """The pinned set exercises variants the tiny local fixtures do not."""
    prompt = json.loads(PROMPT.read_text(encoding="utf-8"))
    groups = prompt["testGroups"]

    assert {group["tagLen"] for group in groups} == {32, 128}
    assert {group["ivLen"] for group in groups} == {96, 120}
    assert 0 in {group["payloadLen"] for group in groups}
    assert 0 in {group["aadLen"] for group in groups}


@pytest.mark.skipif(
    not (VECTORS / "SHA2-256-1.0/prompt.json").is_file(),
    reason="pinned SHA2-256 vectors absent",
)
def test_full_sha2_vector_set(tmp_path: Path) -> None:
    """All 512 AFT cases and the Monte Carlo chain pass; LDT is declared unsupported.

    The MCT group is the real check here: matching NIST's 100-entry
    resultsArray confirms the ``alternate`` chain, which normalises every
    message to the original seed length rather than hashing three digests.
    """
    output = tmp_path / "sha.json"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "acvp_runner",
            "run",
            str(VECTORS / "SHA2-256-1.0/prompt.json"),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["summary"]["passed"] == 513
    assert report["summary"]["failed"] == 0
    assert report["summary"]["unsupported"] == 4

    monte_carlo = [
        case for case in report["cases"] if "Monte Carlo" in (case.get("diagnostic") or "")
    ]
    assert len(monte_carlo) == 1
    assert monte_carlo[0]["status"] == "PASS"


@pytest.mark.skipif(
    not (VECTORS / "HMAC-SHA2-256-1.0/prompt.json").is_file(),
    reason="pinned HMAC-SHA2-256 vectors absent",
)
def test_full_hmac_vector_set(tmp_path: Path) -> None:
    """All 975 HMAC cases pass, including the truncated-MAC groups."""
    output = tmp_path / "hmac.json"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "acvp_runner",
            "run",
            str(VECTORS / "HMAC-SHA2-256-1.0/prompt.json"),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["summary"] == {
        "total": 975,
        "passed": 975,
        "failed": 0,
        "errored": 0,
        "skipped": 0,
        "unsupported": 0,
    }
