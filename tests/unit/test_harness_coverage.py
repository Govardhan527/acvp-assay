"""Every algorithm family must be reachable through an external harness.

The project's headline claim is that an implementation which cannot be linked
against — an HSM, a smartcard, an embedded device — can still be tested. That
claim is only true if *every* family accepts ``--provider-command``, so these
tests guard it directly.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from acvp_assay.algorithms import run_vector_file
from acvp_assay.models import ResultStatus
from acvp_assay.providers.digest import SubprocessHashProvider, SubprocessMacProvider
from acvp_assay.providers.ecdsa import SubprocessEcdsaProvider
from acvp_assay.providers.subprocess_harness import (
    HarnessProtocolError,
    HarnessUnsupportedError,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"
REFERENCE = f"{sys.executable} {ROOT / 'examples/reference_harness.py'}"


def script(tmp_path: Path, body: str) -> list[str]:
    """Write a one-shot harness and return its argument vector."""
    path = tmp_path / "h.py"
    path.write_text(f"import json, sys\nrequest = json.loads(sys.stdin.read())\n{body}\n")
    return [sys.executable, str(path)]


@pytest.mark.parametrize(
    ("directory", "expected_passes"),
    [
        ("aes-gcm-valid-encrypt", 1),
        ("sha2-256-known-answers", 2),
        ("hmac-sha2-256-known-answers", 2),
        ("ecdsa-p256-sigver", 2),
    ],
)
def test_every_family_runs_through_the_reference_harness(
    directory: str, expected_passes: int
) -> None:
    """AES-GCM, SHA-2, HMAC and ECDSA all accept an external provider."""
    prompt = FIXTURES / directory / "prompt.json"

    results, metadata = run_vector_file(
        prompt, prompt.parent / "expectedResults.json", provider_command=REFERENCE
    )

    assert metadata.name == "reference-harness", "results must be attributed to the harness"
    assert sum(1 for r in results if r.status is ResultStatus.PASS) == expected_passes
    assert not [r for r in results if r.status in (ResultStatus.FAIL, ResultStatus.ERROR)]


@pytest.mark.parametrize(
    "directory",
    ["aes-gcm-valid-encrypt", "sha2-256-known-answers", "hmac-sha2-256-known-answers"],
)
def test_harness_and_in_process_agree(directory: str) -> None:
    """The boundary must be faithful: both providers reach the same verdicts."""
    prompt = FIXTURES / directory / "prompt.json"
    expected = prompt.parent / "expectedResults.json"

    in_process, _ = run_vector_file(prompt, expected)
    harness, _ = run_vector_file(prompt, expected, provider_command=REFERENCE)

    assert [(r.tg_id, r.tc_id, r.status) for r in in_process] == [
        (r.tg_id, r.tc_id, r.status) for r in harness
    ]


# --- the "unsupported" outcome --------------------------------------------


def test_declined_case_is_unsupported_not_an_error(tmp_path: Path) -> None:
    """A harness saying it lacks a capability is coverage news, not a failure.

    Reporting it as an ERROR would tell a customer their implementation is
    broken when it simply does not implement that curve.
    """
    command = script(tmp_path, 'sys.stdout.write(json.dumps({"error": "unsupported"}))')

    with pytest.raises(HarnessUnsupportedError):
        SubprocessHashProvider("SHA2-256", command).digest(b"abc")


@pytest.mark.parametrize(
    "directory", ["sha2-256-known-answers", "hmac-sha2-256-known-answers", "ecdsa-p256-sigver"]
)
def test_a_declining_harness_yields_unsupported_cases(tmp_path: Path, directory: str) -> None:
    """Declined cases surface as UNSUPPORTED across every family."""
    meta = (
        '{"name":"stub","libraryName":"s","libraryVersion":"0",'
        '"backendName":"s","backendVersion":"0"}'
    )
    command_file = tmp_path / "decline.py"
    command_file.write_text(
        "import json, sys\n"
        "req = json.loads(sys.stdin.read())\n"
        f"out = {meta} if req['operation'] == 'metadata' else "
        '{"error": "unsupported"}\n'
        "sys.stdout.write(json.dumps(out))\n"
    )
    prompt = FIXTURES / directory / "prompt.json"

    results, _ = run_vector_file(
        prompt,
        prompt.parent / "expectedResults.json",
        provider_command=f"{sys.executable} {command_file}",
    )

    assert results
    assert {r.status for r in results} == {ResultStatus.UNSUPPORTED}
    assert all("declined" in (r.diagnostic or "") for r in results)


def test_external_ecdsa_does_not_prejudge_capability() -> None:
    """Curve support is the implementation's to declare, not ours to assume.

    An HSM may offer binary curves that ``cryptography`` does not; filtering on
    the built-in provider's table would wrongly report them unsupported.
    """
    assert SubprocessEcdsaProvider(["true"]).supports(curve="B-233", hash_algorithm="SHA2-256")


# --- provider-level contract details --------------------------------------


def test_monte_carlo_chain_is_delegated_whole(tmp_path: Path) -> None:
    """The harness runs the 100,000-iteration chain; the caller does not drive it."""
    command = script(
        tmp_path,
        'assert request["operation"] == "digest-mct", request\n'
        'assert request["alternate"] is True, request\n'
        'sys.stdout.write(json.dumps({"md": ["AA" * 32] * 100}))',
    )

    digests = SubprocessHashProvider("SHA2-256", command).digest_mct(b"seed", alternate=True)

    assert len(digests) == 100
    assert digests[0] == bytes.fromhex("AA" * 32)


@pytest.mark.parametrize(
    ("literal", "message"),
    [
        ('{"md": "notalist"}', "no 'md' array"),
        ('{"md": [7]}', "non-string md at index 0"),
        ('{"md": ["ZZ"]}', "invalid hex md at index 0"),
    ],
)
def test_malformed_monte_carlo_responses_are_rejected(
    tmp_path: Path, literal: str, message: str
) -> None:
    """A broken chain response names what was wrong with it."""
    command = script(tmp_path, f"sys.stdout.write({literal!r})")

    with pytest.raises(HarnessProtocolError, match=message):
        SubprocessHashProvider("SHA2-256", command).digest_mct(b"seed", alternate=False)


def test_mac_request_carries_the_truncation_length(tmp_path: Path) -> None:
    """``macLen`` must cross the boundary, or truncated groups silently fail."""
    command = script(
        tmp_path,
        'assert request["macLen"] == 80, request\n'
        'sys.stdout.write(json.dumps({"mac": "AABBCCDDEEFF00112233"}))',
    )

    value = SubprocessMacProvider("HMAC-SHA2-256", command).mac(
        key=b"k", message=b"m", mac_length_bits=80
    )

    assert len(value) == 10


def test_ecdsa_sign_returns_the_key_it_generated(tmp_path: Path) -> None:
    """sigGen must return the public key, since the signature is verified under it."""
    command = script(
        tmp_path,
        'sys.stdout.write(json.dumps({"qx": "01", "qy": "02", "r": "03", "s": "04"}))',
    )

    produced = SubprocessEcdsaProvider(command).sign(
        curve="P-256", hash_algorithm="SHA2-256", message=b"m"
    )

    assert (produced.qx, produced.qy, produced.r, produced.s) == (
        b"\x01",
        b"\x02",
        b"\x03",
        b"\x04",
    )


def test_ecdsa_verify_requires_a_boolean_verdict(tmp_path: Path) -> None:
    """A verdict question must be answered with a real boolean."""
    command = script(tmp_path, 'sys.stdout.write(json.dumps({"testPassed": "yes"}))')

    with pytest.raises(HarnessProtocolError, match="boolean"):
        SubprocessEcdsaProvider(command).verify(
            curve="P-256",
            hash_algorithm="SHA2-256",
            message=b"m",
            qx=b"\x01",
            qy=b"\x02",
            r=b"\x03",
            s=b"\x04",
        )


def test_ecdsa_verdict_crosses_the_boundary_intact(tmp_path: Path) -> None:
    """Both verdicts round-trip; a false one is an answer, not an error."""
    command = script(tmp_path, 'sys.stdout.write(json.dumps({"testPassed": False}))')

    verdict = SubprocessEcdsaProvider(command).verify(
        curve="P-256",
        hash_algorithm="SHA2-256",
        message=b"m",
        qx=b"\x01",
        qy=b"\x02",
        r=b"\x03",
        s=b"\x04",
    )

    assert verdict is False


def test_reference_harness_declines_what_it_lacks() -> None:
    """The shipped example reports 'unsupported' rather than crashing."""
    import subprocess

    completed = subprocess.run(
        [sys.executable, str(ROOT / "examples/reference_harness.py")],
        input=json.dumps({"operation": "digest", "algorithm": "SHA3-256", "message": "616263"}),
        capture_output=True,
        text=True,
        check=False,
    )

    assert json.loads(completed.stdout) == {"error": "unsupported"}


def test_reference_harness_matches_published_known_answers() -> None:
    """The example's own outputs agree with FIPS 180-4 and RFC 4231."""
    import subprocess

    def ask(request: dict[str, Any]) -> dict[str, Any]:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "examples/reference_harness.py")],
            input=json.dumps(request),
            capture_output=True,
            text=True,
            check=False,
        )
        result: dict[str, Any] = json.loads(completed.stdout)
        return result

    assert ask({"operation": "digest", "algorithm": "SHA2-256", "message": "616263"})["md"] == (
        "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
    )
    assert (
        ask(
            {
                "operation": "mac",
                "algorithm": "HMAC-SHA2-256",
                "key": "0B" * 20,
                "message": "4869205468657265",
                "macLen": 256,
            }
        )["mac"]
        == "B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7"
    )
