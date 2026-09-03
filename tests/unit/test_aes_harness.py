"""The AES families reached through an external harness.

These are the operations that let a vendor point the runner at *their* module
rather than at this project's OpenSSL binding. Every assertion below is against
the shipped reference harness, which implements the wire contract without
importing anything from the package -- so it exercises the protocol rather than
a shortcut through it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from acvp_assay.providers.aes_block import CBC, CTR, OFB, SubprocessAesBlockProvider
from acvp_assay.providers.aes_modes import (
    CryptographyAesModeProvider,
    SubprocessAesModeProvider,
)
from acvp_assay.providers.subprocess_harness import HarnessProtocolError

ROOT = Path(__file__).resolve().parents[2]
HARNESS = [sys.executable, str(ROOT / "examples/reference_harness.py")]
KEY = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
IV = bytes.fromhex("101112131415161718191A1B1C1D1E1F")
BLOCK = bytes.fromhex("00112233445566778899AABBCCDDEEFF")


def block_provider() -> SubprocessAesBlockProvider:
    """A chaining-mode provider backed by the reference harness."""
    return SubprocessAesBlockProvider(HARNESS, timeout_seconds=20)


def mode_provider() -> SubprocessAesModeProvider:
    """An ECB/CMAC/GMAC/key-wrap provider backed by the reference harness."""
    return SubprocessAesModeProvider(HARNESS, timeout_seconds=20)


def test_ecb_through_the_harness_matches_fips_197() -> None:
    """The published FIPS 197 known answer, computed across the wire."""
    provider = mode_provider()

    produced = provider.ecb(key=KEY, data=BLOCK, encrypt=True)

    assert produced.hex().upper() == "69C4E0D86A7B0430D8CDB78070B4C55A"
    provider.close()


@pytest.mark.parametrize("algorithm", [CBC, CTR, OFB])
def test_chaining_modes_round_trip_through_the_harness(algorithm: str) -> None:
    """Decrypting an encryption over the wire returns the original payload."""
    provider = block_provider()

    encrypted = provider.transform(algorithm=algorithm, key=KEY, iv=IV, data=BLOCK, encrypt=True)
    decrypted = provider.transform(
        algorithm=algorithm, key=KEY, iv=IV, data=encrypted, encrypt=False
    )

    assert encrypted != BLOCK
    assert decrypted == BLOCK
    provider.close()


@pytest.mark.parametrize("algorithm", [CBC, OFB])
def test_the_monte_carlo_chain_agrees_with_the_built_in_provider(algorithm: str) -> None:
    """The harness runs the chain itself, and must reach the same answer.

    Delegating the chain is what makes it affordable -- 100 x 1000 iterations
    would otherwise be 100,000 exchanges per case -- but it also moves the IV
    advance rule into the vendor's code, which is where it is easiest to get
    wrong. This pins the two implementations together.
    """
    from acvp_assay.providers.aes_block import CryptographyAesBlockProvider

    harness = block_provider()
    built_in = CryptographyAesBlockProvider()

    over_wire = harness.monte_carlo(algorithm=algorithm, key=KEY, iv=IV, data=BLOCK, encrypt=True)
    locally = built_in.monte_carlo(algorithm=algorithm, key=KEY, iv=IV, data=BLOCK, encrypt=True)

    assert over_wire == locally
    harness.close()


def test_the_ecb_monte_carlo_chain_agrees_with_the_built_in_provider() -> None:
    """ECB reports triples, not quads: it has no IV to carry."""
    harness = mode_provider()

    over_wire = harness.ecb_monte_carlo(key=KEY, data=BLOCK, encrypt=True)
    locally = CryptographyAesModeProvider().ecb_monte_carlo(key=KEY, data=BLOCK, encrypt=True)

    assert over_wire == locally
    assert all(len(entry) == 3 for entry in over_wire)
    harness.close()


def test_counter_mode_has_no_monte_carlo_chain_to_delegate() -> None:
    """CTR defines none, so the runner must not ask a harness for one."""
    provider = block_provider()

    with pytest.raises(ValueError, match="no Monte Carlo test"):
        provider.monte_carlo(algorithm=CTR, key=KEY, iv=IV, data=BLOCK, encrypt=True)
    provider.close()


def test_cmac_and_gmac_agree_with_the_built_in_provider() -> None:
    """Both are truncated to a per-group length, which is easy to drop."""
    harness = mode_provider()
    built_in = CryptographyAesModeProvider()

    over_wire_mac = harness.cmac(key=KEY, message=b"acvp", mac_length_bits=96)
    over_wire_tag = harness.gmac(key=KEY, iv=IV[:12], aad=b"\xaa\xbb", tag_length_bits=96)

    assert over_wire_mac == built_in.cmac(key=KEY, message=b"acvp", mac_length_bits=96)
    assert over_wire_tag == built_in.gmac(key=KEY, iv=IV[:12], aad=b"\xaa\xbb", tag_length_bits=96)
    assert len(over_wire_mac) == 12
    harness.close()


@pytest.mark.parametrize("padded", [False, True])
def test_key_wrapping_round_trips_through_the_harness(padded: bool) -> None:
    """Both the padded and unpadded constructions cross the wire."""
    provider = mode_provider()
    payload = bytes(range(32))

    wrapped = provider.key_wrap(key=KEY, data=payload, padded=padded, wrap=True)
    unwrapped = provider.key_wrap(key=KEY, data=wrapped, padded=padded, wrap=False)

    assert unwrapped == payload
    provider.close()


def test_a_corrupt_wrapping_is_a_value_error_not_a_crash() -> None:
    """Half of each upstream unwrap set is deliberately invalid.

    The harness reports it with the reserved "authentication failed" error, and
    the provider translates that to the ValueError this boundary promises. A
    harness that crashed instead would score a conforming module as broken.
    """
    provider = mode_provider()

    with pytest.raises(ValueError, match="unwrapping failed"):
        provider.key_wrap(key=KEY, data=b"\x00" * 40, padded=False, wrap=False)
    provider.close()


def test_a_mode_the_harness_lacks_is_declined(tmp_path: Path) -> None:
    """Capability is the harness's to declare, not the runner's to assume."""
    script = tmp_path / "narrow.py"
    script.write_text(
        "import json, sys\n"
        "for _line in sys.stdin:\n"
        '    print(json.dumps({"error": "unsupported"}), flush=True)\n'
    )
    provider = SubprocessAesBlockProvider([sys.executable, str(script)], timeout_seconds=5)

    from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

    with pytest.raises(HarnessUnsupportedError):
        provider.transform(algorithm=CBC, key=KEY, iv=IV, data=BLOCK, encrypt=True)
    provider.close()


def test_a_malformed_monte_carlo_array_is_reported(tmp_path: Path) -> None:
    """A harness that answers the wrong shape fails loudly, not silently."""
    for payload, message in (
        ('{"resultsArray": "nope"}', "resultsArray"),
        ('{"resultsArray": ["nope"]}', "non-object"),
        ('{"resultsArray": [{"key": "zz"}]}', "invalid hex"),
    ):
        script = tmp_path / "bad.py"
        script.write_text(
            f"import json, sys\nfor _line in sys.stdin:\n    print({payload!r}, flush=True)\n"
        )
        provider = SubprocessAesBlockProvider([sys.executable, str(script)], timeout_seconds=5)

        with pytest.raises(HarnessProtocolError, match=message):
            provider.monte_carlo(algorithm=CBC, key=KEY, iv=IV, data=BLOCK, encrypt=True)
        provider.close()


def test_the_runner_routes_every_aes_family_to_a_harness(tmp_path: Path) -> None:
    """--provider-command is accepted, not refused, for the AES families."""
    from acvp_assay.algorithms import run_vector_file

    prompt = {
        "vsId": 1,
        "algorithm": "ACVP-AES-CBC",
        "revision": "1.0",
        "testGroups": [
            {
                "tgId": 1,
                "testType": "AFT",
                "direction": "encrypt",
                "keyLen": 128,
                "tests": [{"tcId": 1, "key": KEY.hex(), "iv": IV.hex(), "pt": BLOCK.hex()}],
            }
        ],
    }
    from acvp_assay.providers.aes_block import CryptographyAesBlockProvider

    expected_ct = CryptographyAesBlockProvider().transform(
        algorithm=CBC, key=KEY, iv=IV, data=BLOCK, encrypt=True
    )
    expected = {
        "vsId": 1,
        "testGroups": [{"tgId": 1, "tests": [{"tcId": 1, "ct": expected_ct.hex()}]}],
    }
    (tmp_path / "prompt.json").write_text(json.dumps(prompt), encoding="utf-8")
    (tmp_path / "expectedResults.json").write_text(json.dumps(expected), encoding="utf-8")

    results, metadata = run_vector_file(
        tmp_path / "prompt.json",
        tmp_path / "expectedResults.json",
        provider_command=" ".join(HARNESS),
    )

    assert metadata.name == "reference-harness"
    assert [r.status.name for r in results] == ["PASS"]
