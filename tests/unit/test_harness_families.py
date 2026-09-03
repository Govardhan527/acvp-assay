"""The AES and RSA families reached through an external harness.

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
from acvp_assay.providers.rsa import SubprocessRsaProvider
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


# --------------------------------------------------------------------- RSA


def rsa_provider() -> SubprocessRsaProvider:
    """An RSA provider backed by the reference harness."""
    from acvp_assay.providers.rsa import SubprocessRsaProvider

    return SubprocessRsaProvider(HARNESS, timeout_seconds=60)


def test_rsa_signs_a_whole_group_under_one_key() -> None:
    """ACVP reports the public key once per group, so the group signs together.

    Asking case by case would either force the harness to cache a key or
    produce a response document that cannot be expressed.
    """
    provider = rsa_provider()

    signed = provider.sign_group(
        signature_type="pkcs1v1.5",
        hash_algorithm="SHA2-256",
        mask_function="none",
        modulo=2048,
        salt_length=0,
        messages=[b"one", b"two", b"three"],
    )

    assert len(signed.signatures) == 3
    assert len(set(signed.signatures)) == 3
    assert len(signed.n) == 256
    # Every signature verifies under the single key the harness reported.
    for message, signature in zip([b"one", b"two", b"three"], signed.signatures, strict=True):
        assert provider.verify(
            signature_type="pkcs1v1.5",
            hash_algorithm="SHA2-256",
            mask_function="none",
            salt_length=0,
            n=int.from_bytes(signed.n, "big"),
            e=int.from_bytes(signed.e, "big"),
            message=message,
            signature=signature,
        )
    provider.close()


def test_rsa_verify_rejects_a_bogus_signature() -> None:
    """A rejection is an answer; ACVP builds invalid signatures in deliberately."""
    provider = rsa_provider()
    signed = provider.sign_group(
        signature_type="pss",
        hash_algorithm="SHA2-256",
        mask_function="mgf1",
        modulo=2048,
        salt_length=32,
        messages=[b"acvp"],
    )

    assert not provider.verify(
        signature_type="pss",
        hash_algorithm="SHA2-256",
        mask_function="mgf1",
        salt_length=32,
        n=int.from_bytes(signed.n, "big"),
        e=int.from_bytes(signed.e, "big"),
        message=b"acvp",
        signature=b"\x00" * 256,
    )
    provider.close()


def test_a_shake_mask_reaches_the_harness_and_is_declined() -> None:
    """maskFunction is a field of its own and must cross the wire.

    FIPS 186-5 lets PSS use SHAKE as its mask generation function, which is a
    different question from hashAlg. Omitting it from the request let the
    harness default to MGF1 and answer six upstream cases confidently wrong.
    """
    from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

    provider = rsa_provider()

    with pytest.raises(HarnessUnsupportedError):
        provider.sign_group(
            signature_type="pss",
            hash_algorithm="SHA3-256",
            mask_function="shake-128",
            modulo=2048,
            salt_length=32,
            messages=[b"acvp"],
        )
    provider.close()


def test_the_rsa_primitives_cross_the_wire_with_their_own_bounds() -> None:
    """The two primitives use different ranges, and both must survive the trip."""
    provider = rsa_provider()
    n, d = 3233, 2753

    assert provider.signature_primitive(n=n, d=d, message=1) == 1
    assert provider.signature_primitive(n=n, d=d, message=n) is None
    # 1 is in range for a signature and out of range for a decryption.
    assert provider.decryption_primitive(n=n, d=d, ciphertext=1) is None
    assert provider.decryption_primitive(n=n, d=d, ciphertext=2) is not None
    provider.close()


def test_the_crt_primitive_crosses_the_wire() -> None:
    """Half the upstream groups never supply d, only the CRT parameters."""
    p = 0xE1B1E1B7C1F3D5D7C7D3E1F5B7C3D1E5F7B1C3D5E7F1B3C5D7E1F3B5C7D1E499
    q = 0xC3D5E7F1B3C5D7E1F3B5C7D1E3F5B7C1D3E5F7B1C5D7E3F1B5C7D1E3F5B7C21D
    n = p * q
    d = pow(65537, -1, (p - 1) * (q - 1))
    message = 0x2468ACE0
    provider = rsa_provider()

    produced = provider.signature_primitive_crt(
        n=n, p=p, q=q, dmp1=d % (p - 1), dmq1=d % (q - 1), iqmp=pow(q, -1, p), message=message
    )

    assert produced == pow(message, d, n)
    provider.close()


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ('{"n": "01", "e": "01"}', "signatures"),
        ('{"n": "01", "e": "01", "signatures": ["AA", "BB"]}', "for 1 messages"),
        ('{"n": "01", "e": "01", "signatures": [1]}', "non-string"),
        ('{"n": "01", "e": "01", "signatures": ["zz"]}', "invalid hex"),
    ],
)
def test_a_malformed_signature_group_is_reported(
    tmp_path: Path, payload: str, message: str
) -> None:
    """A harness answering the wrong shape fails loudly, not silently."""
    script = tmp_path / "bad.py"
    script.write_text(
        "import json, sys\nfor _line in sys.stdin:\n    print(" + repr(payload) + ", flush=True)\n"
    )
    provider = SubprocessRsaProvider([sys.executable, str(script)], timeout_seconds=5)

    with pytest.raises(HarnessProtocolError, match=message):
        provider.sign_group(
            signature_type="pkcs1v1.5",
            hash_algorithm="SHA2-256",
            mask_function="none",
            modulo=2048,
            salt_length=0,
            messages=[b"one"],
        )
    provider.close()


def test_a_non_boolean_verdict_from_a_harness_is_reported(tmp_path: Path) -> None:
    """sigVer answers a verdict; anything else is a protocol failure."""
    script = tmp_path / "vague.py"
    script.write_text(
        "import json, sys\n"
        "for _line in sys.stdin:\n"
        '    print(json.dumps({"testPassed": "maybe"}), flush=True)\n'
    )
    provider = SubprocessRsaProvider([sys.executable, str(script)], timeout_seconds=5)

    with pytest.raises(HarnessProtocolError, match="testPassed"):
        provider.verify(
            signature_type="pkcs1v1.5",
            hash_algorithm="SHA2-256",
            mask_function="none",
            salt_length=0,
            n=3233,
            e=17,
            message=b"acvp",
            signature=b"\x00",
        )
    provider.close()


def test_the_harness_capability_check_is_optimistic() -> None:
    """Deciding what a harness cannot do would be this runner's assumption."""
    provider = rsa_provider()

    assert provider.supports(
        signature_type="pss", hash_algorithm="SHAKE-128", mask_function="shake-256"
    )
    provider.close()


@pytest.mark.parametrize(
    ("mode", "group_extra", "case_extra", "expected_case"),
    [
        ("sigGen", {"sigType": "pss", "hashAlg": "SHAKE-128", "saltLen": 32}, {}, {}),
        (
            "sigVer",
            {
                "sigType": "pss",
                "hashAlg": "SHAKE-128",
                "saltLen": 32,
                "n": "C5" + "A3" * 255,
                "e": "010001",
            },
            {"signature": "00" * 256},
            {"testPassed": False},
        ),
        (
            "signaturePrimitive",
            {},
            {"n": "0C95", "d": "05"},
            {"testPassed": True, "signature": "0020"},
        ),
    ],
)
def test_a_declined_rsa_case_is_reported_unsupported(
    tmp_path: Path,
    mode: str,
    group_extra: dict[str, object],
    case_extra: dict[str, object],
    expected_case: dict[str, object],
) -> None:
    """Every RSA path must survive a harness saying "I do not implement this".

    sigGen declines a whole group, because the group signs in one exchange;
    sigVer and the primitives decline case by case. All three are reported
    UNSUPPORTED rather than crashing the run or scoring a wrong answer.
    """
    from acvp_assay.algorithms import rsa as rsa_alg

    script = tmp_path / "narrow.py"
    script.write_text(
        "import json, sys\n"
        "for _line in sys.stdin:\n"
        '    print(json.dumps({"error": "unsupported"}), flush=True)\n'
    )
    prompt = {
        "vsId": 1,
        "algorithm": "RSA",
        "mode": mode,
        "revision": "FIPS186-5",
        "testGroups": [
            {
                "tgId": 1,
                "testType": "AFT",
                "modulo": 2048,
                **group_extra,
                "tests": [{"tcId": 1, "message": b"acvp".hex(), **case_extra}],
            }
        ],
    }
    expected = {
        "vsId": 1,
        "testGroups": [{"tgId": 1, "tests": [{"tcId": 1, **expected_case}]}],
    }
    provider = SubprocessRsaProvider([sys.executable, str(script)], timeout_seconds=5)

    results = rsa_alg.run_vector_set(
        rsa_alg.parse_vector_set(prompt),
        rsa_alg.parse_expected_results(expected),
        provider,
    )

    assert results[0].status.name == "UNSUPPORTED"
    assert "declined" in (results[0].diagnostic or "")
    provider.close()


def test_a_harness_that_signs_but_declines_to_verify_is_reported(tmp_path: Path) -> None:
    """sigGen checks its own signature, so a decline there is still a decline.

    An implementation may sign and not verify -- a signing-only HSM key is the
    obvious case. The group is answered and the check is not, which is an
    UNSUPPORTED case rather than a failed one.
    """
    from acvp_assay.algorithms import rsa as rsa_alg

    script = tmp_path / "signer.py"
    script.write_text(
        "import json, sys\n"
        "for _line in sys.stdin:\n"
        "    request = json.loads(_line)\n"
        '    if request["operation"] == "rsa-sign-group":\n'
        '        print(json.dumps({"n": "C5" + "A3" * 255, "e": "010001",'
        ' "signatures": ["00" * 256]}), flush=True)\n'
        "    else:\n"
        '        print(json.dumps({"error": "unsupported"}), flush=True)\n'
    )
    prompt = {
        "vsId": 1,
        "algorithm": "RSA",
        "mode": "sigGen",
        "revision": "FIPS186-5",
        "testGroups": [
            {
                "tgId": 1,
                "testType": "AFT",
                "sigType": "pkcs1v1.5",
                "hashAlg": "SHA2-256",
                "modulo": 2048,
                "tests": [{"tcId": 1, "message": b"acvp".hex()}],
            }
        ],
    }
    expected = {"vsId": 1, "testGroups": [{"tgId": 1, "tests": [{"tcId": 1}]}]}
    provider = SubprocessRsaProvider([sys.executable, str(script)], timeout_seconds=5)

    results = rsa_alg.run_vector_set(
        rsa_alg.parse_vector_set(prompt),
        rsa_alg.parse_expected_results(expected),
        provider,
    )

    assert results[0].status.name == "UNSUPPORTED"
    assert "declined" in (results[0].diagnostic or "")
    provider.close()
