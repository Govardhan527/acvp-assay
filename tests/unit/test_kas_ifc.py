"""KAS-IFC-SSC and KTS-IFC: key agreement and transport over RSA.

Two properties here were settled by running against five live sessions rather
than one, and both would have shipped from a single session:

* **KAS2's concatenation order follows the role, not ownership.** The
  initiator's contribution always comes first, so an initiator emits
  ``own || recovered`` and a responder ``recovered || own``. Derived from an
  initiator-only group it looks like "own first" and is silently wrong for every
  responder case.
* **A VAL failure never isolates one condition.** Across nine failing VAL cases,
  six carrying two independent checks, not one failed only one of them.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from acvp_assay.algorithms import kas_ifc as algorithm
from acvp_assay.models import ResultStatus
from acvp_assay.parser import AcvpValidationError
from acvp_assay.providers.kas_ifc import (
    KAS1,
    KAS2,
    CryptographyKasIfc,
    RsaKey,
    SubprocessKasIfc,
)
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

_GENERATED = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_NUMBERS = _GENERATED.private_numbers()
KEY = RsaKey(
    n=_NUMBERS.public_numbers.n,
    e=_NUMBERS.public_numbers.e,
    d=_NUMBERS.d,
    p=_NUMBERS.p,
    q=_NUMBERS.q,
)
SIZE = KEY.size


def provider() -> CryptographyKasIfc:
    return CryptographyKasIfc()


def test_recover_inverts_the_public_operation() -> None:
    z = 12345678901234567890
    ciphertext = pow(z, KEY.e, KEY.n).to_bytes(SIZE, "big")
    assert provider().recover(key=KEY, ciphertext=ciphertext) == z.to_bytes(SIZE, "big")


def test_recover_pads_to_the_modulus_length() -> None:
    """ACVP compares bytes, so a short Z that dropped leading zeros is wrong."""
    ciphertext = pow(1, KEY.e, KEY.n).to_bytes(SIZE, "big")
    recovered = provider().recover(key=KEY, ciphertext=ciphertext)
    assert len(recovered) == SIZE
    assert recovered == (1).to_bytes(SIZE, "big")


def test_a_ciphertext_outside_the_modulus_is_refused() -> None:
    with pytest.raises(ValueError, match="not a residue"):
        provider().recover(key=KEY, ciphertext=(KEY.n + 1).to_bytes(SIZE + 1, "big"))


def test_originate_stays_inside_the_modulus_and_round_trips() -> None:
    for _ in range(8):
        z, c = provider().originate(peer_n=KEY.n, peer_e=KEY.e)
        assert 1 <= int.from_bytes(z, "big") < KEY.n
        assert provider().recover(key=KEY, ciphertext=c) == z


def test_oaep_round_trips_and_refuses_an_unknown_hash() -> None:
    dkm, ciphertext = provider().oaep_encrypt(
        peer_n=KEY.n, peer_e=KEY.e, hash_alg="SHA2-256", length_bytes=32
    )
    assert provider().oaep_decrypt(key=KEY, ciphertext=ciphertext, hash_alg="SHA2-256") == dkm
    with pytest.raises(ValueError, match="unsupported OAEP hash"):
        provider().oaep_encrypt(peer_n=KEY.n, peer_e=KEY.e, hash_alg="MD5", length_bytes=32)


def _case(**fields: Any) -> algorithm.IfcCase:
    base: dict[str, Any] = {
        "tc_id": 1,
        "iut_key": None,
        "peer_n": None,
        "peer_e": None,
        "server_c": None,
        "iut_c": None,
        "iut_z": None,
        "claimed_z": None,
    }
    base.update(fields)
    return algorithm.IfcCase(**base)


def _group(**fields: Any) -> algorithm.IfcGroup:
    base: dict[str, Any] = {
        "tg_id": 1,
        "scheme": KAS2,
        "kas_role": "initiator",
        "test_type": "VAL",
        "hash_alg": None,
        "key_bits": None,
        "tests": (),
    }
    base.update(fields)
    return algorithm.IfcGroup(**base)


def _vector_set(algorithm_name: str = "KAS-IFC-SSC") -> algorithm.IfcVectorSet:
    return algorithm.IfcVectorSet(
        vs_id=1, algorithm=algorithm_name, revision="Sp800-56Br2", groups=()
    )


def test_kas2_puts_the_initiators_contribution_first_whichever_side_we_are() -> None:
    """The bug five sessions caught and one session would have shipped."""
    own = b"\x01" * SIZE
    peer_z = 9999
    server_c = pow(peer_z, KEY.e, KEY.n).to_bytes(SIZE, "big")
    recovered = peer_z.to_bytes(SIZE, "big")
    case = _case(iut_key=KEY, server_c=server_c, iut_z=own)

    as_initiator = algorithm.shared_secret(
        _vector_set(), _group(kas_role="initiator"), case, provider()
    )
    as_responder = algorithm.shared_secret(
        _vector_set(), _group(kas_role="responder"), case, provider()
    )
    assert as_initiator == own + recovered
    assert as_responder == recovered + own
    assert as_initiator != as_responder


def test_kas1_carries_one_secret_only() -> None:
    own = b"\x02" * SIZE
    case = _case(iut_key=KEY, iut_z=own)
    assert algorithm.shared_secret(_vector_set(), _group(scheme=KAS1), case, provider()) == own


@pytest.mark.parametrize(
    ("name", "scheme", "role", "expected"),
    [
        ("KAS-IFC-SSC", KAS1, "responder", False),
        ("KAS-IFC-SSC", KAS1, "initiator", True),
        ("KAS-IFC-SSC", KAS2, "responder", True),
        ("KAS-IFC-SSC", KAS2, "initiator", True),
        ("KTS-IFC", KAS1, "responder", False),
        ("KTS-IFC", KAS1, "initiator", True),
    ],
)
def test_which_aft_cases_have_to_originate_material(
    name: str, scheme: str, role: str, expected: bool
) -> None:
    """KAS2 has both parties contribute, so neither role is a pure recovery."""
    group = _group(scheme=scheme, kas_role=role, test_type="AFT")
    assert algorithm.originates(_vector_set(name), group) is expected


def test_a_val_case_never_originates_whatever_its_role() -> None:
    for role in ("initiator", "responder"):
        assert not algorithm.originates(_vector_set(), _group(kas_role=role, test_type="VAL"))


def _hex(value: int) -> str:
    text = format(value, "X")
    return text if len(text) % 2 == 0 else "0" + text


def _prompt(**group_fields: Any) -> dict[str, Any]:
    z = 4242
    server_c = pow(z, KEY.e, KEY.n).to_bytes(SIZE, "big")
    group: dict[str, Any] = {
        "tgId": 1,
        "testType": "VAL",
        "scheme": KAS1,
        "kasRole": "responder",
        "tests": [
            {
                "tcId": 1,
                "iutN": _hex(KEY.n),
                "iutE": _hex(KEY.e),
                "iutD": _hex(KEY.d),
                "iutP": _hex(KEY.p),
                "iutQ": _hex(KEY.q),
                "serverC": server_c.hex().upper(),
                "z": z.to_bytes(SIZE, "big").hex().upper(),
            }
        ],
    }
    group.update(group_fields)
    return {
        "vsId": 1,
        "algorithm": "KAS-IFC-SSC",
        "revision": "Sp800-56Br2",
        "testGroups": [group],
    }


def _verdict(value: bool) -> dict[str, Any]:
    return {"vsId": 1, "testGroups": [{"tgId": 1, "tests": [{"tcId": 1, "testPassed": value}]}]}


def test_a_val_case_that_agrees_passes() -> None:
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(_prompt()),
        algorithm.parse_expected_results(_verdict(True)),
        provider(),
    )
    assert [r.status for r in results] == [ResultStatus.PASS]


def test_a_corrupted_secret_is_agreed_to_fail() -> None:
    prompt = _prompt()
    prompt["testGroups"][0]["tests"][0]["z"] = "00" * SIZE
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(prompt),
        algorithm.parse_expected_results(_verdict(False)),
        provider(),
    )
    assert results[0].status is ResultStatus.PASS


def test_disagreeing_with_the_recorded_verdict_fails() -> None:
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(_prompt()),
        algorithm.parse_expected_results(_verdict(False)),
        provider(),
    )
    assert results[0].status is ResultStatus.FAIL


def test_an_originating_case_is_declined_with_its_reason() -> None:
    prompt = _prompt(testType="AFT", kasRole="initiator")
    results = algorithm.run_vector_set(algorithm.parse_vector_set(prompt), {}, provider())
    assert results[0].status is ResultStatus.UNSUPPORTED
    assert results[0].diagnostic is not None
    assert "submit to ACVTS" in results[0].diagnostic


def test_a_recover_only_aft_case_is_checked() -> None:
    prompt = _prompt(testType="AFT", kasRole="responder", scheme=KAS1)
    z = prompt["testGroups"][0]["tests"][0].pop("z")
    expected = {"vsId": 1, "testGroups": [{"tgId": 1, "tests": [{"tcId": 1, "z": z}]}]}
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(prompt),
        algorithm.parse_expected_results(expected),
        provider(),
    )
    assert [r.status for r in results] == [ResultStatus.PASS]


def test_an_unknown_scheme_is_declined() -> None:
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(_prompt(scheme="KAS3")),
        algorithm.parse_expected_results(_verdict(True)),
        provider(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_a_case_with_no_recorded_result_is_declined() -> None:
    results = algorithm.run_vector_set(algorithm.parse_vector_set(_prompt()), {}, provider())
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_a_harness_declining_is_unsupported_not_an_error() -> None:
    class Declining(CryptographyKasIfc):
        def recover(self, **kwargs: Any) -> bytes:
            raise HarnessUnsupportedError("declined")

    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(_prompt()),
        algorithm.parse_expected_results(_verdict(True)),
        Declining(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_an_impossible_case_is_declined_rather_than_raising() -> None:
    class Refusing(CryptographyKasIfc):
        def recover(self, **kwargs: Any) -> bytes:
            raise ValueError("not a residue modulo n")

    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(_prompt()),
        algorithm.parse_expected_results(_verdict(True)),
        Refusing(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_parsing_rejects_an_unrelated_algorithm() -> None:
    prompt = _prompt()
    prompt["algorithm"] = "KAS-ECC-SSC"
    with pytest.raises(AcvpValidationError):
        algorithm.parse_vector_set(prompt)


def test_files_load_and_report_their_provider(tmp_path: Path) -> None:
    prompt = tmp_path / "prompt.json"
    expected = tmp_path / "expectedResults.json"
    prompt.write_text(json.dumps(_prompt()), encoding="utf-8")
    expected.write_text(json.dumps(_verdict(True)), encoding="utf-8")
    assert algorithm.load_vector_set(prompt).vs_id == 1
    assert algorithm.load_expected_results(expected)[(1, 1)]["testPassed"] is True
    built = algorithm.provider_for(None, 1.0)
    assert isinstance(built, CryptographyKasIfc)
    assert algorithm.metadata_for(built).name == "cryptography-kas-ifc"
    assert isinstance(algorithm.provider_for("true", 1.0), SubprocessKasIfc)


class _Recording(SubprocessKasIfc):
    def __init__(self, reply: Mapping[str, object]) -> None:  # noqa: D107
        self.requests: list[dict[str, object]] = []
        self._reply = reply

    def invoke(self, request: Mapping[str, object]) -> Mapping[str, object]:
        self.requests.append(dict(request))
        return self._reply


def test_the_wire_sends_the_whole_private_key_for_a_recovery() -> None:
    """A harness cannot decrypt without the key ACVP hands the runner."""
    harness = _Recording({"z": "AB" * SIZE})
    harness.recover(key=KEY, ciphertext=b"\x01" * SIZE)
    request = harness.requests[0]
    assert request["operation"] == "kas-ifc-recover"
    assert {"iutN", "iutE", "iutD", "iutP", "iutQ"} <= set(request)


def test_every_integer_on_the_wire_has_an_even_hex_length() -> None:
    """`format(65537, "X")` is five digits and `bytes.fromhex` refuses it.

    65537 is the commonest RSA public exponent there is, so a harness parsing
    the obvious way would crash on almost every case.
    """
    harness = _Recording({"z": "AB" * SIZE, "c": "CD" * SIZE, "dkm": "EF" * 32})
    harness.recover(key=KEY, ciphertext=b"\x01" * SIZE)
    harness.originate(peer_n=KEY.n, peer_e=65537)
    harness.oaep_encrypt(peer_n=KEY.n, peer_e=65537, hash_alg="SHA2-256", length_bytes=32)
    for request in harness.requests:
        for field, value in request.items():
            if field in {"operation", "hashAlg", "keyLen"}:
                continue
            assert isinstance(value, str)
            assert len(value) % 2 == 0, f"{field} has an odd hex length: {value!r}"
            bytes.fromhex(value)


def test_the_wire_covers_all_four_operations() -> None:
    harness = _Recording({"z": "AB" * SIZE, "c": "CD" * SIZE, "dkm": "EF" * 32})
    harness.recover(key=KEY, ciphertext=b"\x01" * SIZE)
    harness.originate(peer_n=KEY.n, peer_e=KEY.e)
    harness.oaep_decrypt(key=KEY, ciphertext=b"\x01" * SIZE, hash_alg="SHA2-256")
    harness.oaep_encrypt(peer_n=KEY.n, peer_e=KEY.e, hash_alg="SHA2-256", length_bytes=32)
    assert [r["operation"] for r in harness.requests] == [
        "kas-ifc-recover",
        "kas-ifc-originate",
        "kts-ifc-decrypt",
        "kts-ifc-encrypt",
    ]
    assert harness.requests[3]["keyLen"] == 256


def _kts_prompt(**group_fields: Any) -> dict[str, Any]:
    dkm, ciphertext = provider().oaep_encrypt(
        peer_n=KEY.n, peer_e=KEY.e, hash_alg="SHA2-256", length_bytes=32
    )
    group: dict[str, Any] = {
        "tgId": 1,
        "testType": "AFT",
        "scheme": "KTS-OAEP-basic",
        "kasRole": "responder",
        "l": 256,
        "ktsConfiguration": {"hashAlg": "SHA2-256"},
        "tests": [
            {
                "tcId": 1,
                "iutN": _hex(KEY.n),
                "iutE": _hex(KEY.e),
                "iutD": _hex(KEY.d),
                "iutP": _hex(KEY.p),
                "iutQ": _hex(KEY.q),
                "serverC": ciphertext.hex().upper(),
            }
        ],
    }
    group.update(group_fields)
    return {
        "vsId": 2,
        "algorithm": "KTS-IFC",
        "revision": "Sp800-56Br2",
        "testGroups": [group],
        "_dkm": dkm.hex().upper(),
    }


def test_a_kts_recovery_case_is_checked() -> None:
    prompt = _kts_prompt()
    expected = {
        "vsId": 2,
        "testGroups": [{"tgId": 1, "tests": [{"tcId": 1, "dkm": prompt.pop("_dkm")}]}],
    }
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(prompt),
        algorithm.parse_expected_results(expected),
        provider(),
    )
    assert [r.status for r in results] == [ResultStatus.PASS]


def test_a_wrong_kts_recovery_fails() -> None:
    prompt = _kts_prompt()
    prompt.pop("_dkm")
    expected = {"vsId": 2, "testGroups": [{"tgId": 1, "tests": [{"tcId": 1, "dkm": "00" * 32}]}]}
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(prompt),
        algorithm.parse_expected_results(expected),
        provider(),
    )
    assert results[0].status is ResultStatus.FAIL
    assert results[0].diagnostic == "dkm differs"


def test_a_kts_case_with_no_recorded_dkm_is_declined() -> None:
    prompt = _kts_prompt()
    prompt.pop("_dkm")
    expected = {"vsId": 2, "testGroups": [{"tgId": 1, "tests": [{"tcId": 1}]}]}
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(prompt),
        algorithm.parse_expected_results(expected),
        provider(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_a_kts_group_without_a_hash_is_declined() -> None:
    prompt = _kts_prompt(ktsConfiguration={})
    prompt.pop("_dkm")
    expected = {"vsId": 2, "testGroups": [{"tgId": 1, "tests": [{"tcId": 1, "dkm": "00" * 32}]}]}
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(prompt),
        algorithm.parse_expected_results(expected),
        provider(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_an_aft_case_with_no_recorded_z_is_declined() -> None:
    prompt = _prompt(testType="AFT", kasRole="responder", scheme=KAS1)
    prompt["testGroups"][0]["tests"][0].pop("z")
    expected = {"vsId": 1, "testGroups": [{"tgId": 1, "tests": [{"tcId": 1}]}]}
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(prompt),
        algorithm.parse_expected_results(expected),
        provider(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_a_val_case_with_no_recorded_verdict_is_declined() -> None:
    expected = {"vsId": 1, "testGroups": [{"tgId": 1, "tests": [{"tcId": 1}]}]}
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(_prompt()),
        algorithm.parse_expected_results(expected),
        provider(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_a_val_case_with_no_claimed_secret_is_declined() -> None:
    prompt = _prompt()
    prompt["testGroups"][0]["tests"][0].pop("z")
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(prompt),
        algorithm.parse_expected_results(_verdict(True)),
        provider(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_the_second_val_condition_is_checked_when_the_case_carries_it() -> None:
    """An initiator VAL case offers two checks; a corrupted iutC must fail.

    NIST's own vectors never separate the two conditions -- across nine failing
    cases none broke only one -- so this is the only place the second one is
    exercised on its own.
    """
    z = 4242
    prompt = _prompt(kasRole="initiator", scheme=KAS1)
    case = prompt["testGroups"][0]["tests"][0]
    case["iutZ"] = z.to_bytes(SIZE, "big").hex().upper()
    case["serverN"] = _hex(KEY.n)
    case["serverE"] = _hex(KEY.e)
    case["iutC"] = "11" * SIZE  # not the encryption of iutZ
    case["z"] = z.to_bytes(SIZE, "big").hex().upper()
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(prompt),
        algorithm.parse_expected_results(_verdict(False)),
        provider(),
    )
    assert results[0].status is ResultStatus.PASS  # we agree it should fail


def test_an_initiator_val_case_without_a_peer_key_is_declined() -> None:
    prompt = _prompt(kasRole="initiator", scheme=KAS1)
    case = prompt["testGroups"][0]["tests"][0]
    case["iutZ"] = (4242).to_bytes(SIZE, "big").hex().upper()
    case["iutC"] = "11" * SIZE
    case["z"] = (4242).to_bytes(SIZE, "big").hex().upper()
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(prompt),
        algorithm.parse_expected_results(_verdict(True)),
        provider(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_a_group_with_no_kts_configuration_parses() -> None:
    """KAS groups have no ktsConfiguration at all; that is not an error."""
    parsed = algorithm.parse_vector_set(_prompt())
    assert parsed.groups[0].hash_alg is None


def test_a_case_without_a_full_key_reports_no_key() -> None:
    prompt = _prompt()
    prompt["testGroups"][0]["tests"][0].pop("iutQ")
    assert algorithm.parse_vector_set(prompt).groups[0].tests[0].iut_key is None
