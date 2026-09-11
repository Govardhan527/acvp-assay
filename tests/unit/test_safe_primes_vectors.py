"""Parsing and execution for safePrimes and KAS-FFC-SSC vector sets.

The arithmetic is covered in ``test_generated_key_ranges.py``. What is covered
here is the layer around it, and one property in particular: the cases this
runner *cannot* check must come back UNSUPPORTED carrying the reason, never as
a quiet pass. Both families have such cases -- safePrimes keyGen and the KAS
AFT groups -- and session 766220 is the standing proof that treating them as
green would be wrong.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from acvp_assay.algorithms import kas_ffc as ffc_algorithm
from acvp_assay.algorithms import safe_primes as sp_algorithm
from acvp_assay.models import DeclineReason, ResultStatus
from acvp_assay.parser import AcvpValidationError
from acvp_assay.providers.kas_ffc import PythonKasFfc, SubprocessKasFfc
from acvp_assay.providers.safe_primes import (
    SAFE_PRIME_GROUPS,
    PythonSafePrimes,
    SubprocessSafePrimes,
)
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

GROUP = "MODP-2048"
PRIME = SAFE_PRIME_GROUPS[GROUP]
SIZE = (PRIME.bit_length() + 7) // 8


def _pair() -> tuple[bytes, bytes]:
    return PythonSafePrimes().key_gen(group=GROUP)


def _sp_prompt(mode: str, cases: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "vsId": 11,
        "algorithm": "safePrimes",
        "mode": mode,
        "revision": "1.0",
        "testGroups": [{"tgId": 3, "testType": "AFT", "safePrimeGroup": GROUP, "tests": cases}],
    }


def _verdicts(*verdicts: bool) -> dict[str, Any]:
    return {
        "vsId": 11,
        "testGroups": [
            {
                "tgId": 3,
                "tests": [
                    {"tcId": index + 1, "testPassed": value} for index, value in enumerate(verdicts)
                ],
            }
        ],
    }


# --------------------------------------------------------------------- safePrimes


def test_key_gen_is_declined_with_its_reason_never_passed() -> None:
    """The case NIST rejected in 766220. A pass here would hide it."""
    prompt = _sp_prompt("keyGen", [{"tcId": 1}, {"tcId": 2}])
    results = sp_algorithm.run_vector_set(
        sp_algorithm.parse_vector_set(prompt), {}, PythonSafePrimes()
    )
    assert [r.status for r in results] == [ResultStatus.UNSUPPORTED] * 2
    assert results[0].diagnostic is not None
    assert "submit to ACVTS" in results[0].diagnostic
    # A limitation of the method, and only that. The code must not blame the
    # implementation or the vector, and must not read as a gap in this runner.
    assert {r.decline_reason for r in results} == {DeclineReason.OFFLINE_UNDECIDABLE}


def test_key_ver_agrees_with_a_recorded_verdict() -> None:
    x, y = _pair()
    prompt = _sp_prompt("keyVer", [{"tcId": 1, "x": x.hex(), "y": y.hex()}])
    results = sp_algorithm.run_vector_set(
        sp_algorithm.parse_vector_set(prompt),
        sp_algorithm.parse_expected_results(_verdicts(True)),
        PythonSafePrimes(),
    )
    assert results[0].status is ResultStatus.PASS


def test_key_ver_disagreeing_with_the_recorded_verdict_fails() -> None:
    x, y = _pair()
    prompt = _sp_prompt("keyVer", [{"tcId": 1, "x": x.hex(), "y": y.hex()}])
    results = sp_algorithm.run_vector_set(
        sp_algorithm.parse_vector_set(prompt),
        sp_algorithm.parse_expected_results(_verdicts(False)),
        PythonSafePrimes(),
    )
    assert results[0].status is ResultStatus.FAIL
    assert results[0].diagnostic is not None
    assert "testPassed=False" in results[0].diagnostic


def test_a_wrong_public_key_is_rejected_as_the_server_would() -> None:
    x, _ = _pair()
    wrong = (2).to_bytes(SIZE, "big")
    prompt = _sp_prompt("keyVer", [{"tcId": 1, "x": x.hex(), "y": wrong.hex()}])
    results = sp_algorithm.run_vector_set(
        sp_algorithm.parse_vector_set(prompt),
        sp_algorithm.parse_expected_results(_verdicts(False)),
        PythonSafePrimes(),
    )
    assert results[0].status is ResultStatus.PASS  # we agree it should fail


def test_an_unknown_group_is_declined() -> None:
    prompt = _sp_prompt("keyVer", [{"tcId": 1, "x": "01", "y": "02"}])
    prompt["testGroups"][0]["safePrimeGroup"] = "modp-8192"
    results = sp_algorithm.run_vector_set(
        sp_algorithm.parse_vector_set(prompt),
        sp_algorithm.parse_expected_results(_verdicts(True)),
        PythonSafePrimes(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_a_key_ver_case_missing_a_value_is_declined() -> None:
    prompt = _sp_prompt("keyVer", [{"tcId": 1, "x": "01"}])
    results = sp_algorithm.run_vector_set(
        sp_algorithm.parse_vector_set(prompt),
        sp_algorithm.parse_expected_results(_verdicts(True)),
        PythonSafePrimes(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_a_case_with_no_recorded_verdict_is_declined() -> None:
    x, y = _pair()
    prompt = _sp_prompt("keyVer", [{"tcId": 1, "x": x.hex(), "y": y.hex()}])
    results = sp_algorithm.run_vector_set(
        sp_algorithm.parse_vector_set(prompt), {}, PythonSafePrimes()
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_a_harness_declining_is_unsupported_not_an_error() -> None:
    class Declining(PythonSafePrimes):
        def key_ver(self, **kwargs: Any) -> bool:
            raise HarnessUnsupportedError("declined")

    x, y = _pair()
    prompt = _sp_prompt("keyVer", [{"tcId": 1, "x": x.hex(), "y": y.hex()}])
    results = sp_algorithm.run_vector_set(
        sp_algorithm.parse_vector_set(prompt),
        sp_algorithm.parse_expected_results(_verdicts(True)),
        Declining(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_safe_primes_parsing_rejects_the_wrong_algorithm_or_mode() -> None:
    prompt = _sp_prompt("keyVer", [{"tcId": 1, "x": "01", "y": "02"}])
    prompt["algorithm"] = "KAS-FFC-SSC"
    with pytest.raises(AcvpValidationError):
        sp_algorithm.parse_vector_set(prompt)
    prompt = _sp_prompt("keySwap", [{"tcId": 1, "x": "01", "y": "02"}])
    with pytest.raises(AcvpValidationError):
        sp_algorithm.parse_vector_set(prompt)


def test_safe_primes_files_load_and_report_their_provider(tmp_path: Path) -> None:
    x, y = _pair()
    prompt = tmp_path / "prompt.json"
    expected = tmp_path / "expectedResults.json"
    prompt.write_text(
        json.dumps(_sp_prompt("keyVer", [{"tcId": 1, "x": x.hex(), "y": y.hex()}])),
        encoding="utf-8",
    )
    expected.write_text(json.dumps(_verdicts(True)), encoding="utf-8")
    assert sp_algorithm.load_vector_set(prompt).vs_id == 11
    assert sp_algorithm.load_expected_results(expected)[(3, 1)]["testPassed"] is True
    provider = sp_algorithm.provider_for(None, 1.0)
    assert isinstance(provider, PythonSafePrimes)
    assert sp_algorithm.metadata_for(provider).name == "python-safe-primes"
    assert isinstance(sp_algorithm.provider_for("true", 1.0), SubprocessSafePrimes)


# --------------------------------------------------------------------- KAS-FFC-SSC


def _ffc_prompt(test_type: str, cases: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "vsId": 12,
        "algorithm": "KAS-FFC-SSC",
        "revision": "Sp800-56Ar3",
        "testGroups": [
            {
                "tgId": 4,
                "testType": test_type,
                "scheme": "dhEphem",
                "kasRole": "initiator",
                "domainParameterGenerationMode": GROUP,
                "tests": cases,
            }
        ],
    }


def _ffc_verdicts(*verdicts: bool) -> dict[str, Any]:
    return {
        "vsId": 12,
        "testGroups": [
            {
                "tgId": 4,
                "tests": [
                    {"tcId": index + 1, "testPassed": value} for index, value in enumerate(verdicts)
                ],
            }
        ],
    }


def _ffc_case() -> dict[str, Any]:
    provider = PythonKasFfc()
    private, _ = provider.generate(group=GROUP)
    _, peer_public = provider.generate(group=GROUP)
    z = provider.shared_secret(group=GROUP, private_key=private, peer_public=peer_public)
    return {
        "tcId": 1,
        "ephemeralPrivateIut": private.hex(),
        "ephemeralPublicServer": peer_public.hex(),
        "z": z.hex(),
    }


def test_kas_ffc_aft_is_declined_with_its_reason() -> None:
    results = ffc_algorithm.run_vector_set(
        ffc_algorithm.parse_vector_set(_ffc_prompt("AFT", [_ffc_case()])), {}, PythonKasFfc()
    )
    assert results[0].status is ResultStatus.UNSUPPORTED
    assert results[0].diagnostic is not None
    assert "submit to ACVTS" in results[0].diagnostic


def test_kas_ffc_val_agrees_with_a_recorded_verdict() -> None:
    results = ffc_algorithm.run_vector_set(
        ffc_algorithm.parse_vector_set(_ffc_prompt("VAL", [_ffc_case()])),
        ffc_algorithm.parse_expected_results(_ffc_verdicts(True)),
        PythonKasFfc(),
    )
    assert results[0].status is ResultStatus.PASS


def test_kas_ffc_val_with_a_corrupted_z_agrees_it_should_fail() -> None:
    case = _ffc_case()
    case["z"] = "00" * SIZE
    results = ffc_algorithm.run_vector_set(
        ffc_algorithm.parse_vector_set(_ffc_prompt("VAL", [case])),
        ffc_algorithm.parse_expected_results(_ffc_verdicts(False)),
        PythonKasFfc(),
    )
    assert results[0].status is ResultStatus.PASS


def test_a_peer_key_outside_the_range_is_a_failing_case_not_an_error() -> None:
    """1 and p-1 look like keys and are useless; neither should raise."""
    case = _ffc_case()
    case["ephemeralPublicServer"] = (1).to_bytes(SIZE, "big").hex()
    results = ffc_algorithm.run_vector_set(
        ffc_algorithm.parse_vector_set(_ffc_prompt("VAL", [case])),
        ffc_algorithm.parse_expected_results(_ffc_verdicts(False)),
        PythonKasFfc(),
    )
    assert results[0].status is ResultStatus.PASS


@pytest.mark.parametrize(
    ("field", "value"),
    [("scheme", "dhHybrid1"), ("testType", "GDT"), ("domainParameterGenerationMode", "modp-8192")],
)
def test_an_unsupported_group_property_is_declined(field: str, value: str) -> None:
    prompt = _ffc_prompt("VAL", [_ffc_case()])
    prompt["testGroups"][0][field] = value
    results = ffc_algorithm.run_vector_set(
        ffc_algorithm.parse_vector_set(prompt),
        ffc_algorithm.parse_expected_results(_ffc_verdicts(True)),
        PythonKasFfc(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_a_val_case_missing_a_value_is_declined() -> None:
    case = _ffc_case()
    del case["z"]
    results = ffc_algorithm.run_vector_set(
        ffc_algorithm.parse_vector_set(_ffc_prompt("VAL", [case])),
        ffc_algorithm.parse_expected_results(_ffc_verdicts(True)),
        PythonKasFfc(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_a_val_case_with_no_recorded_verdict_is_declined() -> None:
    results = ffc_algorithm.run_vector_set(
        ffc_algorithm.parse_vector_set(_ffc_prompt("VAL", [_ffc_case()])), {}, PythonKasFfc()
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_a_kas_harness_declining_is_unsupported_not_an_error() -> None:
    class Declining(PythonKasFfc):
        def shared_secret(self, **kwargs: Any) -> bytes:
            raise HarnessUnsupportedError("declined")

    results = ffc_algorithm.run_vector_set(
        ffc_algorithm.parse_vector_set(_ffc_prompt("VAL", [_ffc_case()])),
        ffc_algorithm.parse_expected_results(_ffc_verdicts(True)),
        Declining(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_kas_ffc_parsing_rejects_the_wrong_algorithm() -> None:
    prompt = _ffc_prompt("VAL", [_ffc_case()])
    prompt["algorithm"] = "KAS-ECC-SSC"
    with pytest.raises(AcvpValidationError):
        ffc_algorithm.parse_vector_set(prompt)


def test_kas_ffc_files_load_and_report_their_provider(tmp_path: Path) -> None:
    prompt = tmp_path / "prompt.json"
    expected = tmp_path / "expectedResults.json"
    prompt.write_text(json.dumps(_ffc_prompt("VAL", [_ffc_case()])), encoding="utf-8")
    expected.write_text(json.dumps(_ffc_verdicts(True)), encoding="utf-8")
    assert ffc_algorithm.load_vector_set(prompt).vs_id == 12
    assert ffc_algorithm.load_expected_results(expected)[(4, 1)]["testPassed"] is True
    provider = ffc_algorithm.provider_for(None, 1.0)
    assert isinstance(provider, PythonKasFfc)
    assert ffc_algorithm.metadata_for(provider).name == "python-kas-ffc-ssc"
    assert isinstance(ffc_algorithm.provider_for("true", 1.0), SubprocessKasFfc)


# --------------------------------------------------------------------- the wire


class _RecordingSafePrimes(SubprocessSafePrimes):
    def __init__(self, reply: Mapping[str, object]) -> None:  # noqa: D107
        self.requests: list[dict[str, object]] = []
        self._reply = reply

    def invoke(self, request: Mapping[str, object]) -> Mapping[str, object]:
        self.requests.append(dict(request))
        return self._reply


class _RecordingKasFfc(SubprocessKasFfc):
    def __init__(self, reply: Mapping[str, object]) -> None:  # noqa: D107
        self.requests: list[dict[str, object]] = []
        self._reply = reply

    def invoke(self, request: Mapping[str, object]) -> Mapping[str, object]:
        self.requests.append(dict(request))
        return self._reply


def test_the_safe_primes_wire_names_the_group_and_returns_a_pair() -> None:
    harness = _RecordingSafePrimes({"x": "0A", "y": "0B"})
    assert harness.key_gen(group=GROUP) == (b"\x0a", b"\x0b")
    assert harness.requests[0] == {"operation": "safe-primes-keygen", "safePrimeGroup": GROUP}


def test_the_safe_primes_wire_carries_a_verdict() -> None:
    harness = _RecordingSafePrimes({"testPassed": True})
    assert harness.key_ver(group=GROUP, x=b"\x01", y=b"\x02") is True
    assert harness.requests[0]["operation"] == "safe-primes-keyver"
    assert harness.requests[0]["x"] == "01"


def test_a_harness_verdict_that_is_not_a_boolean_is_refused() -> None:
    """ "true" is not True. Coercing it would invent a verdict."""
    harness = _RecordingSafePrimes({"testPassed": "true"})
    with pytest.raises(ValueError, match="boolean testPassed"):
        harness.key_ver(group=GROUP, x=b"\x01", y=b"\x02")


def test_the_kas_ffc_wire_carries_both_operations() -> None:
    harness = _RecordingKasFfc({"z": "0C", "privateKey": "0D", "publicKey": "0E"})
    assert harness.supports(group="anything at all") is True
    assert harness.shared_secret(group=GROUP, private_key=b"\x01", peer_public=b"\x02") == b"\x0c"
    assert harness.generate(group=GROUP) == (b"\x0d", b"\x0e")
    assert [r["operation"] for r in harness.requests] == ["kas-ffc-ssc", "kas-ffc-keygen"]


def test_the_built_in_provider_refuses_a_group_it_does_not_know() -> None:
    assert PythonKasFfc().supports(group=GROUP) is True
    assert PythonKasFfc().supports(group="modp-8192") is False


def test_both_families_agree_on_the_group_names_they_offer() -> None:
    """One table serves both, which is why they were built together."""
    from acvp_assay.providers.kas_ffc import supported_groups
    from acvp_assay.providers.safe_primes import group_names

    assert group_names() == supported_groups() == tuple(SAFE_PRIME_GROUPS)
    assert set(group_names()) == {
        "MODP-2048",
        "MODP-3072",
        "MODP-4096",
        "ffdhe2048",
        "ffdhe3072",
        "ffdhe4096",
    }


@pytest.mark.parametrize("public", [0, 1])
def test_a_public_key_at_the_bottom_of_the_range_is_rejected(public: int) -> None:
    """1 is a subgroup element whose "secret" is no secret; 0 is not a key.

    NIST's own keyVer vectors never present one -- all 18 of their failing cases
    are simply a y that is not g^x -- so this boundary is checked here or not at
    all.
    """
    x, _ = _pair()
    assert not PythonSafePrimes().key_ver(group=GROUP, x=x, y=public.to_bytes(SIZE, "big"))


def test_a_public_key_at_the_top_of_the_range_is_rejected() -> None:
    x, _ = _pair()
    assert not PythonSafePrimes().key_ver(group=GROUP, x=x, y=(PRIME - 1).to_bytes(SIZE, "big"))
