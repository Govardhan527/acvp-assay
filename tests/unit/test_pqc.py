"""Tests for ML-KEM and ML-DSA vector handling.

There is no local ML-KEM or ML-DSA implementation to test against — the pinned
``cryptography`` has neither — so correctness of the *cryptography* is not
claimed here. What is verified is the plumbing: that real NIST vector files
parse into the right shapes, that each function is routed to the right
comparison, and that disagreements are caught rather than swallowed. A stub
provider replays NIST's own expected values to exercise the passing path, and
a deliberately wrong stub proves failures surface.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from acvp_assay.algorithms import UnsupportedAlgorithmError, pqc, run_vector_file
from acvp_assay.models import ResultStatus
from acvp_assay.parser import AcvpValidationError
from acvp_assay.providers.pqc import (
    MlDsaProvider,
    MlKemProvider,
    SubprocessMlDsaProvider,
    SubprocessMlKemProvider,
)

ROOT = Path(__file__).resolve().parents[2]
ML_KEM = ROOT / "vectors/ML-KEM-encapDecap-FIPS203"
ML_DSA = ROOT / "vectors/ML-DSA-sigVer-FIPS204"

requires_ml_kem = pytest.mark.skipif(
    not (ML_KEM / "prompt.json").is_file(), reason="pinned ML-KEM vectors absent"
)
requires_ml_dsa = pytest.mark.skipif(
    not (ML_DSA / "prompt.json").is_file(), reason="pinned ML-DSA vectors absent"
)


class ReplayingKemProvider:
    """Stub that answers from NIST's own expected results, keyed by input.

    It resolves by the inputs it is handed rather than by case index, exactly
    as a real implementation must: nothing about the case identity is visible
    across the provider boundary.
    """

    def __init__(
        self,
        vector_set: pqc.PqcVectorSet,
        expected: pqc.PqcExpectedSet,
        *,
        corrupt: bool = False,
    ) -> None:
        self._corrupt = corrupt
        self._encap: dict[tuple[bytes, bytes], tuple[bytes, bytes]] = {}
        self._decap: dict[tuple[bytes, bytes], bytes] = {}
        self._checks: dict[bytes, bool] = {}
        for group in vector_set.test_groups:
            for case in group.tests:
                answer = expected.cases[(group.tg_id, case.tc_id)]
                if group.function == "encapsulation":
                    self._encap[(case.fields["ek"], case.fields["m"])] = (
                        answer.values["c"],
                        answer.values["k"],
                    )
                elif group.function == "decapsulation":
                    self._decap[(case.fields["dk"], case.fields["c"])] = answer.values["k"]
                elif answer.test_passed is not None:
                    key_type = "ek" if group.function == "encapsulationKeyCheck" else "dk"
                    self._checks[case.fields[key_type]] = answer.test_passed

    @staticmethod
    def metadata() -> Any:
        from acvp_assay.models import ProviderMetadata

        return ProviderMetadata("stub", "stub", "0", "stub", "0")

    def _spoil(self, value: bytes) -> bytes:
        return bytes([value[0] ^ 0xFF]) + value[1:] if self._corrupt else value

    def encapsulate(
        self, *, parameter_set: str, encapsulation_key: bytes, seed: bytes
    ) -> tuple[bytes, bytes]:
        ciphertext, shared = self._encap[(encapsulation_key, seed)]
        return self._spoil(ciphertext), self._spoil(shared)

    def decapsulate(
        self, *, parameter_set: str, decapsulation_key: bytes, ciphertext: bytes
    ) -> bytes:
        return self._spoil(self._decap[(decapsulation_key, ciphertext)])

    def check_key(self, *, parameter_set: str, key_type: str, key: bytes) -> bool:
        verdict = self._checks[key]
        return not verdict if self._corrupt else verdict


class UnusedKemProvider:
    """KEM stub for paths that must decline before any operation is attempted."""

    def metadata(self) -> Any:
        from acvp_assay.models import ProviderMetadata

        return ProviderMetadata("stub", "stub", "0", "stub", "0")

    def encapsulate(
        self, *, parameter_set: str, encapsulation_key: bytes, seed: bytes
    ) -> tuple[bytes, bytes]:
        raise AssertionError("provider must not be called for a declined case")

    def decapsulate(
        self, *, parameter_set: str, decapsulation_key: bytes, ciphertext: bytes
    ) -> bytes:
        raise AssertionError("provider must not be called for a declined case")

    def check_key(self, *, parameter_set: str, key_type: str, key: bytes) -> bool:
        raise AssertionError("provider must not be called for a declined case")


class FixedDsaProvider:
    """Stub whose verification verdict is fixed in advance."""

    def __init__(self, verdict: bool) -> None:
        self._verdict = verdict

    def metadata(self) -> Any:
        from acvp_assay.models import ProviderMetadata

        return ProviderMetadata("stub", "stub", "0", "stub", "0")

    def verify(
        self,
        *,
        parameter_set: str,
        public_key: bytes,
        message: bytes,
        signature: bytes,
        context: bytes,
        signature_interface: str = "external",
    ) -> bool:
        return self._verdict


def test_stubs_satisfy_the_provider_protocols() -> None:
    """The protocols are structural, so any conforming object can be a provider."""
    assert isinstance(FixedDsaProvider(True), MlDsaProvider)
    empty = pqc.PqcVectorSet(1, "ML-KEM", "FIPS203", "encapDecap", ())
    assert isinstance(
        ReplayingKemProvider(empty, pqc.PqcExpectedSet(vs_id=1, cases={})), MlKemProvider
    )


# --- parsing real NIST files ----------------------------------------------


@requires_ml_kem
def test_ml_kem_vectors_parse_into_all_four_functions() -> None:
    """The real encapDecap file exercises every ML-KEM function shape."""
    vector_set = pqc.load_vector_set(ML_KEM / "prompt.json")
    expected = pqc.load_expected_results(ML_KEM / "expectedResults.json")

    functions = {group.function for group in vector_set.test_groups}
    assert functions == {
        "encapsulation",
        "decapsulation",
        "encapsulationKeyCheck",
        "decapsulationKeyCheck",
    }
    assert sum(1 for case in expected.cases.values() if case.test_passed is not None) == 60
    assert sum(1 for case in expected.cases.values() if case.values) == 105


@requires_ml_dsa
def test_ml_dsa_sig_ver_is_entirely_verdict_only() -> None:
    """Every ML-DSA sigVer case is judged on a boolean, never on bytes."""
    expected = pqc.load_expected_results(ML_DSA / "expectedResults.json")

    assert len(expected.cases) == 180
    assert all(case.test_passed is not None for case in expected.cases.values())
    assert all(not case.values for case in expected.cases.values())


@requires_ml_kem
def test_replaying_provider_passes_every_ml_kem_case() -> None:
    """Correct outputs pass across all four functions."""
    vector_set = pqc.load_vector_set(ML_KEM / "prompt.json")
    expected = pqc.load_expected_results(ML_KEM / "expectedResults.json")

    results = pqc.run_ml_kem(vector_set, expected, ReplayingKemProvider(vector_set, expected))

    assert {r.status for r in results} == {ResultStatus.PASS}
    assert len(results) == 165


@requires_ml_kem
def test_wrong_outputs_are_caught_across_every_ml_kem_function() -> None:
    """A provider that returns wrong bytes or wrong verdicts fails, never passes."""
    vector_set = pqc.load_vector_set(ML_KEM / "prompt.json")
    expected = pqc.load_expected_results(ML_KEM / "expectedResults.json")

    results = pqc.run_ml_kem(
        vector_set, expected, ReplayingKemProvider(vector_set, expected, corrupt=True)
    )

    assert ResultStatus.PASS not in {r.status for r in results}
    assert {r.status for r in results} == {ResultStatus.FAIL}


@requires_ml_dsa
def test_ml_dsa_verdicts_are_compared_both_ways() -> None:
    """A fixed-true verifier passes the valid cases and fails the invalid ones."""
    vector_set = pqc.load_vector_set(ML_DSA / "prompt.json")
    expected = pqc.load_expected_results(ML_DSA / "expectedResults.json")

    accepting = pqc.run_ml_dsa(vector_set, expected, FixedDsaProvider(True))
    rejecting = pqc.run_ml_dsa(vector_set, expected, FixedDsaProvider(False))

    executed = [r for r in accepting if r.status is not ResultStatus.UNSUPPORTED]
    accepted_pass = sum(1 for r in accepting if r.status is ResultStatus.PASS)
    rejected_pass = sum(1 for r in rejecting if r.status is ResultStatus.PASS)

    assert executed, "some groups must be executable"
    assert accepted_pass + rejected_pass == len(executed)
    assert accepted_pass and rejected_pass, "the set must contain both verdicts"
    assert any(r.diagnostic == "accepted a signature ACVP declares invalid" for r in accepting)
    assert any(r.diagnostic == "rejected a signature ACVP declares valid" for r in rejecting)


# --- synthetic edge cases --------------------------------------------------


def kem_documents(function: str, parameter_set: str = "ML-KEM-512") -> tuple[Any, Any]:
    """Build a one-case ML-KEM prompt/expected pair for a given function."""
    prompt = {
        "vsId": 1,
        "algorithm": "ML-KEM",
        "revision": "FIPS203",
        "mode": "encapDecap",
        "testGroups": [
            {
                "tgId": 1,
                "parameterSet": parameter_set,
                "function": function,
                "tests": [{"tcId": 1, "ek": "AABB", "dk": "CCDD", "c": "EEFF", "m": "0011"}],
            }
        ],
    }
    expected = {
        "vsId": 1,
        "testGroups": [{"tgId": 1, "tests": [{"tcId": 1, "c": "EEFF", "k": "2233"}]}],
    }
    return prompt, expected


def test_unsupported_parameter_set_is_declared() -> None:
    """A parameter set outside FIPS 203 is declared rather than attempted."""
    prompt, expected = kem_documents("encapsulation", parameter_set="ML-KEM-9999")

    results = pqc.run_ml_kem(
        pqc.parse_vector_set(prompt), pqc.parse_expected_results(expected), UnusedKemProvider()
    )

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "ML-KEM-9999" in (results[0].diagnostic or "")


def test_unknown_function_is_declared() -> None:
    """An ML-KEM function this runner does not implement is declared."""
    prompt, expected = kem_documents("keyGen")

    results = pqc.run_ml_kem(
        pqc.parse_vector_set(prompt), pqc.parse_expected_results(expected), UnusedKemProvider()
    )

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "function 'keyGen'" in (results[0].diagnostic or "")


def test_missing_expected_entries_are_declared() -> None:
    """Cases with nothing recorded to compare against are declared."""
    prompt, _ = kem_documents("encapsulation")
    empty = {"vsId": 1, "testGroups": []}

    kem = pqc.run_ml_kem(
        pqc.parse_vector_set(prompt), pqc.parse_expected_results(empty), UnusedKemProvider()
    )
    prompt["algorithm"] = "ML-DSA"
    prompt["mode"] = "sigVer"
    prompt["testGroups"][0]["parameterSet"] = "ML-DSA-44"
    dsa = pqc.run_ml_dsa(
        pqc.parse_vector_set(prompt), pqc.parse_expected_results(empty), FixedDsaProvider(True)
    )

    assert kem[0].status is ResultStatus.UNSUPPORTED
    assert dsa[0].status is ResultStatus.UNSUPPORTED


def test_key_check_without_a_verdict_is_declared() -> None:
    """A key-check case needs a boolean to be judged against."""
    prompt, _ = kem_documents("encapsulationKeyCheck")
    expected = {"vsId": 1, "testGroups": [{"tgId": 1, "tests": [{"tcId": 1, "k": "2233"}]}]}

    results = pqc.run_ml_kem(
        pqc.parse_vector_set(prompt), pqc.parse_expected_results(expected), UnusedKemProvider()
    )

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert results[0].diagnostic == "no expected verdict recorded"


def test_unsupported_ml_dsa_parameter_set_is_declared() -> None:
    """An ML-DSA parameter set outside FIPS 204 is declared."""
    prompt, expected = kem_documents("sigVer", parameter_set="ML-DSA-99")
    prompt["algorithm"] = "ML-DSA"
    prompt["mode"] = "sigVer"

    results = pqc.run_ml_dsa(
        pqc.parse_vector_set(prompt), pqc.parse_expected_results(expected), FixedDsaProvider(True)
    )

    assert results[0].status is ResultStatus.UNSUPPORTED


def test_parse_rejects_a_non_pqc_algorithm() -> None:
    """Only ML-KEM and ML-DSA are handled by this module."""
    prompt, _ = kem_documents("encapsulation")
    prompt["algorithm"] = "SLH-DSA"

    with pytest.raises(AcvpValidationError, match="unsupported algorithm"):
        pqc.parse_vector_set(prompt)


def test_load_from_files(tmp_path: Path) -> None:
    """The file entry points parse prompt and expected documents."""
    prompt, expected = kem_documents("encapsulation")
    (tmp_path / "prompt.json").write_text(json.dumps(prompt), encoding="utf-8")
    (tmp_path / "expectedResults.json").write_text(json.dumps(expected), encoding="utf-8")

    assert pqc.load_vector_set(tmp_path / "prompt.json").algorithm == "ML-KEM"
    assert pqc.load_expected_results(tmp_path / "expectedResults.json").vs_id == 1


# --- dispatch and the deliberate absence of a built-in provider ------------


def test_pqc_without_a_harness_explains_why(tmp_path: Path) -> None:
    """PQC needs an external implementation, and the error says so plainly."""
    prompt, expected = kem_documents("encapsulation")
    (tmp_path / "prompt.json").write_text(json.dumps(prompt), encoding="utf-8")
    (tmp_path / "expectedResults.json").write_text(json.dumps(expected), encoding="utf-8")

    with pytest.raises(UnsupportedAlgorithmError, match="no built-in provider"):
        run_vector_file(tmp_path / "prompt.json", tmp_path / "expectedResults.json")


def harness(tmp_path: Path, body: str) -> list[str]:
    """Write a one-shot harness script and return its argument vector."""
    script = tmp_path / "pqc_harness.py"
    script.write_text(f"import json, sys\nrequest = json.loads(sys.stdin.read())\n{body}\n")
    return [sys.executable, str(script)]


def test_subprocess_kem_provider_speaks_the_wire_contract(tmp_path: Path) -> None:
    """ML-KEM operations reach an external harness and decode its response."""
    command = harness(
        tmp_path,
        'op = request["operation"]\n'
        'out = {"ml-kem-encapsulate": {"c": "AABB", "k": "CCDD"},\n'
        '       "ml-kem-decapsulate": {"k": "CCDD"},\n'
        '       "ml-kem-key-check": {"testPassed": True}}[op]\n'
        "sys.stdout.write(json.dumps(out))",
    )
    provider = SubprocessMlKemProvider(command)

    assert provider.encapsulate(parameter_set="ML-KEM-512", encapsulation_key=b"", seed=b"") == (
        bytes.fromhex("AABB"),
        bytes.fromhex("CCDD"),
    )
    assert provider.decapsulate(
        parameter_set="ML-KEM-512", decapsulation_key=b"", ciphertext=b""
    ) == bytes.fromhex("CCDD")
    assert provider.check_key(parameter_set="ML-KEM-512", key_type="ek", key=b"")


def test_subprocess_dsa_provider_speaks_the_wire_contract(tmp_path: Path) -> None:
    """ML-DSA verification reaches an external harness and returns its verdict."""
    command = harness(tmp_path, 'sys.stdout.write(json.dumps({"testPassed": False}))')

    verdict = SubprocessMlDsaProvider(command).verify(
        parameter_set="ML-DSA-44",
        public_key=b"",
        message=b"",
        signature=b"",
        context=b"",
    )

    assert verdict is False


def test_non_boolean_verdict_is_a_protocol_error(tmp_path: Path) -> None:
    """A harness must answer a verdict question with a real boolean."""
    from acvp_assay.providers.subprocess_harness import HarnessProtocolError

    command = harness(tmp_path, 'sys.stdout.write(json.dumps({"testPassed": "yes"}))')

    with pytest.raises(HarnessProtocolError, match="boolean"):
        SubprocessMlKemProvider(command).check_key(
            parameter_set="ML-KEM-512", key_type="ek", key=b""
        )


def test_missing_kem_inputs_are_declared() -> None:
    """A case lacking the inputs its function needs is declared, not crashed on."""
    for function, drop in (
        ("encapsulation", "ek"),
        ("decapsulation", "dk"),
        ("encapsulationKeyCheck", "ek"),
    ):
        prompt, expected = kem_documents(function)
        del prompt["testGroups"][0]["tests"][0][drop]
        if function == "encapsulationKeyCheck":
            expected["testGroups"][0]["tests"][0]["testPassed"] = True

        results = pqc.run_ml_kem(
            pqc.parse_vector_set(prompt),
            pqc.parse_expected_results(expected),
            UnusedKemProvider(),
        )

        assert results[0].status is ResultStatus.UNSUPPORTED
        assert "missing" in (results[0].diagnostic or "")


@pytest.mark.parametrize(
    ("mutation", "fragment"),
    [
        ({"externalMu": True}, "externalMu"),
        ({"preHash": "preHash"}, "preHash"),
    ],
)
def test_ml_dsa_modes_outside_the_contract_are_declared(
    mutation: dict[str, Any], fragment: str
) -> None:
    """externalMu and preHash groups are declared rather than misinterpreted."""
    prompt, _ = kem_documents("sigVer", parameter_set="ML-DSA-44")
    prompt["algorithm"] = "ML-DSA"
    prompt["mode"] = "sigVer"
    prompt["testGroups"][0].update(mutation)
    prompt["testGroups"][0]["tests"][0].update({"pk": "AA", "message": "BB", "signature": "CC"})
    expected = {"vsId": 1, "testGroups": [{"tgId": 1, "tests": [{"tcId": 1, "testPassed": True}]}]}

    results = pqc.run_ml_dsa(
        pqc.parse_vector_set(prompt), pqc.parse_expected_results(expected), FixedDsaProvider(True)
    )

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert fragment in (results[0].diagnostic or "")


def test_ml_dsa_missing_fields_are_declared() -> None:
    """A sigVer case must carry the key, message, and signature it is judged on."""
    prompt, _ = kem_documents("sigVer", parameter_set="ML-DSA-44")
    prompt["algorithm"] = "ML-DSA"
    prompt["mode"] = "sigVer"
    expected = {"vsId": 1, "testGroups": [{"tgId": 1, "tests": [{"tcId": 1, "testPassed": True}]}]}

    results = pqc.run_ml_dsa(
        pqc.parse_vector_set(prompt), pqc.parse_expected_results(expected), FixedDsaProvider(True)
    )

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "missing" in (results[0].diagnostic or "")


def test_pqc_dispatch_routes_both_families_through_a_harness(tmp_path: Path) -> None:
    """ML-KEM and ML-DSA both reach an external harness via the CLI dispatcher."""
    script = tmp_path / "h.py"
    script.write_text(
        "import json, sys\n"
        "req = json.loads(sys.stdin.read())\n"
        "op = req['operation']\n"
        "out = {'metadata': {'name': 'stub', 'libraryName': 'stub', 'libraryVersion': '0',\n"
        "                    'backendName': 'stub', 'backendVersion': '0'},\n"
        "       'ml-kem-encapsulate': {'c': 'EEFF', 'k': '2233'},\n"
        "       'ml-dsa-verify': {'testPassed': True}}[op]\n"
        "sys.stdout.write(json.dumps(out))\n"
    )
    command = f"{sys.executable} {script}"

    prompt, expected = kem_documents("encapsulation")
    (tmp_path / "prompt.json").write_text(json.dumps(prompt), encoding="utf-8")
    (tmp_path / "expectedResults.json").write_text(json.dumps(expected), encoding="utf-8")
    kem_results, kem_metadata = run_vector_file(
        tmp_path / "prompt.json", tmp_path / "expectedResults.json", provider_command=command
    )

    dsa_prompt, _ = kem_documents("sigVer", parameter_set="ML-DSA-44")
    dsa_prompt["algorithm"] = "ML-DSA"
    dsa_prompt["mode"] = "sigVer"
    dsa_prompt["testGroups"][0]["tests"][0].update({"pk": "AA", "message": "BB", "signature": "CC"})
    (tmp_path / "prompt.json").write_text(json.dumps(dsa_prompt), encoding="utf-8")
    (tmp_path / "expectedResults.json").write_text(
        json.dumps(
            {"vsId": 1, "testGroups": [{"tgId": 1, "tests": [{"tcId": 1, "testPassed": True}]}]}
        ),
        encoding="utf-8",
    )
    dsa_results, _ = run_vector_file(
        tmp_path / "prompt.json", tmp_path / "expectedResults.json", provider_command=command
    )

    assert kem_metadata.name == "stub"
    assert kem_results[0].status is ResultStatus.PASS
    assert dsa_results[0].status is ResultStatus.PASS


def test_signature_interface_reaches_the_harness(tmp_path: Path) -> None:
    """``signatureInterface`` must cross the boundary, not be assumed external.

    ML-DSA's internal interface omits the domain separator and context prefix
    the external one applies. Dropping this field made nine real NIST cases
    report a conforming implementation as rejecting valid signatures.
    """
    script = tmp_path / "echo.py"
    script.write_text(
        "import json, sys\n"
        "req = json.loads(sys.stdin.read())\n"
        "sys.stdout.write(json.dumps({'testPassed': req['signatureInterface'] == 'internal'}))\n"
    )
    provider = SubprocessMlDsaProvider([sys.executable, str(script)])

    assert provider.verify(
        parameter_set="ML-DSA-44",
        public_key=b"",
        message=b"",
        signature=b"",
        context=b"",
        signature_interface="internal",
    )
    assert not provider.verify(
        parameter_set="ML-DSA-44",
        public_key=b"",
        message=b"",
        signature=b"",
        context=b"",
        signature_interface="external",
    )
