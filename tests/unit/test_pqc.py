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
from typing import Any, cast

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
ML_KEM_KEYGEN = ROOT / "vectors/ML-KEM-keyGen-FIPS203"
ML_DSA_KEYGEN = ROOT / "vectors/ML-DSA-keyGen-FIPS204"
ML_DSA_SIGGEN = ROOT / "vectors/ML-DSA-sigGen-FIPS204"

requires_ml_kem = pytest.mark.skipif(
    not (ML_KEM / "prompt.json").is_file(), reason="pinned ML-KEM vectors absent"
)
requires_ml_dsa = pytest.mark.skipif(
    not (ML_DSA / "prompt.json").is_file(), reason="pinned ML-DSA vectors absent"
)
requires_ml_kem_keygen = pytest.mark.skipif(
    not (ML_KEM_KEYGEN / "prompt.json").is_file(), reason="pinned ML-KEM keyGen vectors absent"
)
requires_ml_dsa_keygen = pytest.mark.skipif(
    not (ML_DSA_KEYGEN / "prompt.json").is_file(), reason="pinned ML-DSA keyGen vectors absent"
)
requires_ml_dsa_siggen = pytest.mark.skipif(
    not (ML_DSA_SIGGEN / "prompt.json").is_file(), reason="pinned ML-DSA sigGen vectors absent"
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
        self._keygen: dict[tuple[bytes, bytes], tuple[bytes, bytes]] = {}
        self._encap: dict[tuple[bytes, bytes], tuple[bytes, bytes]] = {}
        self._decap: dict[tuple[bytes, bytes], bytes] = {}
        self._checks: dict[bytes, bool] = {}
        for group in vector_set.test_groups:
            for case in group.tests:
                answer = expected.cases[(group.tg_id, case.tc_id)]
                if group.function == "keyGen":
                    self._keygen[(case.fields["d"], case.fields["z"])] = (
                        answer.values["ek"],
                        answer.values["dk"],
                    )
                elif group.function == "encapsulation":
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
        from acvp_assay.models import ProviderKind, ProviderMetadata

        return ProviderMetadata("stub", "stub", "0", "stub", "0", ProviderKind.BUILTIN)

    def _spoil(self, value: bytes) -> bytes:
        return bytes([value[0] ^ 0xFF]) + value[1:] if self._corrupt else value

    def generate_key(self, *, parameter_set: str, d: bytes, z: bytes) -> tuple[bytes, bytes]:
        encapsulation, decapsulation = self._keygen[(d, z)]
        return self._spoil(encapsulation), self._spoil(decapsulation)

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
        from acvp_assay.models import ProviderKind, ProviderMetadata

        return ProviderMetadata("stub", "stub", "0", "stub", "0", ProviderKind.BUILTIN)

    def generate_key(self, *, parameter_set: str, d: bytes, z: bytes) -> tuple[bytes, bytes]:
        raise AssertionError("provider must not be called for a declined case")

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
    """Stub whose verification verdict is fixed in advance.

    It generates and signs by replaying whatever it is told to, because these
    tests are about routing rather than about ML-DSA: ``generate_key`` and
    ``sign`` exist so the stub satisfies the provider protocol, and the paths
    that use them supply their own answers.
    """

    def __init__(
        self,
        verdict: bool,
        *,
        keys: dict[bytes, tuple[bytes, bytes]] | None = None,
        signatures: dict[bytes, bytes] | None = None,
    ) -> None:
        self._verdict = verdict
        self._keys = keys or {}
        self._signatures = signatures or {}
        self.signed: list[dict[str, object]] = []

    def metadata(self) -> Any:
        from acvp_assay.models import ProviderKind, ProviderMetadata

        return ProviderMetadata("stub", "stub", "0", "stub", "0", ProviderKind.BUILTIN)

    def generate_key(self, *, parameter_set: str, seed: bytes) -> tuple[bytes, bytes]:
        return self._keys[seed]

    def sign(
        self,
        *,
        parameter_set: str,
        secret_key: bytes,
        message: bytes,
        context: bytes | None,
        rnd: bytes | None,
        signature_interface: str,
        pre_hash: str,
        hash_alg: str | None,
        external_mu: bool,
    ) -> bytes:
        self.signed.append(
            {
                "parameterSet": parameter_set,
                "message": message,
                "context": context,
                "rnd": rnd,
                "signatureInterface": signature_interface,
                "preHash": pre_hash,
                "hashAlg": hash_alg,
                "externalMu": external_mu,
            }
        )
        return self._signatures[message]

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


class ReplayingDsaProvider:
    """Stub that answers ML-DSA generation cases from NIST's own recorded answers.

    Like its ML-KEM counterpart it resolves by the inputs it is handed, never by
    case index, because nothing about case identity crosses the provider
    boundary. It also keeps every request it was sent, so a test can assert that
    the group's parameters reached the wire rather than being dropped on the way.
    """

    def __init__(
        self,
        vector_set: pqc.PqcVectorSet,
        expected: pqc.PqcExpectedSet,
        *,
        corrupt: bool = False,
    ) -> None:
        self._corrupt = corrupt
        self._keys: dict[bytes, tuple[bytes, bytes]] = {}
        self._signatures: dict[tuple[bytes, bytes], bytes] = {}
        self.requests: list[dict[str, object]] = []
        for group in vector_set.test_groups:
            for case in group.tests:
                answer = expected.cases[(group.tg_id, case.tc_id)]
                if group.function == "keyGen":
                    self._keys[case.fields["seed"]] = (answer.values["pk"], answer.values["sk"])
                elif group.function == "sigGen":
                    payload = case.fields["mu" if group.external_mu else "message"]
                    self._signatures[(case.fields["sk"], payload)] = answer.values["signature"]

    @staticmethod
    def metadata() -> Any:
        from acvp_assay.models import ProviderKind, ProviderMetadata

        return ProviderMetadata("stub", "stub", "0", "stub", "0", ProviderKind.BUILTIN)

    def _spoil(self, value: bytes) -> bytes:
        return bytes([value[0] ^ 0xFF]) + value[1:] if self._corrupt else value

    def generate_key(self, *, parameter_set: str, seed: bytes) -> tuple[bytes, bytes]:
        public, secret = self._keys[seed]
        return self._spoil(public), self._spoil(secret)

    def sign(
        self,
        *,
        parameter_set: str,
        secret_key: bytes,
        message: bytes,
        context: bytes | None,
        rnd: bytes | None,
        signature_interface: str,
        pre_hash: str,
        hash_alg: str | None,
        external_mu: bool,
    ) -> bytes:
        self.requests.append(
            {
                "parameterSet": parameter_set,
                "context": context,
                "rnd": rnd,
                "signatureInterface": signature_interface,
                "preHash": pre_hash,
                "hashAlg": hash_alg,
                "externalMu": external_mu,
            }
        )
        return self._spoil(self._signatures[(secret_key, message)])

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
        raise AssertionError("the generation sets never verify")


def test_stubs_satisfy_the_provider_protocols() -> None:
    """The protocols are structural, so any conforming object can be a provider."""
    assert isinstance(FixedDsaProvider(True), MlDsaProvider)
    empty_dsa = pqc.PqcVectorSet(1, "ML-DSA", "FIPS204", "keyGen", ())
    assert isinstance(
        ReplayingDsaProvider(empty_dsa, pqc.PqcExpectedSet(vs_id=1, cases={})), MlDsaProvider
    )
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


# --- the generation sets, against NIST's recorded answers -------------------


@requires_ml_kem_keygen
def test_ml_kem_key_gen_compares_both_halves() -> None:
    """A key pair is right only if both halves are; one matching half is still a fail."""
    vector_set = pqc.load_vector_set(ML_KEM_KEYGEN / "prompt.json")
    expected = pqc.load_expected_results(ML_KEM_KEYGEN / "expectedResults.json")

    passing = pqc.run_ml_kem(vector_set, expected, ReplayingKemProvider(vector_set, expected))
    failing = pqc.run_ml_kem(
        vector_set, expected, ReplayingKemProvider(vector_set, expected, corrupt=True)
    )

    assert len(passing) == 75
    assert {r.status for r in passing} == {ResultStatus.PASS}
    assert {r.status for r in failing} == {ResultStatus.FAIL}
    assert failing[0].diagnostic == "dk mismatch, ek mismatch"
    reported = (passing[0].actual.as_document() if passing[0].actual else {}).keys()
    assert set(reported) == {"ek", "dk"}


@requires_ml_dsa_keygen
def test_ml_dsa_key_gen_compares_both_halves() -> None:
    """One 32-byte seed in, an exact public and private key out."""
    vector_set = pqc.load_vector_set(ML_DSA_KEYGEN / "prompt.json")
    expected = pqc.load_expected_results(ML_DSA_KEYGEN / "expectedResults.json")

    passing = pqc.run_ml_dsa(vector_set, expected, ReplayingDsaProvider(vector_set, expected))
    failing = pqc.run_ml_dsa(
        vector_set, expected, ReplayingDsaProvider(vector_set, expected, corrupt=True)
    )

    assert len(passing) == 75
    assert {r.status for r in passing} == {ResultStatus.PASS}
    assert {r.status for r in failing} == {ResultStatus.FAIL}
    assert failing[0].diagnostic == "pk mismatch, sk mismatch"


@requires_ml_dsa_siggen
def test_ml_dsa_sig_gen_carries_every_parameter_its_group_fixes() -> None:
    """All four switches reach the provider, and the set exercises both sides of each.

    This is the assertion that matters for sigGen, because a parameter dropped
    on the way to an implementation does not fail loudly: it produces a valid
    signature of the wrong thing, which looks exactly like a broken module.
    """
    vector_set = pqc.load_vector_set(ML_DSA_SIGGEN / "prompt.json")
    expected = pqc.load_expected_results(ML_DSA_SIGGEN / "expectedResults.json")
    provider = ReplayingDsaProvider(vector_set, expected)

    results = pqc.run_ml_dsa(vector_set, expected, provider)

    assert len(results) == 360
    assert {r.status for r in results} == {ResultStatus.PASS}
    assert len(provider.requests) == 360
    # Deterministic groups send no rnd; hedged ones send the 32 bytes ACVP chose.
    assert sum(1 for r in provider.requests if r["rnd"] is None) == 180
    assert all(len(cast(bytes, r["rnd"])) == 32 for r in provider.requests if r["rnd"])
    # The internal interface carries no context at all, which is not the same
    # thing as carrying an empty one: the prefix it would build differs.
    internal = [r for r in provider.requests if r["signatureInterface"] == "internal"]
    external = [r for r in provider.requests if r["signatureInterface"] == "external"]
    assert len(internal) == len(external) == 180
    assert all(r["context"] is None for r in internal)
    assert all(isinstance(r["context"], bytes) for r in external)
    assert sum(1 for r in provider.requests if r["externalMu"]) == 90
    assert sum(1 for r in provider.requests if r["preHash"] == "preHash") == 90
    assert {r["hashAlg"] for r in provider.requests if r["preHash"] == "preHash"} == {
        "SHA2-224",
        "SHA2-256",
        "SHA2-384",
        "SHA2-512",
        "SHA2-512/224",
        "SHA2-512/256",
        "SHA3-224",
        "SHA3-256",
        "SHA3-384",
        "SHA3-512",
        "SHAKE-128",
        "SHAKE-256",
    }
    assert all(r["hashAlg"] is None for r in provider.requests if r["preHash"] == "pure")


@requires_ml_dsa_siggen
def test_a_wrong_ml_dsa_signature_never_passes() -> None:
    """One flipped byte in every signature, and not one case reports PASS."""
    vector_set = pqc.load_vector_set(ML_DSA_SIGGEN / "prompt.json")
    expected = pqc.load_expected_results(ML_DSA_SIGGEN / "expectedResults.json")

    results = pqc.run_ml_dsa(
        vector_set, expected, ReplayingDsaProvider(vector_set, expected, corrupt=True)
    )

    assert {r.status for r in results} == {ResultStatus.FAIL}
    assert results[0].diagnostic == "signature mismatch"


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
    prompt, expected = kem_documents("reEncapsulation")

    results = pqc.run_ml_kem(
        pqc.parse_vector_set(prompt), pqc.parse_expected_results(expected), UnusedKemProvider()
    )

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "function 'reEncapsulation'" in (results[0].diagnostic or "")


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


def sig_gen_documents(**group: Any) -> tuple[Any, Any]:
    """Build a one-case ML-DSA sigGen prompt/expected pair with the given group shape."""
    case: dict[str, Any] = {"tcId": 1, "sk": "AABB", "message": "CCDD"}
    case.update(cast(dict[str, Any], group.pop("case", {})))
    prompt = {
        "vsId": 1,
        "algorithm": "ML-DSA",
        "revision": "FIPS204",
        "mode": "sigGen",
        "testGroups": [
            {
                "tgId": 1,
                "parameterSet": "ML-DSA-44",
                "deterministic": True,
                "signatureInterface": "external",
                "preHash": "pure",
                **group,
                "tests": [case],
            }
        ],
    }
    expected = {
        "vsId": 1,
        "testGroups": [{"tgId": 1, "tests": [{"tcId": 1, "signature": "EEFF"}]}],
    }
    return prompt, expected


@pytest.mark.parametrize(
    ("group", "drop", "fragment"),
    [
        ({"deterministic": True, "case": {"rnd": "00" * 32}}, None, "deterministic and the case"),
        ({"deterministic": False}, None, "hedged and the case carries none"),
        ({"preHash": "preHash"}, None, "names no hashAlg"),
        ({}, "sk", "missing sk"),
        ({"externalMu": True}, None, "missing mu"),
    ],
)
def test_a_sig_gen_group_that_contradicts_its_cases_is_an_incomplete_vector(
    group: dict[str, Any], drop: str | None, fragment: str
) -> None:
    """Signing anyway would produce a wrong answer for a reason no one could see.

    A deterministic group carrying ``rnd``, or a hedged one carrying none, does
    not say which randomness to use, and the two readings give different
    signatures. There is no safe guess, so the case is declared instead.
    """
    prompt, expected = sig_gen_documents(**group)
    if drop is not None:
        prompt["testGroups"][0]["tests"][0].pop(drop)

    results = pqc.run_ml_dsa(
        pqc.parse_vector_set(prompt), pqc.parse_expected_results(expected), FixedDsaProvider(True)
    )

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert results[0].decline_reason is not None
    assert results[0].decline_reason.value == "vector_incomplete"
    assert fragment in (results[0].diagnostic or "")


def test_a_sig_gen_case_reaches_the_provider_with_its_own_parameters() -> None:
    """The context travels for an external interface and is withheld for an internal one."""
    prompt, expected = sig_gen_documents(case={"context": "1122"})
    provider = FixedDsaProvider(True, signatures={bytes.fromhex("CCDD"): bytes.fromhex("EEFF")})

    results = pqc.run_ml_dsa(
        pqc.parse_vector_set(prompt), pqc.parse_expected_results(expected), provider
    )

    assert results[0].status is ResultStatus.PASS
    assert provider.signed[0]["context"] == bytes.fromhex("1122")
    assert provider.signed[0]["rnd"] is None

    prompt["testGroups"][0]["signatureInterface"] = "internal"
    provider = FixedDsaProvider(True, signatures={bytes.fromhex("CCDD"): bytes.fromhex("EEFF")})
    pqc.run_ml_dsa(pqc.parse_vector_set(prompt), pqc.parse_expected_results(expected), provider)

    assert provider.signed[0]["context"] is None


def test_an_ml_dsa_key_gen_case_without_a_seed_is_declared() -> None:
    """KeyGen is a function of the seed, so a case without one cannot be answered."""
    prompt, expected = sig_gen_documents()
    prompt["mode"] = "keyGen"
    prompt["testGroups"][0]["tests"][0] = {"tcId": 1}
    expected["testGroups"][0]["tests"][0] = {"tcId": 1, "pk": "AA", "sk": "BB"}

    results = pqc.run_ml_dsa(
        pqc.parse_vector_set(prompt), pqc.parse_expected_results(expected), FixedDsaProvider(True)
    )

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "missing seed" in (results[0].diagnostic or "")


def test_an_unknown_ml_dsa_mode_is_declared() -> None:
    """A mode this runner has not built is named rather than guessed at."""
    prompt, expected = sig_gen_documents()
    prompt["mode"] = "sigGenPrime"

    results = pqc.run_ml_dsa(
        pqc.parse_vector_set(prompt), pqc.parse_expected_results(expected), FixedDsaProvider(True)
    )

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "mode 'sigGenPrime'" in (results[0].diagnostic or "")


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


def harness(tmp_path: Path, body: str, *, preamble: str = "") -> list[str]:
    """Write a one-shot harness script and return its argument vector."""
    script = tmp_path / "pqc_harness.py"
    script.write_text(
        "import json, sys\n" + (preamble + "\n" if preamble else "") + "for _line in sys.stdin:\n"
        "    request = json.loads(_line)\n"
        + "\n".join("    " + piece for piece in body.splitlines())
        + '\n    sys.stdout.write("\\n")\n    sys.stdout.flush()\n'
    )
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


def test_the_generation_operations_speak_the_wire_contract(tmp_path: Path) -> None:
    """The three new operations send what their vectors hold and decode the answer."""
    command = harness(
        tmp_path,
        "seen.append(request)\n"
        'op = request["operation"]\n'
        'out = {"ml-kem-keygen": {"ek": "AABB", "dk": "CCDD"},\n'
        '       "ml-dsa-keygen": {"pk": "1122", "sk": "3344"},\n'
        '       "ml-dsa-sign": {"signature": "5566"}}[op]\n'
        'open(record, "w").write(json.dumps(seen))\n'
        "sys.stdout.write(json.dumps(out))",
        preamble=f"seen = []\nrecord = {str(tmp_path / 'seen.json')!r}",
    )

    kem = SubprocessMlKemProvider(command)
    assert kem.generate_key(parameter_set="ML-KEM-512", d=b"\x01", z=b"\x02") == (
        bytes.fromhex("AABB"),
        bytes.fromhex("CCDD"),
    )
    kem.close()

    dsa = SubprocessMlDsaProvider(command)
    assert dsa.generate_key(parameter_set="ML-DSA-44", seed=bytes(32)) == (
        bytes.fromhex("1122"),
        bytes.fromhex("3344"),
    )
    signature = dsa.sign(
        parameter_set="ML-DSA-44",
        secret_key=b"\xaa",
        message=b"\xbb",
        context=b"\xcc",
        rnd=None,
        signature_interface="external",
        pre_hash="pure",
        hash_alg=None,
        external_mu=False,
    )
    dsa.close()

    assert signature == bytes.fromhex("5566")
    sent = json.loads((tmp_path / "seen.json").read_text(encoding="utf-8"))[-1]
    assert sent == {
        "operation": "ml-dsa-sign",
        "parameterSet": "ML-DSA-44",
        "sk": "AA",
        "signatureInterface": "external",
        "preHash": "pure",
        "externalMu": False,
        "deterministic": True,
        "message": "BB",
        "context": "CC",
    }


def test_a_hedged_external_mu_case_sends_mu_and_rnd(tmp_path: Path) -> None:
    """An externalMu case sends `mu` in place of `message`, and says so in its own field."""
    command = harness(
        tmp_path,
        'open(record, "w").write(json.dumps(request))\n'
        'sys.stdout.write(json.dumps({"signature": "5566"}))',
        preamble=f"record = {str(tmp_path / 'seen.json')!r}",
    )
    provider = SubprocessMlDsaProvider(command)

    provider.sign(
        parameter_set="ML-DSA-87",
        secret_key=b"\xaa",
        message=bytes(64),
        context=None,
        rnd=bytes(32),
        signature_interface="internal",
        pre_hash="pure",
        hash_alg=None,
        external_mu=True,
    )
    provider.close()

    sent = json.loads((tmp_path / "seen.json").read_text(encoding="utf-8"))
    assert sent["mu"] == "00" * 64
    assert "message" not in sent
    assert sent["rnd"] == "00" * 32
    assert sent["deterministic"] is False
    assert sent["externalMu"] is True
    assert "context" not in sent


def test_a_harness_that_declines_signing_is_reported_not_crashed(tmp_path: Path) -> None:
    """A decline is a coverage statement, and the claim the harness made is kept."""
    command = harness(
        tmp_path,
        'sys.stdout.write(json.dumps({"error": "unsupported",\n'
        '                             "declineReason": "interface_lacks",\n'
        '                             "detail": "the API takes no rnd"}))',
    )
    prompt, expected = sig_gen_documents()

    results = pqc.run_ml_dsa(
        pqc.parse_vector_set(prompt),
        pqc.parse_expected_results(expected),
        SubprocessMlDsaProvider(command),
    )

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert results[0].decline_reason is not None
    assert results[0].decline_reason.value == "interface_lacks"
    assert results[0].declined_by is not None
    assert results[0].declined_by.value == "harness"
    assert "the API takes no rnd" in (results[0].diagnostic or "")


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
