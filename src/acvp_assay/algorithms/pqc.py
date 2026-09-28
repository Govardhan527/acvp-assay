"""ML-KEM and ML-DSA vector parsing and execution.

Both algorithms are read in two halves. What an implementation *decides* --
ML-KEM's two key checks and ML-DSA ``sigVer`` -- is verdict-only, the shape
ECDSA sigVer introduced. What it *produces* is compared byte for byte, and ACVP
makes that possible by supplying every input the answer depends on:

* ML-KEM ``keyGen`` supplies ``d`` and ``z``, so ``ek`` and ``dk`` are fixed.
* ML-KEM ``encapsulation`` supplies the random ``m``, so ``c`` and ``k`` are.
* ML-KEM ``decapsulation`` compares the recovered ``k``.
* ML-DSA ``keyGen`` supplies the 32-byte seed, so ``pk`` and ``sk`` are.
* ML-DSA ``sigGen`` supplies ``rnd`` wherever the group is hedged, so even a
  randomised signature is a function of the vector.

That last one is the whole reason sigGen is reachable at all. A signing API that
draws its own randomness produces a valid signature that matches nothing, and an
API with no way to accept ``rnd`` cannot answer a hedged case however correct it
is -- which is ``interface_lacks``, not a missing implementation.

Execution requires ``--provider-command``: see ``providers/pqc.py`` for why
there is no built-in implementation.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from acvp_assay.models import (
    CaseValues,
    DeclineClaimant,
    DeclineReason,
    DigestValues,
    KeyPairValues,
    ResultStatus,
    SignatureValues,
    TestCaseResult,
    VerdictValues,
)
from acvp_assay.parser import (
    AcvpValidationError,
    integer,
    list_field,
    mapping,
    optional_hex_bytes,
    optional_string,
    string_field,
)
from acvp_assay.providers.pqc import (
    ML_DSA_PARAMETER_SETS,
    ML_KEM_PARAMETER_SETS,
    MlDsaProvider,
    MlKemProvider,
)
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError, declined_result

ENCAPSULATION = "encapsulation"
DECAPSULATION = "decapsulation"
ENCAP_KEY_CHECK = "encapsulationKeyCheck"
DECAP_KEY_CHECK = "decapsulationKeyCheck"
KEY_CHECKS = (ENCAP_KEY_CHECK, DECAP_KEY_CHECK)
KEY_GEN = "keyGen"
SIG_GEN = "sigGen"
SIG_VER = "sigVer"


@dataclass(frozen=True, slots=True)
class PqcCase:
    """One ML-KEM or ML-DSA case, holding whichever fields its function uses.

    ``hash_alg`` is kept apart from ``fields`` because it is the one case-level
    value ACVP sends as a name rather than as bytes.
    """

    tc_id: int
    fields: Mapping[str, bytes] = field(default_factory=dict)
    hash_alg: str | None = None


@dataclass(frozen=True, slots=True)
class PqcGroup:
    """Cases sharing one parameter set and function."""

    tg_id: int
    parameter_set: str
    function: str
    tests: tuple[PqcCase, ...]
    pre_hash: str = "pure"
    external_mu: bool = False
    signature_interface: str = "external"
    deterministic: bool = True


@dataclass(frozen=True, slots=True)
class PqcVectorSet:
    """One normalized ML-KEM or ML-DSA vector set."""

    vs_id: int
    algorithm: str
    revision: str
    mode: str
    test_groups: tuple[PqcGroup, ...]


@dataclass(frozen=True, slots=True)
class PqcExpectedCase:
    """Expected output for one PQC case: bytes, a verdict, or both."""

    tc_id: int
    values: Mapping[str, bytes]
    test_passed: bool | None


@dataclass(frozen=True, slots=True)
class PqcExpectedSet:
    """Expected PQC results keyed by group and case."""

    vs_id: int
    cases: Mapping[tuple[int, int], PqcExpectedCase]


_CASE_FIELDS = (
    "ek",
    "dk",
    "c",
    "m",
    "d",
    "z",
    "seed",
    "pk",
    "sk",
    "message",
    "signature",
    "context",
    "mu",
    "rnd",
)

#: The expected-result values these families record, by ACVP field name.
_EXPECTED_FIELDS = ("c", "k", "ek", "dk", "pk", "sk", "signature")


def _parse_case(value: object, *, path: str) -> PqcCase:
    document = mapping(value, path)
    present: dict[str, bytes] = {}
    for name in _CASE_FIELDS:
        parsed = optional_hex_bytes(document, name, path)
        if parsed is not None:
            present[name] = parsed
    return PqcCase(
        tc_id=integer(document, "tcId", path),
        fields=present,
        hash_alg=optional_string(document, "hashAlg", path),
    )


def _parse_group(value: object, *, path: str, mode: str) -> PqcGroup:
    document = mapping(value, path)
    tests = tuple(
        _parse_case(entry, path=f"{path}.tests[{index}]")
        for index, entry in enumerate(list_field(document, "tests", path))
    )
    return PqcGroup(
        tg_id=integer(document, "tgId", path),
        parameter_set=string_field(document, "parameterSet", path),
        function=optional_string(document, "function", path) or mode,
        tests=tests,
        pre_hash=optional_string(document, "preHash", path) or "pure",
        external_mu=bool(document.get("externalMu", False)),
        signature_interface=optional_string(document, "signatureInterface", path) or "external",
        deterministic=bool(document.get("deterministic", True)),
    )


def parse_vector_set(value: object) -> PqcVectorSet:
    """Validate and normalize one ML-KEM or ML-DSA vector-set document."""
    document = mapping(value, "$")
    algorithm = string_field(document, "algorithm", "$")
    if algorithm not in ("ML-KEM", "ML-DSA"):
        raise AcvpValidationError("$.algorithm", f"unsupported algorithm {algorithm!r}")
    mode = string_field(document, "mode", "$")
    groups = tuple(
        _parse_group(entry, path=f"$.testGroups[{index}]", mode=mode)
        for index, entry in enumerate(list_field(document, "testGroups", "$"))
    )
    return PqcVectorSet(
        vs_id=integer(document, "vsId", "$"),
        algorithm=algorithm,
        revision=string_field(document, "revision", "$"),
        mode=mode,
        test_groups=groups,
    )


def parse_expected_results(value: object) -> PqcExpectedSet:
    """Validate and normalize ML-KEM or ML-DSA expected results."""
    document = mapping(value, "$")
    cases: dict[tuple[int, int], PqcExpectedCase] = {}
    for group_index, group_value in enumerate(list_field(document, "testGroups", "$")):
        group_path = f"$.testGroups[{group_index}]"
        group = mapping(group_value, group_path)
        tg_id = integer(group, "tgId", group_path)
        for case_index, case_value in enumerate(list_field(group, "tests", group_path)):
            case_path = f"{group_path}.tests[{case_index}]"
            case = mapping(case_value, case_path)
            tc_id = integer(case, "tcId", case_path)
            values: dict[str, bytes] = {}
            for name in _EXPECTED_FIELDS:
                parsed = optional_hex_bytes(case, name, case_path)
                if parsed is not None:
                    values[name] = parsed
            raw = case.get("testPassed")
            cases[(tg_id, tc_id)] = PqcExpectedCase(
                tc_id=tc_id,
                values=values,
                test_passed=raw if isinstance(raw, bool) else None,
            )
    return PqcExpectedSet(vs_id=integer(document, "vsId", "$"), cases=cases)


def load_vector_set(path: str | Path) -> PqcVectorSet:
    """Load and normalize a PQC prompt file."""
    return parse_vector_set(json.loads(Path(path).read_text(encoding="utf-8")))


def load_expected_results(path: str | Path) -> PqcExpectedSet:
    """Load and normalize a PQC expected-results file."""
    return parse_expected_results(json.loads(Path(path).read_text(encoding="utf-8")))


def _unsupported(code: DeclineReason, tg_id: int, tc_id: int, reason: str) -> TestCaseResult:
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=ResultStatus.UNSUPPORTED,
        expected=None,
        actual=None,
        diagnostic=reason,
        decline_reason=code,
        declined_by=DeclineClaimant.RUNNER,
    )


def _verdict_result(
    tg_id: int, tc_id: int, expected: bool, actual: bool, subject: str
) -> TestCaseResult:
    status = ResultStatus.PASS if expected == actual else ResultStatus.FAIL
    diagnostic = None
    if status is ResultStatus.FAIL:
        diagnostic = (
            f"accepted {subject} ACVP declares invalid"
            if actual
            else f"rejected {subject} ACVP declares valid"
        )
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=status,
        expected=VerdictValues(passed=expected),
        actual=VerdictValues(passed=actual),
        diagnostic=diagnostic,
    )


def _compare_bytes(
    tg_id: int,
    tc_id: int,
    expected: Mapping[str, bytes],
    actual: Mapping[str, bytes],
    *,
    render: Callable[[Mapping[str, bytes]], CaseValues] | None = None,
) -> TestCaseResult:
    """Compare every value ACVP recorded, and report under the names it used.

    Only the recorded fields are compared, because a set records what its own
    function produces: keyGen records both halves of the key pair, encapsulation
    records ``c`` and ``k``, decapsulation records ``k`` alone. ``render`` says
    which ``CaseValues`` shape carries them into the report; it defaults to the
    ML-KEM shared secret, which is what the encapDecap functions answer with.
    """
    shape = render or (lambda values: DigestValues(digest=values.get("k")))
    mismatches = sorted(name for name in expected if expected[name] != actual.get(name))
    status = ResultStatus.PASS if not mismatches else ResultStatus.FAIL
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=status,
        expected=shape(expected),
        actual=shape(actual),
        diagnostic=None
        if status is ResultStatus.PASS
        else ", ".join(f"{name} mismatch" for name in mismatches),
    )


def _kem_key_pair(values: Mapping[str, bytes]) -> CaseValues:
    return KeyPairValues(ek=values.get("ek"), dk=values.get("dk"))


def _dsa_key_pair(values: Mapping[str, bytes]) -> CaseValues:
    return KeyPairValues(pk=values.get("pk"), sk=values.get("sk"))


def _signature(values: Mapping[str, bytes]) -> CaseValues:
    return SignatureValues(signature=values.get("signature"))


def _missing(case: PqcCase, *names: str) -> str | None:
    """The vector fields this case's group requires and does not carry."""
    absent = [name for name in names if name not in case.fields]
    return f"case is missing {', '.join(absent)}" if absent else None


def _kem_case(
    group: PqcGroup,
    case: PqcCase,
    expected_case: PqcExpectedCase,
    provider: MlKemProvider,
) -> TestCaseResult:
    """Execute one ML-KEM case in the shape its group's function requires."""
    if group.function == KEY_GEN:
        if absent := _missing(case, "d", "z"):
            return _unsupported(DeclineReason.VECTOR_INCOMPLETE, group.tg_id, case.tc_id, absent)
        encapsulation, decapsulation = provider.generate_key(
            parameter_set=group.parameter_set, d=case.fields["d"], z=case.fields["z"]
        )
        return _compare_bytes(
            group.tg_id,
            case.tc_id,
            expected_case.values,
            {"ek": encapsulation, "dk": decapsulation},
            render=_kem_key_pair,
        )
    if group.function in KEY_CHECKS:
        if expected_case.test_passed is None:
            return _unsupported(
                DeclineReason.OFFLINE_UNDECIDABLE,
                group.tg_id,
                case.tc_id,
                "no expected verdict recorded",
            )
        key_type = "ek" if group.function == ENCAP_KEY_CHECK else "dk"
        if absent := _missing(case, key_type):
            return _unsupported(DeclineReason.VECTOR_INCOMPLETE, group.tg_id, case.tc_id, absent)
        verdict = provider.check_key(
            parameter_set=group.parameter_set, key_type=key_type, key=case.fields[key_type]
        )
        return _verdict_result(group.tg_id, case.tc_id, expected_case.test_passed, verdict, "a key")
    if group.function == ENCAPSULATION:
        if absent := _missing(case, "ek", "m"):
            return _unsupported(DeclineReason.VECTOR_INCOMPLETE, group.tg_id, case.tc_id, absent)
        ciphertext, shared = provider.encapsulate(
            parameter_set=group.parameter_set,
            encapsulation_key=case.fields["ek"],
            seed=case.fields["m"],
        )
        return _compare_bytes(
            group.tg_id, case.tc_id, expected_case.values, {"c": ciphertext, "k": shared}
        )
    if group.function == DECAPSULATION:
        if absent := _missing(case, "dk", "c"):
            return _unsupported(DeclineReason.VECTOR_INCOMPLETE, group.tg_id, case.tc_id, absent)
        shared = provider.decapsulate(
            parameter_set=group.parameter_set,
            decapsulation_key=case.fields["dk"],
            ciphertext=case.fields["c"],
        )
        return _compare_bytes(group.tg_id, case.tc_id, expected_case.values, {"k": shared})
    return _unsupported(
        DeclineReason.RUNNER_LACKS,
        group.tg_id,
        case.tc_id,
        f"function {group.function!r} is not supported",
    )


def _dsa_case(
    group: PqcGroup,
    case: PqcCase,
    expected_case: PqcExpectedCase,
    provider: MlDsaProvider,
) -> TestCaseResult:
    """Execute one ML-DSA case in the shape its group's mode requires."""
    if group.function == KEY_GEN:
        if absent := _missing(case, "seed"):
            return _unsupported(DeclineReason.VECTOR_INCOMPLETE, group.tg_id, case.tc_id, absent)
        public, secret = provider.generate_key(
            parameter_set=group.parameter_set, seed=case.fields["seed"]
        )
        return _compare_bytes(
            group.tg_id,
            case.tc_id,
            expected_case.values,
            {"pk": public, "sk": secret},
            render=_dsa_key_pair,
        )
    if group.function == SIG_GEN:
        return _sig_gen_case(group, case, expected_case, provider)
    if group.function == SIG_VER:
        return _sig_ver_case(group, case, expected_case, provider)
    return _unsupported(
        DeclineReason.RUNNER_LACKS,
        group.tg_id,
        case.tc_id,
        f"mode {group.function!r} is not supported",
    )


def _sig_gen_case(
    group: PqcGroup,
    case: PqcCase,
    expected_case: PqcExpectedCase,
    provider: MlDsaProvider,
) -> TestCaseResult:
    """Sign one case with exactly the randomness, prefix and message its group fixes.

    ``rnd`` is the field that decides whether the answer is comparable at all, so
    a group that contradicts itself about it is reported as an incomplete vector
    rather than signed one way and hoped for: a deterministic group carrying
    ``rnd``, or a hedged one carrying none, would each produce a signature that
    disagrees with NIST for a reason no one could see in the result.
    """
    payload = "mu" if group.external_mu else "message"
    if absent := _missing(case, "sk", payload):
        return _unsupported(DeclineReason.VECTOR_INCOMPLETE, group.tg_id, case.tc_id, absent)
    carries_rnd = "rnd" in case.fields
    if group.deterministic == carries_rnd:
        stated = "deterministic" if group.deterministic else "hedged"
        carried = "carries rnd" if carries_rnd else "carries none"
        return _unsupported(
            DeclineReason.VECTOR_INCOMPLETE,
            group.tg_id,
            case.tc_id,
            f"the group is {stated} and the case {carried}",
        )
    if group.pre_hash != "pure" and case.hash_alg is None:
        return _unsupported(
            DeclineReason.VECTOR_INCOMPLETE,
            group.tg_id,
            case.tc_id,
            "a preHash case names no hashAlg",
        )
    signature = provider.sign(
        parameter_set=group.parameter_set,
        secret_key=case.fields["sk"],
        message=case.fields[payload],
        context=case.fields.get("context") if group.signature_interface == "external" else None,
        rnd=case.fields.get("rnd"),
        signature_interface=group.signature_interface,
        pre_hash=group.pre_hash,
        hash_alg=case.hash_alg,
        external_mu=group.external_mu,
    )
    return _compare_bytes(
        group.tg_id,
        case.tc_id,
        expected_case.values,
        {"signature": signature},
        render=_signature,
    )


def _sig_ver_case(
    group: PqcGroup,
    case: PqcCase,
    expected_case: PqcExpectedCase,
    provider: MlDsaProvider,
) -> TestCaseResult:
    """Reach the verification verdict ACVP recorded for this case.

    Every group shape sigGen can produce, sigVer can present, so the same four
    parameters travel: the interface, the pre-hash and its algorithm, and
    whether the message arrives as a precomputed ``mu``. An implementation that
    cannot express one of them declines it, which is a statement about its
    interface and not a verdict.
    """
    if expected_case.test_passed is None:
        return _unsupported(
            DeclineReason.OFFLINE_UNDECIDABLE,
            group.tg_id,
            case.tc_id,
            "no expected verdict recorded",
        )
    payload = "mu" if group.external_mu else "message"
    if absent := _missing(case, "pk", payload, "signature"):
        return _unsupported(DeclineReason.VECTOR_INCOMPLETE, group.tg_id, case.tc_id, absent)
    if group.pre_hash != "pure" and case.hash_alg is None:
        return _unsupported(
            DeclineReason.VECTOR_INCOMPLETE,
            group.tg_id,
            case.tc_id,
            "a preHash case names no hashAlg",
        )
    verdict = provider.verify(
        parameter_set=group.parameter_set,
        public_key=case.fields["pk"],
        message=case.fields[payload],
        signature=case.fields["signature"],
        context=case.fields.get("context") if group.signature_interface == "external" else None,
        signature_interface=group.signature_interface,
        pre_hash=group.pre_hash,
        hash_alg=case.hash_alg,
        external_mu=group.external_mu,
    )
    return _verdict_result(
        group.tg_id, case.tc_id, expected_case.test_passed, verdict, "a signature"
    )


def _run_cases(
    vector_set: PqcVectorSet,
    expected: PqcExpectedSet,
    parameter_sets: tuple[str, ...],
    execute: Callable[[PqcGroup, PqcCase, PqcExpectedCase], TestCaseResult],
) -> list[TestCaseResult]:
    """Run every case, turning a harness decline into a reported one.

    The three checks before execution are shared because they are properties of
    the run rather than of the algorithm: a parameter set this runner does not
    know, and an answer key with nothing recorded for the case, are the same gap
    whichever family asked.
    """
    results: list[TestCaseResult] = []
    for group in vector_set.test_groups:
        known = group.parameter_set in parameter_sets
        for case in group.tests:
            if not known:
                results.append(
                    _unsupported(
                        DeclineReason.RUNNER_LACKS,
                        group.tg_id,
                        case.tc_id,
                        f"parameter set {group.parameter_set!r} is not supported",
                    )
                )
                continue
            expected_case = expected.cases.get((group.tg_id, case.tc_id))
            if expected_case is None or not (
                expected_case.values or expected_case.test_passed is not None
            ):
                results.append(
                    _unsupported(
                        DeclineReason.OFFLINE_UNDECIDABLE,
                        group.tg_id,
                        case.tc_id,
                        "no expected result recorded",
                    )
                )
                continue
            try:
                results.append(execute(group, case, expected_case))
            except HarnessUnsupportedError as declined:
                results.append(declined_result(group.tg_id, case.tc_id, declined))
    return results


def run_ml_kem(
    vector_set: PqcVectorSet,
    expected: PqcExpectedSet,
    provider: MlKemProvider,
) -> list[TestCaseResult]:
    """Execute every ML-KEM case using the shape its function requires."""
    return _run_cases(
        vector_set,
        expected,
        ML_KEM_PARAMETER_SETS,
        lambda group, case, wanted: _kem_case(group, case, wanted, provider),
    )


def run_ml_dsa(
    vector_set: PqcVectorSet,
    expected: PqcExpectedSet,
    provider: MlDsaProvider,
) -> list[TestCaseResult]:
    """Execute every ML-DSA case: a key pair, a signature, or a verdict."""
    return _run_cases(
        vector_set,
        expected,
        ML_DSA_PARAMETER_SETS,
        lambda group, case, wanted: _dsa_case(group, case, wanted, provider),
    )


__all__ = [
    "PqcExpectedSet",
    "PqcVectorSet",
    "load_expected_results",
    "load_vector_set",
    "parse_expected_results",
    "parse_vector_set",
    "run_ml_dsa",
    "run_ml_kem",
]
