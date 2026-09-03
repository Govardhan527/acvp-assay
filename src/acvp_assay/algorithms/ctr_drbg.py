"""ctrDRBG, revisions 1.0 and SP800-90Ar1.

The result shape is compare-output — one hex string per case — but getting
there is unlike every other family here, because a case is a *sequence* of
operations rather than a single call. ``otherInput`` lists them in order, and
the value compared is the output of the last generation, not the first.

Two details in that sequence are easy to get wrong and silently wrong if you
do. Prediction resistance turns a ``generate`` carrying entropy into a reseed
followed by a generation, and the additional input is consumed by the reseed
rather than by the generation that follows it. And every case generates twice,
discarding the first output; comparing the first would pass a DRBG that never
updates its state.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from acvp_assay.models import DigestValues, ResultStatus, TestCaseResult
from acvp_assay.parser import (
    AcvpValidationError,
    boolean,
    hex_bytes,
    integer,
    list_field,
    mapping,
    optional_boolean,
    optional_hex_bytes,
    optional_integer,
    string_field,
)
from acvp_assay.providers.ctr_drbg import BLOCK_CIPHERS, CryptographyCtrDrbg, CtrDrbgProvider
from acvp_assay.providers.hash_drbg import SEED_LENGTH_BITS, HashDrbg, HmacDrbg

ALGORITHM = "ctrDRBG"
HASH_DRBG = "hashDRBG"
HMAC_DRBG = "hmacDRBG"

#: The three SP 800-90A mechanisms, and the modes each one accepts.
SUPPORTED: dict[str, frozenset[str]] = {
    ALGORITHM: frozenset(BLOCK_CIPHERS),
    HASH_DRBG: frozenset(SEED_LENGTH_BITS),
    HMAC_DRBG: frozenset(SEED_LENGTH_BITS),
}


def provider_for(algorithm: str) -> CtrDrbgProvider:
    """The built-in provider for one DRBG mechanism.

    All three present the same boundary because all three have the same
    lifecycle; only ctrDRBG reads the derivation-function and counter-width
    options, which the other two accept and ignore.
    """
    if algorithm == HASH_DRBG:
        return HashDrbg()
    if algorithm == HMAC_DRBG:
        return HmacDrbg()
    return CryptographyCtrDrbg()


RESEED = "reSeed"
GENERATE = "generate"
_USES = (RESEED, GENERATE)


@dataclass(frozen=True, slots=True)
class DrbgOperation:
    """One step of a case: a reseed, or a generation."""

    intended_use: str
    additional_input: bytes
    entropy: bytes


@dataclass(frozen=True, slots=True)
class DrbgCase:
    """Instantiation inputs plus the ordered operations that follow them."""

    tc_id: int
    entropy: bytes
    nonce: bytes
    personalization: bytes
    operations: tuple[DrbgOperation, ...]


@dataclass(frozen=True, slots=True)
class DrbgGroup:
    """Cases sharing a block cipher mode and one configuration of the DRBG."""

    tg_id: int
    mode: str
    derivation_function: bool
    prediction_resistance: bool
    returned_bits: int
    counter_field_bits: int
    cases: tuple[DrbgCase, ...]


@dataclass(frozen=True, slots=True)
class DrbgVectorSet:
    """A parsed ctrDRBG prompt file."""

    vs_id: int
    algorithm: str
    revision: str
    groups: tuple[DrbgGroup, ...]


@dataclass(frozen=True, slots=True)
class DrbgExpectedSet:
    """Expected returned bits, indexed by case."""

    vs_id: int
    returned_bits: dict[int, bytes]


def _parse_operation(value: object, *, path: str) -> DrbgOperation:
    document = mapping(value, path=path)
    use = string_field(document, "intendedUse", path=path)
    if use not in _USES:
        raise AcvpValidationError(f"{path}.intendedUse", f"expected one of {list(_USES)}")
    return DrbgOperation(
        intended_use=use,
        additional_input=optional_hex_bytes(document, "additionalInput", path=path) or b"",
        entropy=optional_hex_bytes(document, "entropyInput", path=path) or b"",
    )


def _parse_case(value: object, *, path: str) -> DrbgCase:
    document = mapping(value, path=path)
    operations = list_field(document, "otherInput", path=path)
    return DrbgCase(
        tc_id=integer(document, "tcId", path=path),
        entropy=hex_bytes(document, "entropyInput", path=path),
        nonce=optional_hex_bytes(document, "nonce", path=path) or b"",
        personalization=optional_hex_bytes(document, "persoString", path=path) or b"",
        operations=tuple(
            _parse_operation(item, path=f"{path}.otherInput[{index}]")
            for index, item in enumerate(operations)
        ),
    )


def _parse_group(value: object, *, path: str) -> DrbgGroup:
    document = mapping(value, path=path)
    cases = list_field(document, "tests", path=path)
    returned = integer(document, "returnedBitsLen", path=path)
    if returned <= 0 or returned % 8 != 0:
        raise AcvpValidationError(f"{path}.returnedBitsLen", "expected a positive multiple of 8")
    counter_bits = optional_integer(document, "counterFieldLen", path=path) or 0
    if counter_bits < 0:
        raise AcvpValidationError(f"{path}.counterFieldLen", "expected a non-negative integer")
    return DrbgGroup(
        tg_id=integer(document, "tgId", path=path),
        mode=string_field(document, "mode", path=path),
        derivation_function=optional_boolean(document, "derFunc", path=path) or False,
        prediction_resistance=boolean(document, "predResistance", path=path),
        returned_bits=returned,
        counter_field_bits=counter_bits,
        cases=tuple(
            _parse_case(item, path=f"{path}.tests[{index}]") for index, item in enumerate(cases)
        ),
    )


def parse_vector_set(value: object) -> DrbgVectorSet:
    """Parse a ctrDRBG prompt document, rejecting anything malformed."""
    document = mapping(value, path="$")
    algorithm = string_field(document, "algorithm", path="$")
    if algorithm not in SUPPORTED:
        raise AcvpValidationError("$.algorithm", f"expected one of {sorted(SUPPORTED)}")
    groups = list_field(document, "testGroups", path="$")
    return DrbgVectorSet(
        vs_id=integer(document, "vsId", path="$"),
        algorithm=algorithm,
        revision=string_field(document, "revision", path="$"),
        groups=tuple(
            _parse_group(item, path=f"$.testGroups[{index}]") for index, item in enumerate(groups)
        ),
    )


def parse_expected_results(value: object) -> DrbgExpectedSet:
    """Parse the expected results, keyed by case identifier."""
    document = mapping(value, path="$")
    returned: dict[int, bytes] = {}
    for group_index, group_value in enumerate(list_field(document, "testGroups", path="$")):
        group_path = f"$.testGroups[{group_index}]"
        group = mapping(group_value, path=group_path)
        for case_index, case_value in enumerate(list_field(group, "tests", path=group_path)):
            case_path = f"{group_path}.tests[{case_index}]"
            case = mapping(case_value, path=case_path)
            returned[integer(case, "tcId", path=case_path)] = hex_bytes(
                case, "returnedBits", path=case_path
            )
    return DrbgExpectedSet(vs_id=integer(document, "vsId", path="$"), returned_bits=returned)


def load_vector_set(path: str | Path) -> DrbgVectorSet:
    """Read and parse a ctrDRBG prompt file."""
    return parse_vector_set(json.loads(Path(path).read_text(encoding="utf-8")))


def load_expected_results(path: str | Path) -> DrbgExpectedSet:
    """Read and parse a ctrDRBG expected-results file."""
    return parse_expected_results(json.loads(Path(path).read_text(encoding="utf-8")))


def _unsupported(tg_id: int, tc_id: int, reason: str) -> TestCaseResult:
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=ResultStatus.UNSUPPORTED,
        expected=None,
        actual=None,
        diagnostic=reason,
    )


def _run_case(
    group: DrbgGroup,
    case: DrbgCase,
    expected: bytes,
    provider: CtrDrbgProvider,
) -> TestCaseResult:
    """Drive one DRBG through its operation sequence and compare the final output."""
    provider.instantiate(
        mode=group.mode,
        derivation_function=group.derivation_function,
        counter_field_bits=group.counter_field_bits,
        entropy=case.entropy,
        nonce=case.nonce,
        personalization=case.personalization,
    )

    produced: bytes | None = None
    byte_count = group.returned_bits // 8
    for operation in case.operations:
        if operation.intended_use == RESEED:
            provider.reseed(entropy=operation.entropy, additional_input=operation.additional_input)
        elif operation.entropy:
            # Prediction resistance: reseed first, and the additional input is
            # spent there, so the generation that follows carries none.
            provider.reseed(entropy=operation.entropy, additional_input=operation.additional_input)
            produced = provider.generate(byte_count=byte_count, additional_input=b"")
        else:
            produced = provider.generate(
                byte_count=byte_count, additional_input=operation.additional_input
            )

    if produced is None:
        return _unsupported(group.tg_id, case.tc_id, "the case requested no generation")

    status = ResultStatus.PASS if produced == expected else ResultStatus.FAIL
    return TestCaseResult(
        tg_id=group.tg_id,
        tc_id=case.tc_id,
        status=status,
        expected=DigestValues(digest=expected),
        actual=DigestValues(digest=produced),
        diagnostic=None if status is ResultStatus.PASS else "returned bits differ",
    )


def run_vector_set(
    vector_set: DrbgVectorSet,
    expected: DrbgExpectedSet,
    provider: CtrDrbgProvider,
) -> list[TestCaseResult]:
    """Execute every case, declaring the ones this provider cannot answer."""
    results: list[TestCaseResult] = []
    for group in vector_set.groups:
        supported_mode = group.mode in SUPPORTED[vector_set.algorithm]
        for case in group.cases:
            if not supported_mode:
                results.append(
                    _unsupported(
                        group.tg_id,
                        case.tc_id,
                        f"mode {group.mode} is not supported",
                    )
                )
                continue
            wanted = expected.returned_bits.get(case.tc_id)
            if wanted is None:
                results.append(_unsupported(group.tg_id, case.tc_id, "no expected result recorded"))
                continue
            results.append(_run_case(group, case, wanted, provider))
    return results


def supported_modes(algorithm: str = ALGORITHM) -> Sequence[str]:
    """Modes this runner can execute for one DRBG mechanism."""
    return tuple(sorted(SUPPORTED.get(algorithm, frozenset())))


__all__ = [
    "ALGORITHM",
    "HASH_DRBG",
    "HMAC_DRBG",
    "SUPPORTED",
    "DrbgCase",
    "DrbgExpectedSet",
    "DrbgGroup",
    "DrbgOperation",
    "DrbgVectorSet",
    "load_expected_results",
    "load_vector_set",
    "parse_expected_results",
    "parse_vector_set",
    "provider_for",
    "run_vector_set",
    "supported_modes",
]
