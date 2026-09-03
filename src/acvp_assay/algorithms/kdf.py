"""KDF SP 800-108, revision 1.0.

This family inverts the usual arrangement of a vector set. Everywhere else the
prompt carries the inputs and the expected results carry only answers; here the
prompt gives just ``keyIn``, because a conforming implementation chooses its own
``fixedData``. NIST records the choice its reference made alongside the answer,
so the runner reads ``fixedData`` out of the expected results and uses it as an
input.

That is worth stating plainly, because it bounds what a passing run means. It
shows the derivation is correct given that fixed data; it does not exercise the
implementation's freedom to construct fixed data of its own, which is a
property the ACVP server checks and a file-based runner cannot.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from acvp_assay.models import DigestValues, ResultStatus, SafeDiagnostic, TestCaseResult
from acvp_assay.parser import (
    AcvpValidationError,
    hex_bytes,
    integer,
    list_field,
    mapping,
    optional_hex_bytes,
    optional_integer,
    string_field,
)
from acvp_assay.providers.kdf import (
    CMAC_MODES,
    COUNTER_LOCATIONS,
    HMAC_MODES,
    KDF_MODES,
    KdfProvider,
    KdfRequest,
)
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

ALGORITHM = "KDF"


@dataclass(frozen=True, slots=True)
class KdfCase:
    """One derivation's case-level inputs."""

    tc_id: int
    key_in: bytes
    iv: bytes


@dataclass(frozen=True, slots=True)
class KdfGroup:
    """Cases sharing a KDF mode, PRF and counter placement."""

    tg_id: int
    kdf_mode: str
    mac_mode: str
    counter_location: str
    counter_bits: int
    output_bits: int
    cases: tuple[KdfCase, ...]


@dataclass(frozen=True, slots=True)
class KdfVectorSet:
    """A parsed KDF prompt file."""

    vs_id: int
    algorithm: str
    revision: str
    groups: tuple[KdfGroup, ...]


@dataclass(frozen=True, slots=True)
class KdfExpectedCase:
    """The fixed data an implementation chose, and the answer it produced."""

    fixed_data: bytes
    key_out: bytes
    break_location: int


@dataclass(frozen=True, slots=True)
class KdfExpectedSet:
    """Expected results, indexed by case."""

    vs_id: int
    cases: dict[int, KdfExpectedCase]


def _parse_case(value: object, *, path: str) -> KdfCase:
    document = mapping(value, path=path)
    return KdfCase(
        tc_id=integer(document, "tcId", path=path),
        key_in=hex_bytes(document, "keyIn", path=path),
        iv=optional_hex_bytes(document, "iv", path=path) or b"",
    )


def _parse_group(value: object, *, path: str) -> KdfGroup:
    document = mapping(value, path=path)
    kdf_mode = string_field(document, "kdfMode", path=path)
    if kdf_mode not in KDF_MODES:
        raise AcvpValidationError(f"{path}.kdfMode", f"expected one of {list(KDF_MODES)}")
    location = string_field(document, "counterLocation", path=path)
    if location not in COUNTER_LOCATIONS:
        raise AcvpValidationError(
            f"{path}.counterLocation", f"expected one of {list(COUNTER_LOCATIONS)}"
        )
    output_bits = integer(document, "keyOutLength", path=path)
    if output_bits <= 0:
        raise AcvpValidationError(f"{path}.keyOutLength", "expected a positive integer")
    counter_bits = optional_integer(document, "counterLength", path=path) or 0
    if counter_bits < 0 or counter_bits % 8 != 0:
        raise AcvpValidationError(f"{path}.counterLength", "expected a non-negative multiple of 8")
    cases = list_field(document, "tests", path=path)
    return KdfGroup(
        tg_id=integer(document, "tgId", path=path),
        kdf_mode=kdf_mode,
        mac_mode=string_field(document, "macMode", path=path),
        counter_location=location,
        counter_bits=counter_bits,
        output_bits=output_bits,
        cases=tuple(
            _parse_case(item, path=f"{path}.tests[{index}]") for index, item in enumerate(cases)
        ),
    )


def parse_vector_set(value: object) -> KdfVectorSet:
    """Parse a KDF prompt document, rejecting anything malformed."""
    document = mapping(value, path="$")
    algorithm = string_field(document, "algorithm", path="$")
    if algorithm != ALGORITHM:
        raise AcvpValidationError("$.algorithm", f"expected {ALGORITHM!r}")
    groups = list_field(document, "testGroups", path="$")
    return KdfVectorSet(
        vs_id=integer(document, "vsId", path="$"),
        algorithm=algorithm,
        revision=string_field(document, "revision", path="$"),
        groups=tuple(
            _parse_group(item, path=f"$.testGroups[{index}]") for index, item in enumerate(groups)
        ),
    )


def parse_expected_results(value: object) -> KdfExpectedSet:
    """Parse expected results, which carry the fixed data as well as the answer."""
    document = mapping(value, path="$")
    cases: dict[int, KdfExpectedCase] = {}
    for group_index, group_value in enumerate(list_field(document, "testGroups", path="$")):
        group_path = f"$.testGroups[{group_index}]"
        group = mapping(group_value, path=group_path)
        for case_index, case_value in enumerate(list_field(group, "tests", path=group_path)):
            case_path = f"{group_path}.tests[{case_index}]"
            case = mapping(case_value, path=case_path)
            break_location = optional_integer(case, "breakLocation", path=case_path) or 0
            if break_location < 0:
                raise AcvpValidationError(f"{case_path}.breakLocation", "expected non-negative")
            cases[integer(case, "tcId", path=case_path)] = KdfExpectedCase(
                fixed_data=hex_bytes(case, "fixedData", path=case_path),
                key_out=hex_bytes(case, "keyOut", path=case_path),
                break_location=break_location,
            )
    return KdfExpectedSet(vs_id=integer(document, "vsId", path="$"), cases=cases)


def load_vector_set(path: str | Path) -> KdfVectorSet:
    """Read and parse a KDF prompt file."""
    return parse_vector_set(json.loads(Path(path).read_text(encoding="utf-8")))


def load_expected_results(path: str | Path) -> KdfExpectedSet:
    """Read and parse a KDF expected-results file."""
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
    group: KdfGroup,
    case: KdfCase,
    expected: KdfExpectedCase,
    provider: KdfProvider,
) -> TestCaseResult:
    """Derive one key and compare it against NIST's answer."""
    request = KdfRequest(
        mac_mode=group.mac_mode,
        kdf_mode=group.kdf_mode,
        counter_location=group.counter_location,
        counter_bits=group.counter_bits,
        key_in=case.key_in,
        fixed_data=expected.fixed_data,
        output_bits=group.output_bits,
        iv=case.iv,
        break_location=expected.break_location,
    )
    try:
        produced = provider.derive(request)
    except ValueError:
        # Never surface the library's message: it can quote key material.
        return TestCaseResult(
            tg_id=group.tg_id,
            tc_id=case.tc_id,
            status=ResultStatus.ERROR,
            expected=None,
            actual=None,
            diagnostic=SafeDiagnostic.PROVIDER_ERROR,
        )

    status = ResultStatus.PASS if produced == expected.key_out else ResultStatus.FAIL
    return TestCaseResult(
        tg_id=group.tg_id,
        tc_id=case.tc_id,
        status=status,
        expected=DigestValues(digest=expected.key_out),
        actual=DigestValues(digest=produced),
        diagnostic=None if status is ResultStatus.PASS else "derived key differs",
    )


def run_vector_set(
    vector_set: KdfVectorSet,
    expected: KdfExpectedSet,
    provider: KdfProvider,
) -> list[TestCaseResult]:
    """Execute every case, declaring the ones this provider cannot answer."""
    results: list[TestCaseResult] = []
    for group in vector_set.groups:
        known_mac = group.mac_mode in HMAC_MODES or group.mac_mode in CMAC_MODES
        for case in group.cases:
            if not known_mac:
                results.append(
                    _unsupported(
                        group.tg_id,
                        case.tc_id,
                        f"macMode {group.mac_mode} is not supported",
                    )
                )
                continue
            wanted = expected.cases.get(case.tc_id)
            if wanted is None:
                results.append(_unsupported(group.tg_id, case.tc_id, "no expected result recorded"))
                continue
            try:
                results.append(_run_case(group, case, wanted, provider))
            except HarnessUnsupportedError:
                results.append(
                    _unsupported(group.tg_id, case.tc_id, "the harness declined this case")
                )
    return results


__all__ = [
    "ALGORITHM",
    "KdfCase",
    "KdfExpectedCase",
    "KdfExpectedSet",
    "KdfGroup",
    "KdfVectorSet",
    "load_expected_results",
    "load_vector_set",
    "parse_expected_results",
    "parse_vector_set",
    "run_vector_set",
]
