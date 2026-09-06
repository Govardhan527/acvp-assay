"""Parsing and execution for KAS-FFC-SSC (SP 800-56Ar3), scheme dhEphem.

Structured as the ECC sibling is, because the split is the same: a VAL case
supplies everything and is fully checkable here, while an AFT case has the
implementation generate an ephemeral key, so z differs every run and only the
server -- which holds the peer private key -- can verify it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from acvp_assay.models import ProviderMetadata, ResultStatus, TestCaseResult
from acvp_assay.parser import (
    AcvpValidationError,
    integer,
    list_field,
    mapping,
    optional_hex_bytes,
    string_field,
)
from acvp_assay.providers.kas_ffc import (
    ALGORITHM,
    DH_EPHEM,
    KasFfcProvider,
    PythonKasFfc,
    SubprocessKasFfc,
)
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

AFT = "AFT"
VAL = "VAL"


@dataclass(frozen=True, slots=True)
class KasFfcCase:
    """One case: the IUT's private key, the peer's public key, and a claimed z."""

    tc_id: int
    private_key: bytes | None
    peer_public: bytes | None
    claimed_z: bytes | None


@dataclass(frozen=True, slots=True)
class KasFfcGroup:
    """One group: the scheme, the domain parameters, and the test type."""

    tg_id: int
    scheme: str
    group: str
    test_type: str
    tests: tuple[KasFfcCase, ...]


@dataclass(frozen=True, slots=True)
class KasFfcVectorSet:
    """A parsed KAS-FFC-SSC vector set."""

    vs_id: int
    algorithm: str
    revision: str
    groups: tuple[KasFfcGroup, ...]


def _parse_group(value: object, *, path: str) -> KasFfcGroup:
    document = mapping(value, path=path)
    cases = []
    for index, item in enumerate(list_field(document, "tests", path=path)):
        case_path = f"{path}.tests[{index}]"
        case = mapping(item, path=case_path)
        cases.append(
            KasFfcCase(
                tc_id=integer(case, "tcId", path=case_path),
                private_key=optional_hex_bytes(case, "ephemeralPrivateIut", path=case_path),
                peer_public=optional_hex_bytes(case, "ephemeralPublicServer", path=case_path),
                claimed_z=optional_hex_bytes(case, "z", path=case_path),
            )
        )
    return KasFfcGroup(
        tg_id=integer(document, "tgId", path=path),
        scheme=string_field(document, "scheme", path=path),
        group=string_field(document, "domainParameterGenerationMode", path=path),
        test_type=string_field(document, "testType", path=path),
        tests=tuple(cases),
    )


def parse_vector_set(value: object) -> KasFfcVectorSet:
    """Parse a KAS-FFC-SSC vector set, preserving every ACVP id."""
    document = mapping(value, path="$")
    algorithm = string_field(document, "algorithm", path="$")
    if algorithm != ALGORITHM:
        raise AcvpValidationError("$.algorithm", f"expected {ALGORITHM!r}")
    groups = list_field(document, "testGroups", path="$")
    return KasFfcVectorSet(
        vs_id=integer(document, "vsId", path="$"),
        algorithm=algorithm,
        revision=string_field(document, "revision", path="$"),
        groups=tuple(
            _parse_group(item, path=f"$.testGroups[{index}]") for index, item in enumerate(groups)
        ),
    )


def parse_expected_results(value: object) -> dict[tuple[int, int], dict[str, object]]:
    """The expected answer for every case, keyed by group and case."""
    document = mapping(value, path="$")
    found: dict[tuple[int, int], dict[str, object]] = {}
    for group_index, group_value in enumerate(list_field(document, "testGroups", path="$")):
        group_path = f"$.testGroups[{group_index}]"
        group = mapping(group_value, path=group_path)
        tg_id = integer(group, "tgId", path=group_path)
        for case_index, case_value in enumerate(list_field(group, "tests", path=group_path)):
            case_path = f"{group_path}.tests[{case_index}]"
            case = mapping(case_value, path=case_path)
            found[(tg_id, integer(case, "tcId", path=case_path))] = dict(case)
    return found


def _load_json(path: str | Path) -> object:
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def load_vector_set(path: str | Path) -> KasFfcVectorSet:
    """Load and parse a KAS-FFC-SSC vector file."""
    return parse_vector_set(_load_json(path))


def load_expected_results(path: str | Path) -> dict[tuple[int, int], dict[str, object]]:
    """Load and parse a KAS-FFC-SSC expected-results file."""
    return parse_expected_results(_load_json(path))


def provider_for(provider_command: str | None, timeout_seconds: float) -> KasFfcProvider:
    """The built-in provider, or a harness when one is named."""
    if provider_command is None:
        return PythonKasFfc()
    return SubprocessKasFfc.from_command_string(provider_command, timeout_seconds=timeout_seconds)


def metadata_for(provider: KasFfcProvider) -> ProviderMetadata:
    """Report which implementation answered."""
    return provider.metadata()


def _unsupported(tg_id: int, tc_id: int, reason: str) -> TestCaseResult:
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=ResultStatus.UNSUPPORTED,
        expected=None,
        actual=None,
        diagnostic=reason,
    )


def run_vector_set(
    vector_set: KasFfcVectorSet,
    expected: dict[tuple[int, int], dict[str, object]],
    provider: KasFfcProvider,
) -> list[TestCaseResult]:
    """Verify every VAL case, and decline AFT with its reason."""
    results: list[TestCaseResult] = []
    for group in vector_set.groups:
        for case in group.tests:
            key = (group.tg_id, case.tc_id)
            if group.scheme != DH_EPHEM:
                results.append(_unsupported(*key, f"scheme {group.scheme!r} is not supported"))
                continue
            if not provider.supports(group=group.group):
                results.append(
                    _unsupported(*key, f"domain parameters {group.group!r} are not supported")
                )
                continue
            if group.test_type == AFT:
                results.append(
                    _unsupported(
                        *key,
                        "AFT generates an ephemeral key, so z cannot be compared with the "
                        "recorded value; submit to ACVTS, which can verify it",
                    )
                )
                continue
            if group.test_type != VAL:
                results.append(
                    _unsupported(*key, f"test type {group.test_type!r} is not supported")
                )
                continue
            if case.private_key is None or case.peer_public is None or case.claimed_z is None:
                results.append(
                    _unsupported(
                        *key, "a VAL case must supply a private key, a peer public key and z"
                    )
                )
                continue
            recorded = expected.get(key)
            if recorded is None or not isinstance(recorded.get("testPassed"), bool):
                results.append(_unsupported(*key, "no expected verdict recorded"))
                continue
            try:
                computed = provider.shared_secret(
                    group=group.group, private_key=case.private_key, peer_public=case.peer_public
                )
            except HarnessUnsupportedError:
                results.append(_unsupported(*key, "the harness declined this case"))
                continue
            except ValueError:
                # A peer key outside the usable range is a case that should fail,
                # not one that should error.
                computed = b""
            wanted = bool(recorded["testPassed"])
            agrees = (computed == case.claimed_z) == wanted
            results.append(
                TestCaseResult(
                    tg_id=group.tg_id,
                    tc_id=case.tc_id,
                    status=ResultStatus.PASS if agrees else ResultStatus.FAIL,
                    expected=None,
                    actual=None,
                    diagnostic=None if agrees else f"expected testPassed={wanted}",
                )
            )
    return results


__all__ = [
    "AFT",
    "ALGORITHM",
    "DH_EPHEM",
    "VAL",
    "KasFfcCase",
    "KasFfcGroup",
    "KasFfcVectorSet",
    "load_expected_results",
    "load_vector_set",
    "metadata_for",
    "parse_expected_results",
    "parse_vector_set",
    "provider_for",
    "run_vector_set",
]
