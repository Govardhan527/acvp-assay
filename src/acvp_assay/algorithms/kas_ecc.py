"""KAS-ECC-SSC, revision Sp800-56Ar3: elliptic-curve shared-secret computation.

The two test types need different treatment, and the difference is not
cosmetic. ``VAL`` supplies every input including the implementation's own
private key, so the answer is a verdict and is fully checkable offline. ``AFT``
supplies only the peer's public key, so the implementation generates an
ephemeral pair -- and a fresh key yields a different Z on every run, which
cannot be compared with the value NIST recorded from its own.

That makes AFT unanswerable offline and perfectly answerable live: the ACVP
server holds the peer private key, so it can recompute Z from the public key
the implementation reports back. The runner says so rather than inventing a
comparison, and ``responder.py`` answers those cases in full.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from acvp_assay.models import ProviderMetadata, ResultStatus, TestCaseResult, VerdictValues
from acvp_assay.parser import (
    AcvpValidationError,
    hex_bytes,
    integer,
    list_field,
    mapping,
    optional_hex_bytes,
    string_field,
)
from acvp_assay.providers.kas_ecc import (
    EPHEMERAL_UNIFIED,
    CryptographyKasEcc,
    KasEccProvider,
    SubprocessKasEcc,
)

ALGORITHM = "KAS-ECC-SSC"
REVISION = "Sp800-56Ar3"

AFT = "AFT"
VAL = "VAL"


@dataclass(frozen=True, slots=True)
class KasCase:
    """One key-agreement case."""

    tc_id: int
    server_x: bytes
    server_y: bytes
    private_key: bytes | None
    claimed_z: bytes | None


@dataclass(frozen=True, slots=True)
class KasGroup:
    """Cases sharing a curve, scheme and role."""

    tg_id: int
    test_type: str
    curve: str
    scheme: str
    kas_role: str
    tests: tuple[KasCase, ...]


@dataclass(frozen=True, slots=True)
class KasVectorSet:
    """One normalized KAS-ECC-SSC vector set."""

    vs_id: int
    algorithm: str
    revision: str
    groups: tuple[KasGroup, ...]


def _parse_case(value: object, *, path: str) -> KasCase:
    document = mapping(value, path)
    return KasCase(
        tc_id=integer(document, "tcId", path),
        server_x=hex_bytes(document, "ephemeralPublicServerX", path),
        server_y=hex_bytes(document, "ephemeralPublicServerY", path),
        private_key=optional_hex_bytes(document, "ephemeralPrivateIut", path),
        claimed_z=optional_hex_bytes(document, "z", path),
    )


def _parse_group(value: object, *, path: str) -> KasGroup:
    document = mapping(value, path)
    return KasGroup(
        tg_id=integer(document, "tgId", path),
        test_type=string_field(document, "testType", path),
        curve=string_field(document, "domainParameterGenerationMode", path),
        scheme=string_field(document, "scheme", path),
        kas_role=string_field(document, "kasRole", path),
        tests=tuple(
            _parse_case(case, path=f"{path}.tests[{index}]")
            for index, case in enumerate(list_field(document, "tests", path))
        ),
    )


def parse_vector_set(document: object) -> KasVectorSet:
    """Normalize a KAS-ECC-SSC prompt."""
    root = mapping(document, "$")
    return KasVectorSet(
        vs_id=integer(root, "vsId", "$"),
        algorithm=string_field(root, "algorithm", "$"),
        revision=string_field(root, "revision", "$"),
        groups=tuple(
            _parse_group(group, path=f"$.testGroups[{index}]")
            for index, group in enumerate(list_field(root, "testGroups", "$"))
        ),
    )


def parse_expected_results(document: object) -> dict[tuple[int, int], dict[str, object]]:
    """Index expected results by ``(tgId, tcId)``.

    ``tcId`` is normalized to an integer: this set records it as a string in the
    expected-results file and as an integer in the prompt.
    """
    root = mapping(document, "$")
    out: dict[tuple[int, int], dict[str, object]] = {}
    for index, group in enumerate(list_field(root, "testGroups", "$")):
        path = f"$.testGroups[{index}]"
        entry = mapping(group, path)
        tg_id = integer(entry, "tgId", path)
        for position, case in enumerate(list_field(entry, "tests", path)):
            case_path = f"{path}.tests[{position}]"
            values = mapping(case, case_path)
            raw = values.get("tcId")
            if not isinstance(raw, (int, str)):
                raise AcvpValidationError(case_path, "missing tcId")
            out[(tg_id, int(raw))] = dict(values)
    return out


def load_vector_set(path: str | Path) -> KasVectorSet:
    """Read and normalize a prompt file."""
    return parse_vector_set(json.loads(Path(path).read_text(encoding="utf-8")))


def load_expected_results(path: str | Path) -> dict[tuple[int, int], dict[str, object]]:
    """Read and index an expected-results file."""
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


def provider_for(provider_command: str | None, timeout_seconds: float) -> KasEccProvider:
    """The built-in provider, or a harness when one is named."""
    if provider_command is None:
        return CryptographyKasEcc()
    return SubprocessKasEcc.from_command_string(provider_command, timeout_seconds=timeout_seconds)


def run_vector_set(
    vector_set: KasVectorSet,
    expected: dict[tuple[int, int], dict[str, object]],
    provider: KasEccProvider,
) -> list[TestCaseResult]:
    """Execute every case, reporting a verdict for VAL and declining AFT."""
    results: list[TestCaseResult] = []
    for group in vector_set.groups:
        for case in group.tests:
            key = (group.tg_id, case.tc_id)
            if group.scheme != EPHEMERAL_UNIFIED:
                results.append(_unsupported(*key, f"scheme {group.scheme!r} is not supported"))
                continue
            if not provider.supports(curve=group.curve):
                results.append(_unsupported(*key, f"curve {group.curve!r} is not supported"))
                continue
            if group.test_type == AFT:
                # The implementation generates its own ephemeral key, so Z
                # differs from NIST's recorded run every time. Nothing here can
                # check it; ACVTS can, because it holds the peer private key.
                results.append(
                    _unsupported(
                        *key,
                        "AFT generates an ephemeral key, so Z cannot be compared with the "
                        "recorded value; submit to ACVTS, which can verify it",
                    )
                )
                continue
            if group.test_type != VAL:
                results.append(
                    _unsupported(*key, f"test type {group.test_type!r} is not supported")
                )
                continue
            if case.private_key is None or case.claimed_z is None:
                results.append(
                    _unsupported(*key, "a VAL case must supply both a private key and z")
                )
                continue

            expected_case = expected.get(key)
            if expected_case is None or not isinstance(expected_case.get("testPassed"), bool):
                results.append(_unsupported(*key, "no expected verdict recorded"))
                continue

            try:
                computed = provider.shared_secret(
                    curve=group.curve,
                    peer_x=case.server_x,
                    peer_y=case.server_y,
                    private_key=case.private_key,
                )
            except ValueError:
                # A peer point off the curve cannot yield a shared secret, so
                # the honest verdict is that the supplied z does not follow --
                # not an error. ACVP is entitled to send one.
                verdict = False
            else:
                verdict = computed.z == case.claimed_z
            want = bool(expected_case["testPassed"])
            diagnostic = None
            if verdict != want:
                diagnostic = (
                    "accepted a shared secret ACVP declares wrong"
                    if verdict
                    else "rejected a shared secret ACVP declares correct"
                )
            results.append(
                TestCaseResult(
                    tg_id=group.tg_id,
                    tc_id=case.tc_id,
                    status=ResultStatus.PASS if verdict == want else ResultStatus.FAIL,
                    expected=VerdictValues(passed=want),
                    actual=VerdictValues(passed=verdict),
                    diagnostic=diagnostic,
                )
            )
    return results


def metadata_for(provider: KasEccProvider) -> ProviderMetadata:
    """Provider identity, for the report header."""
    return provider.metadata()


__all__ = [
    "AFT",
    "ALGORITHM",
    "EPHEMERAL_UNIFIED",
    "REVISION",
    "VAL",
    "KasEccProvider",
    "KasVectorSet",
    "load_expected_results",
    "load_vector_set",
    "metadata_for",
    "parse_expected_results",
    "parse_vector_set",
    "provider_for",
    "run_vector_set",
]
