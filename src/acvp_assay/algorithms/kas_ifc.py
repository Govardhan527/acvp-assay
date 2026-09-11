"""Parsing and execution for KAS-IFC-SSC and KTS-IFC (SP 800-56Br2).

Which cases can be answered offline is decided by whether the implementation
has to **originate** secret material, and for these families that is more often
"no" than it is for the ECC and FFC variants:

* **KAS1 responder** and **KTS-IFC responder** only recover, using a private key
  the case supplies, so their answers are deterministic and fully checkable.
* **KAS1 initiator**, **either KAS2 role** and **KTS-IFC initiator** originate a
  fresh secret, so the answer differs every run. Those are declined offline with
  the reason and answered in full on submission, where the server recomputes
  them from what is reported.

A VAL case supplies everything and is always checkable.

**On what a VAL case actually tests.** For the initiator schemes two conditions
are available -- that ``iutC`` is the encryption of ``iutZ``, and that ``z`` is
the value derived from it -- and both are checked here. That is deliberately
stronger than what the vectors can distinguish: across five sessions and nine
failing VAL cases, six of which carry both conditions, **not one** failed only
one of them. NIST's generator appears to corrupt the underlying Z, which breaks
both at once. Checking either alone would agree with every vector the server
issues; checking both agrees too, and is correct for a case the server has not
yet generated.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from acvp_assay.models import DeclineReason, ProviderMetadata, ResultStatus, TestCaseResult
from acvp_assay.parser import (
    AcvpValidationError,
    integer,
    list_field,
    mapping,
    optional_hex_bytes,
    optional_integer,
    optional_string,
    string_field,
)
from acvp_assay.providers.kas_ifc import (
    KAS2,
    KAS_IFC,
    KTS_IFC,
    SCHEMES,
    CryptographyKasIfc,
    KasIfcProvider,
    RsaKey,
    SubprocessKasIfc,
)
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

SUPPORTED: tuple[str, ...] = (KAS_IFC, KTS_IFC)
AFT = "AFT"
VAL = "VAL"
INITIATOR = "initiator"


@dataclass(frozen=True, slots=True)
class IfcCase:
    """One case: the IUT's key when it has one, the peer's when it needs it."""

    tc_id: int
    iut_key: RsaKey | None
    peer_n: int | None
    peer_e: int | None
    server_c: bytes | None
    iut_c: bytes | None
    iut_z: bytes | None
    claimed_z: bytes | None


@dataclass(frozen=True, slots=True)
class IfcGroup:
    """One group: the scheme, the role, and for KTS the OAEP configuration."""

    tg_id: int
    scheme: str
    kas_role: str
    test_type: str
    hash_alg: str | None
    key_bits: int | None
    tests: tuple[IfcCase, ...]


@dataclass(frozen=True, slots=True)
class IfcVectorSet:
    """A parsed IFC vector set."""

    vs_id: int
    algorithm: str
    revision: str
    groups: tuple[IfcGroup, ...]


def _key_of(case: dict[str, object], *, path: str) -> RsaKey | None:
    """The IUT's own RSA key, when the case supplies one."""
    parts = {}
    for field in ("iutN", "iutE", "iutD", "iutP", "iutQ"):
        value = optional_hex_bytes(case, field, path=path)
        if value is None:
            return None
        parts[field] = int.from_bytes(value, "big")
    return RsaKey(
        n=parts["iutN"], e=parts["iutE"], d=parts["iutD"], p=parts["iutP"], q=parts["iutQ"]
    )


def _int_of(case: dict[str, object], field: str, *, path: str) -> int | None:
    value = optional_hex_bytes(case, field, path=path)
    return None if value is None else int.from_bytes(value, "big")


def _parse_group(value: object, *, path: str) -> IfcGroup:
    document = mapping(value, path=path)
    configuration = document.get("ktsConfiguration")
    hash_alg = None
    if isinstance(configuration, dict):
        found = configuration.get("hashAlg")
        hash_alg = found if isinstance(found, str) else None
    cases = []
    for index, item in enumerate(list_field(document, "tests", path=path)):
        case_path = f"{path}.tests[{index}]"
        case = dict(mapping(item, path=case_path))
        cases.append(
            IfcCase(
                tc_id=integer(case, "tcId", path=case_path),
                iut_key=_key_of(case, path=case_path),
                peer_n=_int_of(case, "serverN", path=case_path),
                peer_e=_int_of(case, "serverE", path=case_path),
                server_c=optional_hex_bytes(case, "serverC", path=case_path),
                iut_c=optional_hex_bytes(case, "iutC", path=case_path),
                iut_z=optional_hex_bytes(case, "iutZ", path=case_path),
                claimed_z=optional_hex_bytes(case, "z", path=case_path),
            )
        )
    return IfcGroup(
        tg_id=integer(document, "tgId", path=path),
        scheme=string_field(document, "scheme", path=path),
        kas_role=string_field(document, "kasRole", path=path),
        test_type=string_field(document, "testType", path=path),
        hash_alg=hash_alg,
        key_bits=optional_integer(document, "l", path=path),
        tests=tuple(cases),
    )


def parse_vector_set(value: object) -> IfcVectorSet:
    """Parse an IFC vector set, preserving every ACVP id."""
    document = mapping(value, path="$")
    algorithm = string_field(document, "algorithm", path="$")
    if algorithm not in SUPPORTED:
        raise AcvpValidationError("$.algorithm", f"expected one of {list(SUPPORTED)}")
    _ = optional_string(document, "mode", path="$")
    groups = list_field(document, "testGroups", path="$")
    return IfcVectorSet(
        vs_id=integer(document, "vsId", path="$"),
        algorithm=algorithm,
        revision=string_field(document, "revision", path="$"),
        groups=tuple(
            _parse_group(item, path=f"$.testGroups[{index}]") for index, item in enumerate(groups)
        ),
    )


def originates(vector_set: IfcVectorSet, group: IfcGroup) -> bool:
    """Whether the implementation must invent secret material for this group.

    KAS2 has *both* parties contribute, so neither role is a pure recovery; KAS1
    and KTS-IFC put the origination on the initiator alone.
    """
    if group.test_type != AFT:
        return False
    if vector_set.algorithm == KTS_IFC:
        return group.kas_role == INITIATOR
    return group.scheme == KAS2 or group.kas_role == INITIATOR


def parse_expected_results(value: object) -> dict[tuple[int, int], dict[str, object]]:
    """Every expected value, keyed by group and case."""
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


def load_vector_set(path: str | Path) -> IfcVectorSet:
    """Load and parse an IFC vector file."""
    return parse_vector_set(_load_json(path))


def load_expected_results(path: str | Path) -> dict[tuple[int, int], dict[str, object]]:
    """Load and parse an IFC expected-results file."""
    return parse_expected_results(_load_json(path))


def provider_for(provider_command: str | None, timeout_seconds: float) -> KasIfcProvider:
    """The built-in provider, or a harness when one is named."""
    if provider_command is None:
        return CryptographyKasIfc()
    return SubprocessKasIfc.from_command_string(provider_command, timeout_seconds=timeout_seconds)


def metadata_for(provider: KasIfcProvider) -> ProviderMetadata:
    """Report which implementation answered."""
    return provider.metadata()


def _unsupported(code: DeclineReason, tg_id: int, tc_id: int, reason: str) -> TestCaseResult:
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=ResultStatus.UNSUPPORTED,
        expected=None,
        actual=None,
        diagnostic=reason,
        decline_reason=code,
    )


def _result(tg_id: int, tc_id: int, *, agrees: bool, detail: str) -> TestCaseResult:
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=ResultStatus.PASS if agrees else ResultStatus.FAIL,
        expected=None,
        actual=None,
        diagnostic=None if agrees else detail,
    )


def shared_secret(
    vector_set: IfcVectorSet, group: IfcGroup, case: IfcCase, provider: KasIfcProvider
) -> bytes:
    """The Z this case's role and scheme produce from what it supplies.

    KAS2 concatenates rather than combining or hashing, and **the order is by
    role, not by ownership**: the initiator's contribution always comes first.
    So an initiator emits ``own || recovered`` and a responder ``recovered ||
    own``, which look like the same rule from one side and opposite rules from
    the other.

    That asymmetry is why one session was not enough. Deriving the rule from a
    KAS2 *initiator* group alone produces a version that is right for half the
    vectors and silently wrong for the other half; the responder groups in a
    later session were what caught it.
    """
    recovered = b""
    if case.server_c is not None and case.iut_key is not None:
        recovered = provider.recover(key=case.iut_key, ciphertext=case.server_c)
    if group.scheme == KAS2 and case.iut_z is not None:
        if group.kas_role == INITIATOR:
            return case.iut_z + recovered
        return recovered + case.iut_z
    if case.iut_z is not None:
        return case.iut_z
    return recovered


def run_vector_set(
    vector_set: IfcVectorSet,
    expected: dict[tuple[int, int], dict[str, object]],
    provider: KasIfcProvider,
) -> list[TestCaseResult]:
    """Check every case that does not require originating fresh material."""
    results: list[TestCaseResult] = []
    for group in vector_set.groups:
        for case in group.tests:
            key = (group.tg_id, case.tc_id)
            if group.scheme not in SCHEMES and vector_set.algorithm == KAS_IFC:
                results.append(
                    _unsupported(
                        DeclineReason.RUNNER_LACKS,
                        *key,
                        f"scheme {group.scheme!r} is not supported",
                    )
                )
                continue
            if originates(vector_set, group):
                results.append(
                    _unsupported(
                        DeclineReason.OFFLINE_UNDECIDABLE,
                        *key,
                        "this case originates fresh secret material, so it cannot be compared "
                        "with the recorded value; submit to ACVTS, which recomputes it",
                    )
                )
                continue
            recorded = expected.get(key)
            if recorded is None:
                results.append(
                    _unsupported(
                        DeclineReason.OFFLINE_UNDECIDABLE, *key, "no expected result recorded"
                    )
                )
                continue
            try:
                results.append(_check(vector_set, group, case, recorded, provider, key))
            except HarnessUnsupportedError:
                results.append(
                    _unsupported(
                        DeclineReason.IMPLEMENTATION_LACKS, *key, "the harness declined this case"
                    )
                )
            except ValueError as error:
                results.append(
                    _unsupported(
                        DeclineReason.IMPLEMENTATION_LACKS,
                        *key,
                        f"this case cannot be answered: {error.args[0]}",
                    )
                )
    return results


def _check(
    vector_set: IfcVectorSet,
    group: IfcGroup,
    case: IfcCase,
    recorded: dict[str, object],
    provider: KasIfcProvider,
    key: tuple[int, int],
) -> TestCaseResult:
    """One checkable case, VAL or a recover-only AFT."""
    if vector_set.algorithm == KTS_IFC:
        if case.iut_key is None or case.server_c is None or group.hash_alg is None:
            return _unsupported(
                DeclineReason.VECTOR_INCOMPLETE,
                *key,
                "a KTS-IFC recovery case needs a key, a ciphertext and a hash",
            )
        dkm = provider.oaep_decrypt(
            key=case.iut_key, ciphertext=case.server_c, hash_alg=group.hash_alg
        )
        wanted = recorded.get("dkm")
        if not isinstance(wanted, str):
            return _unsupported(DeclineReason.OFFLINE_UNDECIDABLE, *key, "no expected dkm recorded")
        return _result(*key, agrees=dkm.hex().upper() == wanted.upper(), detail="dkm differs")

    if group.test_type == AFT:
        wanted = recorded.get("z")
        if not isinstance(wanted, str):
            return _unsupported(DeclineReason.OFFLINE_UNDECIDABLE, *key, "no expected z recorded")
        produced = shared_secret(vector_set, group, case, provider)
        return _result(*key, agrees=produced.hex().upper() == wanted.upper(), detail="z differs")

    verdict = recorded.get("testPassed")
    if not isinstance(verdict, bool):
        return _unsupported(DeclineReason.OFFLINE_UNDECIDABLE, *key, "no expected verdict recorded")
    if case.claimed_z is None:
        return _unsupported(DeclineReason.VECTOR_INCOMPLETE, *key, "a VAL case must supply z")
    agrees = shared_secret(vector_set, group, case, provider) == case.claimed_z
    # Both conditions, though the server's vectors never separate them; see the
    # module docstring.
    if agrees and case.iut_z is not None and case.iut_c is not None:
        if case.peer_n is None or case.peer_e is None:
            return _unsupported(
                DeclineReason.VECTOR_INCOMPLETE,
                *key,
                "an initiator VAL case must supply the peer public key",
            )
        size = (case.peer_n.bit_length() + 7) // 8
        encrypted = pow(int.from_bytes(case.iut_z, "big"), case.peer_e, case.peer_n)
        agrees = encrypted.to_bytes(size, "big") == case.iut_c
    return _result(*key, agrees=agrees == verdict, detail=f"expected testPassed={verdict}")


__all__ = [
    "AFT",
    "INITIATOR",
    "KTS_IFC",
    "SUPPORTED",
    "VAL",
    "IfcCase",
    "IfcGroup",
    "IfcVectorSet",
    "load_expected_results",
    "load_vector_set",
    "metadata_for",
    "originates",
    "parse_expected_results",
    "parse_vector_set",
    "provider_for",
    "run_vector_set",
    "shared_secret",
]
