"""KDA, mode HKDF, revisions Sp800-56Cr1 and Sp800-56Cr2.

Two test types, and the same split as KAS-ECC-SSC. An AFT case supplies the
inputs and expects the derived keying material back. A VAL case supplies a
candidate ``dkm`` as well, and the answer is a verdict -- ACVP sends wrong ones
deliberately, so rejecting is a correct answer rather than a failure.

Most of the work is assembling ``fixedInfo``. The group declares a pattern and
an encoding, and the case supplies each party's contribution separately; the
derivation cannot be checked at all without building that string exactly as the
pattern says. Only ``uPartyInfo||vPartyInfo`` under ``concatenation`` is built
here -- other patterns name literals, algorithm identifiers or labels, and
guessing at one produces a derivation that is wrong everywhere rather than
merely unsupported.
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
from acvp_assay.providers.kda import (
    ALGORITHM,
    CONCATENATION,
    HKDF_MODE,
    HMAC_HASHES,
    UPARTY_VPARTY,
    CryptographyKda,
    KdaProvider,
    PartyInfo,
    SubprocessKda,
    fixed_info,
)
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

REVISIONS = ("Sp800-56Cr1", "Sp800-56Cr2")
AFT = "AFT"
VAL = "VAL"


@dataclass(frozen=True, slots=True)
class KdaCase:
    """One derivation."""

    tc_id: int
    salt: bytes
    shared_secret: bytes
    output_bits: int
    party_u: PartyInfo
    party_v: PartyInfo
    claimed_dkm: bytes | None


@dataclass(frozen=True, slots=True)
class KdaGroup:
    """Cases sharing a KDF configuration."""

    tg_id: int
    test_type: str
    kdf_type: str
    hmac_alg: str
    pattern: str
    encoding: str
    tests: tuple[KdaCase, ...]


@dataclass(frozen=True, slots=True)
class KdaVectorSet:
    """One normalized KDA vector set."""

    vs_id: int
    algorithm: str
    mode: str
    revision: str
    groups: tuple[KdaGroup, ...]


def _party(value: object, *, path: str) -> PartyInfo:
    document = mapping(value, path)
    return PartyInfo(
        party_id=hex_bytes(document, "partyId", path),
        ephemeral_data=optional_hex_bytes(document, "ephemeralData", path),
    )


def _parse_case(value: object, *, path: str) -> KdaCase:
    document = mapping(value, path)
    parameter = mapping(document.get("kdfParameter"), f"{path}.kdfParameter")
    return KdaCase(
        tc_id=integer(document, "tcId", path),
        salt=hex_bytes(parameter, "salt", f"{path}.kdfParameter"),
        shared_secret=hex_bytes(parameter, "z", f"{path}.kdfParameter"),
        output_bits=integer(parameter, "l", f"{path}.kdfParameter"),
        party_u=_party(document.get("fixedInfoPartyU"), path=f"{path}.fixedInfoPartyU"),
        party_v=_party(document.get("fixedInfoPartyV"), path=f"{path}.fixedInfoPartyV"),
        claimed_dkm=optional_hex_bytes(document, "dkm", path),
    )


def _parse_group(value: object, *, path: str) -> KdaGroup:
    document = mapping(value, path)
    configuration = mapping(document.get("kdfConfiguration"), f"{path}.kdfConfiguration")
    config_path = f"{path}.kdfConfiguration"
    return KdaGroup(
        tg_id=integer(document, "tgId", path),
        test_type=string_field(document, "testType", path),
        kdf_type=string_field(configuration, "kdfType", config_path),
        hmac_alg=string_field(configuration, "hmacAlg", config_path),
        pattern=string_field(configuration, "fixedInfoPattern", config_path),
        encoding=string_field(configuration, "fixedInfoEncoding", config_path),
        tests=tuple(
            _parse_case(case, path=f"{path}.tests[{index}]")
            for index, case in enumerate(list_field(document, "tests", path))
        ),
    )


def parse_vector_set(document: object) -> KdaVectorSet:
    """Normalize a KDA prompt."""
    root = mapping(document, "$")
    return KdaVectorSet(
        vs_id=integer(root, "vsId", "$"),
        algorithm=string_field(root, "algorithm", "$"),
        mode=string_field(root, "mode", "$"),
        revision=string_field(root, "revision", "$"),
        groups=tuple(
            _parse_group(group, path=f"$.testGroups[{index}]")
            for index, group in enumerate(list_field(root, "testGroups", "$"))
        ),
    )


@dataclass(frozen=True, slots=True)
class KdaExpectation:
    """The recorded answer: keying material, or a verdict."""

    dkm: bytes | None
    test_passed: bool | None


def parse_expected_results(document: object) -> dict[tuple[int, int], KdaExpectation]:
    """Index expectations by ``(tgId, tcId)``."""
    from acvp_assay.parser import optional_boolean

    root = mapping(document, "$")
    out: dict[tuple[int, int], KdaExpectation] = {}
    for index, group in enumerate(list_field(root, "testGroups", "$")):
        path = f"$.testGroups[{index}]"
        entry = mapping(group, path)
        tg_id = integer(entry, "tgId", path)
        for position, case in enumerate(list_field(entry, "tests", path)):
            case_path = f"{path}.tests[{position}]"
            values = mapping(case, case_path)
            dkm = optional_hex_bytes(values, "dkm", case_path)
            verdict = optional_boolean(values, "testPassed", case_path)
            if dkm is None and verdict is None:
                raise AcvpValidationError(case_path, "expected a dkm or testPassed value")
            out[(tg_id, integer(values, "tcId", case_path))] = KdaExpectation(dkm, verdict)
    return out


def load_vector_set(path: str | Path) -> KdaVectorSet:
    """Read and normalize a prompt file."""
    return parse_vector_set(json.loads(Path(path).read_text(encoding="utf-8")))


def load_expected_results(path: str | Path) -> dict[tuple[int, int], KdaExpectation]:
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


def provider_for(provider_command: str | None, timeout_seconds: float) -> KdaProvider:
    """The built-in provider, or a harness when one is named."""
    if provider_command is None:
        return CryptographyKda()
    return SubprocessKda.from_command_string(provider_command, timeout_seconds=timeout_seconds)


def _decline_reason(group: KdaGroup) -> str | None:
    """Why this group cannot be answered faithfully, if it cannot."""
    if group.kdf_type.lower() != HKDF_MODE.lower():
        return f"kdfType {group.kdf_type!r} is not implemented; only HKDF is"
    if group.hmac_alg not in HMAC_HASHES:
        return f"hmacAlg {group.hmac_alg!r} is not supported"
    if group.encoding != CONCATENATION:
        return f"fixedInfoEncoding {group.encoding!r} is not implemented"
    if group.pattern != UPARTY_VPARTY:
        return (
            f"fixedInfoPattern {group.pattern!r} is not assembled by this runner; "
            f"register only {UPARTY_VPARTY!r} for a submission"
        )
    return None


def run_vector_set(
    vector_set: KdaVectorSet,
    expected: dict[tuple[int, int], KdaExpectation],
    provider: KdaProvider,
) -> list[TestCaseResult]:
    """Derive every case, comparing bytes for AFT and a verdict for VAL."""
    results: list[TestCaseResult] = []
    for group in vector_set.groups:
        decline = _decline_reason(group)
        for case in group.tests:
            key = (group.tg_id, case.tc_id)
            if decline is not None:
                results.append(_unsupported(*key, decline))
                continue
            info = fixed_info(group.pattern, case.party_u, case.party_v)
            want = expected.get(key)
            if want is None:
                results.append(_unsupported(*key, "no expected result recorded"))
                continue
            try:
                produced = provider.derive(
                    hmac_alg=group.hmac_alg,
                    salt=case.salt,
                    shared_secret=case.shared_secret,
                    info=info,
                    output_bytes=case.output_bits // 8,
                )
            except HarnessUnsupportedError:
                results.append(_unsupported(*key, "the harness declined this case"))
                continue

            if group.test_type == VAL:
                if case.claimed_dkm is None or want.test_passed is None:
                    results.append(_unsupported(*key, "a VAL case needs a dkm and a verdict"))
                    continue
                verdict = produced == case.claimed_dkm
                agreed = verdict == want.test_passed
                results.append(
                    TestCaseResult(
                        tg_id=group.tg_id,
                        tc_id=case.tc_id,
                        status=ResultStatus.PASS if agreed else ResultStatus.FAIL,
                        expected=VerdictValues(passed=want.test_passed),
                        actual=VerdictValues(passed=verdict),
                        diagnostic=None
                        if agreed
                        else (
                            "accepted keying material ACVP declares wrong"
                            if verdict
                            else "rejected keying material ACVP declares correct"
                        ),
                    )
                )
                continue

            if want.dkm is None:
                results.append(_unsupported(*key, "no expected dkm recorded"))
                continue
            matched = produced == want.dkm
            results.append(
                TestCaseResult(
                    tg_id=group.tg_id,
                    tc_id=case.tc_id,
                    status=ResultStatus.PASS if matched else ResultStatus.FAIL,
                    expected=None,
                    actual=None,
                    diagnostic=None if matched else "dkm mismatch",
                )
            )
    return results


def metadata_for(provider: KdaProvider) -> ProviderMetadata:
    """Provider identity, for the report header."""
    return provider.metadata()


__all__ = [
    "AFT",
    "ALGORITHM",
    "REVISIONS",
    "VAL",
    "KdaExpectation",
    "KdaVectorSet",
    "load_expected_results",
    "load_vector_set",
    "metadata_for",
    "parse_expected_results",
    "parse_vector_set",
    "provider_for",
    "run_vector_set",
]
