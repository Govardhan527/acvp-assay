"""Parsing and execution for kdf-components (ssh), TLS-v1.2 and TLS-v1.3.

One module for three registry names because they share a provider and a
customer: a module that terminates a protocol validates them together.

`kdf-components` is one registry name covering nine component KDFs. Only `ssh`
is built here -- the most common of them at 46% of active FIPS 140-3 modules --
and the rest are declined **by name**, so a report says which mode is missing
rather than reporting the whole algorithm as unsupported.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from acvp_assay.models import DeclineReason, ProviderMetadata, ResultStatus, TestCaseResult
from acvp_assay.parser import (
    AcvpValidationError,
    hex_bytes,
    integer,
    list_field,
    mapping,
    optional_hex_bytes,
    optional_string,
    string_field,
)
from acvp_assay.providers.kdf_tls import (
    KDF_COMPONENTS,
    SSH_MODE,
    TLS_V12,
    TLS_V13,
    HashlibProtocolKdf,
    ProtocolKdfProvider,
    SubprocessProtocolKdf,
)
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

SUPPORTED: tuple[str, ...] = (KDF_COMPONENTS, TLS_V12, TLS_V13)

#: The eight TLS 1.3 secrets, as attribute name to ACVP field name.
TLS13_FIELDS: tuple[tuple[str, str], ...] = (
    ("client_early_traffic", "clientEarlyTrafficSecret"),
    ("early_exporter_master", "earlyExporterMasterSecret"),
    ("client_handshake_traffic", "clientHandshakeTrafficSecret"),
    ("server_handshake_traffic", "serverHandshakeTrafficSecret"),
    ("client_application_traffic", "clientApplicationTrafficSecret"),
    ("server_application_traffic", "serverApplicationTrafficSecret"),
    ("exporter_master", "exporterMasterSecret"),
    ("resumption_master", "resumptionMasterSecret"),
)

#: The six SSH values, likewise.
SSH_FIELDS: tuple[tuple[str, str], ...] = (
    ("initial_iv_client", "initialIvClient"),
    ("initial_iv_server", "initialIvServer"),
    ("encryption_key_client", "encryptionKeyClient"),
    ("encryption_key_server", "encryptionKeyServer"),
    ("integrity_key_client", "integrityKeyClient"),
    ("integrity_key_server", "integrityKeyServer"),
)


@dataclass(frozen=True, slots=True)
class KdfCase:
    """One case, holding whichever inputs its algorithm uses."""

    tc_id: int
    values: dict[str, bytes]


@dataclass(frozen=True, slots=True)
class KdfGroup:
    """One group and the parameters it fixes."""

    tg_id: int
    hash_alg: str | None
    cipher: str | None
    running_mode: str | None
    key_block_bits: int | None
    tests: tuple[KdfCase, ...]


@dataclass(frozen=True, slots=True)
class KdfVectorSet:
    """A parsed protocol-KDF vector set."""

    vs_id: int
    algorithm: str
    mode: str | None
    revision: str
    test_groups: tuple[KdfGroup, ...]


_CASE_FIELDS = (
    "k",
    "h",
    "sessionId",
    "preMasterSecret",
    "sessionHash",
    "clientRandom",
    "serverRandom",
    "psk",
    "dhe",
    "helloClientRandom",
    "helloServerRandom",
    "finishedClientRandom",
    "finishedServerRandom",
)


def _parse_group(value: object, *, path: str) -> KdfGroup:
    document = mapping(value, path=path)
    cases = []
    for index, item in enumerate(list_field(document, "tests", path=path)):
        case_path = f"{path}.tests[{index}]"
        case = mapping(item, path=case_path)
        values = {}
        for name in _CASE_FIELDS:
            found = optional_hex_bytes(case, name, path=case_path)
            if found is not None:
                values[name] = found
        cases.append(KdfCase(tc_id=integer(case, "tcId", path=case_path), values=values))
    block = document.get("keyBlockLength")
    return KdfGroup(
        tg_id=integer(document, "tgId", path=path),
        hash_alg=optional_string(document, "hashAlg", path=path)
        or optional_string(document, "hmacAlg", path=path),
        cipher=optional_string(document, "cipher", path=path),
        running_mode=optional_string(document, "runningMode", path=path),
        key_block_bits=integer(document, "keyBlockLength", path=path)
        if isinstance(block, int)
        else None,
        tests=tuple(cases),
    )


def parse_vector_set(value: object) -> KdfVectorSet:
    """Parse a protocol-KDF vector set, preserving every ACVP id."""
    document = mapping(value, path="$")
    algorithm = string_field(document, "algorithm", path="$")
    if algorithm not in SUPPORTED:
        raise AcvpValidationError("$.algorithm", f"expected one of {list(SUPPORTED)}")
    groups = list_field(document, "testGroups", path="$")
    return KdfVectorSet(
        vs_id=integer(document, "vsId", path="$"),
        algorithm=algorithm,
        mode=optional_string(document, "mode", path="$"),
        revision=string_field(document, "revision", path="$"),
        test_groups=tuple(
            _parse_group(item, path=f"$.testGroups[{index}]") for index, item in enumerate(groups)
        ),
    )


def parse_expected_results(value: object) -> dict[tuple[int, int], dict[str, bytes]]:
    """Every expected output value, keyed by group and case."""
    document = mapping(value, path="$")
    found: dict[tuple[int, int], dict[str, bytes]] = {}
    for group_index, group_value in enumerate(list_field(document, "testGroups", path="$")):
        group_path = f"$.testGroups[{group_index}]"
        group = mapping(group_value, path=group_path)
        tg_id = integer(group, "tgId", path=group_path)
        for case_index, case_value in enumerate(list_field(group, "tests", path=group_path)):
            case_path = f"{group_path}.tests[{case_index}]"
            case = mapping(case_value, path=case_path)
            found[(tg_id, integer(case, "tcId", path=case_path))] = {
                name: hex_bytes(case, name, path=case_path) for name in case if name != "tcId"
            }
    return found


def _load_json(path: str | Path) -> object:
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def load_vector_set(path: str | Path) -> KdfVectorSet:
    """Load and parse a protocol-KDF vector file."""
    return parse_vector_set(_load_json(path))


def load_expected_results(path: str | Path) -> dict[tuple[int, int], dict[str, bytes]]:
    """Load and parse a protocol-KDF expected-results file."""
    return parse_expected_results(_load_json(path))


def provider_for(provider_command: str | None, timeout_seconds: float) -> ProtocolKdfProvider:
    """The built-in provider, or a harness when one is named."""
    if provider_command is None:
        return HashlibProtocolKdf()
    return SubprocessProtocolKdf.from_command_string(
        provider_command, timeout_seconds=timeout_seconds
    )


def metadata_for(provider: ProtocolKdfProvider) -> ProviderMetadata:
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


def _compare(
    tg_id: int, tc_id: int, produced: dict[str, bytes], wanted: dict[str, bytes]
) -> TestCaseResult:
    """Every output must match; the first that does not names itself."""
    for field, value in produced.items():
        if field not in wanted:
            return _unsupported(
                DeclineReason.OFFLINE_UNDECIDABLE, tg_id, tc_id, f"no expected {field} recorded"
            )
        if wanted[field] != value:
            return TestCaseResult(
                tg_id=tg_id,
                tc_id=tc_id,
                status=ResultStatus.FAIL,
                expected=None,
                actual=None,
                diagnostic=f"{field} differs",
            )
    return TestCaseResult(
        tg_id=tg_id,
        tc_id=tc_id,
        status=ResultStatus.PASS,
        expected=None,
        actual=None,
        diagnostic=None,
    )


def derive(
    vector_set: KdfVectorSet, group: KdfGroup, case: KdfCase, provider: ProtocolKdfProvider
) -> dict[str, bytes]:
    """Every output value for one case, whichever algorithm it belongs to."""
    values = case.values
    if vector_set.algorithm == KDF_COMPONENTS:
        keys = provider.ssh(
            hash_alg=group.hash_alg or "",
            cipher=group.cipher or "",
            shared_secret=values["k"],
            exchange_hash=values["h"],
            session_id=values["sessionId"],
        )
        return {name: getattr(keys, attr) for attr, name in SSH_FIELDS}
    if vector_set.algorithm == TLS_V12:
        result = provider.tls12(
            hash_alg=group.hash_alg or "",
            pre_master_secret=values["preMasterSecret"],
            session_hash=values["sessionHash"],
            client_random=values["clientRandom"],
            server_random=values["serverRandom"],
            key_block_bytes=(group.key_block_bits or 0) // 8,
        )
        return {"masterSecret": result.master_secret, "keyBlock": result.key_block}
    secrets = provider.tls13(
        hmac_alg=group.hash_alg or "",
        psk=values.get("psk"),
        dhe=values.get("dhe"),
        hello_client=values["helloClientRandom"],
        hello_server=values["helloServerRandom"],
        finished_client=values["finishedClientRandom"],
        finished_server=values["finishedServerRandom"],
    )
    return {name: getattr(secrets, attr) for attr, name in TLS13_FIELDS}


def run_vector_set(
    vector_set: KdfVectorSet,
    expected: dict[tuple[int, int], dict[str, bytes]],
    provider: ProtocolKdfProvider,
) -> list[TestCaseResult]:
    """Derive every case and compare each output with the recorded one."""
    results: list[TestCaseResult] = []
    unsupported_mode = vector_set.algorithm == KDF_COMPONENTS and vector_set.mode != SSH_MODE
    for group in vector_set.test_groups:
        for case in group.tests:
            key = (group.tg_id, case.tc_id)
            if unsupported_mode:
                results.append(
                    _unsupported(
                        DeclineReason.RUNNER_LACKS,
                        *key,
                        f"kdf-components mode {vector_set.mode!r} is not implemented; "
                        f"only {SSH_MODE!r} is",
                    )
                )
                continue
            wanted = expected.get(key)
            if wanted is None:
                results.append(
                    _unsupported(
                        DeclineReason.OFFLINE_UNDECIDABLE, *key, "no expected result recorded"
                    )
                )
                continue
            try:
                produced = derive(vector_set, group, case, provider)
            except HarnessUnsupportedError:
                results.append(
                    _unsupported(
                        DeclineReason.IMPLEMENTATION_LACKS, *key, "the harness declined this case"
                    )
                )
                continue
            except KeyError as error:
                # A field this case must carry is absent from the vector.
                results.append(
                    _unsupported(
                        DeclineReason.VECTOR_INCOMPLETE,
                        *key,
                        f"this case cannot be answered: {error.args[0]}",
                    )
                )
                continue
            except ValueError as error:
                # Raised by the implementation: a hash or cipher the provider
                # refuses, or a harness reply that breaks the protocol.
                results.append(
                    _unsupported(
                        DeclineReason.IMPLEMENTATION_LACKS,
                        *key,
                        f"this case cannot be answered: {error.args[0]}",
                    )
                )
                continue
            results.append(_compare(*key, produced, wanted))
    return results


__all__ = [
    "KDF_COMPONENTS",
    "SSH_FIELDS",
    "SSH_MODE",
    "SUPPORTED",
    "TLS13_FIELDS",
    "KdfCase",
    "KdfGroup",
    "KdfVectorSet",
    "derive",
    "load_expected_results",
    "load_vector_set",
    "metadata_for",
    "parse_expected_results",
    "parse_vector_set",
    "provider_for",
    "run_vector_set",
]
