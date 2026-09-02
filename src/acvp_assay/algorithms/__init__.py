"""Algorithm dispatch: route a vector file to the parser and runner that fit it.

Each family owns its own models, parser, and runner because the shapes differ
too much to share usefully — AES-GCM has directions and authentication
failures, SHA-2 has chained Monte Carlo groups, HMAC has truncated MACs. What
*is* shared is everything downstream of execution: ``TestCaseResult``, the
comparator vocabulary, the reporter, and the exit-code rules.

Adding a family means writing its module and adding one entry here.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Callable
from pathlib import Path

from acvp_assay import parser as aes_parser
from acvp_assay import runner as aes_runner
from acvp_assay.algorithms import aes_modes, ctr_drbg, ecdsa, hmac_mac, kdf, pqc, sha2
from acvp_assay.models import ProviderMetadata, TestCaseResult
from acvp_assay.providers.aes_modes import (
    AesModeProvider as AesModeProviderProtocol,
)
from acvp_assay.providers.aes_modes import CryptographyAesModeProvider
from acvp_assay.providers.cryptography_aesgcm import CryptographyAesGcmProvider
from acvp_assay.providers.ctr_drbg import CryptographyCtrDrbg
from acvp_assay.providers.ctr_drbg import CtrDrbgProvider as CtrDrbgProviderProtocol
from acvp_assay.providers.digest import (
    HASHLIB_ALGORITHMS,
    HashlibHashProvider,
    HashlibMacProvider,
    SubprocessHashProvider,
    SubprocessMacProvider,
)
from acvp_assay.providers.digest import HashProvider as HashProviderProtocol
from acvp_assay.providers.digest import MacProvider as MacProviderProtocol
from acvp_assay.providers.ecdsa import CryptographyEcdsaProvider, SubprocessEcdsaProvider
from acvp_assay.providers.ecdsa import EcdsaProvider as EcdsaProviderProtocol
from acvp_assay.providers.kdf import CryptographyKdf
from acvp_assay.providers.kdf import KdfProvider as KdfProviderProtocol
from acvp_assay.providers.pqc import SubprocessMlDsaProvider, SubprocessMlKemProvider
from acvp_assay.providers.subprocess_harness import SubprocessAesGcmProvider


class UnsupportedAlgorithmError(ValueError):
    """The vector file names an algorithm this runner does not implement."""


def peek_algorithm(vector_file: Path) -> tuple[str, str]:
    """Read just the algorithm and revision from a prompt file."""
    try:
        document = json.loads(vector_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise aes_parser.AcvpValidationError(
            "$", f"invalid JSON at line {error.lineno}, column {error.colno}"
        ) from None
    if not isinstance(document, dict):
        raise aes_parser.AcvpValidationError("$", "expected an object")
    algorithm = document.get("algorithm")
    revision = document.get("revision")
    if not isinstance(algorithm, str) or not isinstance(revision, str):
        raise aes_parser.AcvpValidationError("$", "missing algorithm or revision")
    return algorithm, revision


def supported_algorithms() -> list[str]:
    """List every algorithm name this runner can execute."""
    names = [
        "ACVP-AES-GCM",
        "ECDSA",
        "ML-DSA",
        "ML-KEM",
        ctr_drbg.ALGORITHM,
        kdf.ALGORITHM,
        *aes_modes.SUPPORTED,
        *HASHLIB_ALGORITHMS,
    ]
    names.extend(f"HMAC-{name}" for name in HASHLIB_ALGORITHMS)
    return sorted(names)


def _run_aes_gcm(
    vector_file: Path,
    expected_file: Path,
    provider_command: str | None,
    provider_timeout: float,
) -> tuple[list[TestCaseResult], ProviderMetadata]:
    provider = (
        CryptographyAesGcmProvider()
        if provider_command is None
        else SubprocessAesGcmProvider.from_command_string(
            provider_command, timeout_seconds=provider_timeout
        )
    )
    metadata = provider.metadata()
    vector_set = aes_parser.load_vector_set(vector_file)
    expected = aes_parser.load_expected_results(expected_file)
    return aes_runner.run_vector_set(vector_set, expected, provider), metadata


def _run_sha2(
    algorithm: str,
    vector_file: Path,
    expected_file: Path,
    provider_command: str | None,
    provider_timeout: float,
) -> tuple[list[TestCaseResult], ProviderMetadata]:
    provider: HashProviderProtocol = (
        HashlibHashProvider(algorithm)
        if provider_command is None
        else SubprocessHashProvider(
            algorithm,
            shlex.split(provider_command),
            timeout_seconds=provider_timeout,
        )
    )
    metadata = provider.metadata()
    vector_set = sha2.load_vector_set(vector_file)
    expected = sha2.load_expected_results(expected_file)
    return sha2.run_vector_set(vector_set, expected, provider), metadata


def _run_hmac(
    algorithm: str,
    vector_file: Path,
    expected_file: Path,
    provider_command: str | None,
    provider_timeout: float,
) -> tuple[list[TestCaseResult], ProviderMetadata]:
    provider: MacProviderProtocol = (
        HashlibMacProvider(algorithm)
        if provider_command is None
        else SubprocessMacProvider(
            algorithm,
            shlex.split(provider_command),
            timeout_seconds=provider_timeout,
        )
    )
    metadata = provider.metadata()
    vector_set = hmac_mac.load_vector_set(vector_file)
    expected = hmac_mac.load_expected_results(expected_file)
    return hmac_mac.run_vector_set(vector_set, expected, provider), metadata


def _run_ecdsa(
    vector_file: Path,
    expected_file: Path,
    provider_command: str | None,
    provider_timeout: float,
) -> tuple[list[TestCaseResult], ProviderMetadata]:
    provider: EcdsaProviderProtocol = (
        CryptographyEcdsaProvider()
        if provider_command is None
        else SubprocessEcdsaProvider.from_command_string(
            provider_command, timeout_seconds=provider_timeout
        )
    )
    metadata = provider.metadata()
    vector_set = ecdsa.load_vector_set(vector_file)
    expected = ecdsa.load_expected_results(expected_file)
    return ecdsa.run_vector_set(vector_set, expected, provider), metadata


def _run_pqc(
    algorithm: str,
    vector_file: Path,
    expected_file: Path,
    provider_command: str | None,
    provider_timeout: float,
) -> tuple[list[TestCaseResult], ProviderMetadata]:
    """Run ML-KEM or ML-DSA, which have no built-in provider by design.

    Neither the pinned ``cryptography`` nor a pre-3.5 OpenSSL implements these,
    and for post-quantum work the implementation under test is the customer's
    anyway, so execution goes through an external harness.
    """
    if provider_command is None:
        raise UnsupportedAlgorithmError(
            f"{algorithm} has no built-in provider: the pinned cryptography release "
            "implements neither ML-KEM nor ML-DSA. Supply an implementation with "
            "--provider-command (see docs/architecture.md)."
        )
    vector_set = pqc.load_vector_set(vector_file)
    expected = pqc.load_expected_results(expected_file)
    if algorithm == "ML-KEM":
        kem = SubprocessMlKemProvider.from_command_string(
            provider_command, timeout_seconds=provider_timeout
        )
        return pqc.run_ml_kem(vector_set, expected, kem), kem.metadata()
    dsa = SubprocessMlDsaProvider.from_command_string(
        provider_command, timeout_seconds=provider_timeout
    )
    return pqc.run_ml_dsa(vector_set, expected, dsa), dsa.metadata()


def _run_aes_modes(
    vector_file: Path,
    expected_file: Path,
    provider_command: str | None,
    provider_timeout: float,
) -> tuple[list[TestCaseResult], ProviderMetadata]:
    if provider_command is not None:
        raise UnsupportedAlgorithmError(
            "--provider-command does not yet cover the AES mode families; "
            "run them with the built-in provider"
        )
    provider: AesModeProviderProtocol = CryptographyAesModeProvider()
    metadata = provider.metadata()
    vector_set = aes_modes.load_vector_set(vector_file)
    expected = aes_modes.load_expected_results(expected_file)
    return aes_modes.run_vector_set(vector_set, expected, provider), metadata


def _run_ctr_drbg(
    vector_file: Path,
    expected_file: Path,
    provider_command: str | None,
    provider_timeout: float,
) -> tuple[list[TestCaseResult], ProviderMetadata]:
    if provider_command is not None:
        raise UnsupportedAlgorithmError(
            "--provider-command does not yet cover ctrDRBG; run it with the built-in provider"
        )
    provider: CtrDrbgProviderProtocol = CryptographyCtrDrbg()
    metadata = provider.metadata()
    vector_set = ctr_drbg.load_vector_set(vector_file)
    expected = ctr_drbg.load_expected_results(expected_file)
    return ctr_drbg.run_vector_set(vector_set, expected, provider), metadata


def _run_kdf(
    vector_file: Path,
    expected_file: Path,
    provider_command: str | None,
    provider_timeout: float,
) -> tuple[list[TestCaseResult], ProviderMetadata]:
    if provider_command is not None:
        raise UnsupportedAlgorithmError(
            "--provider-command does not yet cover KDF SP 800-108; "
            "run it with the built-in provider"
        )
    provider: KdfProviderProtocol = CryptographyKdf()
    metadata = provider.metadata()
    vector_set = kdf.load_vector_set(vector_file)
    expected = kdf.load_expected_results(expected_file)
    return kdf.run_vector_set(vector_set, expected, provider), metadata


def run_vector_file(
    vector_file: Path,
    expected_file: Path,
    *,
    provider_command: str | None = None,
    provider_timeout: float = 30.0,
) -> tuple[list[TestCaseResult], ProviderMetadata]:
    """Parse, execute, and classify one vector file, whatever its algorithm."""
    algorithm, _revision = peek_algorithm(vector_file)

    runners: dict[str, Callable[[], tuple[list[TestCaseResult], ProviderMetadata]]] = {}
    if algorithm == "ACVP-AES-GCM":
        runners[algorithm] = lambda: _run_aes_gcm(
            vector_file, expected_file, provider_command, provider_timeout
        )
    elif algorithm in HASHLIB_ALGORITHMS:
        runners[algorithm] = lambda: _run_sha2(
            algorithm, vector_file, expected_file, provider_command, provider_timeout
        )
    elif algorithm in ("ML-KEM", "ML-DSA"):
        runners[algorithm] = lambda: _run_pqc(
            algorithm, vector_file, expected_file, provider_command, provider_timeout
        )
    elif algorithm == kdf.ALGORITHM:
        runners[algorithm] = lambda: _run_kdf(
            vector_file, expected_file, provider_command, provider_timeout
        )
    elif algorithm == ctr_drbg.ALGORITHM:
        runners[algorithm] = lambda: _run_ctr_drbg(
            vector_file, expected_file, provider_command, provider_timeout
        )
    elif algorithm in aes_modes.SUPPORTED:
        runners[algorithm] = lambda: _run_aes_modes(
            vector_file, expected_file, provider_command, provider_timeout
        )
    elif algorithm == "ECDSA":
        runners[algorithm] = lambda: _run_ecdsa(
            vector_file, expected_file, provider_command, provider_timeout
        )
    elif algorithm.removeprefix("HMAC-") in HASHLIB_ALGORITHMS:
        runners[algorithm] = lambda: _run_hmac(
            algorithm, vector_file, expected_file, provider_command, provider_timeout
        )

    if algorithm not in runners:
        raise UnsupportedAlgorithmError(
            f"unsupported algorithm {algorithm!r}; this runner implements "
            f"{', '.join(supported_algorithms())}"
        )
    return runners[algorithm]()


__all__ = [
    "UnsupportedAlgorithmError",
    "peek_algorithm",
    "run_vector_file",
    "supported_algorithms",
]
