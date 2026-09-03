"""Typed internal models.

The result vocabulary every family shares -- ``ResultStatus``,
``SafeDiagnostic``, ``TestCaseResult``, ``ProviderMetadata`` and the
``CaseValues`` shapes -- lives here, alongside the AES-GCM vector models.
Each other family owns its own vector models in ``algorithms/``, because
their group shapes have little in common; what they share is everything
downstream of execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable


class Direction(StrEnum):
    """Supported AES-GCM operation directions."""

    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


class TestType(StrEnum):
    """Supported ACVP test types."""

    AFT = "AFT"


class ResultStatus(StrEnum):
    """Stable per-case result classifications."""

    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"
    UNSUPPORTED = "UNSUPPORTED"


class SafeDiagnostic(StrEnum):
    """Non-secret diagnostics allowed in machine-readable ERROR output."""

    AUTHENTICATION_FAILED = "authentication failed"
    INVALID_CASE = "invalid case"
    PROVIDER_ERROR = "provider error"


_SAFE_DIAGNOSTIC_VALUES = frozenset(member.value for member in SafeDiagnostic)


@dataclass(frozen=True, slots=True)
class AesGcmTestCase:
    """One normalized AES-GCM operation and its ACVP case identity."""

    tc_id: int
    key: bytes
    iv: bytes
    aad: bytes
    plaintext: bytes | None = None
    ciphertext: bytes | None = None
    tag: bytes | None = None


@dataclass(frozen=True, slots=True)
class AesGcmTestGroup:
    """Cases that share one ACVP AES-GCM parameter contract."""

    tg_id: int
    test_type: TestType
    direction: Direction
    key_length_bits: int
    iv_length_bits: int
    payload_length_bits: int
    aad_length_bits: int
    tag_length_bits: int
    iv_generation: str
    iv_generation_mode: str
    tests: tuple[AesGcmTestCase, ...]


@dataclass(frozen=True, slots=True)
class AesGcmVectorSet:
    """One normalized AES-GCM vector set with preserved ACVP identity."""

    vs_id: int
    algorithm: str
    revision: str
    is_sample: bool
    test_groups: tuple[AesGcmTestGroup, ...]


@runtime_checkable
class CaseValues(Protocol):
    """Reportable values for one case, in whatever shape its algorithm uses."""

    def as_document(self) -> dict[str, object]:
        """Render the present values keyed by ACVP field name."""
        ...


def _hex_document(**fields: bytes | None) -> dict[str, object]:
    return {name: value.hex().upper() for name, value in fields.items() if value is not None}


@dataclass(frozen=True, slots=True)
class AesGcmValues:
    """Comparable AES-GCM values for expected and actual outcomes."""

    plaintext: bytes | None = None
    ciphertext: bytes | None = None
    tag: bytes | None = None

    def as_document(self) -> dict[str, object]:
        """Render present values using ACVP's ``pt``/``ct``/``tag`` field names."""
        return _hex_document(pt=self.plaintext, ct=self.ciphertext, tag=self.tag)


@dataclass(frozen=True, slots=True)
class DigestValues:
    """Comparable digest or MAC values for expected and actual outcomes."""

    digest: bytes | None = None
    mac: bytes | None = None

    def as_document(self) -> dict[str, object]:
        """Render present values using ACVP's ``md``/``mac`` field names."""
        return _hex_document(md=self.digest, mac=self.mac)


@dataclass(frozen=True, slots=True)
class VerdictValues:
    """A pass/fail verdict, for tests whose expected result is a boolean.

    ACVP uses this for signature *verification*: the vector supplies a
    signature that may be deliberately invalid, and the correct answer is the
    verdict the implementation reaches, not any bytes it produces.
    """

    passed: bool

    def as_document(self) -> dict[str, object]:
        """Render the verdict using ACVP's ``testPassed`` field name."""
        return {"testPassed": self.passed}


@dataclass(frozen=True, slots=True)
class SignatureValues:
    """A produced signature and the public key it must verify under."""

    qx: bytes | None = None
    qy: bytes | None = None
    r: bytes | None = None
    s: bytes | None = None
    signature: bytes | None = None

    def as_document(self) -> dict[str, object]:
        """Render present values using ACVP's signature field names."""
        return _hex_document(qx=self.qx, qy=self.qy, r=self.r, s=self.s, signature=self.signature)


@dataclass(frozen=True, slots=True)
class ExpectedResultCase:
    """One expected-results case, preserving its ACVP case identity.

    ``test_passed`` mirrors ACVP's ``testPassed`` field. NIST emits it only
    for decrypt cases that are *meant* to fail authentication, where it is
    ``False`` and no plaintext is recorded; cases expected to succeed carry a
    plaintext and omit the field entirely. ``None`` therefore means "not
    stated", which is equivalent to expecting success.
    """

    tc_id: int
    values: AesGcmValues
    test_passed: bool | None = None

    @property
    def expects_authentication_failure(self) -> bool:
        """Whether ACVP declares this case must fail authentication."""
        return self.test_passed is False


@dataclass(frozen=True, slots=True)
class ExpectedResultGroup:
    """Expected-results cases that share one ACVP group identity."""

    tg_id: int
    cases: tuple[ExpectedResultCase, ...]


@dataclass(frozen=True, slots=True)
class ExpectedResultSet:
    """One normalized ACVP expected-results document."""

    vs_id: int
    algorithm: str
    revision: str
    groups: tuple[ExpectedResultGroup, ...]


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    """Identity and versions for one cryptographic provider implementation."""

    name: str
    library_name: str
    library_version: str
    backend_name: str
    backend_version: str


@dataclass(frozen=True, slots=True)
class TestCaseResult:
    """One classified case outcome with safe diagnostic context."""

    tg_id: int
    tc_id: int
    status: ResultStatus
    expected: CaseValues | None
    actual: CaseValues | None
    diagnostic: str | None = None

    def __post_init__(self) -> None:
        """Reject ERROR diagnostics outside the closed safe vocabulary.

        FAIL diagnostics are dynamically built from a fixed set of field
        names (see comparator.compare_values) and are not restricted here.
        ERROR diagnostics must never carry raw exception text, since callers
        construct them from caught provider/library errors that can quote
        secret material; this is enforced on the model itself rather than by
        convention at a single call site.
        """
        if self.status is ResultStatus.ERROR and self.diagnostic not in _SAFE_DIAGNOSTIC_VALUES:
            raise ValueError(
                f"ERROR diagnostic must be one of {sorted(_SAFE_DIAGNOSTIC_VALUES)}, "
                f"got {self.diagnostic!r}"
            )


__all__ = [
    "AesGcmTestCase",
    "AesGcmTestGroup",
    "AesGcmValues",
    "AesGcmVectorSet",
    "CaseValues",
    "DigestValues",
    "Direction",
    "ExpectedResultCase",
    "ExpectedResultGroup",
    "ExpectedResultSet",
    "ProviderMetadata",
    "ResultStatus",
    "SignatureValues",
    "SafeDiagnostic",
    "TestCaseResult",
    "TestType",
    "VerdictValues",
]
