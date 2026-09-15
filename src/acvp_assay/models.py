"""Typed internal models.

The result vocabulary every family shares -- ``ResultStatus``,
``DeclineReason``, ``SafeDiagnostic``, ``TestCaseResult``,
``ProviderMetadata`` and the ``CaseValues`` shapes -- lives here, alongside
the AES-GCM vector models.
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


class DeclineReason(StrEnum):
    """Why a case is UNSUPPORTED. Each member has a different repair.

    That is the test for whether this vocabulary has finished splitting: two
    members sharing a repair would be one state under two names, and while each
    points somewhere different, a further split has nothing left to change.
    """

    #: The implementation under test lacks it: a harness declined, or the
    #: provider's declared capability excludes it. The vendor repairs it.
    IMPLEMENTATION_LACKS = "implementation_lacks"
    #: This runner lacks it: a path not built here, or a value its own tables
    #: do not know. Repaired by building it here.
    RUNNER_LACKS = "runner_lacks"
    #: The method cannot decide it offline: there is no recorded answer to
    #: compare with, or the answer is fresh by construction. Repaired by
    #: submitting to ACVTS, or structurally not at all.
    OFFLINE_UNDECIDABLE = "offline_undecidable"
    #: The vector lacks data its own group requires, or contradicts it.
    #: Repaired by a different registration, or by NIST.
    VECTOR_INCOMPLETE = "vector_incomplete"


class DeclineClaimant(StrEnum):
    """Who asserted a decline: the harness that answered, or this runner."""

    HARNESS = "harness"
    RUNNER = "runner"


#: The reasons a harness may claim. ``runner_lacks`` and ``offline_undecidable``
#: are properties of this runner and of its method, which a harness is never in a
#: position to assert.
HARNESS_CLAIMABLE_REASONS = frozenset(
    {DeclineReason.IMPLEMENTATION_LACKS, DeclineReason.VECTOR_INCOMPLETE}
)


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


class ProviderKind(StrEnum):
    """Whether this runner's own code answered, or an implementation it was pointed at."""

    BUILTIN = "builtin"
    EXTERNAL = "external"


class BuildIdAbsentReason(StrEnum):
    """Why an external provider names no build. Each member has a different remedy."""

    #: The harness sent no ``buildId`` at all, so it predates the field; its author
    #: adds one. Only this runner records this, and a harness may not claim it.
    NOT_REPORTED = "not_reported"
    #: The implementation has a build identity its interface does not expose, as
    #: with PKCS#11, whose two-part versions two builds of one release share. The
    #: vendor exposes it.
    NOT_EXPOSED = "not_exposed"
    #: The implementation records no build identity at all. Its build process
    #: starts recording one.
    NOT_RECORDED = "not_recorded"


#: The absences a harness may declare about itself.
HARNESS_BUILD_ABSENCES = frozenset(
    {BuildIdAbsentReason.NOT_EXPOSED, BuildIdAbsentReason.NOT_RECORDED}
)


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    """Identity and versions for one cryptographic provider implementation.

    ``kind`` has no default, so no provider can be read as the built-in one by
    omission. An external provider also carries ``command``, because its identity
    is what ran and its command is where it ran; a built-in one has no command.

    An external provider carries its build as well: ``build_id``, or ``None`` with
    ``build_id_absent_reason``. A name and a version do not identify a build, since
    two builds a commit apart share both. A built-in provider has neither, because
    this runner's own commit identifies the code that answered.
    """

    name: str
    library_name: str
    library_version: str
    backend_name: str
    backend_version: str
    kind: ProviderKind
    command: str | None = None
    build_id: str | None = None
    build_id_absent_reason: BuildIdAbsentReason | None = None

    def __post_init__(self) -> None:
        """Refuse a kind outside the closed set, and a command or build that contradicts it."""
        if not isinstance(self.kind, ProviderKind):
            raise ValueError(f"provider kind must be a ProviderKind, got {self.kind!r}")
        if (self.kind is ProviderKind.EXTERNAL) != (self.command is not None):
            raise ValueError(
                "an external provider carries its command, and a built-in one does not"
            )
        absent = self.build_id_absent_reason
        if absent is not None and not isinstance(absent, BuildIdAbsentReason):
            raise ValueError(f"a build absence must be a BuildIdAbsentReason, got {absent!r}")
        if self.kind is ProviderKind.BUILTIN:
            if self.build_id is not None or absent is not None:
                raise ValueError("a built-in provider is identified by the runner's commit")
        elif (self.build_id is None) == (absent is None):
            raise ValueError("an external provider carries a build id or the reason it has none")
        if self.build_id == "":
            raise ValueError("a build id is never empty")


@dataclass(frozen=True, slots=True)
class TestCaseResult:
    """One classified case outcome with safe diagnostic context.

    ``decline_reason`` says why a case is UNSUPPORTED, as a code for
    aggregation and filtering; ``diagnostic`` keeps the sentence, for a person
    reading one case.
    """

    tg_id: int
    tc_id: int
    status: ResultStatus
    expected: CaseValues | None
    actual: CaseValues | None
    diagnostic: str | None = None
    decline_reason: DeclineReason | None = None
    declined_by: DeclineClaimant | None = None

    def __post_init__(self) -> None:
        """Enforce both closed vocabularies on the model itself.

        FAIL diagnostics are dynamically built from a fixed set of field
        names (see comparator.compare_values) and are not restricted here.
        ERROR diagnostics must never carry raw exception text, since callers
        construct them from caught provider/library errors that can quote
        secret material; this is enforced on the model itself rather than by
        convention at a single call site.

        UNSUPPORTED must carry a ``DeclineReason``, and no other status may.
        Without one, four states with four different repairs print alike, and
        session 766220's keyGen defect sat behind exactly that: a limitation of
        the method, printed the same as every other gap.

        UNSUPPORTED must also name who declined, ``harness`` or ``runner``, so a
        module author can separate the gaps that are theirs from the runner's. A
        harness may only claim ``implementation_lacks`` or ``vector_incomplete``.
        """
        if self.status is ResultStatus.ERROR and self.diagnostic not in _SAFE_DIAGNOSTIC_VALUES:
            raise ValueError(
                f"ERROR diagnostic must be one of {sorted(_SAFE_DIAGNOSTIC_VALUES)}, "
                f"got {self.diagnostic!r}"
            )
        declined = self.status is ResultStatus.UNSUPPORTED
        if declined and not isinstance(self.decline_reason, DeclineReason):
            raise ValueError(f"UNSUPPORTED requires a DeclineReason, got {self.decline_reason!r}")
        if not declined and self.decline_reason is not None:
            raise ValueError(f"only UNSUPPORTED carries a decline reason, not {self.status.value}")
        if declined and not isinstance(self.declined_by, DeclineClaimant):
            raise ValueError(f"UNSUPPORTED must name who declined it, got {self.declined_by!r}")
        if not declined and self.declined_by is not None:
            raise ValueError(f"only UNSUPPORTED names who declined it, not {self.status.value}")
        if (
            self.declined_by is DeclineClaimant.HARNESS
            and self.decline_reason not in HARNESS_CLAIMABLE_REASONS
        ):
            raise ValueError(f"a harness cannot claim {self.decline_reason}")


__all__ = [
    "AesGcmTestCase",
    "AesGcmTestGroup",
    "AesGcmValues",
    "AesGcmVectorSet",
    "BuildIdAbsentReason",
    "CaseValues",
    "DeclineClaimant",
    "DeclineReason",
    "DigestValues",
    "Direction",
    "ExpectedResultCase",
    "ExpectedResultGroup",
    "ExpectedResultSet",
    "HARNESS_BUILD_ABSENCES",
    "HARNESS_CLAIMABLE_REASONS",
    "ProviderKind",
    "ProviderMetadata",
    "ResultStatus",
    "SignatureValues",
    "SafeDiagnostic",
    "TestCaseResult",
    "TestType",
    "VerdictValues",
]
