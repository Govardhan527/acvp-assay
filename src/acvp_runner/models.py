"""Typed internal models for the AES-GCM MVP."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


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


@dataclass(frozen=True, slots=True)
class AesGcmValues:
    """Comparable AES-GCM values for expected and actual outcomes."""

    plaintext: bytes | None = None
    ciphertext: bytes | None = None
    tag: bytes | None = None


@dataclass(frozen=True, slots=True)
class TestCaseResult:
    """One classified case outcome with safe diagnostic context."""

    tg_id: int
    tc_id: int
    status: ResultStatus
    expected: AesGcmValues | None
    actual: AesGcmValues | None
    diagnostic: str | None = None


__all__ = [
    "AesGcmTestCase",
    "AesGcmTestGroup",
    "AesGcmValues",
    "AesGcmVectorSet",
    "Direction",
    "ResultStatus",
    "TestCaseResult",
    "TestType",
]
