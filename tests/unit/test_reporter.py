"""Tests for deterministic machine-readable reports."""

from __future__ import annotations

import json
from typing import cast

from acvp_runner.models import (
    AesGcmValues,
    ProviderMetadata,
    ResultStatus,
)
from acvp_runner.models import TestCaseResult as CaseResult
from acvp_runner.reporter import ReportSummary, build_report, report_json, summarize


def provider_metadata() -> ProviderMetadata:
    """Return fixed metadata for deterministic report assertions."""
    return ProviderMetadata(
        name="cryptography-aes-gcm",
        library_name="cryptography",
        library_version="50.0.1",
        backend_name="OpenSSL",
        backend_version="OpenSSL test-version",
    )


def all_status_results() -> list[CaseResult]:
    """Return one case in every stable classification."""
    expected = AesGcmValues(ciphertext=b"expected", tag=b"tag")
    actual = AesGcmValues(ciphertext=b"actual", tag=b"tag")
    return [
        CaseResult(1, 1, ResultStatus.PASS, expected, expected),
        CaseResult(1, 2, ResultStatus.FAIL, expected, actual, "ciphertext mismatch"),
        CaseResult(1, 3, ResultStatus.ERROR, expected, None, "provider error"),
        CaseResult(1, 4, ResultStatus.SKIPPED, None, None, "not selected"),
        CaseResult(1, 5, ResultStatus.UNSUPPORTED, None, None, "unsupported group"),
    ]


def test_summary_counts_every_status() -> None:
    """The summary accounts for every input case exactly once."""
    assert summarize(all_status_results()) == ReportSummary(
        total=5,
        passed=1,
        failed=1,
        errored=1,
        skipped=1,
        unsupported=1,
    )


def test_empty_summary_contains_explicit_zeroes() -> None:
    """An empty run keeps a stable summary schema."""
    assert summarize([]) == ReportSummary(0, 0, 0, 0, 0, 0)


def test_report_contains_provider_versions_summary_and_case_values() -> None:
    """Report fields retain IDs, uppercase hex values, and safe diagnostics."""
    report = build_report(all_status_results(), provider_metadata())

    assert report["provider"] == {
        "name": "cryptography-aes-gcm",
        "library": {"name": "cryptography", "version": "50.0.1"},
        "backend": {"name": "OpenSSL", "version": "OpenSSL test-version"},
    }
    assert report["summary"] == {
        "total": 5,
        "passed": 1,
        "failed": 1,
        "errored": 1,
        "skipped": 1,
        "unsupported": 1,
    }
    cases = report["cases"]
    assert isinstance(cases, list)
    assert cases[0] == {
        "tgId": 1,
        "tcId": 1,
        "status": "PASS",
        "expected": {"ct": "6578706563746564", "tag": "746167"},
        "actual": {"ct": "6578706563746564", "tag": "746167"},
    }
    assert cases[1]["diagnostic"] == "ciphertext mismatch"
    assert cases[2]["actual"] is None
    assert cases[3]["expected"] is None


def test_values_report_all_direction_specific_fields() -> None:
    """Plaintext, ciphertext, and tag fields serialize with ACVP names."""
    values = AesGcmValues(plaintext=b"p", ciphertext=b"c", tag=b"t")
    result = CaseResult(7, 8, ResultStatus.PASS, values, values)

    cases = cast(
        list[dict[str, object]],
        build_report([result], provider_metadata())["cases"],
    )
    case = cases[0]

    assert case["expected"] == {"pt": "70", "ct": "63", "tag": "74"}


def test_values_document_omits_absent_fields_independently() -> None:
    """Ciphertext and tag are each emitted only when present, independently."""
    ciphertext_only = AesGcmValues(ciphertext=b"c")
    tag_only = AesGcmValues(tag=b"t")
    result = CaseResult(1, 1, ResultStatus.ERROR, ciphertext_only, tag_only, "provider error")

    cases = cast(
        list[dict[str, object]],
        build_report([result], provider_metadata())["cases"],
    )
    case = cases[0]

    assert case["expected"] == {"ct": "63"}
    assert case["actual"] == {"tag": "74"}


def test_json_is_deterministic_valid_and_newline_terminated() -> None:
    """Serialized reports are stable JSON suitable for files and pipelines."""
    rendered = report_json(all_status_results(), provider_metadata())

    assert rendered.endswith("\n")
    assert json.loads(rendered) == build_report(all_status_results(), provider_metadata())
    assert rendered == report_json(all_status_results(), provider_metadata())
