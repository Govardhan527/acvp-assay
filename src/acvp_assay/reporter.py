"""Machine-readable case and summary reporting."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from acvp_assay.models import (
    CaseValues,
    DeclineReason,
    ProviderMetadata,
    ResultStatus,
    TestCaseResult,
)


@dataclass(frozen=True, slots=True)
class ReportSummary:
    """Stable aggregate counts for one run.

    ``unsupported_by_reason`` breaks ``unsupported`` down by ``DeclineReason``,
    because the total alone cannot say whose repair a gap needs. Every reason is
    present, zero or not, so the schema does not change with the run.
    """

    total: int
    passed: int
    failed: int
    errored: int
    skipped: int
    unsupported: int
    unsupported_by_reason: Mapping[str, int]


def summarize(results: Sequence[TestCaseResult]) -> ReportSummary:
    """Count every stable result classification, and every decline reason."""
    counts = Counter(result.status for result in results)
    reasons = Counter(result.decline_reason for result in results)
    return ReportSummary(
        total=len(results),
        passed=counts[ResultStatus.PASS],
        failed=counts[ResultStatus.FAIL],
        errored=counts[ResultStatus.ERROR],
        skipped=counts[ResultStatus.SKIPPED],
        unsupported=counts[ResultStatus.UNSUPPORTED],
        unsupported_by_reason={reason.value: reasons[reason] for reason in DeclineReason},
    )


def _summary_document(summary: ReportSummary) -> dict[str, object]:
    return {
        "total": summary.total,
        "passed": summary.passed,
        "failed": summary.failed,
        "errored": summary.errored,
        "skipped": summary.skipped,
        "unsupported": summary.unsupported,
        "unsupportedByReason": dict(summary.unsupported_by_reason),
    }


def _values_document(values: CaseValues | None) -> dict[str, object] | None:
    if values is None:
        return None
    return values.as_document()


def _case_document(result: TestCaseResult) -> dict[str, object]:
    document: dict[str, object] = {
        "tgId": result.tg_id,
        "tcId": result.tc_id,
        "status": result.status.value,
        "expected": _values_document(result.expected),
        "actual": _values_document(result.actual),
    }
    if result.diagnostic is not None:
        document["diagnostic"] = result.diagnostic
    if result.decline_reason is not None:
        document["declineReason"] = result.decline_reason.value
    return document


def build_report(
    results: Sequence[TestCaseResult],
    provider: ProviderMetadata,
) -> dict[str, object]:
    """Build the complete machine-readable report document."""
    summary = summarize(results)
    return {
        "provider": {
            "name": provider.name,
            "library": {
                "name": provider.library_name,
                "version": provider.library_version,
            },
            "backend": {
                "name": provider.backend_name,
                "version": provider.backend_version,
            },
        },
        "summary": _summary_document(summary),
        "cases": [_case_document(result) for result in results],
    }


def report_json(
    results: Sequence[TestCaseResult],
    provider: ProviderMetadata,
) -> str:
    """Serialize a report deterministically with a trailing newline."""
    return json.dumps(build_report(results, provider), indent=2, sort_keys=True) + "\n"


__all__ = ["ReportSummary", "build_report", "report_json", "summarize"]
