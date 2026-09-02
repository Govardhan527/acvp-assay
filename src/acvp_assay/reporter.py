"""Machine-readable case and summary reporting."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from dataclasses import asdict, dataclass

from acvp_assay.models import (
    CaseValues,
    ProviderMetadata,
    ResultStatus,
    TestCaseResult,
)


@dataclass(frozen=True, slots=True)
class ReportSummary:
    """Stable aggregate counts for one run."""

    total: int
    passed: int
    failed: int
    errored: int
    skipped: int
    unsupported: int


def summarize(results: Sequence[TestCaseResult]) -> ReportSummary:
    """Count every stable result classification."""
    counts = Counter(result.status for result in results)
    return ReportSummary(
        total=len(results),
        passed=counts[ResultStatus.PASS],
        failed=counts[ResultStatus.FAIL],
        errored=counts[ResultStatus.ERROR],
        skipped=counts[ResultStatus.SKIPPED],
        unsupported=counts[ResultStatus.UNSUPPORTED],
    )


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
        "summary": asdict(summary),
        "cases": [_case_document(result) for result in results],
    }


def report_json(
    results: Sequence[TestCaseResult],
    provider: ProviderMetadata,
) -> str:
    """Serialize a report deterministically with a trailing newline."""
    return json.dumps(build_report(results, provider), indent=2, sort_keys=True) + "\n"


__all__ = ["ReportSummary", "build_report", "report_json", "summarize"]
