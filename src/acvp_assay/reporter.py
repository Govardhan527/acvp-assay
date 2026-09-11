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

#: How a run's cases are partitioned when their concentration is measured.
PARTITION = "cases-by-tgId"


@dataclass(frozen=True, slots=True)
class Concentration:
    """How unevenly a run's cases fall across its test groups.

    A case total reads as breadth, and it can be substantially one or two
    groups. The share therefore travels with what determines it: the partition
    that produced it and how many members that partition has. The same run gives
    a different figure under a different partition, so a share without its
    partition named is a share without its base.
    """

    partition: str
    cardinality: int
    largest_two_share: float | None


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
    concentration: Concentration


def concentration(results: Sequence[TestCaseResult]) -> Concentration:
    """The two largest test groups' share of the cases, with its partition and base.

    The share is null for an empty run, where it is undefined rather than zero.
    """
    groups = Counter(result.tg_id for result in results)
    largest = sum(count for _, count in groups.most_common(2))
    return Concentration(
        partition=PARTITION,
        cardinality=len(groups),
        largest_two_share=round(largest / len(results), 4) if results else None,
    )


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
        concentration=concentration(results),
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
        "concentration": {
            "partition": summary.concentration.partition,
            "cardinality": summary.concentration.cardinality,
            "largestTwoShare": summary.concentration.largest_two_share,
        },
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


__all__ = [
    "Concentration",
    "ReportSummary",
    "build_report",
    "concentration",
    "report_json",
    "summarize",
]
