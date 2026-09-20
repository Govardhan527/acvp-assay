"""Machine-readable case and summary reporting."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from acvp_assay.metadata import runner_document
from acvp_assay.models import (
    HARNESS_CLAIMABLE_REASONS,
    CaseValues,
    DeclineClaimant,
    DeclineReason,
    ProviderKind,
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

    ``unsupported_by_claimant`` splits the same count by who declined: the
    harness, under the two reasons it may claim, and this runner, under all four.
    A module author reads the harness's ``implementation_lacks`` as their own
    list and everything else as someone else's.
    """

    total: int
    passed: int
    failed: int
    errored: int
    skipped: int
    unsupported: int
    unsupported_by_reason: Mapping[str, int]
    unsupported_by_claimant: Mapping[str, Mapping[str, int]]
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
    claims = Counter((result.declined_by, result.decline_reason) for result in results)
    return ReportSummary(
        total=len(results),
        passed=counts[ResultStatus.PASS],
        failed=counts[ResultStatus.FAIL],
        errored=counts[ResultStatus.ERROR],
        skipped=counts[ResultStatus.SKIPPED],
        unsupported=counts[ResultStatus.UNSUPPORTED],
        unsupported_by_reason={reason.value: reasons[reason] for reason in DeclineReason},
        unsupported_by_claimant={
            DeclineClaimant.HARNESS.value: {
                reason.value: claims[(DeclineClaimant.HARNESS, reason)]
                for reason in DeclineReason
                if reason in HARNESS_CLAIMABLE_REASONS
            },
            DeclineClaimant.RUNNER.value: {
                reason.value: claims[(DeclineClaimant.RUNNER, reason)] for reason in DeclineReason
            },
        },
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
        "unsupportedByClaimant": {
            claimant: dict(counts) for claimant, counts in summary.unsupported_by_claimant.items()
        },
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
    if result.declined_by is not None:
        document["declinedBy"] = result.declined_by.value
    return document


def build_report(
    results: Sequence[TestCaseResult],
    provider: ProviderMetadata,
    *,
    runner: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build the complete machine-readable report document.

    ``runner`` identifies the instrument, and is measured from this checkout when
    it is not supplied. A caller passes it to keep a report deterministic, which
    is what the tests do.
    """
    summary = summarize(results)
    return {
        "runner": dict(runner) if runner is not None else runner_document(),
        "provider": _provider_document(provider),
        "summary": _summary_document(summary),
        "cases": [_case_document(result) for result in results],
    }


def _provider_document(provider: ProviderMetadata) -> dict[str, object]:
    """Name the implementation that answered, and say which kind it was.

    ``kind`` makes a run through an external harness impossible to read as a
    built-in one. An external provider also records the command it ran from, and
    its build, or ``null`` with the reason it has none.
    """
    document: dict[str, object] = {
        "name": provider.name,
        "kind": provider.kind.value,
        "library": {
            "name": provider.library_name,
            "version": provider.library_version,
        },
        "backend": {
            "name": provider.backend_name,
            "version": provider.backend_version,
        },
    }
    if provider.command is not None:
        document["command"] = provider.command
    if provider.kind is ProviderKind.EXTERNAL:
        absent = provider.build_id_absent_reason
        document["buildId"] = provider.build_id
        document["buildIdAbsentReason"] = absent.value if absent else None
    return document


def report_json(
    results: Sequence[TestCaseResult],
    provider: ProviderMetadata,
    *,
    runner: Mapping[str, object] | None = None,
) -> str:
    """Serialize a report deterministically with a trailing newline."""
    document = build_report(results, provider, runner=runner)
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


__all__ = [
    "Concentration",
    "ReportSummary",
    "build_report",
    "concentration",
    "report_json",
    "summarize",
]
