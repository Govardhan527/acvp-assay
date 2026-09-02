"""Compare two runs and report what changed.

A validation campaign asks "does this pass today". Conformance is a property
that has to *hold*, and a certificate takes long enough to obtain that a
silent break can go unnoticed for a year. This module answers the other
question: what changed between two runs, and is any of it a regression.

Three findings matter, in descending order:

``regressed``
    A case that passed now fails or errors.
``coverage lost``
    A case that used to be executed is now UNSUPPORTED, SKIPPED, or gone
    entirely. Testing *less* is a regression too, and it is the one that
    hides: totals still look clean because the case simply stopped being
    counted.
``fixed``
    A case that failed now passes. Not a problem, but worth stating.

Provider identity is diffed alongside the cases, because a change in the
library or its backend is usually the cause rather than a detail.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from acvp_assay.parser import (
    AcvpValidationError,
    integer,
    list_field,
    mapping,
    string_field,
)

EXECUTED = frozenset({"PASS", "FAIL", "ERROR"})
FAILING = frozenset({"FAIL", "ERROR"})

VERDICT_REGRESSED = "REGRESSED"
VERDICT_IMPROVED = "IMPROVED"
VERDICT_UNCHANGED = "UNCHANGED"


@dataclass(frozen=True, slots=True)
class CaseChange:
    """One case whose outcome differs between the two runs."""

    tg_id: int
    tc_id: int
    was: str | None
    now: str | None
    diagnostic: str | None = None

    def as_document(self) -> dict[str, object]:
        """Render the change with ACVP's identifier names."""
        return {
            "tgId": self.tg_id,
            "tcId": self.tc_id,
            "was": self.was,
            "now": self.now,
            "diagnostic": self.diagnostic,
        }


@dataclass(frozen=True, slots=True)
class Report:
    """One parsed run report."""

    provider: Mapping[str, object]
    summary: Mapping[str, int]
    cases: Mapping[tuple[int, int], tuple[str, str | None]]


@dataclass(frozen=True, slots=True)
class DiffResult:
    """The complete comparison of two runs."""

    verdict: str
    provider_changed: bool
    baseline_provider: Mapping[str, object]
    current_provider: Mapping[str, object]
    summary_delta: Mapping[str, int]
    regressed: tuple[CaseChange, ...] = ()
    coverage_lost: tuple[CaseChange, ...] = ()
    fixed: tuple[CaseChange, ...] = ()
    still_failing: tuple[CaseChange, ...] = ()
    added: tuple[CaseChange, ...] = ()

    @property
    def has_regressions(self) -> bool:
        """Whether anything got worse, including coverage that disappeared."""
        return bool(self.regressed or self.coverage_lost)


def parse_report(value: object) -> Report:
    """Validate one report document produced by ``acvp-assay run``."""
    document = mapping(value, "$")
    provider = mapping(document.get("provider", {}), "$.provider")
    summary_document = mapping(document.get("summary", {}), "$.summary")
    summary = {
        name: integer(summary_document, name, "$.summary")
        for name in ("total", "passed", "failed", "errored", "skipped", "unsupported")
    }
    cases: dict[tuple[int, int], tuple[str, str | None]] = {}
    for index, entry in enumerate(list_field(document, "cases", "$")):
        path = f"$.cases[{index}]"
        case = mapping(entry, path)
        diagnostic = case.get("diagnostic")
        cases[(integer(case, "tgId", path), integer(case, "tcId", path))] = (
            string_field(case, "status", path),
            diagnostic if isinstance(diagnostic, str) else None,
        )
    return Report(provider=provider, summary=summary, cases=cases)


def load_report(path: str | Path) -> Report:
    """Load and validate one report file."""
    source = Path(path)
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise AcvpValidationError(
            "$", f"invalid JSON at line {error.lineno}, column {error.colno}"
        ) from None
    return parse_report(document)


def compare(baseline: Report, current: Report) -> DiffResult:
    """Classify every difference between two runs."""
    regressed: list[CaseChange] = []
    coverage_lost: list[CaseChange] = []
    fixed: list[CaseChange] = []
    still_failing: list[CaseChange] = []
    added: list[CaseChange] = []

    for key in sorted(baseline.cases.keys() | current.cases.keys()):
        tg_id, tc_id = key
        before = baseline.cases.get(key)
        after = current.cases.get(key)

        if before is None:
            assert after is not None
            added.append(CaseChange(tg_id, tc_id, None, after[0], after[1]))
            continue
        if after is None:
            coverage_lost.append(CaseChange(tg_id, tc_id, before[0], None, "case is no longer run"))
            continue

        was, now = before[0], after[0]
        diagnostic = after[1]
        if was in EXECUTED and now not in EXECUTED:
            coverage_lost.append(CaseChange(tg_id, tc_id, was, now, diagnostic))
        elif was == "PASS" and now in FAILING:
            regressed.append(CaseChange(tg_id, tc_id, was, now, diagnostic))
        elif was in FAILING and now == "PASS":
            fixed.append(CaseChange(tg_id, tc_id, was, now, diagnostic))
        elif was in FAILING and now in FAILING:
            still_failing.append(CaseChange(tg_id, tc_id, was, now, diagnostic))

    delta = {
        name: current.summary[name] - baseline.summary[name] for name in sorted(baseline.summary)
    }
    verdict = VERDICT_UNCHANGED
    if regressed or coverage_lost:
        verdict = VERDICT_REGRESSED
    elif fixed:
        verdict = VERDICT_IMPROVED

    return DiffResult(
        verdict=verdict,
        provider_changed=dict(baseline.provider) != dict(current.provider),
        baseline_provider=baseline.provider,
        current_provider=current.provider,
        summary_delta=delta,
        regressed=tuple(regressed),
        coverage_lost=tuple(coverage_lost),
        fixed=tuple(fixed),
        still_failing=tuple(still_failing),
        added=tuple(added),
    )


def build_document(result: DiffResult) -> dict[str, object]:
    """Build the machine-readable diff document."""
    return {
        "verdict": result.verdict,
        "provider": {
            "changed": result.provider_changed,
            "baseline": dict(result.baseline_provider),
            "current": dict(result.current_provider),
        },
        "summaryDelta": dict(result.summary_delta),
        "counts": {
            "regressed": len(result.regressed),
            "coverageLost": len(result.coverage_lost),
            "fixed": len(result.fixed),
            "stillFailing": len(result.still_failing),
            "added": len(result.added),
        },
        "changes": {
            "regressed": [change.as_document() for change in result.regressed],
            "coverageLost": [change.as_document() for change in result.coverage_lost],
            "fixed": [change.as_document() for change in result.fixed],
            "stillFailing": [change.as_document() for change in result.still_failing],
            "added": [change.as_document() for change in result.added],
        },
    }


def diff_json(result: DiffResult) -> str:
    """Serialize a diff deterministically with a trailing newline."""
    return json.dumps(build_document(result), indent=2, sort_keys=True) + "\n"


def summarize_text(result: DiffResult) -> str:
    """Render a short human-readable summary of what changed."""
    lines = [f"verdict: {result.verdict}"]
    if result.provider_changed:
        lines.append("provider changed between runs:")
        for label, provider in (
            ("  baseline", result.baseline_provider),
            ("  current ", result.current_provider),
        ):
            lines.append(f"{label}: {provider_identity(provider)}")
    for name, changes in (
        ("regressed", result.regressed),
        ("coverage lost", result.coverage_lost),
        ("fixed", result.fixed),
        ("still failing", result.still_failing),
        ("added", result.added),
    ):
        if changes:
            lines.append(f"{name}: {len(changes)}")
            for change in changes[:5]:
                detail = f" ({change.diagnostic})" if change.diagnostic else ""
                lines.append(
                    f"  tgId {change.tg_id} tcId {change.tc_id}: "
                    f"{change.was} -> {change.now}{detail}"
                )
            if len(changes) > 5:
                lines.append(f"  ... and {len(changes) - 5} more")
    return "\n".join(lines) + "\n"


def provider_identity(provider: Mapping[str, object]) -> str:
    """Render provider identity compactly for the text summary."""
    name = provider.get("name", "unknown")
    library = provider.get("library")
    backend = provider.get("backend")
    parts = [str(name)]
    for component in (library, backend):
        if isinstance(component, Mapping):
            parts.append(f"{component.get('name')} {component.get('version')}")
    return ", ".join(parts)


__all__ = [
    "CaseChange",
    "DiffResult",
    "Report",
    "build_document",
    "compare",
    "diff_json",
    "load_report",
    "provider_identity",
    "parse_report",
    "summarize_text",
]
