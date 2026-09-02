"""Tests for run-over-run regression diffing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acvp_assay.cli import main
from acvp_assay.diff import (
    VERDICT_IMPROVED,
    VERDICT_REGRESSED,
    VERDICT_UNCHANGED,
    build_document,
    compare,
    diff_json,
    load_report,
    parse_report,
    provider_identity,
    summarize_text,
)
from acvp_assay.parser import AcvpValidationError

type Case = tuple[int, int, str, str | None]

PROVIDER: dict[str, Any] = {
    "name": "cryptography-aes-gcm",
    "library": {"name": "cryptography", "version": "50.0.1"},
    "backend": {"name": "OpenSSL", "version": "OpenSSL 4.0.2"},
}


def report(
    cases: list[Case],
    *,
    provider: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a report document from (tgId, tcId, status, diagnostic) tuples."""
    documents = []
    for tg_id, tc_id, status, diagnostic in cases:
        case: dict[str, Any] = {"tgId": tg_id, "tcId": tc_id, "status": status}
        if diagnostic is not None:
            case["diagnostic"] = diagnostic
        documents.append(case)
    counts = {
        "total": len(cases),
        "passed": sum(1 for c in cases if c[2] == "PASS"),
        "failed": sum(1 for c in cases if c[2] == "FAIL"),
        "errored": sum(1 for c in cases if c[2] == "ERROR"),
        "skipped": sum(1 for c in cases if c[2] == "SKIPPED"),
        "unsupported": sum(1 for c in cases if c[2] == "UNSUPPORTED"),
    }
    return {
        "provider": provider if provider is not None else PROVIDER,
        "summary": counts,
        "cases": documents,
    }


def diff(
    before: list[Case],
    after: list[Case],
    **kwargs: Any,
) -> Any:
    """Compare two case lists."""
    return compare(
        parse_report(report(before)),
        parse_report(report(after, **kwargs)),
    )


def test_identical_runs_are_unchanged() -> None:
    """A run compared with itself reports nothing and no regression."""
    cases: list[Case] = [(1, 1, "PASS", None), (1, 2, "PASS", None)]

    result = diff(cases, cases)

    assert result.verdict == VERDICT_UNCHANGED
    assert not result.has_regressions
    assert not result.provider_changed


def test_a_broken_case_is_a_regression() -> None:
    """PASS becoming FAIL is the headline finding, with its diagnostic."""
    result = diff([(1, 1, "PASS", None)], [(1, 1, "FAIL", "tag mismatch")])

    assert result.verdict == VERDICT_REGRESSED
    assert result.has_regressions
    assert len(result.regressed) == 1
    assert result.regressed[0].was == "PASS"
    assert result.regressed[0].now == "FAIL"
    assert result.regressed[0].diagnostic == "tag mismatch"


def test_an_errored_case_is_also_a_regression() -> None:
    """ERROR counts as a regression from PASS, not merely a change."""
    result = diff([(1, 1, "PASS", None)], [(1, 1, "ERROR", "authentication failed")])

    assert result.verdict == VERDICT_REGRESSED
    assert len(result.regressed) == 1


def test_a_case_that_stops_being_executed_is_coverage_lost() -> None:
    """Testing less is a regression, and it is the one that hides.

    Totals still look clean because the case simply stops being counted, so
    this must be surfaced as loudly as an outright failure.
    """
    result = diff([(1, 1, "PASS", None)], [(1, 1, "UNSUPPORTED", "curve not supported")])

    assert result.verdict == VERDICT_REGRESSED
    assert result.has_regressions
    assert not result.regressed
    assert len(result.coverage_lost) == 1
    assert result.coverage_lost[0].now == "UNSUPPORTED"


def test_a_disappearing_case_is_coverage_lost() -> None:
    """A case present in the baseline and absent now has stopped being run."""
    result = diff([(1, 1, "PASS", None), (1, 2, "PASS", None)], [(1, 1, "PASS", None)])

    assert result.verdict == VERDICT_REGRESSED
    assert len(result.coverage_lost) == 1
    assert result.coverage_lost[0].tc_id == 2
    assert result.coverage_lost[0].now is None
    assert result.coverage_lost[0].diagnostic == "case is no longer run"


def test_a_repaired_case_is_an_improvement() -> None:
    """FAIL becoming PASS is reported, and is not a regression."""
    result = diff([(1, 1, "FAIL", "tag mismatch")], [(1, 1, "PASS", None)])

    assert result.verdict == VERDICT_IMPROVED
    assert not result.has_regressions
    assert len(result.fixed) == 1


def test_persistent_failures_are_reported_separately() -> None:
    """A case failing in both runs is neither new damage nor a fix."""
    result = diff([(1, 1, "FAIL", "a")], [(1, 1, "ERROR", "invalid case")])

    assert result.verdict == VERDICT_UNCHANGED
    assert len(result.still_failing) == 1
    assert not result.has_regressions


def test_new_cases_are_reported_without_alarming() -> None:
    """Cases that appear are listed but do not count as regressions."""
    result = diff([(1, 1, "PASS", None)], [(1, 1, "PASS", None), (1, 2, "PASS", None)])

    assert result.verdict == VERDICT_UNCHANGED
    assert len(result.added) == 1
    assert result.added[0].was is None


def test_regression_outranks_a_simultaneous_fix() -> None:
    """A run that fixes one case and breaks another is still REGRESSED."""
    result = diff(
        [(1, 1, "PASS", None), (1, 2, "FAIL", "x")],
        [(1, 1, "FAIL", "y"), (1, 2, "PASS", None)],
    )

    assert result.verdict == VERDICT_REGRESSED
    assert len(result.regressed) == 1
    assert len(result.fixed) == 1


def test_provider_change_is_detected_and_summarised() -> None:
    """A changed library or backend is usually the cause, so it is surfaced."""
    upgraded = {**PROVIDER, "backend": {"name": "OpenSSL", "version": "OpenSSL 3.5.0"}}

    result = diff([(1, 1, "PASS", None)], [(1, 1, "PASS", None)], provider=upgraded)

    assert result.provider_changed
    assert "OpenSSL 3.5.0" in provider_identity(result.current_provider)
    assert "provider changed" in summarize_text(result)


def test_summary_delta_reports_the_shift_in_counts() -> None:
    """Per-status deltas describe the run at a glance."""
    result = diff(
        [(1, 1, "PASS", None), (1, 2, "PASS", None)],
        [(1, 1, "PASS", None), (1, 2, "FAIL", "x")],
    )

    assert result.summary_delta["passed"] == -1
    assert result.summary_delta["failed"] == 1
    assert result.summary_delta["total"] == 0


def test_document_and_json_are_deterministic() -> None:
    """The machine-readable diff is stable and complete."""
    result = diff([(1, 1, "PASS", None)], [(1, 1, "FAIL", "tag mismatch")])

    document = build_document(result)
    rendered = diff_json(result)

    assert document["verdict"] == VERDICT_REGRESSED
    assert document["counts"] == {
        "regressed": 1,
        "coverageLost": 0,
        "fixed": 0,
        "stillFailing": 0,
        "added": 0,
    }
    assert rendered.endswith("\n")
    assert json.loads(rendered) == document
    assert rendered == diff_json(result)


def test_text_summary_truncates_long_lists() -> None:
    """A large regression list stays readable in a terminal."""
    before: list[Case] = [(1, index, "PASS", None) for index in range(1, 12)]
    after: list[Case] = [(1, index, "FAIL", "broken") for index in range(1, 12)]

    summary = summarize_text(compare(parse_report(report(before)), parse_report(report(after))))

    assert "regressed: 11" in summary
    assert "and 6 more" in summary


def test_provider_identity_tolerates_a_sparse_provider() -> None:
    """A report without library or backend detail still renders."""
    assert provider_identity({}) == "unknown"


# --- file loading and the CLI ---------------------------------------------


def test_load_report_reads_a_real_report(tmp_path: Path) -> None:
    """The file entry point parses a report written by ``run``."""
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report([(1, 1, "PASS", None)])), encoding="utf-8")

    assert load_report(path).summary["passed"] == 1


@pytest.mark.parametrize(
    ("content", "message"),
    [("not json", "invalid JSON"), ("[]", "expected an object")],
)
def test_malformed_reports_are_rejected(tmp_path: Path, content: str, message: str) -> None:
    """A report that cannot be read fails with a bounded diagnostic."""
    path = tmp_path / "report.json"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(AcvpValidationError, match=message):
        load_report(path)


def test_cli_diff_exits_nonzero_on_regression(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``diff`` fails the build when something got worse, and says what."""
    baseline = tmp_path / "base.json"
    current = tmp_path / "current.json"
    output = tmp_path / "diff.json"
    baseline.write_text(json.dumps(report([(1, 1, "PASS", None)])), encoding="utf-8")
    current.write_text(json.dumps(report([(1, 1, "FAIL", "tag mismatch")])), encoding="utf-8")

    exit_code = main(["diff", str(baseline), str(current), "--output", str(output)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "REGRESSED" in captured.out
    assert json.loads(output.read_text(encoding="utf-8"))["counts"]["regressed"] == 1


def test_cli_diff_exits_zero_when_nothing_got_worse(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An improved or unchanged run passes, so CI stays green."""
    path = tmp_path / "base.json"
    fixed = tmp_path / "fixed.json"
    path.write_text(json.dumps(report([(1, 1, "FAIL", "x")])), encoding="utf-8")
    fixed.write_text(json.dumps(report([(1, 1, "PASS", None)])), encoding="utf-8")

    exit_code = main(["diff", str(path), str(fixed)])

    assert exit_code == 0
    assert "IMPROVED" in capsys.readouterr().out


def test_cli_diff_reports_a_missing_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An unreadable report is an input error, not a crash."""
    exit_code = main(["diff", str(tmp_path / "missing.json"), str(tmp_path / "also.json")])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "error:" in captured.err
