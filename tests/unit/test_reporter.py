"""Tests for deterministic machine-readable reports."""

from __future__ import annotations

import json
from typing import cast

from acvp_assay import __version__
from acvp_assay.models import (
    AesGcmValues,
    BuildIdAbsentReason,
    DeclineClaimant,
    DeclineReason,
    ProviderKind,
    ProviderMetadata,
    ResultStatus,
)
from acvp_assay.models import TestCaseResult as CaseResult
from acvp_assay.reporter import (
    Concentration,
    ReportSummary,
    build_report,
    report_json,
    summarize,
)

NO_DECLINES = {reason.value: 0 for reason in DeclineReason}
#: A fixed instrument identity, so a report assertion does not depend on the checkout.
RUNNER: dict[str, object] = {
    "version": "0.0.0-test",
    "commit": "a" * 40,
    "commitAbsentReason": None,
    "treeClean": True,
}
NO_CLAIMS = {
    "harness": {"implementation_lacks": 0, "vector_incomplete": 0},
    "runner": dict(NO_DECLINES),
}
ONE_GROUP = Concentration("cases-by-tgId", 1, 1.0)


def provider_metadata() -> ProviderMetadata:
    """Return fixed metadata for deterministic report assertions."""
    return ProviderMetadata(
        name="cryptography-aes-gcm",
        library_name="cryptography",
        library_version="50.0.1",
        backend_name="OpenSSL",
        backend_version="OpenSSL test-version",
        kind=ProviderKind.BUILTIN,
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
        CaseResult(
            1,
            5,
            ResultStatus.UNSUPPORTED,
            None,
            None,
            "unsupported group",
            DeclineReason.RUNNER_LACKS,
            DeclineClaimant.RUNNER,
        ),
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
        unsupported_by_reason={**NO_DECLINES, "runner_lacks": 1},
        unsupported_by_claimant={**NO_CLAIMS, "runner": {**NO_DECLINES, "runner_lacks": 1}},
        concentration=ONE_GROUP,
    )


def test_empty_summary_contains_explicit_zeroes() -> None:
    """An empty run keeps a stable summary schema; a share of nothing is undefined."""
    assert summarize([]) == ReportSummary(
        0, 0, 0, 0, 0, 0, NO_DECLINES, NO_CLAIMS, Concentration("cases-by-tgId", 0, None)
    )


def test_the_summary_breaks_declined_cases_down_by_reason() -> None:
    """One UNSUPPORTED total would merge four states with four different repairs."""
    reasons = [
        DeclineReason.IMPLEMENTATION_LACKS,
        DeclineReason.IMPLEMENTATION_LACKS,
        DeclineReason.RUNNER_LACKS,
        DeclineReason.OFFLINE_UNDECIDABLE,
        DeclineReason.VECTOR_INCOMPLETE,
    ]
    results = [
        CaseResult(
            1,
            index,
            ResultStatus.UNSUPPORTED,
            None,
            None,
            "declined",
            reason,
            DeclineClaimant.RUNNER,
        )
        for index, reason in enumerate(reasons, start=1)
    ]

    summary = summarize(results)

    assert summary.unsupported == 5
    assert summary.unsupported_by_reason == {
        "implementation_lacks": 2,
        "runner_lacks": 1,
        "offline_undecidable": 1,
        "vector_incomplete": 1,
    }
    assert sum(summary.unsupported_by_reason.values()) == summary.unsupported


def test_the_concentration_carries_its_partition_and_cardinality() -> None:
    """Ten cases read as breadth; nine of them are in two of the three groups."""
    sizes = {1: 6, 2: 3, 3: 1}
    results = [
        CaseResult(tg_id, tc_id, ResultStatus.PASS, None, None)
        for tg_id, size in sizes.items()
        for tc_id in range(1, size + 1)
    ]

    assert summarize(results).concentration == Concentration("cases-by-tgId", 3, 0.9)


def test_report_contains_provider_versions_summary_and_case_values() -> None:
    """Report fields retain IDs, uppercase hex values, and safe diagnostics."""
    report = build_report(all_status_results(), provider_metadata(), runner=RUNNER)

    assert report["runner"] == RUNNER
    assert report["provider"] == {
        "name": "cryptography-aes-gcm",
        "kind": "builtin",
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
        "unsupportedByReason": {**NO_DECLINES, "runner_lacks": 1},
        "unsupportedByClaimant": {**NO_CLAIMS, "runner": {**NO_DECLINES, "runner_lacks": 1}},
        "concentration": {"partition": "cases-by-tgId", "cardinality": 1, "largestTwoShare": 1.0},
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
    assert cases[4]["declineReason"] == "runner_lacks"
    assert cases[4]["declinedBy"] == "runner"
    assert cases[4]["diagnostic"] == "unsupported group"


def test_values_report_all_direction_specific_fields() -> None:
    """Plaintext, ciphertext, and tag fields serialize with ACVP names."""
    values = AesGcmValues(plaintext=b"p", ciphertext=b"c", tag=b"t")
    result = CaseResult(7, 8, ResultStatus.PASS, values, values)

    cases = cast(
        list[dict[str, object]],
        build_report([result], provider_metadata(), runner=RUNNER)["cases"],
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
        build_report([result], provider_metadata(), runner=RUNNER)["cases"],
    )
    case = cases[0]

    assert case["expected"] == {"ct": "63"}
    assert case["actual"] == {"tag": "74"}


def test_json_is_deterministic_valid_and_newline_terminated() -> None:
    """Serialized reports are stable JSON suitable for files and pipelines."""
    rendered = report_json(all_status_results(), provider_metadata(), runner=RUNNER)

    assert rendered.endswith("\n")
    assert json.loads(rendered) == build_report(
        all_status_results(), provider_metadata(), runner=RUNNER
    )
    assert rendered == report_json(all_status_results(), provider_metadata(), runner=RUNNER)


def test_declines_are_split_by_who_claimed_them() -> None:
    """A module author reads the harness's own claims as their list, and the rest as not."""
    harness, runner = DeclineClaimant.HARNESS, DeclineClaimant.RUNNER
    implementation = DeclineReason.IMPLEMENTATION_LACKS
    unsupported = ResultStatus.UNSUPPORTED
    results = [
        CaseResult(1, 1, unsupported, None, None, "curve", implementation, harness),
        CaseResult(1, 2, unsupported, None, None, "curve", implementation, harness),
        CaseResult(1, 3, unsupported, None, None, "no x", DeclineReason.VECTOR_INCOMPLETE, harness),
        CaseResult(1, 4, unsupported, None, None, "LDT", DeclineReason.RUNNER_LACKS, runner),
        CaseResult(1, 5, unsupported, None, None, "curve", implementation, runner),
    ]

    summary = summarize(results)

    assert summary.unsupported_by_claimant == {
        "harness": {"implementation_lacks": 2, "vector_incomplete": 1},
        "runner": {
            "implementation_lacks": 1,
            "runner_lacks": 1,
            "offline_undecidable": 0,
            "vector_incomplete": 0,
        },
    }
    assert summary.unsupported_by_reason["implementation_lacks"] == 3


def test_an_external_provider_block_carries_its_command_and_build() -> None:
    """Where it ran and which build answered, or the reason no build could be named."""
    external = ProviderMetadata(
        name="pkcs11-harness",
        library_name="SoftHSM",
        library_version="2.6",
        backend_name="PKCS#11",
        backend_version="/usr/lib/softhsm/libsofthsm2.so",
        kind=ProviderKind.EXTERNAL,
        command="./acvp_harness --module /usr/lib/softhsm/libsofthsm2.so",
        build_id_absent_reason=BuildIdAbsentReason.NOT_EXPOSED,
    )

    assert build_report([], external, runner=RUNNER)["provider"] == {
        "name": "pkcs11-harness",
        "kind": "external",
        "command": "./acvp_harness --module /usr/lib/softhsm/libsofthsm2.so",
        "library": {"name": "SoftHSM", "version": "2.6"},
        "backend": {"name": "PKCS#11", "version": "/usr/lib/softhsm/libsofthsm2.so"},
        "buildId": None,
        "buildIdAbsentReason": "not_exposed",
    }


def test_a_report_measures_the_runner_when_none_is_supplied() -> None:
    """Left alone, a report pins the instrument that produced it from this checkout."""
    runner = build_report([], provider_metadata())["runner"]

    assert isinstance(runner, dict)
    assert set(runner) == {"version", "commit", "commitAbsentReason", "treeClean"}
    assert runner["version"] == __version__
    if runner["commit"] is None:
        assert runner["commitAbsentReason"] is not None
    else:
        assert runner["commitAbsentReason"] is None
