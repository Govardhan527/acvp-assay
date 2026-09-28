"""Offline tests for the CMVP post-quantum certificate counter.

Nothing here touches the network. What is tested is the judgement in the tool:
which names count as ML-KEM or ML-DSA, which do not, what the date filter keeps
out of the fetch and never out of the denominator, and that an algorithm listed
without a CAVP validation behind it is not counted as one with.

The counting itself is arithmetic over that judgement, so getting the judgement
wrong is the only way to get a wrong number that looks right.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load_module() -> object:
    """Import tools/cmvp_pqc_count.py, which is not part of the package."""
    spec = importlib.util.spec_from_file_location(
        "cmvp_pqc_count", ROOT / "tools/cmvp_pqc_count.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["cmvp_pqc_count"] = module
    spec.loader.exec_module(module)
    return module


cmvp = _load_module()

APPROVED = (
    '<div class="col-md-3">{name}</div>\n'
    '  <div class="col-md-4">\n'
    '    <a href="../../Cryptographic-Algorithm-Validation-Program/details?validation=1">A123</a>'
)
UNVALIDATED = '<div class="col-md-3">{name}</div>\n  <div class="col-md-4">\n    <span>none</span>'
STANDARD = "<p>Standard FIPS 140-3 Status Active</p>"


def page(*entries: str) -> str:
    """A certificate page carrying these algorithm rows."""
    return STANDARD + "\n" + "\n".join(entries)


@pytest.mark.parametrize(
    ("name", "family"),
    [
        ("ML-KEM KeyGen", "ML-KEM"),
        ("ML-KEM EncapDecap", "ML-KEM"),
        ("ML-DSA KeyGen", "ML-DSA"),
        ("ML-DSA SigGen", "ML-DSA"),
        ("ML-DSA SigVer", "ML-DSA"),
        ("MLKEM", "ML-KEM"),
        ("FIPS 203", "ML-KEM"),
        ("FIPS204 signature", "ML-DSA"),
    ],
)
def test_every_spelling_cmvp_uses_is_counted(name: str, family: str) -> None:
    """The display names CMVP actually writes, and the standards behind them."""
    _, families, names = cmvp.classify(page(APPROVED.format(name=name)))  # type: ignore[attr-defined]

    assert families == [family]
    assert names == [name]


@pytest.mark.parametrize("name", ["Kyber", "CRYSTALS-Kyber", "Dilithium", "CRYSTALS-Dilithium"])
def test_the_pre_standard_names_are_not_counted(name: str) -> None:
    """Kyber is not ML-KEM. Counting it would inflate the figure with what nobody validated.

    The submissions differ from the standards in more than name -- FIPS 203
    changed the key format and the derivation -- so a certificate listing Kyber
    is evidence of something else entirely.
    """
    _, families, _ = cmvp.classify(page(APPROVED.format(name=name)))  # type: ignore[attr-defined]

    assert families == []


@pytest.mark.parametrize("name", ["AES-GCM", "SHA2-256", "RSA SigVer (FIPS186-5)", "KAS-ECC-SSC"])
def test_ordinary_algorithms_are_not_counted(name: str) -> None:
    """The obvious half of the contract, so a broadened pattern is caught."""
    _, families, _ = cmvp.classify(page(APPROVED.format(name=name)))  # type: ignore[attr-defined]

    assert families == []


def test_an_algorithm_without_a_cavp_validation_is_not_counted() -> None:
    """The anchor is the CAVP link: an entry without one is not an approved algorithm."""
    _, families, _ = cmvp.classify(page(UNVALIDATED.format(name="ML-KEM KeyGen")))  # type: ignore[attr-defined]

    assert families == []


def test_a_certificate_carrying_both_families_reports_both() -> None:
    """Five of the fifteen on the 2026-09-28 snapshot list both, and must not count twice."""
    standard, families, names = cmvp.classify(  # type: ignore[attr-defined]
        page(
            APPROVED.format(name="ML-DSA SigVer"),
            APPROVED.format(name="ML-KEM KeyGen"),
            APPROVED.format(name="AES-CBC"),
        )
    )

    assert standard == "FIPS 140-3"
    assert families == ["ML-DSA", "ML-KEM"]
    assert names == ["ML-DSA SigVer", "ML-KEM KeyGen"]


def test_the_loose_reading_sees_what_the_strict_one_may_miss() -> None:
    """The cross-check must fire on a page that names a family with no CAVP link."""
    assert cmvp.mentions_anywhere(page(UNVALIDATED.format(name="ML-KEM KeyGen")))  # type: ignore[attr-defined]
    assert not cmvp.mentions_anywhere(page(APPROVED.format(name="AES-GCM")))  # type: ignore[attr-defined]


def test_only_certificates_that_could_carry_pqc_are_fetched() -> None:
    """The date filter decides what is downloaded, never what is counted.

    FIPS 203 and 204 were published on 13 August 2024, so an earlier validation
    cannot list either. A revalidation adds a date, which is why the rule is
    "any date on or after", not "the first date".
    """
    old = cmvp.Row(certificate=1, status="Active", dates=(dt.date(2019, 5, 1),))  # type: ignore[attr-defined]
    revalidated = cmvp.Row(  # type: ignore[attr-defined]
        certificate=2, status="Active", dates=(dt.date(2019, 5, 1), dt.date(2025, 3, 2))
    )
    on_the_day = cmvp.Row(certificate=3, status="Active", dates=(dt.date(2024, 8, 13),))  # type: ignore[attr-defined]
    dateless = cmvp.Row(certificate=4, status="Historical", dates=())  # type: ignore[attr-defined]

    assert not old.could_carry_pqc
    assert revalidated.could_carry_pqc
    assert on_the_day.could_carry_pqc
    assert not dateless.could_carry_pqc


def test_the_index_parser_reads_a_row_the_way_cmvp_writes_one() -> None:
    """One row of the real markup, reduced to what the parser needs from it."""
    html = (
        '<tr id="cert-row-7"><td><a href="/projects/x/certificate/5282" '
        'id="cert-number-link-7">5282</a></td>'
        '<td id="cert-validation-dates-7">05/20/2026<br>06/01/2026</td></tr>'
    )

    rows = cmvp.parse_index(html, "Active")  # type: ignore[attr-defined]

    assert len(rows) == 1
    assert rows[0].certificate == 5282
    assert rows[0].status == "Active"
    assert rows[0].dates == (dt.date(2026, 5, 20), dt.date(2026, 6, 1))


def test_the_published_csv_and_method_agree_with_each_other() -> None:
    """The two committed outputs are one measurement, and must not drift apart."""
    csv_text = (ROOT / "tools/cmvp-pqc-certificates.csv").read_text(encoding="utf-8")
    method = (ROOT / "tools/METHOD.md").read_text(encoding="utf-8")
    certificates = [line for line in csv_text.strip().splitlines()[1:] if line]

    assert f"| **total** | **5545** | **{len(certificates)}** |" in method
    for line in certificates:
        assert line.split(",")[0] in csv_text
