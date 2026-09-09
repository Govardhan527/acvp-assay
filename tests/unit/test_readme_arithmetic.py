"""The README's own arithmetic must add up.

Every one of these was written correct and went stale as the results table grew,
and all of them were found by a person re-reading the file rather than by the
build:

* the banner said the live server caught "four defects" while the section below
  it listed six;
* a footnote said a vector set was "excluded from the 43" when the table total
  had reached 63 — 43 was the running count when the footnote was written;
* the CI badge claimed 46/46 algorithm names against a body claiming 57, and 46
  was the running count one row further down;
* a paragraph said two sessions were backed by a stored verdict when fifteen
  were, understating the evidence rather than overstating it;
* the sample `diff` output announced ten lost cases and then accounted for six.

`test_documented_counts.py` guards the algorithm count. This guards the numbers
the README derives from *itself*, which is a different failure and, on the
evidence, a more frequent one.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from acvp_assay.algorithms import supported_algorithms

ROOT = Path(__file__).resolve().parents[2]
README = (ROOT / "README.md").read_text(encoding="utf-8")

NUMBER_WORDS = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
    "thirteen": 13,
    "fourteen": 14,
    "fifteen": 15,
    "sixteen": 16,
}

#: One row per live session: id, algorithms, vector sets, cases, verdict.
SESSION_ROW = re.compile(r"^\| (7\d{5}) \|([^|]*)\|\s*(\d+)\s*\|\s*([\d,—-]+)\s*\|", re.M)
COMPLETED = re.compile(r"\| \| \*\*Completed\*\* \| \*\*(\d+)\*\* \| \*\*([\d,]+)\*\* \|")


def _int(text: str) -> int:
    return int(text.replace(",", ""))


def completed() -> tuple[int, int]:
    """The table's own totals row."""
    match = COMPLETED.search(README)
    assert match is not None, "the results table has no Completed row"
    return int(match.group(1)), _int(match.group(2))


def test_the_badge_states_the_real_algorithm_count() -> None:
    """The badge is the first number a reader sees and the easiest to forget."""
    match = re.search(r"NIST%20ACVTS%20Demo-(\d+)%2F(\d+)%20algorithms%20passed", README)
    assert match is not None, "the ACVTS badge is missing or renamed"
    count = len(supported_algorithms())
    assert (int(match.group(1)), int(match.group(2))) == (count, count)


def test_the_banner_counts_the_defects_the_section_lists() -> None:
    """The banner said four for as long as the section listed six."""
    match = re.search(r"caught the (\w+) defects listed under", README)
    assert match is not None, "the banner no longer refers to the defect list"
    claimed = NUMBER_WORDS.get(match.group(1).lower())
    assert claimed is not None, f"unrecognised number word {match.group(1)!r}"
    section = README.split("### What this caught that fixtures did not")[1]
    section = section.split("### Reproducing it")[0]
    listed = len(re.findall(r"^- \*\*", section, re.M))
    assert claimed == listed, f"banner says {claimed} defects, the section lists {listed}"


def test_the_results_table_adds_up() -> None:
    """Totals must equal the rows above them.

    Rows with no case count are the sessions that failed or were abandoned;
    they are listed deliberately and excluded from both totals.
    """
    rows = SESSION_ROW.findall(README)
    assert rows, "no session rows found"
    scored = [row for row in rows if row[3].strip() not in {"—", "-"}]
    sets = sum(int(row[2]) for row in scored)
    cases = sum(_int(row[3]) for row in scored)
    assert (sets, cases) == completed()


def test_every_reference_to_the_table_total_uses_the_current_one() -> None:
    """ "excluded from the 43" outlived the 43 by twenty vector sets."""
    total_sets, total_cases = completed()
    stale = [
        int(value)
        for value in re.findall(r"excluded from the (\d+)", README)
        if int(value) != total_sets
    ]
    assert not stale, f"the table total is {total_sets}; the text still says {stale}"
    for value in re.findall(r"covering ([\d,]+)\s*\n?> ?test cases", README):
        assert _int(value) == total_cases


@pytest.mark.parametrize("label", ["regressed", "coverage lost"])
def test_the_sample_diff_output_accounts_for_what_it_announces(label: str) -> None:
    """A worked example that does not add up teaches the wrong thing."""
    match = re.search(rf"^{re.escape(label)}: (\d+)$(.*?)(?=^\w|\Z)", README, re.M | re.S)
    assert match is not None, f"the sample diff no longer reports {label!r}"
    announced = int(match.group(1))
    body = match.group(2)
    shown = len(re.findall(r"^  tgId ", body, re.M))
    more = re.search(r"\.\.\. and (\d+) more", body)
    accounted = shown + (int(more.group(1)) if more else 0)
    assert announced == accounted, (
        f"{label} says {announced} but the example accounts for {accounted}"
    )


def test_the_stored_verdict_claim_matches_the_table() -> None:
    """Understating the evidence is the costlier direction of this error."""
    match = re.search(r"onward — (\w+) of them — is backed", README)
    assert match is not None, "the stored-verdict sentence has been reworded"
    claimed = NUMBER_WORDS.get(match.group(1).lower())
    assert claimed is not None
    ids = [int(row[0]) for row in SESSION_ROW.findall(README)]
    assert claimed == sum(1 for value in ids if value >= 765508)
