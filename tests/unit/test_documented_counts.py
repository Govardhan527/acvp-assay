"""The documented algorithm count must equal the implemented one.

This guard exists because the drift it prevents actually happened, repeatedly
and unnoticed. The README's Scope section claimed 43 names and "all 40 reach a
harness" while its own banner and coverage table said 46. `docs/limitations.md`
claimed 40 implemented and 22 judged by NIST, months after all of them had been
judged -- an understatement that would have made a prospective user think the
tool did half of what it does. The README's "Not covered" list still named
AES-CCM, AES-XTS, SHAKE, KDA, KAS-ECC-SSC, ML-KEM and ML-DSA long after every
one of them shipped.

Nothing failed when any of that went stale, which is precisely why it stayed
stale. These tests fail instead.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from acvp_assay.algorithms import supported_algorithms

ROOT = Path(__file__).resolve().parents[2]
COUNT = len(supported_algorithms())

#: Every file that states the number out loud, and must therefore state it right.
CLAIM_FILES = ("README.md", "SERVICES.md", "docs/limitations.md")

#: A count claim: "52 algorithm names", "all 52 names", "All 52 supported ...".
CLAIM = re.compile(r"\b(?:all|All)?\s*(\d{2})\s+(?:supported\s+)?algorithm names", re.I)
REACH = re.compile(r"\ball (\d{2})\b(?:\s+\w+){0,3}\s+(?:reach|have been|can be)", re.I)


def _files() -> list[Path]:
    return [ROOT / name for name in CLAIM_FILES]


@pytest.mark.parametrize("path", _files(), ids=lambda p: p.name)
def test_every_algorithm_count_claimed_in_prose_is_the_real_one(path: Path) -> None:
    """A number in the docs that disagrees with the registry is a false claim."""
    text = path.read_text(encoding="utf-8")
    claimed = {int(match) for match in CLAIM.findall(text)}
    wrong = sorted(value for value in claimed if value != COUNT)
    assert not wrong, (
        f"{path.name} claims {wrong} algorithm names; supported_algorithms() has {COUNT}"
    )


@pytest.mark.parametrize("path", _files(), ids=lambda p: p.name)
def test_every_all_n_claim_is_the_real_one(path: Path) -> None:
    """ "All 46 reach a harness" has to move when the 46 does."""
    text = path.read_text(encoding="utf-8")
    claimed = {int(match) for match in REACH.findall(text)}
    wrong = sorted(value for value in claimed if value != COUNT)
    assert not wrong, f"{path.name} says 'all {wrong}' where the count is {COUNT}"


#: Implemented names the "Not covered" section may still mention, because each
#: is named to scope a *partial* gap rather than to claim the whole algorithm is
#: missing. Every entry needs a reason; the list must not become a way to silence
#: the check.
PARTIAL_COVERAGE = {
    # "the key-agreement names beyond the two SSC variants built here"
    "KAS-ECC-SSC",
    # "the eight kdf-components modes other than ssh" -- one registry name,
    # nine modes, one of them built.
    "kdf-components",
}


def test_the_not_covered_list_names_nothing_that_is_implemented() -> None:
    """The list that told readers AES-CCM and ML-KEM were missing, for months."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("### Not covered")[1].split("## How vendors use this")[0]
    named = set(re.findall(r"`([A-Za-z0-9\-/.]+)`", section))
    implemented = named & set(supported_algorithms())
    assert implemented <= PARTIAL_COVERAGE, (
        f"README lists these as not covered, but they are implemented: "
        f"{sorted(implemented - PARTIAL_COVERAGE)}"
    )


def test_every_partial_coverage_exemption_is_still_implemented() -> None:
    """An exemption for a name nobody implements is dead weight that hides drift."""
    assert set(supported_algorithms()) >= PARTIAL_COVERAGE


def test_the_guard_would_notice() -> None:
    """Guard the guard: a regex that matches nothing proves nothing."""
    assert CLAIM.findall((ROOT / "README.md").read_text(encoding="utf-8"))
    assert COUNT > 1
