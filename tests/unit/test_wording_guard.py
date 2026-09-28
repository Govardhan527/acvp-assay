"""Fail the build on a claim this project must never make.

`validated`, `CAVP`, `certified` and `FIPS approved` are the four words that turn
test evidence into a claim of validation. Only an accredited CST or 17ACVT
laboratory performs CAVP algorithm validation or FIPS 140-3 module validation,
and ACVTS Production is closed to everyone else; this project runs against the
Demo server, which is a development environment.

The audience is laboratories and compliance buyers, who are acutely sensitive to
overclaiming, so the cost of one careless sentence is out of all proportion to
its size. A guard is the right shape for that, because the risk is drift: nobody
writes "acvp-assay validates your module" on purpose, and a small edit to a
disclaimer can produce it by accident.

Two rules, because reports and prose fail differently:

* A **report** is generated, and nothing in one has any business carrying these
  words. They are banned outright.
* **Prose** has to name what it disclaims, and a script called
  `cavp_frequency.py` has to be called something. Every legitimate use is
  reviewed and listed in ``tests/wording-allowlist.md``, exact line by exact
  line. Anything else fails.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from acvp_assay.cli import main

ROOT = Path(__file__).resolve().parents[2]
ALLOWLIST = ROOT / "tests/wording-allowlist.md"
FIXTURES = ROOT / "fixtures"

#: The four claims. Matched case-insensitively, because a capital letter is not
#: a defence.
GUARDED = re.compile(r"validated|cavp|certified|fips[ -]approved", re.IGNORECASE)

#: Where the words appear inside a name rather than in a sentence: the frequency
#: script, its test, and its cache directory. These are identifiers, and renaming
#: them to satisfy a text search would make the tree harder to read for nothing.
IDENTIFIERS = re.compile(r"cavp[_-]frequency|\.cavp-cache|cavp-cache")

#: Every file whose prose is guarded, named rather than globbed: a glob over the
#: root would sweep in whatever untracked working notes happen to be sitting
#: there, and a guard that fails on a file nobody publishes is a guard people
#: learn to ignore. Source and tests are excluded on purpose -- `validated` in a
#: docstring about validating a parameter is the ordinary English word, and this
#: is about what the project says publicly.
PROSE = sorted(
    {
        ROOT / "README.md",
        ROOT / "SERVICES.md",
        ROOT / "CONTRIBUTING.md",
        ROOT / "CHANGELOG.md",
        ROOT / "BUILDLOG.md",
        ROOT / "fixtures/README.md",
        *ROOT.glob("docs/*.md"),
        *ROOT.glob("docs/decisions/*.md"),
        *ROOT.glob("examples/*/README.md"),
    }
)


def _allowlist() -> set[tuple[str, str]]:
    """Every reviewed (path, line) pair, read from the committed allowlist."""
    allowed: set[tuple[str, str]] = set()
    for raw in ALLOWLIST.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or " :: " not in line:
            continue
        path, _, text = line.partition(" :: ")
        # A path that is not a file here is prose about the format, not an entry.
        if (ROOT / path.strip()).is_file():
            allowed.add((path.strip(), text.strip()))
    return allowed


def claims(path: Path, text: str, allowed: set[tuple[str, str]]) -> list[str]:
    """Every guarded word in this text that is not a reviewed use."""
    relative = path.relative_to(ROOT).as_posix()
    found: list[str] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not GUARDED.search(IDENTIFIERS.sub("", line)):
            continue
        if (relative, line) in allowed:
            continue
        found.append(f"{relative}:{number}: {line[:120]}")
    return found


@pytest.mark.parametrize("path", PROSE, ids=lambda path: path.relative_to(ROOT).as_posix())
def test_no_prose_claims_validation_without_review(path: Path) -> None:
    """Every guarded word in published prose is one somebody signed off."""
    found = claims(path, path.read_text(encoding="utf-8"), _allowlist())

    assert not found, (
        "unreviewed use of a guarded word:\n  "
        + "\n  ".join(found)
        + f"\n\nIf it is legitimate, add the exact line to {ALLOWLIST.name} with its reason."
    )


def test_the_allowlist_has_no_stale_entries() -> None:
    """A disclaimer that was reworded must not leave permission behind for the old one."""
    stale = [
        f"{path} :: {line[:80]}"
        for path, line in sorted(_allowlist())
        if line not in (ROOT / path).read_text(encoding="utf-8")
    ]

    assert not stale, "these allowlist entries no longer match any line:\n  " + "\n  ".join(stale)


def test_no_generated_report_carries_a_guarded_word(tmp_path: Path) -> None:
    """A report is machine-written, and nothing in one needs any of these words.

    Every shipped fixture is run, including the deliberately corrupted ones, so
    the diagnostics, decline reasons and provider metadata a real report carries
    are all scanned rather than assumed clean.
    """
    offenders: list[str] = []
    for prompt in sorted(FIXTURES.glob("*/prompt.json")):
        output = tmp_path / f"{prompt.parent.name}.json"
        main(["run", str(prompt), "--output", str(output)])
        report = json.loads(output.read_text(encoding="utf-8"))
        rendered = json.dumps(report)
        if GUARDED.search(rendered):
            offenders.append(prompt.parent.name)

    assert not offenders, f"a generated report used a guarded word: {offenders}"


def test_the_guard_would_notice() -> None:
    """The guard is only worth having if it fires, so make it fire."""
    claim = "acvp-assay validated this module against NIST's vectors."

    assert claims(ROOT / "README.md", claim, _allowlist())
    assert claims(ROOT / "README.md", "It is CAVP certified.", _allowlist())
    assert GUARDED.search("a FIPS approved module")
    # And it does not fire on the identifiers that merely contain the letters.
    assert not claims(ROOT / "README.md", "run scripts/cavp_frequency.py fetch", _allowlist())
