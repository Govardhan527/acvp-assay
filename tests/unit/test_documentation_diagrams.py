"""Mermaid blocks in the docs must actually render on GitHub.

A diagram that fails to parse shows a red error box in place of the picture,
and nothing in the ordinary gate notices -- the file is still valid Markdown
and the tests still pass. That happened: a semicolon inside a ``Note over``
text ended the statement early, and the live-session diagram rendered as a
parse error until a reader reported it.

These are structural checks, not a parser. They cover the constructs that have
actually broken, which is a narrower and more useful claim than pretending to
validate the grammar.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BLOCK = re.compile(r"```mermaid\n(.*?)```", re.S)


def markdown_files() -> list[Path]:
    """Every committed Markdown file that might carry a diagram."""
    return sorted(
        path
        for path in [*ROOT.glob("*.md"), *ROOT.glob("docs/**/*.md"), *ROOT.glob("examples/**/*.md")]
        if path.is_file()
    )


def diagrams() -> list[tuple[Path, int, str]]:
    """Every Mermaid block, with the file and its position in it."""
    found: list[tuple[Path, int, str]] = []
    for path in markdown_files():
        for index, body in enumerate(BLOCK.findall(path.read_text(encoding="utf-8")), 1):
            found.append((path, index, body))
    return found


def statements(body: str) -> list[tuple[int, str]]:
    """Numbered, non-blank, non-comment lines of a diagram."""
    return [
        (number, line.strip())
        for number, line in enumerate(body.splitlines(), 1)
        if line.strip() and not line.strip().startswith("%%")
    ]


def test_the_documentation_actually_contains_diagrams() -> None:
    """Guard the guard: a passing suite over zero diagrams proves nothing."""
    assert len(diagrams()) >= 9


@pytest.mark.parametrize(
    ("path", "index", "body"), diagrams(), ids=lambda v: v.name if isinstance(v, Path) else str(v)
)
def test_a_diagram_carries_no_statement_separator(path: Path, index: int, body: str) -> None:
    """A semicolon ends a Mermaid statement, truncating whatever follows.

    This is the one that shipped broken. Inside a quoted flowchart label it is
    usually tolerated, but a ``Note over`` text is not quoted and the parser
    stops dead.
    """
    offenders = [f"line {n}: {t}" for n, t in statements(body) if ";" in t]
    assert not offenders, f"{path.name} diagram {index} has semicolons: {offenders}"


@pytest.mark.parametrize(
    ("path", "index", "body"), diagrams(), ids=lambda v: v.name if isinstance(v, Path) else str(v)
)
def test_a_diagram_uses_no_escape_or_entity(path: Path, index: int, body: str) -> None:
    """``\\n`` renders literally, and HTML entities smuggle in a semicolon."""
    offenders = [
        f"line {n}: {t}" for n, t in statements(body) if "\\n" in t or re.search(r"&[a-zA-Z]+;", t)
    ]
    assert not offenders, f"{path.name} diagram {index}: {offenders}"


@pytest.mark.parametrize(
    ("path", "index", "body"), diagrams(), ids=lambda v: v.name if isinstance(v, Path) else str(v)
)
def test_a_flowchart_label_containing_markup_is_quoted(path: Path, index: int, body: str) -> None:
    """An unquoted label with a tag or slash is a parse error."""
    if not statements(body)[0][1].startswith("flowchart"):
        pytest.skip("not a flowchart")
    offenders = []
    for number, text in statements(body):
        for match in re.finditer(r"[A-Za-z0-9_]+\[([^\]]*)\]", text):
            label = match.group(1)
            if ("<" in label or "/" in label) and not label.startswith('"'):
                offenders.append(f"line {number}: {label[:50]}")
    assert not offenders, f"{path.name} diagram {index}: {offenders}"


@pytest.mark.parametrize(
    ("path", "index", "body"), diagrams(), ids=lambda v: v.name if isinstance(v, Path) else str(v)
)
def test_a_sequence_diagram_only_uses_declared_participants(
    path: Path, index: int, body: str
) -> None:
    """A typo in a participant name silently invents a new lifeline."""
    lines = statements(body)
    if not lines[0][1].startswith("sequenceDiagram"):
        pytest.skip("not a sequence diagram")
    declared = {
        match.group(1)
        for _, text in lines
        for match in [re.match(r"participant\s+([A-Za-z0-9_]+)", text)]
        if match
    }
    assert declared, "a sequence diagram should declare its participants"

    # Match the arrow forms explicitly, longest first. A greedy \S+ swallows
    # the first hyphen of "-->>" and reports the sender as "H-", which is how
    # this check first failed against diagrams that were perfectly valid.
    arrows = ("-->>", "->>", "--x", "-->", "--)", "->", "-x", "-)")
    used: set[str] = set()
    for _, text in lines:
        note = re.match(r"Note\s+(?:over|left of|right of)\s+([^:]+):", text)
        if note:
            used |= {part.strip() for part in note.group(1).split(",")}
            continue
        head = text.split(":", 1)[0]
        for arrow in arrows:
            if arrow in head:
                left, _, right = head.partition(arrow)
                used |= {left.strip(), right.strip().split("+")[-1].strip()}
                break
    undeclared = sorted(name for name in used - declared if name)
    assert not undeclared, f"{path.name} diagram {index} uses undeclared: {undeclared}"


@pytest.mark.parametrize(
    ("path", "index", "body"), diagrams(), ids=lambda v: v.name if isinstance(v, Path) else str(v)
)
def test_a_diagram_declares_a_type_first(path: Path, index: int, body: str) -> None:
    """Mermaid needs a diagram type on the first line."""
    first = statements(body)[0][1]
    known = ("flowchart", "graph", "sequenceDiagram", "classDiagram", "stateDiagram", "erDiagram")
    assert first.startswith(known), f"{path.name} diagram {index} starts with {first!r}"


def test_the_checks_catch_the_failure_that_shipped() -> None:
    """The regression this file exists for.

    A semicolon inside a Note is exactly what rendered as a parse error on
    GitHub, so assert the check rejects it rather than trusting that it would.
    """
    broken = "sequenceDiagram\n    participant A\n    Note over A: one thing; and another\n"
    offenders = [t for _, t in statements(broken) if ";" in t]
    assert offenders, "the semicolon check would not have caught the reported bug"
