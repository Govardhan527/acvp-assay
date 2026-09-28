#!/usr/bin/env python3
"""Compare a freshly probed liboqs capability file with the recorded one.

``examples/liboqs/capabilities.json`` records what the pinned liboqs exposes.
Re-probing on another machine produces a different compiler, CPU and operating
system, and must produce the same *capabilities*: the same entry points, at the
same layer, with the same pre-hashes available. Those are properties of the
library at the pinned commit, so a difference is liboqs having changed under a
pin that says it did not, or a harness that has stopped reaching it.

    python3 scripts/check_liboqs_capabilities.py fresh.json recorded.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

#: What is compared. ``build`` and ``buildId`` are deliberately absent: they are
#: properties of the machine and of the binary, and are expected to differ.
COMPARED = ("library", "mlKem", "mlDsa", "preHash")


def _load(path: Path) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return document


def differences(fresh: dict[str, Any], recorded: dict[str, Any]) -> list[str]:
    """Every capability that differs, named well enough to act on."""
    found: list[str] = []
    for section in COMPARED:
        if fresh.get(section) != recorded.get(section):
            found.append(
                f"{section}: probed {json.dumps(fresh.get(section), sort_keys=True)}, "
                f"recorded {json.dumps(recorded.get(section), sort_keys=True)}"
            )
    return found


def main(argv: list[str] | None = None) -> int:
    """Compare two capability files and report what moved."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fresh", type=Path, help="the capability file just probed")
    parser.add_argument("recorded", type=Path, help="the one committed in examples/liboqs")
    arguments = parser.parse_args(argv)

    found = differences(_load(arguments.fresh), _load(arguments.recorded))
    if not found:
        print("capabilities match the recorded probe")
        return 0
    print("liboqs exposes something different from what was recorded:", file=sys.stderr)
    for difference in found:
        print(f"  {difference}", file=sys.stderr)
    print(
        "\nRe-run ./examples/liboqs/acvp_harness --capabilities and commit the result "
        "if the change is intended.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
