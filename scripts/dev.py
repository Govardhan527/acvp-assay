"""Small cross-platform development task runner."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENV = ROOT / ".venv"


def _venv_python() -> Path:
    relative = Path("Scripts/python.exe") if os.name == "nt" else Path("bin/python")
    return VENV / relative


def _run(arguments: Sequence[str | Path]) -> None:
    subprocess.run([str(argument) for argument in arguments], cwd=ROOT, check=True)


def setup() -> None:
    """Create the local environment and install development dependencies."""
    python = _venv_python()
    if not python.exists():
        _run([sys.executable, "-m", "venv", VENV])
    _run([python, "-m", "pip", "install", "--upgrade", "pip"])
    _run([python, "-m", "pip", "install", "--editable", ".[dev]"])


def require_environment() -> Path:
    """Return the local Python executable or explain how to create it."""
    python = _venv_python()
    if not python.exists():
        raise SystemExit("missing .venv; run 'python3.12 scripts/dev.py setup' first")
    return python


def test() -> None:
    """Run formatting, lint, typing, and test checks."""
    python = require_environment()
    _run([python, "-m", "ruff", "format", "--check", "."])
    _run([python, "-m", "ruff", "check", "."])
    _run([python, "-m", "mypy"])
    _run([python, "-m", "pytest"])


def verify() -> None:
    """Run all checks and build distributable artifacts."""
    python = require_environment()
    test()
    _run([python, "-m", "build"])


def demo() -> None:
    """Run the smallest executable package demonstration."""
    _run([require_environment(), "-m", "acvp_assay", "info"])


def vectors() -> None:
    """Download and verify the pinned upstream NIST vector files."""
    _run([require_environment(), ROOT / "scripts/fetch_vectors.py"])


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch a development command."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("setup", "test", "verify", "demo", "vectors"))
    command = parser.parse_args(argv).command
    commands = {
        "setup": setup,
        "test": test,
        "verify": verify,
        "demo": demo,
        "vectors": vectors,
    }
    commands[command]()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
