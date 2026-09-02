"""Integration tests for the installed command path."""

from __future__ import annotations

import json
import subprocess
import sys


def test_module_info_command() -> None:
    """The package is executable through Python's module interface."""
    completed = subprocess.run(
        [sys.executable, "-m", "acvp_assay", "info"],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(completed.stdout)
    assert completed.stderr == ""
    assert payload["provider"] == "OpenSSL (via cryptography)"
