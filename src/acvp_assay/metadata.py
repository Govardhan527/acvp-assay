"""Runtime and provider metadata.

``runner_version`` is a claim about the instrument; it does not identify it.
Two runs a commit apart report the same version, so the commit is pinned beside
it, in full, because an abbreviated hash is not fetchable and collides as
history grows. When there is no commit to report, the reason is reported
instead: "no commit" covers three states with three different remedies, and a
bare null would merge them.
"""

from __future__ import annotations

import platform
import re
import subprocess
from enum import StrEnum
from pathlib import Path

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend

from acvp_assay import __version__

PACKAGE = Path(__file__).resolve().parent

#: A full object name: 40 hex digits in a SHA-1 repository, 64 in a SHA-256 one.
FULL_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")

GIT_TIMEOUT_SECONDS = 10


class CommitAbsentReason(StrEnum):
    """Why ``runner_commit`` is null. Each member has a different remedy."""

    #: Running from an installed wheel: no commit exists to name.
    NO_CHECKOUT = "no_checkout"
    #: A source tree that is not under version control.
    NOT_A_REPOSITORY = "not_a_repository"
    #: git could not be run here; a commit may exist and was not reachable.
    VCS_UNAVAILABLE = "vcs_unavailable"


def source_root(package: Path = PACKAGE) -> Path | None:
    """The source tree this package runs from, or ``None`` for an installed copy.

    A checkout keeps the package at ``src/acvp_assay`` beside ``pyproject.toml``;
    a wheel installs it straight into ``site-packages``, which has neither. This
    is decided before git is asked anything, because a wheel installed into a
    virtualenv inside a checkout would otherwise report the checkout's commit,
    which says nothing about the installed code.
    """
    root = package.parent.parent
    if package.parent.name == "src" and (root / "pyproject.toml").is_file():
        return root
    return None


def _git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=GIT_TIMEOUT_SECONDS,
    )


def _absent(reason: CommitAbsentReason) -> dict[str, str | bool | None]:
    return {
        "runner_commit": None,
        "runner_commit_absent_reason": reason.value,
        "runner_tree_clean": None,
    }


def runner_identity(package: Path = PACKAGE) -> dict[str, str | bool | None]:
    """The commit this runner was built from and whether the tree matched it, or why not."""
    root = source_root(package)
    if root is None:
        return _absent(CommitAbsentReason.NO_CHECKOUT)
    if not any((directory / ".git").exists() for directory in (root, *root.parents)):
        return _absent(CommitAbsentReason.NOT_A_REPOSITORY)
    try:
        # Exit status 1 means git ran and the repository it found does not track
        # this tree: a copy dropped inside some unrelated checkout. That
        # checkout's HEAD would name the wrong code.
        tracked = _git(root, "ls-files", "--error-unmatch", "--", str(package.relative_to(root)))
        if tracked.returncode == 1:
            return _absent(CommitAbsentReason.NOT_A_REPOSITORY)
        head = _git(root, "rev-parse", "--verify", "HEAD")
        status = _git(root, "status", "--porcelain")
    except (OSError, subprocess.SubprocessError):
        return _absent(CommitAbsentReason.VCS_UNAVAILABLE)
    commit = head.stdout.strip()
    failed = tracked.returncode or head.returncode or status.returncode
    if failed or not FULL_COMMIT.fullmatch(commit):
        return _absent(CommitAbsentReason.VCS_UNAVAILABLE)
    return {
        "runner_commit": commit,
        "runner_commit_absent_reason": None,
        "runner_tree_clean": status.stdout == "",
    }


def runtime_metadata() -> dict[str, str | bool | None]:
    """Return the versions and commit that identify this runner and its provider."""
    return {
        "cryptography_version": cryptography.__version__,
        "openssl_version": backend.openssl_version_text(),
        "provider": "OpenSSL (via cryptography)",
        "python_version": platform.python_version(),
        "runner_version": __version__,
        **runner_identity(),
    }
