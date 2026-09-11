"""Unit tests for runtime metadata, and for the runner's own identity.

A version string is a claim about the instrument; the commit identifies it.
Each state in which there is no commit to name is tested separately, because
they have different remedies and a bare null would merge them.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from acvp_assay.metadata import (
    FULL_COMMIT,
    CommitAbsentReason,
    runner_identity,
    runtime_metadata,
    source_root,
)

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def _tree(root: Path) -> Path:
    """Lay out a source tree the way a checkout does, and return its package."""
    package = root / "src" / "acvp_assay"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (root / "pyproject.toml").write_text("", encoding="utf-8")
    return package


def _git(root: Path, *arguments: str) -> str:
    identity = ["-c", "user.name=test", "-c", "user.email=test@example.invalid"]
    return subprocess.run(
        ["git", *identity, "-c", "commit.gpgsign=false", *arguments],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _absent(reason: CommitAbsentReason) -> dict[str, object]:
    return {
        "runner_commit": None,
        "runner_commit_absent_reason": reason.value,
        "runner_tree_clean": None,
    }


def test_runtime_metadata_has_stable_schema() -> None:
    """Runtime metadata exposes the fields required by later result reports."""
    assert set(runtime_metadata()) == {
        "cryptography_version",
        "openssl_version",
        "provider",
        "python_version",
        "runner_commit",
        "runner_commit_absent_reason",
        "runner_tree_clean",
        "runner_version",
    }


def test_a_commit_is_full_or_absent_with_its_reason() -> None:
    """Whatever state this suite runs in, a null commit never stands alone."""
    identity = runtime_metadata()
    commit = identity["runner_commit"]
    if commit is None:
        assert identity["runner_commit_absent_reason"] in set(CommitAbsentReason)
        assert identity["runner_tree_clean"] is None
    else:
        assert isinstance(commit, str)
        assert FULL_COMMIT.fullmatch(commit)
        assert identity["runner_commit_absent_reason"] is None
        assert isinstance(identity["runner_tree_clean"], bool)


def test_an_abbreviated_hash_is_not_a_commit() -> None:
    """Seven digits are not fetchable and collide as history grows."""
    assert not FULL_COMMIT.fullmatch("a164be0")
    assert FULL_COMMIT.fullmatch("a" * 40)
    assert FULL_COMMIT.fullmatch("a" * 64)


def test_an_installed_copy_has_no_commit_to_name(tmp_path: Path) -> None:
    """A wheel in site-packages carries no history, so there is nothing to ask git."""
    package = tmp_path / "site-packages" / "acvp_assay"
    package.mkdir(parents=True)

    assert source_root(package) is None
    assert runner_identity(package) == _absent(CommitAbsentReason.NO_CHECKOUT)


def test_an_installed_copy_inside_a_checkout_does_not_borrow_its_commit(tmp_path: Path) -> None:
    """A virtualenv inside a checkout holds installed code, not the checkout's HEAD."""
    (tmp_path / ".git").mkdir()
    package = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages" / "acvp_assay"
    package.mkdir(parents=True)

    assert runner_identity(package) == _absent(CommitAbsentReason.NO_CHECKOUT)


def test_a_source_tree_outside_version_control_says_so(tmp_path: Path) -> None:
    """No repository anywhere above the tree: git is never consulted."""
    if any((directory / ".git").exists() for directory in tmp_path.parents):
        pytest.skip("the temporary directory is itself inside a repository")
    package = _tree(tmp_path)

    assert source_root(package) == tmp_path
    assert runner_identity(package) == _absent(CommitAbsentReason.NOT_A_REPOSITORY)


def test_git_missing_from_path_is_not_the_same_as_no_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A repository is present and git cannot be run: a commit may exist unseen."""
    package = _tree(tmp_path)
    (tmp_path / ".git").mkdir()
    empty = tmp_path / "no-git-here"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))

    assert runner_identity(package) == _absent(CommitAbsentReason.VCS_UNAVAILABLE)


@needs_git
def test_a_repository_git_cannot_read_is_unavailable(tmp_path: Path) -> None:
    """A ``.git`` that git rejects is a reachability failure, not an absent repository."""
    package = _tree(tmp_path)
    (tmp_path / ".git").mkdir()

    assert runner_identity(package) == _absent(CommitAbsentReason.VCS_UNAVAILABLE)


@needs_git
def test_a_committed_tree_reports_its_full_commit_and_cleanliness(tmp_path: Path) -> None:
    """The commit is HEAD in full, and an edit since then is reported, not hidden."""
    package = _tree(tmp_path)
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "baseline")
    head = _git(tmp_path, "rev-parse", "HEAD").strip()

    assert runner_identity(package) == {
        "runner_commit": head,
        "runner_commit_absent_reason": None,
        "runner_tree_clean": True,
    }

    (package / "__init__.py").write_text("changed = True\n", encoding="utf-8")

    assert runner_identity(package)["runner_tree_clean"] is False


@needs_git
def test_a_copy_inside_an_unrelated_repository_is_not_given_its_commit(tmp_path: Path) -> None:
    """The repository above the tree does not track it, so its HEAD names other code."""
    _git(tmp_path, "init", "-q")
    (tmp_path / "unrelated.txt").write_text("x\n", encoding="utf-8")
    _git(tmp_path, "add", "unrelated.txt")
    _git(tmp_path, "commit", "-q", "-m", "unrelated")
    package = _tree(tmp_path / "copied")

    assert runner_identity(package) == _absent(CommitAbsentReason.NOT_A_REPOSITORY)
