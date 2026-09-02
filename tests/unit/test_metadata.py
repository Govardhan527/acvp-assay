"""Unit tests for provider metadata."""

from acvp_assay.metadata import runtime_metadata


def test_runtime_metadata_has_stable_schema() -> None:
    """Runtime metadata exposes the fields required by later result reports."""
    assert set(runtime_metadata()) == {
        "cryptography_version",
        "openssl_version",
        "provider",
        "python_version",
        "runner_version",
    }
