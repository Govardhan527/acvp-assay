"""Runtime and provider metadata."""

from __future__ import annotations

import platform

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend

from acvp_assay import __version__


def runtime_metadata() -> dict[str, str]:
    """Return the versions that identify this runner and its future provider."""
    return {
        "cryptography_version": cryptography.__version__,
        "openssl_version": backend.openssl_version_text(),
        "provider": "OpenSSL (via cryptography)",
        "python_version": platform.python_version(),
        "runner_version": __version__,
    }
