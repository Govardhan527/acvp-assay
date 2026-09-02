"""Offline tests for the pinned upstream vector fetcher.

None of these touch the network: CI must stay deterministic, so only the
verification logic and the pin/document agreement are exercised here.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
VECTOR_SOURCES = ROOT / "docs/vector-sources.md"


def _load_module() -> object:
    """Import scripts/fetch_vectors.py, which is not part of the package."""
    spec = importlib.util.spec_from_file_location(
        "fetch_vectors", ROOT / "scripts/fetch_vectors.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["fetch_vectors"] = module
    spec.loader.exec_module(module)
    return module


fetch_vectors = _load_module()


def test_every_pin_is_documented_in_vector_sources() -> None:
    """The script and docs/vector-sources.md must not drift apart."""
    document = VECTOR_SOURCES.read_text(encoding="utf-8")

    assert fetch_vectors.COMMIT in document  # type: ignore[attr-defined]
    for pinned in fetch_vectors.PINNED_FILES:  # type: ignore[attr-defined]
        assert pinned.sha256 in document, f"{pinned.label} hash missing from vector-sources.md"
        assert pinned.directory in document


def test_pinned_urls_target_the_pinned_commit() -> None:
    """Every download URL is immutable, never a branch name."""
    for pinned in fetch_vectors.PINNED_FILES:  # type: ignore[attr-defined]
        assert fetch_vectors.COMMIT in pinned.url  # type: ignore[attr-defined]
        assert pinned.url.endswith(pinned.name)
        assert "/main/" not in pinned.url


def test_verify_accepts_matching_payload() -> None:
    """A payload matching both size and hash verifies silently."""
    payload = b'{"vsId": 0}'
    pinned = fetch_vectors.PinnedFile(  # type: ignore[attr-defined]
        directory="SAMPLE-1.0",
        name="sample.json",
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
    )

    fetch_vectors.verify(payload, pinned)  # type: ignore[attr-defined]


def test_verify_rejects_wrong_size_before_hashing() -> None:
    """A truncated download is rejected by size."""
    payload = b"short"
    pinned = fetch_vectors.PinnedFile(  # type: ignore[attr-defined]
        directory="SAMPLE-1.0",
        name="sample.json",
        size_bytes=999,
        sha256=hashlib.sha256(payload).hexdigest(),
    )

    with pytest.raises(fetch_vectors.VectorVerificationError, match="expected 999 bytes"):  # type: ignore[attr-defined]
        fetch_vectors.verify(payload, pinned)  # type: ignore[attr-defined]


def test_verify_rejects_tampered_content() -> None:
    """Right size, wrong bytes is still rejected."""
    payload = b"tampered!"
    pinned = fetch_vectors.PinnedFile(  # type: ignore[attr-defined]
        directory="SAMPLE-1.0",
        name="sample.json",
        size_bytes=len(payload),
        sha256="0" * 64,
    )

    with pytest.raises(fetch_vectors.VectorVerificationError, match="expected SHA-256"):  # type: ignore[attr-defined]
        fetch_vectors.verify(payload, pinned)  # type: ignore[attr-defined]
