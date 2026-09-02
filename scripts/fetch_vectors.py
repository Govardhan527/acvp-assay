"""Download and verify the pinned upstream NIST AES-GCM vector files.

The files are fetched into a git-ignored directory and are never committed:
``docs/vector-sources.md`` records the decision not to redistribute them. This
script is the single source of truth for the pins; a unit test asserts that
every value here also appears in that document, so the two cannot drift.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import urllib.error
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "vectors"

REPOSITORY = "usnistgov/ACVP-Server"
COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
JSON_ROOT = "gen-val/json-files"
TIMEOUT_SECONDS = 30


@dataclass(frozen=True, slots=True)
class PinnedFile:
    """One upstream file pinned by size and content hash."""

    directory: str
    name: str
    size_bytes: int
    sha256: str

    @property
    def url(self) -> str:
        """Raw content URL for the pinned commit."""
        return (
            f"https://raw.githubusercontent.com/{REPOSITORY}/{COMMIT}/"
            f"{JSON_ROOT}/{self.directory}/{self.name}"
        )

    @property
    def label(self) -> str:
        """Human-readable identity for progress output."""
        return f"{self.directory}/{self.name}"


AES_GCM = "ACVP-AES-GCM-1.0"
SHA2_256 = "SHA2-256-1.0"
HMAC_SHA2_256 = "HMAC-SHA2-256-1.0"

PINNED_FILES = (
    PinnedFile(
        directory=AES_GCM,
        name="registration.json",
        size_bytes=376,
        sha256="70dbf2189f673d756013d758539fc57994c1415efa43cd1524d59ca1346c4038",
    ),
    PinnedFile(
        directory=AES_GCM,
        name="prompt.json",
        size_bytes=15187,
        sha256="78114cb01d1f436a1f6d0b47bf2fdb9a78f805fbae59c31a813c32edb4e00821",
    ),
    PinnedFile(
        directory=AES_GCM,
        name="expectedResults.json",
        size_bytes=6067,
        sha256="5d4f4bfff5af3284548296f3637ed75bb92f7eb94e6fa04524d1546353e4cff8",
    ),
    PinnedFile(
        directory=SHA2_256,
        name="prompt.json",
        size_bytes=948259,
        sha256="9c4ec74e526cced84cd6dfdf130f2908e2d340b45ea5d9ea0a4019987ee49dac",
    ),
    PinnedFile(
        directory=SHA2_256,
        name="expectedResults.json",
        size_bytes=77375,
        sha256="776688ef7b6e4dd18ce203ee7d9ee45c6c597248f6c00ec70bdbd59176109e05",
    ),
    PinnedFile(
        directory=HMAC_SHA2_256,
        name="prompt.json",
        size_bytes=347221,
        sha256="efb49edda31524c8fe9ffdb4fc92120f041b01ca06f6496f97939240bf1cdcf9",
    ),
    PinnedFile(
        directory=HMAC_SHA2_256,
        name="expectedResults.json",
        size_bytes=88459,
        sha256="dae3412189dfe11a63b40780f16c6c3304b5d9c2dff5351f653711903cf09e1f",
    ),
)


class VectorVerificationError(RuntimeError):
    """A downloaded file did not match its pinned size or hash."""


def verify(payload: bytes, pinned: PinnedFile) -> None:
    """Raise unless the payload matches the pinned size and SHA-256 exactly."""
    if len(payload) != pinned.size_bytes:
        raise VectorVerificationError(
            f"{pinned.label}: expected {pinned.size_bytes} bytes, got {len(payload)}"
        )
    digest = hashlib.sha256(payload).hexdigest()
    if digest != pinned.sha256:
        raise VectorVerificationError(
            f"{pinned.label}: expected SHA-256 {pinned.sha256}, got {digest}"
        )


def _is_current(destination: Path, pinned: PinnedFile) -> bool:
    if not destination.is_file():
        return False
    try:
        verify(destination.read_bytes(), pinned)
    except VectorVerificationError:
        return False
    return True


def fetch(pinned: PinnedFile) -> bytes:
    """Download one pinned file and verify it before returning its bytes."""
    with urllib.request.urlopen(pinned.url, timeout=TIMEOUT_SECONDS) as response:
        payload: bytes = response.read()
    verify(payload, pinned)
    return payload


def main(argv: Sequence[str] | None = None) -> int:
    """Fetch every pinned vector file into the git-ignored vectors directory."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify already-downloaded files without contacting the network",
    )
    arguments = parser.parse_args(argv)

    failures = 0
    for pinned in PINNED_FILES:
        destination = DESTINATION / pinned.directory / pinned.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if _is_current(destination, pinned):
            print(f"ok       {pinned.label} (already verified)")
            continue
        if arguments.check:
            print(f"MISSING  {pinned.label}", file=sys.stderr)
            failures += 1
            continue
        try:
            payload = fetch(pinned)
        except (urllib.error.URLError, TimeoutError) as error:
            print(f"FAILED   {pinned.label}: {error}", file=sys.stderr)
            failures += 1
            continue
        except VectorVerificationError as error:
            print(f"REJECTED {error}", file=sys.stderr)
            failures += 1
            continue
        destination.write_bytes(payload)
        print(f"fetched  {pinned.label} ({pinned.size_bytes} bytes, sha256 verified)")

    if failures:
        print(f"\n{failures} file(s) unavailable or unverified", file=sys.stderr)
        return 1
    print(f"\nAll {len(PINNED_FILES)} pinned files verified in {DESTINATION.relative_to(ROOT)}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
