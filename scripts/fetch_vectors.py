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
ECDSA_SIGGEN = "ECDSA-SigGen-FIPS186-5"
ECDSA_SIGVER = "ECDSA-SigVer-FIPS186-5"
ML_KEM = "ML-KEM-encapDecap-FIPS203"
ML_DSA_SIGVER = "ML-DSA-sigVer-FIPS204"
CMAC_AES = "CMAC-AES-1.0"
AES_ECB = "ACVP-AES-ECB-1.0"
AES_GMAC = "ACVP-AES-GMAC-1.0"
AES_KW = "ACVP-AES-KW-1.0"
AES_KWP = "ACVP-AES-KWP-1.0"
CTR_DRBG = "ctrDRBG-1.0"
CTR_DRBG_R1 = "ctrDRBG-SP800-90Ar1"
KDF_108 = "KDF-1.0"

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
    PinnedFile(
        directory=ECDSA_SIGGEN,
        name="prompt.json",
        size_bytes=987281,
        sha256="a07cfcf2e3bdbda1cbf82cefc6f38a2d0559ee8852b2f0276a200e0747b46744",
    ),
    PinnedFile(
        directory=ECDSA_SIGGEN,
        name="expectedResults.json",
        size_bytes=1057697,
        sha256="64ddfc8cdf1e4d693e888e40bab5d898aa4a6684812ed94371e90bb040559c6d",
    ),
    PinnedFile(
        directory=ECDSA_SIGVER,
        name="prompt.json",
        size_bytes=150759,
        sha256="2547cabd9a6006943ff611d4990fad18162b51a614cd2d7986769a3e94dee7e3",
    ),
    PinnedFile(
        directory=ECDSA_SIGVER,
        name="expectedResults.json",
        size_bytes=16027,
        sha256="c4f2e21e9c6391a5349a81237b5c508466ce05f0d6eb6dbcecb17b458a6c5171",
    ),
    PinnedFile(
        directory=ML_KEM,
        name="prompt.json",
        size_bytes=624189,
        sha256="998e22dfb12efb14ce9fdff911ca634b13612819a1806f25da69adba7e16db91",
    ),
    PinnedFile(
        directory=ML_KEM,
        name="expectedResults.json",
        size_bytes=190940,
        sha256="9089ec6ff2424da9f2782b89b2f831a329a3e28d6e5e24b802b78ff36ac61cdf",
    ),
    PinnedFile(
        directory=ML_DSA_SIGVER,
        name="prompt.json",
        size_bytes=3125947,
        sha256="e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e",
    ),
    PinnedFile(
        directory=ML_DSA_SIGVER,
        name="expectedResults.json",
        size_bytes=13956,
        sha256="e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6",
    ),
    PinnedFile(
        directory=CMAC_AES,
        name="prompt.json",
        size_bytes=4533505,
        sha256="e2c412bbe9a63640ceb490e38fbad809259b4829b28995995994567547bd2cec",
    ),
    PinnedFile(
        directory=CMAC_AES,
        name="expectedResults.json",
        size_bytes=61378,
        sha256="ec48d26649b963183f3ceefb4b4c74563eddb51ff3c44ef92029ca05d58b7bcf",
    ),
    PinnedFile(
        directory=AES_ECB,
        name="prompt.json",
        size_bytes=369982,
        sha256="b4ec2a6e7011a9d7fb453aef52b32872cc7509dda07b13b28237d9b8f56076e9",
    ),
    PinnedFile(
        directory=AES_ECB,
        name="expectedResults.json",
        size_bytes=343166,
        sha256="4893c2718529d4af5a10f10335118e5a462808a0857005440c52b1083d71da18",
    ),
    PinnedFile(
        directory=AES_GMAC,
        name="prompt.json",
        size_bytes=13084,
        sha256="6bdac25495398b2221191fb8e1cd0a8c54664b33b52984c49b6d539c5d6e2d66",
    ),
    PinnedFile(
        directory=AES_GMAC,
        name="expectedResults.json",
        size_bytes=4976,
        sha256="9eacc97af44ed0b58bc35217c689f49e24b9dcc3567126bd55038ebe164b1d43",
    ),
    PinnedFile(
        directory=AES_KW,
        name="prompt.json",
        size_bytes=5021125,
        sha256="3e0c5a5fb8da3b484e42d73528a6a6e87c9a4c5e6386bc5bb98bbfcaa27831f3",
    ),
    PinnedFile(
        directory=AES_KW,
        name="expectedResults.json",
        size_bytes=4100580,
        sha256="ff722dcbc986252c4de5d7df10da5d74e677765524bcdcb666dfc7f4f6c08f34",
    ),
    PinnedFile(
        directory=AES_KWP,
        name="prompt.json",
        size_bytes=4869914,
        sha256="c39175c5f2eab4168c1e8d5bd6d1658ce83590499dabbf0f6f33d6533d3f7bc1",
    ),
    PinnedFile(
        directory=AES_KWP,
        name="expectedResults.json",
        size_bytes=4001079,
        sha256="114774bb317bc6fdb2491fa41e1c5d3b2b27f23ccb4d2b004d8610abc5689751",
    ),
    PinnedFile(
        directory=CTR_DRBG,
        name="prompt.json",
        size_bytes=244292,
        sha256="35a2fda242abd3e8e9c6c89a2878ee1d4d499c48c7458d67025bc8b5ff361420",
    ),
    PinnedFile(
        directory=CTR_DRBG,
        name="expectedResults.json",
        size_bytes=264148,
        sha256="46608d7bbcaf0f6408a1905f81a77d3e2e90bfd5cee5a84dd78d4c51de1c6143",
    ),
    PinnedFile(
        directory=CTR_DRBG_R1,
        name="prompt.json",
        size_bytes=371608,
        sha256="7ddb75bdd25bcb6183102146872c0f97a5227603b2ea64c63771ffe2daf938ae",
    ),
    PinnedFile(
        directory=CTR_DRBG_R1,
        name="expectedResults.json",
        size_bytes=42956,
        sha256="c805df470563ec6e91413cde1a29b2574b7c33b67fd3a7bf3179b7ac26c77a6e",
    ),
    PinnedFile(
        directory=KDF_108,
        name="prompt.json",
        size_bytes=3429414,
        sha256="a97ac943f775fc249e258bc27a189075eb11e8c4029ae8eb39fd555671c610b8",
    ),
    PinnedFile(
        directory=KDF_108,
        name="expectedResults.json",
        size_bytes=3496097,
        sha256="bdba2cbbf68679db995c47e4bc8c53aa4c39c4a54e07c367450e4f91b83329e0",
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
