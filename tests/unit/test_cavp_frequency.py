"""Offline tests for the CAVP certificate frequency counter.

None of these touch the network. What is worth testing here is the one piece of
judgement in the script: the map from a CAVP certificate's display name onto the
ACVP registry name that would have to be implemented to test it. Get that wrong
and the measured build order is wrong in a way no later step would catch.

The cases below are display names taken verbatim from active certificates.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load_module() -> object:
    """Import scripts/cavp_frequency.py, which is not part of the package."""
    spec = importlib.util.spec_from_file_location(
        "cavp_frequency", ROOT / "scripts/cavp_frequency.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["cavp_frequency"] = module
    spec.loader.exec_module(module)
    return module


cavp_frequency = _load_module()
registry_name = cavp_frequency.registry_name  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("display", "expected"),
    [
        # An operation qualifier is not part of the registry name: a module
        # validating four RSA operations still needs exactly one ACVP name.
        ("RSA SigGen (FIPS186-4)", "RSA"),
        ("RSA SigVer (FIPS186-5)", "RSA"),
        ("ECDSA KeyGen (FIPS186-4)", "ECDSA"),
        ("AES-XTS Testing Revision 2.0", "ACVP-AES-XTS"),
        ("KAS-ECC-SSC Sp800-56Ar3", "KAS-ECC-SSC"),
        ("KDA HKDF Sp800-56Cr1", "KDA"),
        # The MAC families invert their name between the two programmes.
        ("AES-CMAC", "CMAC-AES"),
        ("TDES-CMAC", "CMAC-TDES"),
        # Every DRBG spells its name differently from the registry.
        ("Counter DRBG", "ctrDRBG"),
        ("Hash DRBG", "hashDRBG"),
        ("HMAC DRBG", "hmacDRBG"),
        # Nine component KDFs share the single registry name kdf-components,
        # while the two TLS versions are registry names in their own right.
        ("KDF SSH", "kdf-components"),
        ("KDF ANS 9.42", "kdf-components"),
        ("KDF IKEv2", "kdf-components"),
        ("TLS v1.2 KDF RFC7627", "TLS-v1.2"),
        ("TLS v1.3 KDF", "TLS-v1.3"),
        # SP800-108r1 added KMAC as a mode of KDF, which is not the KMAC name.
        ("KDF SP800-108", "KDF"),
        ("KDF KMAC Sp800-108r1", "KDF"),
        ("KMAC-128", "KMAC-128"),
        # Digests and HMACs already agree between the programmes.
        ("SHA2-512/256", "SHA2-512/256"),
        ("HMAC-SHA3-256", "HMAC-SHA3-256"),
        ("SHAKE-128", "SHAKE-128"),
        # Prefix matching must not swallow a longer, distinct family.
        ("Safe Primes Key Generation", "safePrimes"),
        ("Deterministic ECDSA SigGen (FIPS186-5)", "DetECDSA"),
        ("KAS-IFC-SSC Sp800-56Br2", "KAS-IFC-SSC"),
        ("KTS-IFC Sp800-56Br2", "KTS-IFC"),
    ],
)
def test_a_display_name_maps_to_its_registry_name(display: str, expected: str) -> None:
    assert registry_name(display) == expected


def test_an_unknown_display_name_is_reported_rather_than_guessed() -> None:
    """Silently dropping a name would undercount it, so None must come back."""
    assert registry_name("Some Algorithm Nobody Has Implemented") is None


def test_the_dead_set_is_only_three_key_tdes() -> None:
    """Anything else set aside as dead would quietly bias the ranking."""
    dead = cavp_frequency.DEAD  # type: ignore[attr-defined]
    assert all("TDES" in name for name in dead)
    assert len(dead) == 14


# --- the trend column ------------------------------------------------------

trend = cavp_frequency.trend  # type: ignore[attr-defined]
TREND = cavp_frequency.TREND  # type: ignore[attr-defined]
TRENDS = cavp_frequency.TRENDS  # type: ignore[attr-defined]


def test_the_trend_vocabulary_is_closed() -> None:
    """Four values, each saying something different about what a count means."""
    assert TRENDS == ("stable", "decaying", "mandated", "dead")
    assert {value for value, _ in TREND.values()} <= set(TRENDS) - {"stable"}


def test_every_trend_names_the_standard_behind_it() -> None:
    """A trend without its source would be the claim this column exists to stop making."""
    for name, (_, source) in TREND.items():
        assert source.strip(), f"{name} has a trend and no source"


def test_the_ranks_a_standard_contradicts_carry_their_trend() -> None:
    """The three caveats the prose used to hold alone."""
    assert trend("DSA") == "decaying"
    assert trend("ML-KEM") == trend("ML-DSA") == "mandated"
    assert all(trend(name) == "dead" for name in cavp_frequency.DEAD)  # type: ignore[attr-defined]
    assert trend("SHA2-256") == "stable"


def test_the_published_table_carries_the_scripts_trend_on_every_row() -> None:
    """Someone generating capability files reads the column, so it must agree with its source."""
    document = (ROOT / "docs/algorithm-frequency.md").read_text(encoding="utf-8")
    rows = [line for line in document.splitlines() if line.startswith("| `")]
    assert rows, "the frequency table is missing"
    for row in rows:
        cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
        name = cells[0].strip("`")
        assert len(cells) == 7, f"{name} has no trend column"
        assert cells[6] == trend(name), f"{name}: table says {cells[6]}, script says {trend(name)}"
