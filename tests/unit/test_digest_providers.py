"""Tests for the hash and MAC providers, including the Monte Carlo chain."""

from __future__ import annotations

import hashlib

import pytest

from acvp_assay.providers.digest import (
    MCT_OUTER_ITERATIONS,
    HashlibHashProvider,
    HashlibMacProvider,
    HashProvider,
    MacProvider,
    monte_carlo,
    ssl_version_text,
)

# FIPS 180-4 published values, independent of this implementation.
SHA256_ABC = bytes.fromhex("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")
SHA256_EMPTY = bytes.fromhex("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
# RFC 4231 test case 1.
HMAC_RFC4231_1 = bytes.fromhex("B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7")


def test_hash_provider_matches_published_values() -> None:
    """SHA-256 digests agree with FIPS 180-4 known answers."""
    provider = HashlibHashProvider("SHA2-256")

    assert provider.digest(b"abc") == SHA256_ABC
    assert provider.digest(b"") == SHA256_EMPTY


@pytest.mark.parametrize(
    "algorithm",
    ["SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-512/224", "SHA2-512/256"],
)
def test_every_supported_hash_is_constructible(algorithm: str) -> None:
    """Each advertised SHA-2 variant produces a digest of the right width."""
    provider = HashlibHashProvider(algorithm)
    expected_bits = int(algorithm.rsplit("-", 1)[-1].split("/")[-1])

    assert len(provider.digest(b"abc")) == expected_bits // 8
    assert isinstance(provider, HashProvider)


def test_unsupported_hash_algorithm_is_rejected() -> None:
    """An algorithm outside the supported map fails loudly at construction."""
    with pytest.raises(ValueError, match="unsupported hash algorithm"):
        HashlibHashProvider("SHA3-256")


def test_mac_provider_matches_rfc4231_and_truncates() -> None:
    """HMAC agrees with RFC 4231 and honours macLen truncation."""
    provider = HashlibMacProvider("HMAC-SHA2-256")
    key = bytes.fromhex("0B" * 20)

    full = provider.mac(key=key, message=b"Hi There", mac_length_bits=256)
    truncated = provider.mac(key=key, message=b"Hi There", mac_length_bits=80)

    assert full == HMAC_RFC4231_1
    assert truncated == HMAC_RFC4231_1[:10]
    assert isinstance(provider, MacProvider)


def test_unsupported_mac_algorithm_is_rejected() -> None:
    """A MAC over an unsupported hash fails at construction."""
    with pytest.raises(ValueError, match="unsupported MAC algorithm"):
        HashlibMacProvider("HMAC-SHA3-256")


@pytest.mark.parametrize("mac_length_bits", [0, -8, 12])
def test_invalid_mac_lengths_are_rejected(mac_length_bits: int) -> None:
    """macLen must be a positive whole number of bytes."""
    provider = HashlibMacProvider("HMAC-SHA2-256")

    with pytest.raises(ValueError, match="positive multiple of 8"):
        provider.mac(key=b"k", message=b"m", mac_length_bits=mac_length_bits)


def test_mac_length_beyond_the_digest_is_rejected() -> None:
    """A truncation longer than the digest cannot be satisfied."""
    provider = HashlibMacProvider("HMAC-SHA2-256")

    with pytest.raises(ValueError, match="exceeds"):
        provider.mac(key=b"k", message=b"m", mac_length_bits=512)


def test_standard_monte_carlo_follows_the_specified_chain() -> None:
    """The standard chain hashes A||B||C untruncated, feeding the seed forward."""
    seed = b"seed-value"

    outputs = monte_carlo(seed, lambda m: hashlib.sha256(m).digest(), alternate=False)

    assert len(outputs) == MCT_OUTER_ITERATIONS
    # Recompute only the first outer iteration independently.
    a = b = c = seed
    for _ in range(1000):
        current = hashlib.sha256(a + b + c).digest()
        a, b, c = b, c, current
    assert outputs[0] == c


def test_alternate_monte_carlo_normalises_to_the_initial_seed_length() -> None:
    """The alternate chain truncates or zero-pads every message to the seed width.

    The width is the *original* seed's, captured once: later iterations start
    from a one-digest seed and must pad up to it rather than shrink.
    """
    seed = bytes(range(64))

    outputs = monte_carlo(seed, lambda m: hashlib.sha256(m).digest(), alternate=True)

    seen_lengths: set[int] = set()

    def recording_digest(message: bytes) -> bytes:
        seen_lengths.add(len(message))
        return hashlib.sha256(message).digest()

    monte_carlo(seed, recording_digest, alternate=True)

    assert len(outputs) == MCT_OUTER_ITERATIONS
    assert seen_lengths == {len(seed)}


def test_alternate_and_standard_chains_differ() -> None:
    """The two variants are genuinely different algorithms, not aliases."""
    seed = bytes(range(64))

    standard = monte_carlo(seed, lambda m: hashlib.sha256(m).digest(), alternate=False)
    alternate = monte_carlo(seed, lambda m: hashlib.sha256(m).digest(), alternate=True)

    assert standard != alternate


def test_provider_metadata_identifies_the_implementation() -> None:
    """Reports attribute digests to hashlib and its OpenSSL build."""
    metadata = HashlibHashProvider("SHA2-256").metadata()

    assert metadata.name == "hashlib-sha2-256"
    assert metadata.library_name == "hashlib"
    assert metadata.backend_version == ssl_version_text()
