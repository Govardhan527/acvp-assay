"""Generators must satisfy the spec's domain constraints, not merely themselves.

This file exists because of one defect, and the defect is worth stating because
the shape of it recurs.

`safePrimes` keyGen drew its private key from [1, p-2] instead of [1, q-1] where
q = (p-1)/2. Generator 2 has order q, so g^x == g^(x mod q): an out-of-range x
produces a **perfectly valid public key**. The obvious test -- generate a pair,
then verify it -- passed every time, because y really was correct. key_ver was
right, key_gen was wrong, and the two agreed with each other. NIST rejected the
whole vector set; nothing local had complained.

The lesson generalises past this family. Wherever the runner *generates* a value
rather than reproducing a recorded one, the offline runner necessarily declines
the case, so the only judge is the server. A round-trip check is not enough
there: it proves the two halves agree, not that either is in spec. These tests
assert the domain constraint itself.

The exposure is bounded and worth naming: it is exactly the generators whose
arithmetic this project does by hand. Where `cryptography` generates the key --
ECDSA, RSA, KAS-ECC-SSC -- the library enforces its own ranges.
"""

from __future__ import annotations

import pytest

from acvp_assay.providers.kas_ffc import PythonKasFfc
from acvp_assay.providers.safe_primes import (
    GENERATOR,
    SAFE_PRIME_GROUPS,
    PythonSafePrimes,
)

#: Draws per group. The original defect put roughly half of all keys out of
#: range, so across six groups this is 24 independent chances to see it -- a
#: generator that wrong survives with probability 2**-24. Twelve draws cost four
#: seconds of gate time on the 4096-bit groups alone and bought nothing, which
#: is the wrong trade for a check this decisive.
DRAWS = 4


def subgroup_order(group: str) -> int:
    """q = (p-1)/2, the order of the subgroup generator 2 produces."""
    return (SAFE_PRIME_GROUPS[group] - 1) // 2


@pytest.mark.parametrize("group", sorted(SAFE_PRIME_GROUPS))
def test_safe_primes_keygen_stays_inside_the_subgroup_order(group: str) -> None:
    """The constraint NIST checks and no local check can see."""
    provider = PythonSafePrimes()
    order = subgroup_order(group)
    for _ in range(DRAWS):
        x, _ = provider.key_gen(group=group)
        value = int.from_bytes(x, "big")
        assert 1 <= value < order, f"x is outside [1, q-1] for {group}"


@pytest.mark.parametrize("group", sorted(SAFE_PRIME_GROUPS))
def test_kas_ffc_ephemeral_keys_stay_inside_the_subgroup_order(group: str) -> None:
    """The same arithmetic, so the same constraint and the same blind spot."""
    provider = PythonKasFfc()
    order = subgroup_order(group)
    for _ in range(DRAWS):
        private, _ = provider.generate(group=group)
        value = int.from_bytes(private, "big")
        assert 1 <= value < order, f"ephemeral private key is outside [1, q-1] for {group}"


@pytest.mark.parametrize("group", sorted(SAFE_PRIME_GROUPS))
def test_a_generated_public_key_is_still_the_matching_one(group: str) -> None:
    """The round trip, kept -- but it is the weaker of the two claims.

    This is the test that passed all along while the generator was wrong. It is
    worth keeping and worth labelling: it proves key_gen and key_ver agree, not
    that either satisfies the specification.
    """
    provider = PythonSafePrimes()
    x, y = provider.key_gen(group=group)
    assert provider.key_ver(group=group, x=x, y=y)
    assert pow(GENERATOR, int.from_bytes(x, "big"), SAFE_PRIME_GROUPS[group]) == int.from_bytes(
        y, "big"
    )


@pytest.mark.parametrize("group", sorted(SAFE_PRIME_GROUPS))
def test_a_public_key_from_an_out_of_range_private_key_still_verifies(group: str) -> None:
    """Prove the blind spot is real rather than asserted.

    If an out-of-range x produced a detectably wrong y, the original defect
    would have been caught locally. It does not, and this pins that: y is valid
    for x + q, which is why only the server could see the error.
    """
    prime = SAFE_PRIME_GROUPS[group]
    order = subgroup_order(group)
    out_of_range = (order + 7).to_bytes((prime.bit_length() + 7) // 8, "big")
    y = pow(GENERATOR, order + 7, prime).to_bytes((prime.bit_length() + 7) // 8, "big")
    assert PythonSafePrimes().key_ver(group=group, x=out_of_range, y=y)
    assert int.from_bytes(out_of_range, "big") >= order


@pytest.mark.parametrize("group", sorted(SAFE_PRIME_GROUPS))
def test_two_parties_reach_the_same_secret(group: str) -> None:
    provider = PythonKasFfc()
    a_private, a_public = provider.generate(group=group)
    b_private, b_public = provider.generate(group=group)
    assert provider.shared_secret(
        group=group, private_key=a_private, peer_public=b_public
    ) == provider.shared_secret(group=group, private_key=b_private, peer_public=a_public)


@pytest.mark.parametrize("group", sorted(SAFE_PRIME_GROUPS))
def test_the_prime_is_the_one_the_rfc_specifies(group: str) -> None:
    """A transcription error would fail every case in its group, not some.

    Fermat base 2 is decisive against a typo, and these are safe primes with
    p = 7 mod 8, so 2 is a quadratic residue and generates the order-q subgroup.
    """
    prime = SAFE_PRIME_GROUPS[group]
    assert prime.bit_length() == int("".join(c for c in group if c.isdigit()))
    assert prime % 8 == 7
    assert pow(2, prime - 1, prime) == 1
    assert pow(2, (prime - 1) // 2, prime) == 1
