"""AES-CFB8 and AES-CFB1: the modes whose feedback is smaller than a block.

The Monte Carlo chain for these is a different algorithm from the whole-block
one, not a parameterisation of it, and CFB1 is the only mode in the project
whose payload is measured in bits. Both facts are load-bearing, so both are
pinned here.
"""

from __future__ import annotations

from collections.abc import Mapping

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from acvp_assay.providers.aes_block import (
    BLOCK_BITS,
    CFB1,
    CFB8,
    CHAINING_MODES,
    SEGMENT_BITS,
    CryptographyAesBlockProvider,
    SubprocessAesBlockProvider,
    _from_bits,
    _to_bits,
)

KEY = bytes(range(16))
IV = bytes(range(16, 32))


def provider() -> CryptographyAesBlockProvider:
    return CryptographyAesBlockProvider()


def test_a_bit_string_packs_most_significant_bit_first() -> None:
    """ACVP carries a one-bit payload of 1 as ``80``, never as ``01``.

    Packing the other way round produces answers that are right about the
    cipher and wrong about the encoding, which the server rejects and an
    offline round trip does not notice.
    """
    assert _from_bits([1]) == b"\x80"
    assert _from_bits([0, 1]) == b"\x40"
    assert _to_bits(b"\x80", 1) == [1]
    assert _to_bits(b"\x40", 2) == [0, 1]


@pytest.mark.parametrize("count", [1, 2, 7, 8, 9, 15, 16, 31])
def test_cfb1_round_trips_at_any_bit_length(count: int) -> None:
    """Decrypting a CFB1 ciphertext returns the bits that went in."""
    payload = _from_bits([(index * 7 + 3) % 2 for index in range(count)])
    encrypted = provider().transform(
        algorithm=CFB1, key=KEY, iv=IV, data=payload, encrypt=True, payload_bits=count
    )
    decrypted = provider().transform(
        algorithm=CFB1, key=KEY, iv=IV, data=encrypted, encrypt=False, payload_bits=count
    )
    assert _to_bits(decrypted, count) == _to_bits(payload, count)


def test_cfb1_answers_only_the_declared_bits() -> None:
    """A shorter payloadLen must change the answer, not just trim it.

    This is the difference the response builder missed: encrypting the whole
    padded byte agrees with a byte-oriented reading of the case and disagrees
    with NIST.
    """
    one = provider().transform(
        algorithm=CFB1, key=KEY, iv=IV, data=b"\x80", encrypt=True, payload_bits=1
    )
    eight = provider().transform(
        algorithm=CFB1, key=KEY, iv=IV, data=b"\x80", encrypt=True, payload_bits=8
    )
    assert one != eight
    assert _to_bits(one, 1) == _to_bits(eight, 1)


def test_cfb8_agrees_with_the_library_mode() -> None:
    """CFB8 is a library mode, so the provider must not diverge from it."""
    payload = bytes(range(32))
    cipher = Cipher(algorithms.AES(KEY), modes.CFB8(IV)).encryptor()
    assert (
        provider().transform(algorithm=CFB8, key=KEY, iv=IV, data=payload, encrypt=True)
        == cipher.update(payload) + cipher.finalize()
    )


@pytest.mark.parametrize("algorithm", [CFB8, CFB1])
def test_a_segment_mode_declares_a_monte_carlo_test(algorithm: str) -> None:
    assert CHAINING_MODES[algorithm] is True
    assert BLOCK_BITS % SEGMENT_BITS[algorithm] == 0


@pytest.mark.parametrize("algorithm", [CFB8, CFB1])
def test_the_segment_chain_advances_key_and_iv_every_iteration(algorithm: str) -> None:
    """A chain that reuses its key would still return 100 quads."""
    quads = provider().monte_carlo(algorithm=algorithm, key=KEY, iv=IV, data=b"\x00", encrypt=True)
    assert len(quads) == 100
    keys = [key for key, _, _, _ in quads]
    ivs = [iv for _, iv, _, _ in quads]
    assert len(set(keys)) == len(keys)
    assert len(set(ivs)) == len(ivs)
    assert keys[0] == KEY
    assert ivs[0] == IV


def test_ctr_still_refuses_a_monte_carlo_chain() -> None:
    """Adding two segment modes must not loosen the mode that has no chain."""
    with pytest.raises(ValueError, match="no Monte Carlo test"):
        provider().monte_carlo(
            algorithm="ACVP-AES-CTR", key=KEY, iv=IV, data=b"\x00" * 16, encrypt=True
        )


class _RecordingHarness(SubprocessAesBlockProvider):
    """A harness client that records the request instead of running one."""

    def __init__(self) -> None:  # noqa: D107 - deliberately skips the real setup
        self.requests: list[dict[str, object]] = []

    def invoke(self, request: Mapping[str, object]) -> Mapping[str, object]:
        self.requests.append(dict(request))
        if request["operation"] == "block-mct":
            return {"resultsArray": []}
        return {"out": "80"}


def test_the_wire_carries_payload_len_only_when_there_is_one() -> None:
    """Sending it for every mode would change the input of existing harnesses.

    A byte-oriented mode already says its length in the hex, so the field would
    be redundant there -- and a harness written against the old contract would
    start seeing a key it does not expect.
    """
    harness = _RecordingHarness()
    harness.transform(algorithm=CFB1, key=KEY, iv=IV, data=b"\x80", encrypt=True, payload_bits=1)
    harness.transform(algorithm=CFB8, key=KEY, iv=IV, data=b"\x00", encrypt=True)
    harness.monte_carlo(algorithm=CFB1, key=KEY, iv=IV, data=b"\x80", encrypt=True, payload_bits=1)
    harness.monte_carlo(algorithm=CFB8, key=KEY, iv=IV, data=b"\x00", encrypt=True)
    assert [request.get("payloadLen") for request in harness.requests] == [1, None, 1, None]
