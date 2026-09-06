"""AES-CBC-CS1, -CS2 and -CS3: one algorithm and three orderings.

The three registry names run identical cryptography and differ only in whether
the last two ciphertext blocks are written in reverse order. Reading them as
three algorithms is the expensive mistake, so the orderings are pinned against
each other here rather than each against a hardcoded answer.
"""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from acvp_assay.providers.aes_cs import (
    BLOCK,
    CS1,
    CS2,
    CS3,
    SUPPORTED,
    CryptographyAesCs,
    SubprocessAesCs,
    swaps,
)

KEY = bytes(range(16))
IV = bytes(range(16, 32))


def provider() -> CryptographyAesCs:
    return CryptographyAesCs()


@pytest.mark.parametrize(
    ("algorithm", "partial", "expected"),
    [
        (CS1, True, False),
        (CS1, False, False),
        (CS2, True, True),
        (CS2, False, False),
        (CS3, True, True),
        (CS3, False, True),
    ],
)
def test_only_cs2_depends_on_whether_the_last_block_is_partial(
    algorithm: str, partial: bool, expected: bool
) -> None:
    assert swaps(algorithm, partial=partial) is expected


@pytest.mark.parametrize("algorithm", SUPPORTED)
@pytest.mark.parametrize("length", [16, 17, 31, 32, 33, 47, 64])
def test_a_payload_round_trips(algorithm: str, length: int) -> None:
    payload = bytes((index * 11 + 5) % 256 for index in range(length))
    encrypted = provider().transform(
        algorithm=algorithm, key=KEY, iv=IV, data=payload, encrypt=True
    )
    assert len(encrypted) == length
    assert (
        provider().transform(algorithm=algorithm, key=KEY, iv=IV, data=encrypted, encrypt=False)
        == payload
    )


@pytest.mark.parametrize("length", [32, 48, 64])
def test_cs1_and_cs2_agree_when_nothing_is_partial(length: int) -> None:
    """CS2 only reorders a partial final block, so a whole payload is CS1."""
    payload = bytes(range(length))
    assert provider().transform(
        algorithm=CS1, key=KEY, iv=IV, data=payload, encrypt=True
    ) == provider().transform(algorithm=CS2, key=KEY, iv=IV, data=payload, encrypt=True)


@pytest.mark.parametrize("length", [17, 33, 47])
def test_cs2_and_cs3_agree_when_the_last_block_is_partial(length: int) -> None:
    payload = bytes(range(length))
    assert provider().transform(
        algorithm=CS2, key=KEY, iv=IV, data=payload, encrypt=True
    ) == provider().transform(algorithm=CS3, key=KEY, iv=IV, data=payload, encrypt=True)


@pytest.mark.parametrize("length", [32, 48])
def test_cs3_reorders_where_cs1_does_not(length: int) -> None:
    """A whole payload separates CS3 from the other two, which is the only
    case where CS3's 'always' is visible."""
    payload = bytes(range(length))
    one = provider().transform(algorithm=CS1, key=KEY, iv=IV, data=payload, encrypt=True)
    three = provider().transform(algorithm=CS3, key=KEY, iv=IV, data=payload, encrypt=True)
    assert one != three
    assert one[: -BLOCK * 2] == three[: -BLOCK * 2]
    assert one[-BLOCK * 2 :] == three[-BLOCK:] + three[-BLOCK * 2 : -BLOCK]


@pytest.mark.parametrize("algorithm", SUPPORTED)
def test_one_block_is_plain_cbc_because_there_is_nothing_to_steal(algorithm: str) -> None:
    payload = bytes(range(BLOCK))
    answers = {
        name: provider().transform(algorithm=name, key=KEY, iv=IV, data=payload, encrypt=True)
        for name in SUPPORTED
    }
    assert len(set(answers.values())) == 1
    assert len(answers[algorithm]) == BLOCK


def test_a_payload_shorter_than_a_block_is_refused() -> None:
    """Stealing needs something to steal from; ACVP never issues one."""
    with pytest.raises(ValueError, match="at least one full block"):
        provider().transform(algorithm=CS1, key=KEY, iv=IV, data=b"\x00" * 8, encrypt=True)


def test_an_unknown_variant_is_refused() -> None:
    with pytest.raises(ValueError, match="unsupported ciphertext-stealing mode"):
        provider().transform(
            algorithm="ACVP-AES-CBC-CS4", key=KEY, iv=IV, data=b"\x00" * 32, encrypt=True
        )


class _RecordingHarness(SubprocessAesCs):
    """A harness client that records the request instead of running one."""

    def __init__(self) -> None:  # noqa: D107 - deliberately skips the real setup
        self.requests: list[dict[str, object]] = []

    def invoke(self, request: Mapping[str, object]) -> Mapping[str, object]:
        self.requests.append(dict(request))
        return {"out": "AA" * 32}


def test_the_wire_names_one_operation_for_all_three_variants() -> None:
    """One operation, with the variant in `algorithm`.

    Three operations would make a harness implement the same cryptography three
    times and choose the ordering in three places.
    """
    harness = _RecordingHarness()
    for algorithm in SUPPORTED:
        harness.transform(algorithm=algorithm, key=KEY, iv=IV, data=bytes(32), encrypt=True)
    assert {request["operation"] for request in harness.requests} == {"cbc-cs"}
    assert [request["algorithm"] for request in harness.requests] == list(SUPPORTED)
    assert harness.requests[0]["direction"] == "encrypt"


def test_the_provider_identifies_its_backend() -> None:
    """The report names what answered, which is the point of recording it."""
    metadata = provider().metadata()
    assert metadata.name == "cryptography-aes-cbc-cs"
    assert metadata.library_name == "cryptography"
    assert metadata.backend_name == "OpenSSL"
    assert metadata.library_version
