"""Tests for the external-harness provider and its wire contract."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from acvp_assay.providers.subprocess_harness import (
    HarnessProtocolError,
    SubprocessAesGcmProvider,
)

KEY = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
IV = bytes.fromhex("101112131415161718191A1B")


def harness(tmp_path: Path, body: str) -> SubprocessAesGcmProvider:
    """Write a one-shot harness script and return a provider that invokes it."""
    script = tmp_path / "harness.py"
    script.write_text(f"import json, sys\nrequest = json.loads(sys.stdin.read())\n{body}\n")
    return SubprocessAesGcmProvider([sys.executable, str(script)])


def responding(tmp_path: Path, literal: str) -> SubprocessAesGcmProvider:
    """Return a provider whose harness always prints the given literal."""
    return harness(tmp_path, f"sys.stdout.write({literal!r})")


def test_reference_harness_round_trips_encrypt_and_decrypt() -> None:
    """The shipped example satisfies the contract for both directions."""
    example = Path(__file__).resolve().parents[2] / "examples/reference_harness.py"
    provider = SubprocessAesGcmProvider([sys.executable, str(example)])

    encrypted = provider.encrypt(
        key=KEY, iv=IV, plaintext=b"payload", aad=b"context", tag_length_bits=128
    )
    assert encrypted.ciphertext is not None
    assert encrypted.tag is not None

    decrypted = provider.decrypt(
        key=KEY,
        iv=IV,
        ciphertext=encrypted.ciphertext,
        aad=b"context",
        tag=encrypted.tag,
    )
    assert decrypted.plaintext == b"payload"

    metadata = provider.metadata()
    assert metadata.name == "reference-harness"
    assert metadata.backend_name == "OpenSSL"


def test_reference_harness_reports_a_rejected_tag_as_invalid_tag() -> None:
    """A corrupted tag surfaces as InvalidTag, matching the in-process provider."""
    example = Path(__file__).resolve().parents[2] / "examples/reference_harness.py"
    provider = SubprocessAesGcmProvider([sys.executable, str(example)])
    encrypted = provider.encrypt(key=KEY, iv=IV, plaintext=b"payload", aad=b"", tag_length_bits=128)
    assert encrypted.ciphertext is not None
    assert encrypted.tag is not None
    forged = bytes([encrypted.tag[0] ^ 0x01]) + encrypted.tag[1:]

    with pytest.raises(InvalidTag):
        provider.decrypt(key=KEY, iv=IV, ciphertext=encrypted.ciphertext, aad=b"", tag=forged)


def test_empty_command_is_rejected() -> None:
    """A provider cannot be built without something to invoke."""
    with pytest.raises(ValueError, match="must not be empty"):
        SubprocessAesGcmProvider([])


def test_from_command_string_splits_shell_style() -> None:
    """A command string becomes an argument vector."""
    provider = SubprocessAesGcmProvider.from_command_string("python3 my_harness.py --flag")

    assert provider.command == ["python3", "my_harness.py", "--flag"]


def test_missing_command_is_a_bounded_error() -> None:
    """A command that does not exist fails as an invalid case, not a crash."""
    provider = SubprocessAesGcmProvider(["definitely-not-a-real-command-xyz"])

    with pytest.raises(HarnessProtocolError, match="not found"):
        provider.metadata()


def test_non_executable_command_is_a_bounded_error(tmp_path: Path) -> None:
    """A harness without the execute bit reports a clear permission failure."""
    script = tmp_path / "not-executable.sh"
    script.write_text("#!/bin/sh\necho {}\n")
    script.chmod(0o644)
    provider = SubprocessAesGcmProvider([str(script)])

    with pytest.raises(HarnessProtocolError, match="not executable"):
        provider.metadata()


def test_timeout_is_a_bounded_error(tmp_path: Path) -> None:
    """A hung harness is abandoned rather than blocking the run forever."""
    script = tmp_path / "slow.py"
    script.write_text("import time\ntime.sleep(30)\n")
    provider = SubprocessAesGcmProvider([sys.executable, str(script)], timeout_seconds=0.2)

    with pytest.raises(HarnessProtocolError, match="timed out"):
        provider.metadata()


def test_nonzero_exit_is_reported_without_leaking_output(tmp_path: Path) -> None:
    """A crashing harness yields a status-only diagnostic."""
    provider = harness(tmp_path, "sys.exit(3)")

    with pytest.raises(HarnessProtocolError, match="exited with status 3"):
        provider.metadata()


@pytest.mark.parametrize(
    ("literal", "message"),
    [
        ("not json at all", "not valid JSON"),
        ("[1, 2, 3]", "not an object"),
    ],
)
def test_malformed_responses_are_rejected(tmp_path: Path, literal: str, message: str) -> None:
    """Output that is not a JSON object is a contract violation."""
    provider = responding(tmp_path, literal)

    with pytest.raises(HarnessProtocolError, match=message):
        provider.metadata()


def test_generic_harness_error_does_not_become_invalid_tag(tmp_path: Path) -> None:
    """Only the exact authentication-failure string means a rejected tag."""
    provider = responding(tmp_path, '{"error": "something else broke"}')

    with pytest.raises(HarnessProtocolError, match="reported a failure"):
        provider.decrypt(key=KEY, iv=IV, ciphertext=b"", aad=b"", tag=b"")


def test_harness_error_text_is_not_echoed(tmp_path: Path) -> None:
    """A harness error message never reaches the caller verbatim.

    Harness errors can quote key material, and diagnostics end up in reports
    that are shared as evidence.
    """
    provider = responding(tmp_path, '{"error": "key 00112233445566778899AABBCCDDEEFF failed"}')

    with pytest.raises(HarnessProtocolError) as captured:
        provider.metadata()

    assert "00112233445566778899AABBCCDDEEFF" not in str(captured.value)


def test_metadata_requires_every_identifying_field(tmp_path: Path) -> None:
    """Partial metadata is refused: attribution is the point of the field."""
    provider = responding(tmp_path, '{"name": "x", "libraryName": "y"}')

    with pytest.raises(HarnessProtocolError, match="libraryVersion"):
        provider.metadata()


@pytest.mark.parametrize(
    ("literal", "message"),
    [
        ('{"tag": "AABB"}', "missing 'ct'"),
        ('{"ct": 7, "tag": "AABB"}', "non-string 'ct'"),
        ('{"ct": "ZZZZ", "tag": "AABB"}', "invalid hex in 'ct'"),
    ],
)
def test_encrypt_response_fields_are_validated(tmp_path: Path, literal: str, message: str) -> None:
    """A malformed encrypt response names the offending field."""
    provider = responding(tmp_path, literal)

    with pytest.raises(HarnessProtocolError, match=message):
        provider.encrypt(key=KEY, iv=IV, plaintext=b"", aad=b"", tag_length_bits=128)


def test_request_encodes_empty_values_as_empty_hex(tmp_path: Path) -> None:
    """Zero-length payload and AAD are real NIST cases and must round-trip."""
    provider = harness(
        tmp_path,
        'assert request["pt"] == "", request\n'
        'assert request["aad"] == "", request\n'
        'assert request["tagLen"] == 32, request\n'
        'sys.stdout.write(\'{"ct": "", "tag": "AABBCCDD"}\')',
    )

    values = provider.encrypt(key=KEY, iv=IV, plaintext=b"", aad=b"", tag_length_bits=32)

    assert values.ciphertext == b""
    assert values.tag == bytes.fromhex("AABBCCDD")


def test_request_hex_is_uppercase(tmp_path: Path) -> None:
    """Hex on the wire matches ACVP's uppercase convention."""
    provider = harness(
        tmp_path,
        'assert request["key"] == "000102030405060708090A0B0C0D0E0F", request\n'
        'sys.stdout.write(\'{"pt": "00"}\')',
    )

    assert provider.decrypt(key=KEY, iv=IV, ciphertext=b"", aad=b"", tag=b"").plaintext == b"\x00"
