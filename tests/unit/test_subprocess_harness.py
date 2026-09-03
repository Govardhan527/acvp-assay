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
    """Write a looping harness script and return a provider that invokes it."""
    script = tmp_path / "harness.py"
    script.write_text(
        "import json, sys\n"
        "for _line in sys.stdin:\n"
        "    request = json.loads(_line)\n"
        + "\n".join("    " + piece for piece in body.splitlines())
        + '\n    sys.stdout.write("\\n")\n    sys.stdout.flush()\n'
    )
    return SubprocessAesGcmProvider([sys.executable, str(script)], timeout_seconds=2)


def responding(tmp_path: Path, literal: str) -> SubprocessAesGcmProvider:
    """Return a provider whose harness always prints the given literal."""
    return harness(tmp_path, f"sys.stdout.write({literal!r})")


def test_reference_harness_round_trips_encrypt_and_decrypt() -> None:
    """The shipped example satisfies the contract for both directions."""
    example = Path(__file__).resolve().parents[2] / "examples/reference_harness.py"
    provider = SubprocessAesGcmProvider([sys.executable, str(example)], timeout_seconds=5)

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
    provider = SubprocessAesGcmProvider([sys.executable, str(example)], timeout_seconds=5)
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


def test_a_one_shot_harness_still_works(tmp_path: Path) -> None:
    """A harness that reads stdin to EOF is detected and driven one case at a time.

    This is the easiest kind to write -- a shell script with `jq` naturally
    takes this shape -- so it stays supported even though a looping harness is
    both faster and the recommended contract. It cannot answer until its input
    closes, so the transport gives it an end-of-input rather than deadlocking.
    """
    script = tmp_path / "oneshot.py"
    script.write_text(
        "import json, sys\n"
        "request = json.loads(sys.stdin.read())\n"
        'print(json.dumps({"name": "one-shot", "libraryName": "l", '
        '"libraryVersion": "1", "backendName": "b", "backendVersion": "2"}))\n'
    )
    client = SubprocessAesGcmProvider([sys.executable, str(script)], timeout_seconds=3)

    first = client.metadata()
    second = client.metadata()

    assert first.name == "one-shot"
    assert second.name == "one-shot"
    client.close()


def test_a_looping_harness_is_kept_alive(tmp_path: Path) -> None:
    """A looping harness answers repeatedly from one process.

    Keeping it alive is the point: spawning per case costs about 75 ms here,
    and an implementation reached over PKCS#11 or a serial link would have to
    re-establish its session every time.
    """
    script = tmp_path / "loop.py"
    script.write_text(
        "import json, os, sys\n"
        "for _line in sys.stdin:\n"
        '    print(json.dumps({"name": str(os.getpid()), "libraryName": "l", '
        '"libraryVersion": "1", "backendName": "b", "backendVersion": "2"}), flush=True)\n'
    )
    client = SubprocessAesGcmProvider([sys.executable, str(script)], timeout_seconds=3)

    first = client.metadata()
    second = client.metadata()

    # Same pid across calls: one process served both.
    assert first.name == second.name
    client.close()


def test_a_persistent_harness_that_stops_answering_times_out(tmp_path: Path) -> None:
    """A wedged device fails its case rather than stalling the whole run.

    This is what --provider-timeout is for. The harness here answers the first
    request, so it is classified persistent, then goes silent.
    """
    script = tmp_path / "wedge.py"
    script.write_text(
        "import json, sys, time\n"
        "first = True\n"
        "for _line in sys.stdin:\n"
        "    if first:\n"
        '        print(json.dumps({"name": "w", "libraryName": "l", "libraryVersion": "1",'
        ' "backendName": "b", "backendVersion": "2"}), flush=True)\n'
        "        first = False\n"
        "    else:\n"
        "        time.sleep(60)\n"
    )
    client = SubprocessAesGcmProvider([sys.executable, str(script)], timeout_seconds=1)
    client.metadata()

    with pytest.raises(HarnessProtocolError, match="timed out"):
        client.metadata()
    client.close()


def test_a_harness_that_never_answers_times_out(tmp_path: Path) -> None:
    """Silence with and without an end-of-input is reported, not waited on forever."""
    script = tmp_path / "silent.py"
    script.write_text("import sys, time\nsys.stdin.read()\ntime.sleep(60)\n")
    client = SubprocessAesGcmProvider([sys.executable, str(script)], timeout_seconds=1)

    with pytest.raises(HarnessProtocolError, match="without answering"):
        client.metadata()
    client.close()


def test_writing_to_a_dead_harness_is_reported(tmp_path: Path) -> None:
    """A harness that exits without reading is a protocol failure, not a hang."""
    script = tmp_path / "dead.py"
    script.write_text("import sys\nsys.exit(0)\n")
    client = SubprocessAesGcmProvider([sys.executable, str(script)], timeout_seconds=5)

    with pytest.raises(HarnessProtocolError):
        client.metadata()
    client.close()


def test_the_client_closes_its_harness(tmp_path: Path) -> None:
    """Closing ends the process, and works as a context manager and when repeated."""
    script = tmp_path / "loop.py"
    script.write_text(
        "import json, sys\n"
        "for _line in sys.stdin:\n"
        '    print(json.dumps({"name": "l", "libraryName": "l", "libraryVersion": "1",'
        ' "backendName": "b", "backendVersion": "2"}), flush=True)\n'
    )
    with SubprocessAesGcmProvider([sys.executable, str(script)], timeout_seconds=3) as client:
        client.metadata()
        process = client._process
        assert process is not None and process.poll() is None

    assert process.poll() is not None
    client.close()  # idempotent


def test_a_harness_that_ignores_its_input_is_reported(tmp_path: Path) -> None:
    """Writing to a harness that has closed stdin is a protocol failure."""
    script = tmp_path / "deaf.py"
    script.write_text(
        "import json, os, sys\n"
        "os.close(0)\n"
        'print(json.dumps({"name": "d", "libraryName": "l", "libraryVersion": "1",'
        ' "backendName": "b", "backendVersion": "2"}), flush=True)\n'
        "import time; time.sleep(30)\n"
    )
    client = SubprocessAesGcmProvider([sys.executable, str(script)], timeout_seconds=3)
    client.metadata()

    with pytest.raises(HarnessProtocolError):
        for _ in range(200):
            client.metadata()
    client.close()


def test_a_one_shot_harness_that_goes_silent_times_out(tmp_path: Path) -> None:
    """Once classified one-shot, a later silent run still fails its case cleanly."""
    marker = tmp_path / "seen"
    script = tmp_path / "flaky.py"
    script.write_text(
        "import json, pathlib, sys, time\n"
        f"marker = pathlib.Path({str(marker)!r})\n"
        "sys.stdin.read()\n"
        "if marker.exists():\n"
        "    time.sleep(30)\n"
        "marker.write_text('x')\n"
        'print(json.dumps({"name": "f", "libraryName": "l", "libraryVersion": "1",'
        ' "backendName": "b", "backendVersion": "2"}))\n'
    )
    client = SubprocessAesGcmProvider([sys.executable, str(script)], timeout_seconds=2)
    client.metadata()

    with pytest.raises(HarnessProtocolError, match="timed out"):
        client.metadata()
    client.close()


def test_closing_a_harness_that_will_not_exit_kills_it(tmp_path: Path) -> None:
    """A harness that ignores end-of-input is killed rather than waited on."""
    script = tmp_path / "stubborn.py"
    script.write_text(
        "import json, signal, sys, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "for _line in sys.stdin:\n"
        '    print(json.dumps({"name": "s", "libraryName": "l", "libraryVersion": "1",'
        ' "backendName": "b", "backendVersion": "2"}), flush=True)\n'
        "time.sleep(60)\n"
    )
    client = SubprocessAesGcmProvider([sys.executable, str(script)], timeout_seconds=1)
    client.metadata()
    process = client._process
    assert process is not None

    client.close()

    assert process.poll() is not None


def test_blank_lines_from_a_harness_are_ignored(tmp_path: Path) -> None:
    """A harness may pad its output; only the response line counts.

    Worth tolerating because the natural shell implementation -- `echo` into a
    pipeline -- emits stray newlines easily, and refusing them would reject a
    harness that is otherwise answering correctly.
    """
    script = tmp_path / "chatty.py"
    script.write_text(
        "import json, sys\n"
        "for _line in sys.stdin:\n"
        '    print("", flush=True)\n'
        '    print("   ", flush=True)\n'
        '    print(json.dumps({"name": "c", "libraryName": "l", "libraryVersion": "1",'
        ' "backendName": "b", "backendVersion": "2"}), flush=True)\n'
    )
    client = SubprocessAesGcmProvider([sys.executable, str(script)], timeout_seconds=3)

    assert client.metadata().name == "c"
    client.close()
