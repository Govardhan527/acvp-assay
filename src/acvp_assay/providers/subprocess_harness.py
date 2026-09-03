"""Provider that delegates AES-GCM operations to an external program.

The external program — the "harness" — reads one JSON request on stdin and
writes one JSON response on stdout. That is the entire contract, so a harness
can be written in any language and can front an HSM, a smartcard, an embedded
device, or a library this project cannot link against.

Requests::

    {"operation": "metadata"}
    {"operation": "encrypt", "key": HEX, "iv": HEX, "aad": HEX, "pt": HEX, "tagLen": 128}
    {"operation": "decrypt", "key": HEX, "iv": HEX, "aad": HEX, "ct": HEX, "tag": HEX}

Responses::

    {"name": ..., "libraryName": ..., "libraryVersion": ...,
     "backendName": ..., "backendVersion": ...}
    {"ct": HEX, "tag": HEX}
    {"pt": HEX}
    {"error": "authentication failed"}

Hex is uppercase on the wire and either case is accepted on the way in; empty
byte strings are the empty string, which real vectors do use for zero-length
payloads and AAD.

``{"error": "unsupported"}`` lets a harness decline a case it does not
implement -- a curve, parameter set, or mode it lacks -- which is reported
UNSUPPORTED rather than as a failure. Capability is the implementation's to
declare, not this runner's to assume.

``{"error": "authentication failed"}`` is the one error the caller must be able
to state, because a rejected tag is a *correct* outcome for roughly a third of
NIST's decrypt cases. It is translated into the same ``InvalidTag`` the
in-process provider raises, so verdict handling upstream is identical for every
provider. Any other error becomes a bounded invalid-case failure.

The harness is invoked once per operation. That keeps the contract trivial to
implement — read stdin, write stdout, exit — at the cost of one process spawn
per case; a persistent mode can be added later without changing the wire format.

The harness's stderr is inherited rather than captured, so a developer sees
diagnostics live while nothing from it can reach the machine-readable report.
That matters because a crashing harness may print key material, and reports are
shared as evidence.
"""

from __future__ import annotations

import json
import select
import shlex
import subprocess
import time
from collections.abc import Mapping, Sequence
from typing import Self

from cryptography.exceptions import InvalidTag

from acvp_assay.models import AesGcmValues, ProviderMetadata

_POLL_SECONDS = 0.2
_PROBE_SECONDS = 5.0
DEFAULT_TIMEOUT_SECONDS = 30.0
AUTHENTICATION_FAILED = "authentication failed"
UNSUPPORTED = "unsupported"

_METADATA_FIELDS = (
    ("name", "name"),
    ("libraryName", "library_name"),
    ("libraryVersion", "library_version"),
    ("backendName", "backend_name"),
    ("backendVersion", "backend_version"),
)


class HarnessUnsupportedError(Exception):
    """The harness declined a case it does not implement.

    Deliberately not a ``ValueError``: an implementation saying "I do not
    support this curve/parameter set" is a coverage statement, not a failure,
    and must be reported UNSUPPORTED rather than as an errored case.
    """


class HarnessProtocolError(ValueError):
    """The external harness violated the request/response contract.

    Deriving from ``ValueError`` is deliberate: the runner already classifies
    a provider ``ValueError`` as a bounded invalid-case error, so a broken
    harness degrades into a reported case rather than a crashed run.
    """


def _encode(value: bytes) -> str:
    return value.hex().upper()


def _decode(document: Mapping[str, object], key: str) -> bytes:
    if key not in document:
        raise HarnessProtocolError(f"harness response is missing {key!r}")
    value = document[key]
    if not isinstance(value, str):
        raise HarnessProtocolError(f"harness returned a non-string {key!r}")
    try:
        return bytes.fromhex(value)
    except ValueError:
        raise HarnessProtocolError(f"harness returned invalid hex in {key!r}") from None


def _reap(process: subprocess.Popen[str], timeout_seconds: float) -> None:
    """Wait briefly for a finished harness, then kill it.

    An unbounded ``wait`` here would undo the timeout that just fired: a
    harness that stops answering usually also declines to exit, and the run
    would stall in the cleanup instead of the request.
    """
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _read_line(process: subprocess.Popen[str], timeout_seconds: float) -> str | None:
    """Read one response line, or None if nothing arrived before the deadline.

    The read is polled rather than blocking so a wedged implementation cannot
    hang the run -- that is what ``--provider-timeout`` is for. A device that
    stops answering is a result to report, not a reason to stall forever.
    """
    assert process.stdout is not None  # noqa: S101
    deadline = time.monotonic() + timeout_seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        if not select.select([process.stdout], [], [], min(remaining, _POLL_SECONDS))[0]:
            continue
        line: str = process.stdout.readline()
        if line == "":
            status = process.poll()
            raise HarnessProtocolError(
                f"harness exited with status {status}" if status else "harness closed its output"
            )
        if line.strip():
            return line


def decode_mct_quads(response: Mapping[str, object]) -> list[tuple[bytes, bytes, bytes, bytes]]:
    """Decode a Monte Carlo ``resultsArray`` of key, IV, input and output."""
    entries = response.get("resultsArray")
    if not isinstance(entries, list):
        raise HarnessProtocolError("harness returned no 'resultsArray' for the Monte Carlo chain")
    quads: list[tuple[bytes, bytes, bytes, bytes]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise HarnessProtocolError(f"harness returned a non-object at resultsArray[{index}]")
        try:
            quads.append(
                tuple(  # type: ignore[arg-type]
                    bytes.fromhex(str(entry.get(name, ""))) for name in ("key", "iv", "in", "out")
                )
            )
        except ValueError:
            raise HarnessProtocolError(
                f"harness returned invalid hex at resultsArray[{index}]"
            ) from None
    return quads


class HarnessClient:
    """Speaks newline-delimited JSON to a long-lived external command.

    The harness is started once and kept alive: one JSON request per line on
    its stdin, one JSON response per line on its stdout, until stdin closes.

    That the process persists is the whole design. Spawning per case costs
    about 75 ms here, which is roughly fifty times the work itself and would
    add nine minutes to a single AES key wrap set. Worse, an implementation
    reached over PKCS#11, a serial link or a network session would have to
    re-establish that session for every case, which for an HSM means a login
    per case. Vendors are the reason: the tool exists to reach implementations
    that cannot be linked against, and those are exactly the ones for which
    setup is expensive.

    The loop a harness needs is five lines in any language::

        for line in sys.stdin:
            request = json.loads(line)
            print(json.dumps(handle(request)), flush=True)

    ``flush`` matters. A harness that buffers its stdout will appear to hang.
    """

    def __init__(
        self,
        command: Sequence[str],
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if not command:
            raise ValueError("harness command must not be empty")
        self._command = list(command)
        self._timeout_seconds = timeout_seconds
        self._process: subprocess.Popen[str] | None = None
        self._one_shot_mode: bool | None = None

    @classmethod
    def from_command_string(
        cls,
        command: str,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> Self:
        """Build a client from a shell-style command string."""
        return cls(shlex.split(command), timeout_seconds=timeout_seconds)

    @property
    def command(self) -> list[str]:
        """The argument vector this client invokes."""
        return list(self._command)

    def metadata(self) -> ProviderMetadata:
        """Ask the harness to identify its implementation and versions."""
        response = self.invoke({"operation": "metadata"})
        values: dict[str, str] = {}
        for wire_name, field_name in _METADATA_FIELDS:
            value = response.get(wire_name)
            if not isinstance(value, str):
                raise HarnessProtocolError(f"harness metadata is missing {wire_name!r}")
            values[field_name] = value
        return ProviderMetadata(**values)

    def _start(self) -> subprocess.Popen[str]:
        """Start the harness, or return the one already running."""
        if self._process is not None and self._process.poll() is None:
            return self._process
        try:
            self._process = subprocess.Popen(  # noqa: S603 - the command is the user's own
                self._command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            raise HarnessProtocolError(f"harness command not found: {self._command[0]!r}") from None
        except PermissionError:
            raise HarnessProtocolError(
                f"harness command is not executable: {self._command[0]!r}"
            ) from None
        return self._process

    def close(self) -> None:
        """Close the harness's stdin and wait for it to exit."""
        process = self._process
        self._process = None
        if process is None or process.poll() is not None:
            return
        assert process.stdin is not None  # noqa: S101 - always created with a pipe
        try:
            process.stdin.close()
            process.wait(timeout=self._timeout_seconds)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
            process.wait()

    def __enter__(self) -> Self:
        """Enter a context that closes the harness on exit."""
        return self

    def __exit__(self, *_: object) -> None:
        """Close the harness."""
        self.close()

    def _write(self, process: subprocess.Popen[str], payload: str) -> None:
        assert process.stdin is not None  # noqa: S101
        try:
            process.stdin.write(payload + "\n")
            process.stdin.flush()
        except (BrokenPipeError, ValueError):
            raise HarnessProtocolError("harness closed its input before answering") from None

    def _one_shot(self, payload: str) -> str:
        """Run the harness once for this request, closing stdin so it sees EOF."""
        process = self._start()
        self._process = None
        self._write(process, payload)
        assert process.stdin is not None  # noqa: S101
        process.stdin.close()
        line = _read_line(process, self._timeout_seconds)
        _reap(process, self._timeout_seconds)
        if line is None:
            raise HarnessProtocolError(f"harness timed out after {self._timeout_seconds:g}s")
        return line

    def _persistent(self, payload: str) -> str:
        process = self._start()
        self._write(process, payload)
        line = _read_line(process, self._timeout_seconds)
        if line is None:
            process.kill()
            self._process = None
            raise HarnessProtocolError(f"harness timed out after {self._timeout_seconds:g}s")
        return line

    def _detect(self, payload: str) -> str:
        """First exchange: work out which contract this harness speaks.

        A harness that loops over stdin answers straight away. One that reads
        stdin to EOF -- the easiest kind to write, and the shape a shell script
        with `jq` naturally takes -- cannot answer until its input closes, so it
        stays silent. Rather than deadlock, wait a bounded moment and then give
        it the EOF it is waiting for.

        Misjudging a merely slow persistent harness as one-shot costs speed and
        nothing else: the answer is still read, and every later request simply
        starts a fresh process. Silence is the only signal available here, so
        the safe reading of it is the cheap one.
        """
        process = self._start()
        self._write(process, payload)
        line = _read_line(process, min(self._timeout_seconds, _PROBE_SECONDS))
        if line is not None:
            self._one_shot_mode = False
            return line

        assert process.stdin is not None  # noqa: S101
        process.stdin.close()
        self._process = None
        line = _read_line(process, self._timeout_seconds)
        _reap(process, self._timeout_seconds)
        if line is None:
            raise HarnessProtocolError(
                f"harness timed out after {self._timeout_seconds:g}s without answering, "
                "with and without an end-of-input"
            )
        self._one_shot_mode = True
        return line

    def invoke(self, request: Mapping[str, object]) -> Mapping[str, object]:
        payload = json.dumps(request)
        if self._one_shot_mode is None:
            line = self._detect(payload)
        elif self._one_shot_mode:
            line = self._one_shot(payload)
        else:
            line = self._persistent(payload)

        try:
            response: object = json.loads(line)
        except json.JSONDecodeError:
            raise HarnessProtocolError("harness returned output that is not valid JSON") from None
        if not isinstance(response, Mapping):
            raise HarnessProtocolError("harness returned a JSON value that is not an object")

        error = response.get("error")
        if error is not None:
            if error == AUTHENTICATION_FAILED:
                raise InvalidTag
            if error == UNSUPPORTED:
                raise HarnessUnsupportedError
            raise HarnessProtocolError("harness reported a failure")
        return response


class SubprocessAesGcmProvider(HarnessClient):
    """AES-GCM operations performed by an external command."""

    def encrypt(
        self,
        *,
        key: bytes,
        iv: bytes,
        plaintext: bytes,
        aad: bytes,
        tag_length_bits: int,
    ) -> AesGcmValues:
        """Encrypt through the harness, returning ciphertext and tag separately."""
        response = self.invoke(
            {
                "operation": "encrypt",
                "key": _encode(key),
                "iv": _encode(iv),
                "aad": _encode(aad),
                "pt": _encode(plaintext),
                "tagLen": tag_length_bits,
            }
        )
        return AesGcmValues(
            ciphertext=_decode(response, "ct"),
            tag=_decode(response, "tag"),
        )

    def decrypt(
        self,
        *,
        key: bytes,
        iv: bytes,
        ciphertext: bytes,
        aad: bytes,
        tag: bytes,
    ) -> AesGcmValues:
        """Decrypt through the harness, or raise ``InvalidTag`` when it rejects the tag."""
        response = self.invoke(
            {
                "operation": "decrypt",
                "key": _encode(key),
                "iv": _encode(iv),
                "aad": _encode(aad),
                "ct": _encode(ciphertext),
                "tag": _encode(tag),
            }
        )
        return AesGcmValues(plaintext=_decode(response, "pt"))


__all__ = [
    "AUTHENTICATION_FAILED",
    "DEFAULT_TIMEOUT_SECONDS",
    "UNSUPPORTED",
    "HarnessClient",
    "HarnessProtocolError",
    "HarnessUnsupportedError",
    "SubprocessAesGcmProvider",
    "decode_hex",
]

decode_hex = _decode
