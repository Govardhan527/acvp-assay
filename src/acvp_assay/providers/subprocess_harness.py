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
import shlex
import subprocess
from collections.abc import Mapping, Sequence
from typing import Self

from cryptography.exceptions import InvalidTag

from acvp_assay.models import AesGcmValues, ProviderMetadata

DEFAULT_TIMEOUT_SECONDS = 30.0
AUTHENTICATION_FAILED = "authentication failed"

_METADATA_FIELDS = (
    ("name", "name"),
    ("libraryName", "library_name"),
    ("libraryVersion", "library_version"),
    ("backendName", "backend_name"),
    ("backendVersion", "backend_version"),
)


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


class HarnessClient:
    """Speaks the one-request-per-invocation JSON contract to an external command.

    Shared by every algorithm family's subprocess provider, so the transport,
    timeout, and error-to-diagnostic rules are defined once.
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

    def invoke(self, request: Mapping[str, object]) -> Mapping[str, object]:
        try:
            completed = subprocess.run(
                self._command,
                input=json.dumps(request),
                stdout=subprocess.PIPE,
                text=True,
                timeout=self._timeout_seconds,
                check=False,
            )
        except FileNotFoundError:
            raise HarnessProtocolError(f"harness command not found: {self._command[0]!r}") from None
        except PermissionError:
            raise HarnessProtocolError(
                f"harness command is not executable: {self._command[0]!r}"
            ) from None
        except subprocess.TimeoutExpired:
            raise HarnessProtocolError(
                f"harness timed out after {self._timeout_seconds:g}s"
            ) from None

        if completed.returncode != 0:
            raise HarnessProtocolError(f"harness exited with status {completed.returncode}")

        try:
            response: object = json.loads(completed.stdout)
        except json.JSONDecodeError:
            raise HarnessProtocolError("harness returned output that is not valid JSON") from None
        if not isinstance(response, Mapping):
            raise HarnessProtocolError("harness returned a JSON value that is not an object")

        error = response.get("error")
        if error is not None:
            if error == AUTHENTICATION_FAILED:
                raise InvalidTag
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
    "HarnessClient",
    "HarnessProtocolError",
    "SubprocessAesGcmProvider",
    "decode_hex",
]

decode_hex = _decode
