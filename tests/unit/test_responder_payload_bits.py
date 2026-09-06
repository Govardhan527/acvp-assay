"""The response builder must carry CFB1's bit count, and a regression proves it.

This is a bug the offline suite could not have caught. The runner passes
``payload_bits`` when it verifies a case against expected results, so CFB1
agreed with NIST's own sample file and passed offline. The submission path
builds its document through a *different* function, that function did not pass
the bit count, and the answers it produced covered the zero padding the hex
encoding adds rather than the declared payload. Only the live server said so --
session 766207 returned ``fail`` for the CFB1 vector set while every offline
case passed.

The test therefore watches the call rather than the answer: what went wrong was
an argument that was never passed, in a path no fixture exercised.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from acvp_assay import responder
from acvp_assay.providers.aes_block import CryptographyAesBlockProvider

PROMPT: dict[str, Any] = {
    "vsId": 1,
    "algorithm": "ACVP-AES-CFB1",
    "revision": "1.0",
    "testGroups": [
        {
            "tgId": 1,
            "testType": "AFT",
            "direction": "encrypt",
            "tests": [
                {"tcId": 1, "key": "00" * 16, "iv": "11" * 16, "pt": "80", "payloadLen": 1},
                {"tcId": 2, "key": "00" * 16, "iv": "11" * 16, "pt": "80", "payloadLen": 8},
            ],
        }
    ],
}


class _Recorder(CryptographyAesBlockProvider):
    """The real provider, with every transform call recorded."""

    def __init__(self) -> None:
        self.calls: list[int | None] = []

    def transform(self, **kwargs: Any) -> bytes:
        self.calls.append(kwargs.get("payload_bits"))
        return super().transform(**kwargs)


@pytest.fixture
def prompt_file(tmp_path: Path) -> Path:
    path = tmp_path / "prompt.json"
    path.write_text(json.dumps(PROMPT), encoding="utf-8")
    return path


def test_the_response_builder_passes_the_declared_bit_count(
    prompt_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorder = _Recorder()
    monkeypatch.setattr(responder, "CryptographyAesBlockProvider", lambda: recorder)
    responder.build_response(prompt_file)
    assert recorder.calls == [1, 8]


def test_two_bit_lengths_over_one_payload_give_different_answers(prompt_file: Path) -> None:
    """The guard above only matters because the bit count changes the answer."""
    document = responder.build_response(prompt_file)
    groups = document["testGroups"]
    assert isinstance(groups, list)
    cases = groups[0]["tests"]
    assert cases[0]["ct"] != cases[1]["ct"]
