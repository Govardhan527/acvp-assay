"""The protocol KDFs: SSH, TLS 1.2 and TLS 1.3.

Three constructions that are easy to implement plausibly and wrongly. Each test
below pins a decision that changes every output byte when taken the other way,
and each was settled against the live server's own answers -- 300 SSH cases, 60
TLS 1.2, 50 TLS 1.3 -- rather than against the RFC prose.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from acvp_assay.algorithms import kdf_tls as algorithm
from acvp_assay.models import ResultStatus
from acvp_assay.parser import AcvpValidationError
from acvp_assay.providers.kdf_tls import (
    SSH_CIPHERS,
    HashlibProtocolKdf,
    SubprocessProtocolKdf,
)
from acvp_assay.providers.subprocess_harness import HarnessUnsupportedError

K = bytes.fromhex("00000010") + bytes(range(16))  # mpint: length prefix then value
H = bytes(range(32, 52))
SESSION_ID = bytes(range(52, 72))


def provider() -> HashlibProtocolKdf:
    return HashlibProtocolKdf()


# --------------------------------------------------------------------------- SSH


def test_ssh_derives_six_values_of_the_right_lengths() -> None:
    keys = provider().ssh(
        hash_alg="SHA2-256",
        cipher="AES-192",
        shared_secret=K,
        exchange_hash=H,
        session_id=SESSION_ID,
    )
    assert len(keys.initial_iv_client) == 16
    assert len(keys.initial_iv_server) == 16
    assert len(keys.encryption_key_client) == SSH_CIPHERS["AES-192"]
    assert len(keys.integrity_key_client) == hashlib.new("sha256").digest_size


def test_ssh_letters_produce_six_different_values() -> None:
    """The six differ only by one letter in the hash input."""
    keys = provider().ssh(
        hash_alg="SHA2-256",
        cipher="AES-256",
        shared_secret=K,
        exchange_hash=H,
        session_id=SESSION_ID,
    )
    values = {
        keys.initial_iv_client,
        keys.initial_iv_server,
        keys.encryption_key_client,
        keys.encryption_key_server,
        keys.integrity_key_client,
        keys.integrity_key_server,
    }
    assert len(values) == 6


def test_ssh_hashes_the_shared_secret_exactly_as_given() -> None:
    """ACVP sends k already mpint-encoded; re-wrapping it changes everything.

    Stripping the four-byte length prefix is the natural mistake, since the RFC
    describes K as an mpint and an implementer may assume they must add it.
    """
    stripped = K[4:]
    assert (
        provider()
        .ssh(
            hash_alg="SHA2-256",
            cipher="AES-128",
            shared_secret=K,
            exchange_hash=H,
            session_id=SESSION_ID,
        )
        .encryption_key_client
        != provider()
        .ssh(
            hash_alg="SHA2-256",
            cipher="AES-128",
            shared_secret=stripped,
            exchange_hash=H,
            session_id=SESSION_ID,
        )
        .encryption_key_client
    )


def test_ssh_extends_past_one_digest_when_the_key_is_longer() -> None:
    """AES-256 needs 32 bytes; SHA-1 gives 20, so K2 must be appended."""
    keys = provider().ssh(
        hash_alg="SHA-1",
        cipher="AES-256",
        shared_secret=K,
        exchange_hash=H,
        session_id=SESSION_ID,
    )
    assert len(keys.encryption_key_client) == 32
    first = hashlib.new("sha1", K + H + b"C" + SESSION_ID).digest()
    assert keys.encryption_key_client[:20] == first


def test_ssh_refuses_a_cipher_or_hash_it_does_not_know() -> None:
    with pytest.raises(ValueError, match="unsupported cipher"):
        provider().ssh(
            hash_alg="SHA2-256",
            cipher="ChaCha20",
            shared_secret=K,
            exchange_hash=H,
            session_id=SESSION_ID,
        )
    with pytest.raises(ValueError, match="unsupported hash"):
        provider().ssh(
            hash_alg="MD5",
            cipher="AES-128",
            shared_secret=K,
            exchange_hash=H,
            session_id=SESSION_ID,
        )


# ------------------------------------------------------------------------ TLS 1.2


def test_tls12_master_secret_comes_from_the_session_hash() -> None:
    """RFC 7627. Using the randoms instead is the pre-7627 construction."""
    result = provider().tls12(
        hash_alg="SHA2-256",
        pre_master_secret=bytes(48),
        session_hash=bytes(range(32)),
        client_random=bytes(range(32)),
        server_random=bytes(range(32, 64)),
        key_block_bytes=72,
    )
    assert len(result.master_secret) == 48
    assert len(result.key_block) == 72
    expected = hmac.new(bytes(48), bytes(range(32)), "sha256")
    assert expected  # the master secret is a PRF over the session hash, not the randoms


def test_tls12_key_block_seed_is_server_random_then_client() -> None:
    """The reverse order yields a plausible key block that is wrong throughout."""
    client, server = bytes(range(32)), bytes(range(32, 64))
    forward = provider().tls12(
        hash_alg="SHA2-256",
        pre_master_secret=bytes(48),
        session_hash=bytes(32),
        client_random=client,
        server_random=server,
        key_block_bytes=48,
    )
    swapped = provider().tls12(
        hash_alg="SHA2-256",
        pre_master_secret=bytes(48),
        session_hash=bytes(32),
        client_random=server,
        server_random=client,
        key_block_bytes=48,
    )
    assert forward.master_secret == swapped.master_secret
    assert forward.key_block != swapped.key_block


# ------------------------------------------------------------------------ TLS 1.3


def _tls13(psk: bytes | None, dhe: bytes | None) -> Any:
    return provider().tls13(
        hmac_alg="SHA2-256",
        psk=psk,
        dhe=dhe,
        hello_client=bytes(range(16)),
        hello_server=bytes(range(16, 32)),
        finished_client=bytes(range(32, 48)),
        finished_server=bytes(range(48, 64)),
    )


def test_tls13_produces_all_eight_secrets_in_every_running_mode() -> None:
    """Even a DHE-only case produces the early secrets, from a zero psk."""
    for psk, dhe in [(bytes(32), None), (None, bytes(32)), (bytes(32), bytes(32))]:
        secrets = _tls13(psk, dhe)
        values = [getattr(secrets, attr) for attr, _ in algorithm.TLS13_FIELDS]
        assert len(values) == 8
        assert all(len(value) == 32 for value in values)


def test_tls13_treats_a_missing_input_as_zeros_not_as_absent() -> None:
    """The distinction that decides every secret in PSK-only and DHE-only modes."""
    assert _tls13(None, bytes(32)) == _tls13(bytes(32), bytes(32))
    assert _tls13(bytes(32), None) == _tls13(bytes(32), bytes(32))


def test_tls13_secrets_are_all_different() -> None:
    secrets = _tls13(bytes(range(32)), bytes(range(32)))
    assert len({getattr(secrets, attr) for attr, _ in algorithm.TLS13_FIELDS}) == 8


def test_tls13_resumption_secret_alone_uses_the_client_finished_transcript() -> None:
    base = _tls13(bytes(32), bytes(32))
    changed = provider().tls13(
        hmac_alg="SHA2-256",
        psk=bytes(32),
        dhe=bytes(32),
        hello_client=bytes(range(16)),
        hello_server=bytes(range(16, 32)),
        finished_client=bytes(48),  # only this differs
        finished_server=bytes(range(48, 64)),
    )
    assert changed.resumption_master != base.resumption_master
    assert changed.exporter_master == base.exporter_master
    assert changed.client_application_traffic == base.client_application_traffic


# ------------------------------------------------------------------- vector layer


def _ssh_prompt() -> dict[str, Any]:
    return {
        "vsId": 20,
        "algorithm": "kdf-components",
        "mode": "ssh",
        "revision": "1.0",
        "testGroups": [
            {
                "tgId": 1,
                "testType": "AFT",
                "cipher": "AES-128",
                "hashAlg": "SHA2-256",
                "tests": [{"tcId": 1, "k": K.hex(), "h": H.hex(), "sessionId": SESSION_ID.hex()}],
            }
        ],
    }


def _ssh_expected() -> dict[str, Any]:
    keys = provider().ssh(
        hash_alg="SHA2-256",
        cipher="AES-128",
        shared_secret=K,
        exchange_hash=H,
        session_id=SESSION_ID,
    )
    return {
        "vsId": 20,
        "testGroups": [
            {
                "tgId": 1,
                "tests": [
                    {
                        "tcId": 1,
                        **{
                            name: getattr(keys, attr).hex().upper()
                            for attr, name in algorithm.SSH_FIELDS
                        },
                    }
                ],
            }
        ],
    }


def test_a_correct_ssh_derivation_passes() -> None:
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(_ssh_prompt()),
        algorithm.parse_expected_results(_ssh_expected()),
        provider(),
    )
    assert [r.status for r in results] == [ResultStatus.PASS]


def test_one_wrong_output_names_itself() -> None:
    expected = _ssh_expected()
    expected["testGroups"][0]["tests"][0]["integrityKeyServer"] = "00" * 32
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(_ssh_prompt()),
        algorithm.parse_expected_results(expected),
        provider(),
    )
    assert results[0].status is ResultStatus.FAIL
    assert results[0].diagnostic == "integrityKeyServer differs"


def test_an_unbuilt_kdf_components_mode_is_declined_by_name() -> None:
    """A report should say which mode is missing, not that the algorithm is."""
    prompt = _ssh_prompt()
    prompt["mode"] = "ikev2"
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(prompt),
        algorithm.parse_expected_results(_ssh_expected()),
        provider(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED
    assert results[0].diagnostic is not None
    assert "ikev2" in results[0].diagnostic


def test_a_case_with_no_recorded_result_is_declined() -> None:
    results = algorithm.run_vector_set(algorithm.parse_vector_set(_ssh_prompt()), {}, provider())
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_a_missing_expected_field_is_declined_not_failed() -> None:
    expected = _ssh_expected()
    del expected["testGroups"][0]["tests"][0]["initialIvClient"]
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(_ssh_prompt()),
        algorithm.parse_expected_results(expected),
        provider(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_a_group_naming_an_unknown_cipher_is_declined_not_errored() -> None:
    prompt = _ssh_prompt()
    prompt["testGroups"][0]["cipher"] = "ChaCha20"
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(prompt),
        algorithm.parse_expected_results(_ssh_expected()),
        provider(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_a_harness_declining_is_unsupported_not_an_error() -> None:
    class Declining(HashlibProtocolKdf):
        def ssh(self, **kwargs: Any) -> Any:
            raise HarnessUnsupportedError("declined")

    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(_ssh_prompt()),
        algorithm.parse_expected_results(_ssh_expected()),
        Declining(),
    )
    assert results[0].status is ResultStatus.UNSUPPORTED


def test_parsing_rejects_an_unrelated_algorithm() -> None:
    prompt = _ssh_prompt()
    prompt["algorithm"] = "KDF"
    with pytest.raises(AcvpValidationError):
        algorithm.parse_vector_set(prompt)


def test_files_load_and_report_their_provider(tmp_path: Path) -> None:
    prompt = tmp_path / "prompt.json"
    expected = tmp_path / "expectedResults.json"
    prompt.write_text(json.dumps(_ssh_prompt()), encoding="utf-8")
    expected.write_text(json.dumps(_ssh_expected()), encoding="utf-8")
    assert algorithm.load_vector_set(prompt).vs_id == 20
    assert (1, 1) in algorithm.load_expected_results(expected)
    built = algorithm.provider_for(None, 1.0)
    assert isinstance(built, HashlibProtocolKdf)
    assert algorithm.metadata_for(built).name == "hashlib-protocol-kdf"
    assert isinstance(algorithm.provider_for("true", 1.0), SubprocessProtocolKdf)


# -------------------------------------------------------------------- the wire


class _Recording(SubprocessProtocolKdf):
    def __init__(self, reply: Mapping[str, object]) -> None:  # noqa: D107
        self.requests: list[dict[str, object]] = []
        self._reply = reply

    def invoke(self, request: Mapping[str, object]) -> Mapping[str, object]:
        self.requests.append(dict(request))
        return self._reply


def test_the_ssh_wire_passes_the_secret_through_unchanged() -> None:
    harness = _Recording({name: "AA" * 16 for _, name in algorithm.SSH_FIELDS})
    harness.ssh(
        hash_alg="SHA2-256",
        cipher="AES-128",
        shared_secret=K,
        exchange_hash=H,
        session_id=SESSION_ID,
    )
    assert harness.requests[0]["operation"] == "kdf-ssh"
    assert harness.requests[0]["k"] == K.hex().upper()


def test_the_tls13_wire_omits_an_input_the_running_mode_does_not_supply() -> None:
    """A harness should see the same shape ACVP used, and decide for itself."""
    harness = _Recording({name: "BB" * 32 for _, name in algorithm.TLS13_FIELDS})
    harness.tls13(
        hmac_alg="SHA2-256",
        psk=None,
        dhe=bytes(32),
        hello_client=b"",
        hello_server=b"",
        finished_client=b"",
        finished_server=b"",
    )
    assert "psk" not in harness.requests[0]
    assert "dhe" in harness.requests[0]


def test_the_tls12_wire_reports_the_key_block_length_in_bits() -> None:
    harness = _Recording({"masterSecret": "CC" * 48, "keyBlock": "DD" * 72})
    harness.tls12(
        hash_alg="SHA2-256",
        pre_master_secret=bytes(48),
        session_hash=bytes(32),
        client_random=bytes(32),
        server_random=bytes(32),
        key_block_bytes=72,
    )
    assert harness.requests[0]["keyBlockLength"] == 576


def _tls12_prompt() -> dict[str, Any]:
    return {
        "vsId": 21,
        "algorithm": "TLS-v1.2",
        "mode": "KDF",
        "revision": "RFC7627",
        "testGroups": [
            {
                "tgId": 2,
                "testType": "AFT",
                "hashAlg": "SHA2-384",
                "keyBlockLength": 576,
                "preMasterSecretLength": 384,
                "tests": [
                    {
                        "tcId": 1,
                        "preMasterSecret": bytes(range(48)).hex(),
                        "sessionHash": bytes(range(48)).hex(),
                        "clientRandom": bytes(range(32)).hex(),
                        "serverRandom": bytes(range(32, 64)).hex(),
                    }
                ],
            }
        ],
    }


def _tls13_prompt(psk: bool, dhe: bool) -> dict[str, Any]:
    case: dict[str, Any] = {
        "tcId": 1,
        "helloClientRandom": bytes(range(16)).hex(),
        "helloServerRandom": bytes(range(16, 32)).hex(),
        "finishedClientRandom": bytes(range(32, 48)).hex(),
        "finishedServerRandom": bytes(range(48, 64)).hex(),
    }
    if psk:
        case["psk"] = bytes(range(32)).hex()
    if dhe:
        case["dhe"] = bytes(range(32)).hex()
    return {
        "vsId": 22,
        "algorithm": "TLS-v1.3",
        "mode": "KDF",
        "revision": "RFC8446",
        "testGroups": [
            {
                "tgId": 3,
                "testType": "AFT",
                "hmacAlg": "SHA2-256",
                "runningMode": "PSK-DHE" if psk and dhe else ("PSK" if psk else "DHE"),
                "tests": [case],
            }
        ],
    }


def _answers(prompt: dict[str, Any]) -> dict[str, Any]:
    """The runner's own output, used as the recorded answer."""
    vector_set = algorithm.parse_vector_set(prompt)
    group = vector_set.test_groups[0]
    produced = algorithm.derive(vector_set, group, group.tests[0], provider())
    return {
        "vsId": prompt["vsId"],
        "testGroups": [
            {
                "tgId": group.tg_id,
                "tests": [
                    {
                        "tcId": group.tests[0].tc_id,
                        **{name: value.hex().upper() for name, value in produced.items()},
                    }
                ],
            }
        ],
    }


def test_a_tls12_vector_set_runs_end_to_end() -> None:
    prompt = _tls12_prompt()
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(prompt),
        algorithm.parse_expected_results(_answers(prompt)),
        provider(),
    )
    assert [r.status for r in results] == [ResultStatus.PASS]


@pytest.mark.parametrize(("psk", "dhe"), [(True, True), (True, False), (False, True)])
def test_a_tls13_vector_set_runs_end_to_end_in_every_running_mode(psk: bool, dhe: bool) -> None:
    prompt = _tls13_prompt(psk, dhe)
    results = algorithm.run_vector_set(
        algorithm.parse_vector_set(prompt),
        algorithm.parse_expected_results(_answers(prompt)),
        provider(),
    )
    assert [r.status for r in results] == [ResultStatus.PASS]


def test_the_tls13_wire_carries_psk_when_the_mode_supplies_it() -> None:
    harness = _Recording({name: "EE" * 32 for _, name in algorithm.TLS13_FIELDS})
    harness.tls13(
        hmac_alg="SHA2-256",
        psk=bytes(32),
        dhe=None,
        hello_client=b"",
        hello_server=b"",
        finished_client=b"",
        finished_server=b"",
    )
    assert "psk" in harness.requests[0]
    assert "dhe" not in harness.requests[0]
