"""The protocol KDFs: SSH, TLS 1.2 and TLS 1.3.

Three registry names, three genuinely different constructions, grouped because
a module that terminates a protocol validates them together and because the
measurement put all three near the top of what was missing -- `kdf-components`
on 56% of active FIPS 140-3 modules, `TLS-v1.2` on 41%, `TLS-v1.3` on 28%.

Each rule below was reproduced from the live server's own answers before any of
this was written: 300 SSH cases, 60 TLS 1.2, 50 TLS 1.3.

The details worth stating, because each one is a place to be quietly wrong:

* **SSH's shared secret arrives already mpint-encoded.** ACVP sends ``k`` with
  its four-byte SSH length prefix in place, so it is hashed as received. Adding
  a prefix, or stripping one, changes every derived byte.
* **TLS 1.2 here is RFC 7627**, the extended master secret: the master secret
  comes from the session hash, not from the two randoms. The key block still
  uses the randoms, and in the order *server then client*, which is the reverse
  of how they are usually written down.
* **TLS 1.3's missing input is zeros, not absent.** A PSK-only case supplies no
  ``dhe`` and a DHE-only case supplies no ``psk``; each is replaced by a string
  of zero bytes as long as the hash, and all eight secrets are still produced.
"""

from __future__ import annotations

import hashlib
import hmac
import platform
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from acvp_assay.models import ProviderMetadata
from acvp_assay.providers.digest import HASHLIB_ALGORITHMS, ssl_version_text
from acvp_assay.providers.subprocess_harness import HarnessClient, decode_hex

KDF_COMPONENTS = "kdf-components"
TLS_V12 = "TLS-v1.2"
TLS_V13 = "TLS-v1.3"

#: The one `kdf-components` mode built here. The others are declined by name so
#: a report says which, rather than reporting the whole algorithm as missing:
#: tls (20% of modules), ikev2 (18%), ans9.42 (17%), snmp (17%), ans9.63 (24%),
#: srtp (8%), ikev1 (5%), tpm (0.1%).
SSH_MODE = "ssh"

#: SSH cipher names, mapped to their key length in bytes. The IV is a block, so
#: it is 16 bytes for every AES.
SSH_CIPHERS: dict[str, int] = {"AES-128": 16, "AES-192": 24, "AES-256": 32}
SSH_IV_BYTES = 16

#: The six values RFC 4253 derives, in the order of the single letter that
#: separates them.
SSH_LETTERS = (
    (b"A", "initialIvClient"),
    (b"B", "initialIvServer"),
    (b"C", "encryptionKeyClient"),
    (b"D", "encryptionKeyServer"),
    (b"E", "integrityKeyClient"),
    (b"F", "integrityKeyServer"),
)


@dataclass(frozen=True, slots=True)
class SshKeys:
    """The six values one SSH exchange derives."""

    initial_iv_client: bytes
    initial_iv_server: bytes
    encryption_key_client: bytes
    encryption_key_server: bytes
    integrity_key_client: bytes
    integrity_key_server: bytes


@dataclass(frozen=True, slots=True)
class Tls12Keys:
    """The master secret and the key block that follows from it."""

    master_secret: bytes
    key_block: bytes


@dataclass(frozen=True, slots=True)
class Tls13Secrets:
    """The eight secrets of the RFC 8446 key schedule."""

    client_early_traffic: bytes
    early_exporter_master: bytes
    client_handshake_traffic: bytes
    server_handshake_traffic: bytes
    client_application_traffic: bytes
    server_application_traffic: bytes
    exporter_master: bytes
    resumption_master: bytes


@runtime_checkable
class ProtocolKdfProvider(Protocol):
    """Replaceable boundary for the protocol key-derivation functions."""

    def metadata(self) -> ProviderMetadata:
        """Identify the provider library and its cryptographic backend."""
        ...

    def ssh(
        self,
        *,
        hash_alg: str,
        cipher: str,
        shared_secret: bytes,
        exchange_hash: bytes,
        session_id: bytes,
    ) -> SshKeys:
        """Derive the six SSH keys (RFC 4253 section 7.2)."""
        ...

    def tls12(
        self,
        *,
        hash_alg: str,
        pre_master_secret: bytes,
        session_hash: bytes,
        client_random: bytes,
        server_random: bytes,
        key_block_bytes: int,
    ) -> Tls12Keys:
        """Derive the extended master secret and key block (RFC 7627)."""
        ...

    def tls13(
        self,
        *,
        hmac_alg: str,
        psk: bytes | None,
        dhe: bytes | None,
        hello_client: bytes,
        hello_server: bytes,
        finished_client: bytes,
        finished_server: bytes,
    ) -> Tls13Secrets:
        """Run the RFC 8446 key schedule."""
        ...


class HashlibProtocolKdf:
    """The three protocol KDFs over `hashlib` and `hmac`."""

    def metadata(self) -> ProviderMetadata:
        """Identify hashlib and the OpenSSL build behind it."""
        return ProviderMetadata(
            name="hashlib-protocol-kdf",
            library_name="hashlib",
            library_version=platform.python_version(),
            backend_name="OpenSSL",
            backend_version=ssl_version_text(),
        )

    def _name(self, algorithm: str) -> str:
        if algorithm not in HASHLIB_ALGORITHMS:
            raise ValueError(f"unsupported hash {algorithm!r}")
        return HASHLIB_ALGORITHMS[algorithm]

    # ------------------------------------------------------------------ SSH

    def ssh(
        self,
        *,
        hash_alg: str,
        cipher: str,
        shared_secret: bytes,
        exchange_hash: bytes,
        session_id: bytes,
    ) -> SshKeys:
        """Derive the six SSH keys (RFC 4253 section 7.2)."""
        name = self._name(hash_alg)
        if cipher not in SSH_CIPHERS:
            raise ValueError(f"unsupported cipher {cipher!r}")
        key_bytes = SSH_CIPHERS[cipher]
        integrity_bytes = hashlib.new(name).digest_size
        sizes = {
            "initialIvClient": SSH_IV_BYTES,
            "initialIvServer": SSH_IV_BYTES,
            "encryptionKeyClient": key_bytes,
            "encryptionKeyServer": key_bytes,
            "integrityKeyClient": integrity_bytes,
            "integrityKeyServer": integrity_bytes,
        }
        derived = {
            field: self._ssh_one(
                name, shared_secret, exchange_hash, session_id, letter, sizes[field]
            )
            for letter, field in SSH_LETTERS
        }
        return SshKeys(
            initial_iv_client=derived["initialIvClient"],
            initial_iv_server=derived["initialIvServer"],
            encryption_key_client=derived["encryptionKeyClient"],
            encryption_key_server=derived["encryptionKeyServer"],
            integrity_key_client=derived["integrityKeyClient"],
            integrity_key_server=derived["integrityKeyServer"],
        )

    def _ssh_one(
        self, name: str, k: bytes, h: bytes, session_id: bytes, letter: bytes, want: int
    ) -> bytes:
        """K1 = HASH(K||H||X||session_id); K(n+1) = HASH(K||H||K1..Kn)."""
        out = hashlib.new(name, k + h + letter + session_id).digest()
        while len(out) < want:
            out += hashlib.new(name, k + h + out).digest()
        return out[:want]

    # -------------------------------------------------------------- TLS 1.2

    def _p_hash(self, name: str, secret: bytes, seed: bytes, length: int) -> bytes:
        """TLS 1.2 P_hash: A(0) = seed, A(i) = HMAC(secret, A(i-1))."""
        out, a = b"", seed
        while len(out) < length:
            a = hmac.new(secret, a, name).digest()
            out += hmac.new(secret, a + seed, name).digest()
        return out[:length]

    def tls12(
        self,
        *,
        hash_alg: str,
        pre_master_secret: bytes,
        session_hash: bytes,
        client_random: bytes,
        server_random: bytes,
        key_block_bytes: int,
    ) -> Tls12Keys:
        """Derive the extended master secret and key block (RFC 7627)."""
        name = self._name(hash_alg)
        master = self._p_hash(name, pre_master_secret, b"extended master secret" + session_hash, 48)
        # Server random first. The other order produces a plausible key block
        # that disagrees on every byte.
        block = self._p_hash(
            name, master, b"key expansion" + server_random + client_random, key_block_bytes
        )
        return Tls12Keys(master_secret=master, key_block=block)

    # -------------------------------------------------------------- TLS 1.3

    def _expand_label(
        self, name: str, secret: bytes, label: bytes, context: bytes, length: int
    ) -> bytes:
        full = b"tls13 " + label
        info = (
            length.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(context)]) + context
        )
        out, block, counter = b"", b"", 1
        while len(out) < length:
            block = hmac.new(secret, block + info + bytes([counter]), name).digest()
            out += block
            counter += 1
        return out[:length]

    def _derive_secret(self, name: str, secret: bytes, label: bytes, messages: bytes) -> bytes:
        size = hashlib.new(name).digest_size
        return self._expand_label(name, secret, label, hashlib.new(name, messages).digest(), size)

    def tls13(
        self,
        *,
        hmac_alg: str,
        psk: bytes | None,
        dhe: bytes | None,
        hello_client: bytes,
        hello_server: bytes,
        finished_client: bytes,
        finished_server: bytes,
    ) -> Tls13Secrets:
        """Run the RFC 8446 key schedule."""
        name = self._name(hmac_alg)
        zeros = b"\x00" * hashlib.new(name).digest_size
        early = hmac.new(zeros, psk if psk is not None else zeros, name).digest()
        handshake = hmac.new(
            self._derive_secret(name, early, b"derived", b""),
            dhe if dhe is not None else zeros,
            name,
        ).digest()
        master = hmac.new(
            self._derive_secret(name, handshake, b"derived", b""), zeros, name
        ).digest()
        hello = hello_client + hello_server
        through_server = hello + finished_server
        return Tls13Secrets(
            client_early_traffic=self._derive_secret(name, early, b"c e traffic", hello_client),
            early_exporter_master=self._derive_secret(name, early, b"e exp master", hello_client),
            client_handshake_traffic=self._derive_secret(name, handshake, b"c hs traffic", hello),
            server_handshake_traffic=self._derive_secret(name, handshake, b"s hs traffic", hello),
            client_application_traffic=self._derive_secret(
                name, master, b"c ap traffic", through_server
            ),
            server_application_traffic=self._derive_secret(
                name, master, b"s ap traffic", through_server
            ),
            exporter_master=self._derive_secret(name, master, b"exp master", through_server),
            resumption_master=self._derive_secret(
                name, master, b"res master", through_server + finished_client
            ),
        )


class SubprocessProtocolKdf(HarnessClient):
    """The protocol KDFs performed by an external harness."""

    def ssh(
        self,
        *,
        hash_alg: str,
        cipher: str,
        shared_secret: bytes,
        exchange_hash: bytes,
        session_id: bytes,
    ) -> SshKeys:
        """Ask the harness for the six SSH keys."""
        response = self.invoke(
            {
                "operation": "kdf-ssh",
                "hashAlg": hash_alg,
                "cipher": cipher,
                # Already mpint-encoded, and passed on as received.
                "k": shared_secret.hex().upper(),
                "h": exchange_hash.hex().upper(),
                "sessionId": session_id.hex().upper(),
            }
        )
        return SshKeys(
            initial_iv_client=decode_hex(response, "initialIvClient"),
            initial_iv_server=decode_hex(response, "initialIvServer"),
            encryption_key_client=decode_hex(response, "encryptionKeyClient"),
            encryption_key_server=decode_hex(response, "encryptionKeyServer"),
            integrity_key_client=decode_hex(response, "integrityKeyClient"),
            integrity_key_server=decode_hex(response, "integrityKeyServer"),
        )

    def tls12(
        self,
        *,
        hash_alg: str,
        pre_master_secret: bytes,
        session_hash: bytes,
        client_random: bytes,
        server_random: bytes,
        key_block_bytes: int,
    ) -> Tls12Keys:
        """Ask the harness for the master secret and key block."""
        response = self.invoke(
            {
                "operation": "kdf-tls12",
                "hashAlg": hash_alg,
                "preMasterSecret": pre_master_secret.hex().upper(),
                "sessionHash": session_hash.hex().upper(),
                "clientRandom": client_random.hex().upper(),
                "serverRandom": server_random.hex().upper(),
                "keyBlockLength": key_block_bytes * 8,
            }
        )
        return Tls12Keys(
            master_secret=decode_hex(response, "masterSecret"),
            key_block=decode_hex(response, "keyBlock"),
        )

    def tls13(
        self,
        *,
        hmac_alg: str,
        psk: bytes | None,
        dhe: bytes | None,
        hello_client: bytes,
        hello_server: bytes,
        finished_client: bytes,
        finished_server: bytes,
    ) -> Tls13Secrets:
        """Ask the harness to run the key schedule."""
        request: dict[str, object] = {
            "operation": "kdf-tls13",
            "hmacAlg": hmac_alg,
            "helloClientRandom": hello_client.hex().upper(),
            "helloServerRandom": hello_server.hex().upper(),
            "finishedClientRandom": finished_client.hex().upper(),
            "finishedServerRandom": finished_server.hex().upper(),
        }
        # Sent only when the running mode supplies them, so a harness sees the
        # same shape ACVP used and decides for itself what a missing one means.
        if psk is not None:
            request["psk"] = psk.hex().upper()
        if dhe is not None:
            request["dhe"] = dhe.hex().upper()
        response = self.invoke(request)
        return Tls13Secrets(
            client_early_traffic=decode_hex(response, "clientEarlyTrafficSecret"),
            early_exporter_master=decode_hex(response, "earlyExporterMasterSecret"),
            client_handshake_traffic=decode_hex(response, "clientHandshakeTrafficSecret"),
            server_handshake_traffic=decode_hex(response, "serverHandshakeTrafficSecret"),
            client_application_traffic=decode_hex(response, "clientApplicationTrafficSecret"),
            server_application_traffic=decode_hex(response, "serverApplicationTrafficSecret"),
            exporter_master=decode_hex(response, "exporterMasterSecret"),
            resumption_master=decode_hex(response, "resumptionMasterSecret"),
        )


__all__ = [
    "KDF_COMPONENTS",
    "SSH_CIPHERS",
    "SSH_IV_BYTES",
    "SSH_LETTERS",
    "SSH_MODE",
    "TLS_V12",
    "TLS_V13",
    "HashlibProtocolKdf",
    "ProtocolKdfProvider",
    "SshKeys",
    "SubprocessProtocolKdf",
    "Tls12Keys",
    "Tls13Secrets",
]
