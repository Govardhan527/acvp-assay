"""Produce ACVP *responses*, for submission to a live ACVTS server.

Everything else in this package verifies: it reads a prompt beside the expected
results NIST published and reports whether they agree. That is the right shape
for regression work, and it is not the shape ACVTS asks for. A live test session
hands over a prompt and nothing else; the client computes answers, submits them,
and the server returns the verdict.

So this module answers rather than checks. It reuses the same providers, which
is the point -- a response submitted from here exercises exactly the code path
the offline runner exercises, so agreement with NIST online is evidence about
the providers rather than about a second implementation written to pass.

Two rules shape everything here.

**Refuse rather than half-answer.** A submission missing cases is scored as
wrong answers, not as an incomplete run, so a family or a capability that
cannot be answered faithfully raises instead of emitting a partial document.

**Verification cases answer with a verdict.** Where ACVP supplies a signature,
tag or wrapping that may be deliberately invalid, the answer is ``testPassed``
-- the verdict reached, not any bytes produced.
"""

from __future__ import annotations

import json
import secrets
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TypeVar

from acvp_assay import parser
from acvp_assay.algorithms import (
    aes_block,
    aes_modes,
    ctr_drbg,
    ecdsa,
    hmac_mac,
    kas_ecc,
    kdf,
    pqc,
    rsa,
    sha2,
)
from acvp_assay.models import Direction
from acvp_assay.providers.aes_block import (
    CHAINING_MODES,
    AesBlockProvider,
    CryptographyAesBlockProvider,
    SubprocessAesBlockProvider,
)
from acvp_assay.providers.aes_modes import (
    AesModeProvider,
    CryptographyAesModeProvider,
    SubprocessAesModeProvider,
)
from acvp_assay.providers.base import AesGcmProvider
from acvp_assay.providers.cryptography_aesgcm import CryptographyAesGcmProvider
from acvp_assay.providers.ctr_drbg import CryptographyCtrDrbg, SubprocessDrbg, run_drbg_case
from acvp_assay.providers.digest import (
    HASHLIB_ALGORITHMS,
    HashlibHashProvider,
    HashlibMacProvider,
    HashProvider,
    MacProvider,
    SubprocessHashProvider,
    SubprocessMacProvider,
)
from acvp_assay.providers.ecdsa import (
    CryptographyEcdsaProvider,
    EcdsaProvider,
    SubprocessEcdsaProvider,
)
from acvp_assay.providers.hash_drbg import HashDrbg, HmacDrbg
from acvp_assay.providers.kas_ecc import CURVES as KAS_CURVES
from acvp_assay.providers.kas_ecc import (
    CryptographyKasEcc,
    KasEccProvider,
    SubprocessKasEcc,
)
from acvp_assay.providers.kdf import (
    CMAC_MODES,
    HMAC_MODES,
    MIDDLE_FIXED,
    CryptographyKdf,
    KdfProvider,
    KdfRequest,
    SubprocessKdfProvider,
)
from acvp_assay.providers.pqc import (
    ML_DSA_PARAMETER_SETS,
    ML_KEM_PARAMETER_SETS,
    SubprocessMlDsaProvider,
    SubprocessMlKemProvider,
)
from acvp_assay.providers.rsa import (
    CryptographyRsaProvider,
    RsaProvider,
    SubprocessRsaProvider,
)
from acvp_assay.providers.subprocess_harness import (
    DEFAULT_TIMEOUT_SECONDS,
    HarnessClient,
    HarnessUnsupportedError,
    SubprocessAesGcmProvider,
)

_ClientT = TypeVar("_ClientT", bound=HarnessClient)

#: ``fixedData`` is chosen by the implementation under test, so a submission
#: must invent it and report what it used. Sixteen bytes matches the width the
#: upstream sample set uses.
FIXED_DATA_BYTES = 16


class ResponseError(RuntimeError):
    """A response cannot be constructed faithfully for this vector set."""


@dataclass
class Harness:
    """A vendor implementation to answer with, in place of the built-in providers.

    This is what makes a live session say something about the vendor's product
    rather than about ``cryptography``: the same builders run, but every value
    submitted comes back over the harness protocol from the vendor's own code.

    A family may need more than one client (RSA signing and the primitives, for
    instance), and each holds a live subprocess, so every client opened is kept
    here and closed together once the document is built.
    """

    command: str
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        self._clients: list[HarnessClient] = []

    def open(self, client: _ClientT) -> _ClientT:
        """Adopt a freshly built harness client, to be closed with the rest."""
        self._clients.append(client)
        return client

    def close(self) -> None:
        """Shut down every subprocess this harness started."""
        while self._clients:
            self._clients.pop().close()


class _Builder(Protocol):
    def __call__(
        self, document: dict[str, object], harness: Harness | None
    ) -> list[dict[str, object]]:
        """Build the ``testGroups`` array of a response."""
        ...


def _hex(value: bytes) -> str:
    return value.hex().upper()


# --------------------------------------------------------------------------- SHA-2


def _sha2_groups(
    document: dict[str, object], harness: Harness | None = None
) -> list[dict[str, object]]:
    """A digest per AFT case; the whole chain per Monte Carlo case."""
    vector_set = sha2.parse_vector_set(document)
    provider: HashProvider = (
        HashlibHashProvider(vector_set.algorithm)
        if harness is None
        else harness.open(
            SubprocessHashProvider(
                vector_set.algorithm,
                shlex.split(harness.command),
                timeout_seconds=harness.timeout_seconds,
            )
        )
    )
    groups: list[dict[str, object]] = []
    for group in vector_set.test_groups:
        cases: list[dict[str, object]] = []
        for case in group.tests:
            # Checked before the message: an LDT case carries a size descriptor
            # rather than a message, so "no message" would misdescribe a
            # capability this runner deliberately declines.
            if group.test_type is sha2.Sha2TestType.LDT or case.is_large:
                raise ResponseError(
                    f"tgId {group.tg_id} is a large data test, which this runner declines; "
                    "do not register LDT capabilities for a submission"
                )
            assert case.message is not None  # noqa: S101 - the parser guarantees it
            if group.test_type is sha2.Sha2TestType.MCT:
                version = group.mct_version or "standard"
                if version not in sha2.SUPPORTED_MCT_VERSIONS:
                    raise ResponseError(f"mctVersion {version!r} is not supported")
                chain = provider.digest_mct(case.message, alternate=version == "alternate")
                cases.append({"tcId": case.tc_id, "resultsArray": [{"md": _hex(d)} for d in chain]})
            else:
                cases.append({"tcId": case.tc_id, "md": _hex(provider.digest(case.message))})
        groups.append({"tgId": group.tg_id, "tests": cases})
    return groups


# --------------------------------------------------------------------------- HMAC


def _hmac_groups(
    document: dict[str, object], harness: Harness | None = None
) -> list[dict[str, object]]:
    """One MAC per case, truncated to the group's ``macLen``."""
    vector_set = hmac_mac.parse_vector_set(document)
    underlying = vector_set.algorithm.removeprefix("HMAC-")
    provider: MacProvider = (
        HashlibMacProvider(underlying)
        if harness is None
        else harness.open(
            SubprocessMacProvider(
                underlying, shlex.split(harness.command), timeout_seconds=harness.timeout_seconds
            )
        )
    )
    return [
        {
            "tgId": group.tg_id,
            "tests": [
                {
                    "tcId": case.tc_id,
                    "mac": _hex(
                        provider.mac(
                            key=case.key,
                            message=case.message,
                            mac_length_bits=group.mac_length_bits,
                        )
                    ),
                }
                for case in group.tests
            ],
        }
        for group in vector_set.test_groups
    ]


# --------------------------------------------------------------------------- AES-GCM


def _aes_gcm_groups(
    document: dict[str, object], harness: Harness | None = None
) -> list[dict[str, object]]:
    """Ciphertext and tag when encrypting; plaintext or a verdict when decrypting."""
    vector_set = parser.parse_vector_set(document)
    provider: AesGcmProvider = (
        CryptographyAesGcmProvider()
        if harness is None
        else harness.open(
            SubprocessAesGcmProvider.from_command_string(
                harness.command, timeout_seconds=harness.timeout_seconds
            )
        )
    )
    groups: list[dict[str, object]] = []
    for group in vector_set.test_groups:
        if group.iv_generation == "internal":
            raise ResponseError(
                f"tgId {group.tg_id} asks the implementation to generate the IV, which this "
                "runner does not do; register ivGen 'external' for a submission"
            )
        cases: list[dict[str, object]] = []
        for case in group.tests:
            if group.direction is Direction.ENCRYPT:
                assert case.plaintext is not None  # noqa: S101
                produced = provider.encrypt(
                    key=case.key,
                    iv=case.iv,
                    plaintext=case.plaintext,
                    aad=case.aad,
                    tag_length_bits=group.tag_length_bits,
                )
                assert produced.ciphertext is not None and produced.tag is not None  # noqa: S101
                cases.append(
                    {
                        "tcId": case.tc_id,
                        "ct": _hex(produced.ciphertext),
                        "tag": _hex(produced.tag),
                    }
                )
                continue
            assert case.ciphertext is not None and case.tag is not None  # noqa: S101
            try:
                decrypted = provider.decrypt(
                    key=case.key,
                    iv=case.iv,
                    ciphertext=case.ciphertext,
                    aad=case.aad,
                    tag=case.tag,
                )
            except Exception:  # noqa: BLE001 - any rejection is the verdict
                # ACVP builds deliberate authentication failures into decrypt
                # groups. Rejecting one is the right answer, not an error.
                cases.append({"tcId": case.tc_id, "testPassed": False})
                continue
            assert decrypted.plaintext is not None  # noqa: S101
            cases.append({"tcId": case.tc_id, "testPassed": True, "pt": _hex(decrypted.plaintext)})
        groups.append({"tgId": group.tg_id, "tests": cases})
    return groups


# --------------------------------------------------------------------------- AES modes


def _aes_mode_case(
    algorithm: str, group: aes_modes.AesGroup, case: aes_modes.AesCase, provider: AesModeProvider
) -> dict[str, object]:
    """Answer one ECB, CMAC, GMAC, KW or KWP case."""
    if algorithm == aes_modes.ECB:
        encrypt = group.direction == "encrypt"
        produced = provider.ecb(
            key=case.fields["key"],
            data=case.fields["pt" if encrypt else "ct"],
            encrypt=encrypt,
        )
        return {"tcId": case.tc_id, "ct" if encrypt else "pt": _hex(produced)}

    if algorithm == aes_modes.CMAC:
        assert group.mac_length_bits is not None  # noqa: S101
        produced = provider.cmac(
            key=case.fields["key"],
            message=case.fields.get("message", b""),
            mac_length_bits=group.mac_length_bits,
        )
        if group.direction == "gen":
            return {"tcId": case.tc_id, "mac": _hex(produced)}
        return {"tcId": case.tc_id, "testPassed": produced == case.fields.get("mac")}

    if algorithm == aes_modes.GMAC:
        assert group.tag_length_bits is not None  # noqa: S101
        produced = provider.gmac(
            key=case.fields["key"],
            iv=case.fields["iv"],
            aad=case.fields.get("aad", b""),
            tag_length_bits=group.tag_length_bits,
        )
        if group.direction == "encrypt":
            return {"tcId": case.tc_id, "tag": _hex(produced)}
        return {"tcId": case.tc_id, "testPassed": produced == case.fields.get("tag")}

    wrap = group.direction == "encrypt"
    try:
        produced = provider.key_wrap(
            key=case.fields["key"],
            data=case.fields["pt" if wrap else "ct"],
            padded=algorithm == aes_modes.KWP,
            wrap=wrap,
        )
    except ValueError:
        # Half of each upstream unwrap group is a deliberately corrupt
        # wrapping; refusing it is the answer.
        return {"tcId": case.tc_id, "testPassed": False}
    if wrap:
        return {"tcId": case.tc_id, "ct": _hex(produced)}
    return {"tcId": case.tc_id, "testPassed": True, "pt": _hex(produced)}


def _aes_modes_groups(
    document: dict[str, object], harness: Harness | None = None
) -> list[dict[str, object]]:
    """ECB (including Monte Carlo), CMAC, GMAC and the two key wraps."""
    vector_set = aes_modes.parse_vector_set(document)
    algorithm = vector_set.algorithm
    provider: AesModeProvider = (
        CryptographyAesModeProvider()
        if harness is None
        else harness.open(
            SubprocessAesModeProvider.from_command_string(
                harness.command, timeout_seconds=harness.timeout_seconds
            )
        )
    )
    groups: list[dict[str, object]] = []
    for group in vector_set.test_groups:
        if algorithm in (aes_modes.KW, aes_modes.KWP) and group.kw_cipher != (
            aes_modes.STANDARD_KW_CIPHER
        ):
            raise ResponseError(
                f"tgId {group.tg_id} uses kwCipher {group.kw_cipher!r}, which this runner "
                "does not implement; register only 'cipher' for a submission"
            )
        cases: list[dict[str, object]] = []
        for case in group.tests:
            if algorithm == aes_modes.ECB and group.test_type == "MCT":
                encrypt = group.direction == "encrypt"
                chain = provider.ecb_monte_carlo(
                    key=case.fields["key"],
                    data=case.fields["pt" if encrypt else "ct"],
                    encrypt=encrypt,
                )
                cases.append(
                    {
                        "tcId": case.tc_id,
                        "resultsArray": [
                            {
                                "key": _hex(key),
                                "pt" if encrypt else "ct": _hex(source),
                                "ct" if encrypt else "pt": _hex(result),
                            }
                            for key, source, result in chain
                        ],
                    }
                )
                continue
            cases.append(_aes_mode_case(algorithm, group, case, provider))
        groups.append({"tgId": group.tg_id, "tests": cases})
    return groups


# --------------------------------------------------------------------------- AES chaining


def _aes_block_groups(
    document: dict[str, object], harness: Harness | None = None
) -> list[dict[str, object]]:
    """CBC, CTR, OFB and CFB128: one transform per case, plus the MCT chain."""
    vector_set = aes_block.parse_vector_set(document)
    algorithm = vector_set.algorithm
    provider: AesBlockProvider = (
        CryptographyAesBlockProvider()
        if harness is None
        else harness.open(
            SubprocessAesBlockProvider.from_command_string(
                harness.command, timeout_seconds=harness.timeout_seconds
            )
        )
    )
    groups: list[dict[str, object]] = []
    for group in vector_set.test_groups:
        encrypt = group.direction == "encrypt"
        name = "ct" if encrypt else "pt"
        source = "pt" if encrypt else "ct"
        cases: list[dict[str, object]] = []
        for case in group.tests:
            if group.test_type == aes_block.MCT:
                if not CHAINING_MODES[algorithm]:
                    raise ResponseError(f"{algorithm} has no Monte Carlo test to answer")
                chain = provider.monte_carlo(
                    algorithm=algorithm,
                    key=case.fields["key"],
                    iv=case.fields["iv"],
                    data=case.fields[source],
                    encrypt=encrypt,
                )
                cases.append(
                    {
                        "tcId": case.tc_id,
                        "resultsArray": [
                            {
                                "key": _hex(key),
                                "iv": _hex(iv),
                                source: _hex(started),
                                name: _hex(produced),
                            }
                            for key, iv, started, produced in chain
                        ],
                    }
                )
                continue
            cases.append(
                {
                    "tcId": case.tc_id,
                    name: _hex(
                        provider.transform(
                            algorithm=algorithm,
                            key=case.fields["key"],
                            iv=case.fields["iv"],
                            data=case.fields[source],
                            encrypt=encrypt,
                        )
                    ),
                }
            )
        groups.append({"tgId": group.tg_id, "tests": cases})
    return groups


# --------------------------------------------------------------------------- ctrDRBG


def _ctr_drbg_groups(
    document: dict[str, object], harness: Harness | None = None
) -> list[dict[str, object]]:
    """The bits returned by the second generation of each case."""
    vector_set = ctr_drbg.parse_vector_set(document)
    provider: ctr_drbg.DrbgRunner
    if harness is not None:
        provider = harness.open(
            SubprocessDrbg(
                vector_set.algorithm,
                shlex.split(harness.command),
                timeout_seconds=harness.timeout_seconds,
            )
        )
    elif vector_set.algorithm == ctr_drbg.ALGORITHM:
        provider = CryptographyCtrDrbg()
    else:
        provider = HashDrbg() if vector_set.algorithm == ctr_drbg.HASH_DRBG else HmacDrbg()
    groups: list[dict[str, object]] = []
    for group in vector_set.groups:
        # Capability is the implementation's to declare. With a harness the
        # mode travels on the wire and the harness answers or declines it; the
        # built-in table describes only the built-in provider.
        if harness is None and group.mode not in ctr_drbg.SUPPORTED[vector_set.algorithm]:
            raise ResponseError(
                f"tgId {group.tg_id} uses mode {group.mode!r}, which the built-in provider does "
                f"not implement for {vector_set.algorithm}; three-key TDES has been disallowed "
                "for this use since 2023. Pass --provider-command to answer it from an "
                "implementation that offers it."
            )
        cases: list[dict[str, object]] = []
        for case in group.cases:
            # One driver for the whole case, shared with the offline runner, so
            # the prediction-resistance and generate-twice rules live in exactly
            # one place rather than in every caller. A harness takes the same
            # case in a single exchange instead.
            arguments = {
                "mode": group.mode,
                "derivation_function": group.derivation_function,
                "counter_field_bits": group.counter_field_bits,
                "byte_count": group.returned_bits // 8,
                "entropy": case.entropy,
                "nonce": case.nonce,
                "personalization": case.personalization,
                "operations": [
                    (step.intended_use, step.additional_input, step.entropy)
                    for step in case.operations
                ],
            }
            produced: bytes | None
            if isinstance(provider, SubprocessDrbg):
                produced = provider.run_case(**arguments)  # type: ignore[arg-type]
            else:
                produced = run_drbg_case(provider, **arguments)  # type: ignore[arg-type]
            if produced is None:
                raise ResponseError(f"tgId {group.tg_id} tcId {case.tc_id} requests no generation")
            cases.append({"tcId": case.tc_id, "returnedBits": _hex(produced)})
        groups.append({"tgId": group.tg_id, "tests": cases})
    return groups


# --------------------------------------------------------------------------- KDF


def _kdf_groups(
    document: dict[str, object], harness: Harness | None = None
) -> list[dict[str, object]]:
    """Derived keying material, plus the fixed data this client chose.

    Unlike every other family here, the prompt does not supply the whole input:
    SP 800-108 leaves ``fixedData`` to the implementation. So a submission has
    to invent it and report it, and the server checks that ``keyOut`` follows
    from what was reported.
    """
    vector_set = kdf.parse_vector_set(document)
    provider: KdfProvider = (
        CryptographyKdf()
        if harness is None
        else harness.open(
            SubprocessKdfProvider.from_command_string(
                harness.command, timeout_seconds=harness.timeout_seconds
            )
        )
    )
    groups: list[dict[str, object]] = []
    for group in vector_set.groups:
        # As with the DRBGs: macMode is sent to the harness, which decides.
        if (
            harness is None
            and group.mac_mode not in HMAC_MODES
            and group.mac_mode not in CMAC_MODES
        ):
            raise ResponseError(
                f"tgId {group.tg_id} uses macMode {group.mac_mode!r}, which the built-in "
                "provider does not implement; pass --provider-command to answer it from an "
                "implementation that offers it"
            )
        cases: list[dict[str, object]] = []
        for case in group.cases:
            fixed_data = secrets.token_bytes(FIXED_DATA_BYTES)
            break_location = 0
            answer: dict[str, object] = {"tcId": case.tc_id, "fixedData": _hex(fixed_data)}
            if group.counter_location == MIDDLE_FIXED:
                # A bit offset strictly inside the fixed data, and never on the
                # very edge, which would be indistinguishable from before/after.
                break_location = secrets.randbelow(len(fixed_data) * 8 - 1) + 1
                answer["breakLocation"] = break_location
            derived = provider.derive(
                KdfRequest(
                    mac_mode=group.mac_mode,
                    kdf_mode=group.kdf_mode,
                    counter_location=group.counter_location,
                    counter_bits=group.counter_bits,
                    key_in=case.key_in,
                    fixed_data=fixed_data,
                    output_bits=group.output_bits,
                    iv=case.iv,
                    break_location=break_location,
                )
            )
            answer["keyOut"] = _hex(derived)
            cases.append(answer)
        groups.append({"tgId": group.tg_id, "tests": cases})
    return groups


# --------------------------------------------------------------------------- ECDSA


def _ecdsa_groups(
    document: dict[str, object], harness: Harness | None = None
) -> list[dict[str, object]]:
    """Signatures under one key per group, or a verdict per case."""
    vector_set = ecdsa.parse_vector_set(document)
    provider: EcdsaProvider = (
        CryptographyEcdsaProvider()
        if harness is None
        else harness.open(
            SubprocessEcdsaProvider.from_command_string(
                harness.command, timeout_seconds=harness.timeout_seconds
            )
        )
    )
    groups: list[dict[str, object]] = []
    for group in vector_set.test_groups:
        if group.component_test:
            raise ResponseError(
                f"tgId {group.tg_id} is a component test, which this runner does not answer"
            )
        if not provider.supports(curve=group.curve, hash_algorithm=group.hash_algorithm):
            raise ResponseError(
                f"tgId {group.tg_id} uses {group.curve} with {group.hash_algorithm}, which this "
                "OpenSSL build does not offer"
            )
        if vector_set.mode == ecdsa.SIG_VER:
            cases: list[dict[str, object]] = []
            for case in group.tests:
                assert case.qx is not None and case.qy is not None  # noqa: S101
                assert case.r is not None and case.s is not None  # noqa: S101
                cases.append(
                    {
                        "tcId": case.tc_id,
                        "testPassed": provider.verify(
                            curve=group.curve,
                            hash_algorithm=group.hash_algorithm,
                            message=case.message,
                            qx=case.qx,
                            qy=case.qy,
                            r=case.r,
                            s=case.s,
                        ),
                    }
                )
            groups.append({"tgId": group.tg_id, "tests": cases})
            continue

        # One key for the whole group: ACVP reports qx/qy at group level, so a
        # fresh key per case would be unreportable.
        signed = provider.sign_group(
            curve=group.curve,
            hash_algorithm=group.hash_algorithm,
            messages=[case.message for case in group.tests],
        )
        groups.append(
            {
                "tgId": group.tg_id,
                "qx": _hex(signed.qx),
                "qy": _hex(signed.qy),
                "tests": [
                    {"tcId": case.tc_id, "r": _hex(r), "s": _hex(s)}
                    for case, (r, s) in zip(group.tests, signed.signatures, strict=True)
                ],
            }
        )
    return groups


# --------------------------------------------------------------------------- RSA


def _rsa_groups(
    document: dict[str, object], harness: Harness | None = None
) -> list[dict[str, object]]:
    """Signatures under one key per group, verdicts, or raw primitive output."""
    vector_set = rsa.parse_vector_set(document)
    provider: RsaProvider = (
        CryptographyRsaProvider()
        if harness is None
        else harness.open(
            SubprocessRsaProvider.from_command_string(
                harness.command, timeout_seconds=harness.timeout_seconds
            )
        )
    )
    groups: list[dict[str, object]] = []
    for group in vector_set.test_groups:
        signing = vector_set.mode in (rsa.SIG_GEN, rsa.SIG_VER)
        if signing and not provider.supports(
            signature_type=group.signature_type,
            hash_algorithm=group.hash_algorithm,
            mask_function=group.mask_function,
        ):
            raise ResponseError(
                f"tgId {group.tg_id} uses {group.signature_type} with "
                f"{group.hash_algorithm} and mask {group.mask_function or 'none'}, which "
                "this build does not offer"
            )
        cases: list[dict[str, object]] = []

        if vector_set.mode == rsa.SIG_GEN:
            signed = provider.sign_group(
                signature_type=group.signature_type,
                hash_algorithm=group.hash_algorithm,
                mask_function=group.mask_function,
                modulo=group.modulo,
                salt_length=group.salt_length,
                messages=[case.message for case in group.tests],
            )
            groups.append(
                {
                    "tgId": group.tg_id,
                    "n": _hex(signed.n),
                    "e": _hex(signed.e),
                    "tests": [
                        {"tcId": case.tc_id, "signature": _hex(signature)}
                        for case, signature in zip(group.tests, signed.signatures, strict=True)
                    ],
                }
            )
            continue

        for case in group.tests:
            if vector_set.mode == rsa.SIG_VER:
                cases.append(
                    {
                        "tcId": case.tc_id,
                        "testPassed": provider.verify(
                            signature_type=group.signature_type,
                            hash_algorithm=group.hash_algorithm,
                            mask_function=group.mask_function,
                            salt_length=group.salt_length,
                            n=int.from_bytes(group.n, "big"),
                            e=int.from_bytes(group.e, "big"),
                            message=case.message,
                            signature=case.signature,
                        ),
                    }
                )
                continue

            number = int.from_bytes
            n = number(case.n, "big")
            if vector_set.mode == rsa.SIGNATURE_PRIMITIVE:
                if case.d:
                    produced = provider.signature_primitive(
                        n=n, d=number(case.d, "big"), message=number(case.message, "big")
                    )
                else:
                    produced = provider.signature_primitive_crt(
                        n=n,
                        p=number(case.p, "big"),
                        q=number(case.q, "big"),
                        dmp1=number(case.dmp1, "big"),
                        dmq1=number(case.dmq1, "big"),
                        iqmp=number(case.iqmp, "big"),
                        message=number(case.message, "big"),
                    )
                field = "signature"
            else:
                produced = provider.decryption_primitive(
                    n=n, d=number(case.d, "big"), ciphertext=number(case.ciphertext, "big")
                )
                field = "pt"
            # An out-of-range input is answered with the verdict alone: there
            # is no value to report, and reporting one would be a wrong answer.
            if produced is None:
                cases.append({"tcId": case.tc_id, "testPassed": False})
            else:
                cases.append(
                    {
                        "tcId": case.tc_id,
                        "testPassed": True,
                        field: _hex(produced.to_bytes(group.modulo // 8, "big")),
                    }
                )
        groups.append({"tgId": group.tg_id, "tests": cases})
    return groups


# --------------------------------------------------------------------------- KAS-ECC


def _kas_ecc_groups(
    document: dict[str, object], harness: Harness | None = None
) -> list[dict[str, object]]:
    """Z per case, with the public key the implementation used to reach it.

    This is the family where a live session can check something the offline
    runner cannot. An AFT case has the implementation generate an ephemeral
    key, so Z differs every run and cannot be compared with any recorded value
    -- but the server holds the peer private key, so it can recompute Z from
    the public key reported here. VAL cases answer with a verdict instead.
    """
    vector_set = kas_ecc.parse_vector_set(document)
    provider: KasEccProvider = (
        CryptographyKasEcc()
        if harness is None
        else harness.open(
            SubprocessKasEcc.from_command_string(
                harness.command, timeout_seconds=harness.timeout_seconds
            )
        )
    )
    groups: list[dict[str, object]] = []
    for group in vector_set.groups:
        if group.scheme != kas_ecc.EPHEMERAL_UNIFIED:
            raise ResponseError(
                f"tgId {group.tg_id} uses scheme {group.scheme!r}, which this runner does not "
                "answer; register only 'ephemeralUnified' for a submission"
            )
        if harness is None and group.curve not in KAS_CURVES:
            raise ResponseError(
                f"tgId {group.tg_id} uses {group.curve}, which the built-in provider does not "
                "offer; pass --provider-command to answer it from an implementation that does"
            )
        cases: list[dict[str, object]] = []
        for case in group.tests:
            computed = provider.shared_secret(
                curve=group.curve,
                peer_x=case.server_x,
                peer_y=case.server_y,
                private_key=case.private_key,
            )
            if group.test_type == kas_ecc.VAL:
                if case.claimed_z is None:
                    raise ResponseError(
                        f"tgId {group.tg_id} tcId {case.tc_id} is a VAL case with no z"
                    )
                cases.append({"tcId": case.tc_id, "testPassed": computed.z == case.claimed_z})
            else:
                cases.append(
                    {
                        "tcId": case.tc_id,
                        "ephemeralPublicIutX": _hex(computed.x),
                        "ephemeralPublicIutY": _hex(computed.y),
                        "z": _hex(computed.z),
                    }
                )
        groups.append({"tgId": group.tg_id, "tests": cases})
    return groups


# --------------------------------------------------------------------------- PQC


def _require_harness(harness: Harness | None, algorithm: str) -> Harness:
    """PQC has no built-in provider, so a submission must come from a harness.

    ``cryptography`` implements neither ML-KEM nor ML-DSA, and inventing an
    answer is not an option: ACVP scores a missing case as a wrong answer. So
    this refuses clearly rather than emitting a document nobody computed.
    """
    if harness is None:
        raise ResponseError(
            f"{algorithm} has no built-in provider, so a submission cannot be built from this "
            "runner alone. Pass --provider-command naming your implementation; "
            "examples/pqc_reference_harness.py shows the shape."
        )
    return harness


def _ml_kem_groups(
    document: dict[str, object], harness: Harness | None = None
) -> list[dict[str, object]]:
    """Ciphertext and shared secret when encapsulating, the secret when decapsulating.

    The two key-check functions answer with a verdict instead: ACVP supplies
    keys that are deliberately malformed, and rejecting one is the correct
    answer rather than an error.
    """
    vector_set = pqc.parse_vector_set(document)
    provider = _require_harness(harness, vector_set.algorithm).open(
        SubprocessMlKemProvider.from_command_string(
            harness.command,  # type: ignore[union-attr]
            timeout_seconds=harness.timeout_seconds,  # type: ignore[union-attr]
        )
    )
    groups: list[dict[str, object]] = []
    for group in vector_set.test_groups:
        if group.parameter_set not in ML_KEM_PARAMETER_SETS:
            raise ResponseError(
                f"tgId {group.tg_id} uses parameter set {group.parameter_set!r}, which is not "
                "an ML-KEM parameter set this runner recognises"
            )
        cases: list[dict[str, object]] = []
        for case in group.tests:
            if group.function in pqc.KEY_CHECKS:
                key_type = "ek" if group.function == pqc.ENCAP_KEY_CHECK else "dk"
                if key_type not in case.fields:
                    raise ResponseError(
                        f"tgId {group.tg_id} tcId {case.tc_id} is missing {key_type}"
                    )
                cases.append(
                    {
                        "tcId": case.tc_id,
                        "testPassed": provider.check_key(
                            parameter_set=group.parameter_set,
                            key_type=key_type,
                            key=case.fields[key_type],
                        ),
                    }
                )
            elif group.function == pqc.ENCAPSULATION:
                if not {"ek", "m"} <= set(case.fields):
                    raise ResponseError(f"tgId {group.tg_id} tcId {case.tc_id} is missing ek or m")
                ciphertext, shared = provider.encapsulate(
                    parameter_set=group.parameter_set,
                    encapsulation_key=case.fields["ek"],
                    seed=case.fields["m"],
                )
                cases.append({"tcId": case.tc_id, "c": _hex(ciphertext), "k": _hex(shared)})
            elif group.function == pqc.DECAPSULATION:
                if not {"dk", "c"} <= set(case.fields):
                    raise ResponseError(f"tgId {group.tg_id} tcId {case.tc_id} is missing dk or c")
                cases.append(
                    {
                        "tcId": case.tc_id,
                        "k": _hex(
                            provider.decapsulate(
                                parameter_set=group.parameter_set,
                                decapsulation_key=case.fields["dk"],
                                ciphertext=case.fields["c"],
                            )
                        ),
                    }
                )
            else:
                raise ResponseError(
                    f"tgId {group.tg_id} uses function {group.function!r}, which this runner "
                    "does not answer"
                )
        groups.append({"tgId": group.tg_id, "tests": cases})
    return groups


def _ml_dsa_groups(
    document: dict[str, object], harness: Harness | None = None
) -> list[dict[str, object]]:
    """A verdict per case: ACVP supplies signatures that may be deliberately invalid."""
    vector_set = pqc.parse_vector_set(document)
    provider = _require_harness(harness, vector_set.algorithm).open(
        SubprocessMlDsaProvider.from_command_string(
            harness.command,  # type: ignore[union-attr]
            timeout_seconds=harness.timeout_seconds,  # type: ignore[union-attr]
        )
    )
    groups: list[dict[str, object]] = []
    for group in vector_set.test_groups:
        if group.parameter_set not in ML_DSA_PARAMETER_SETS:
            raise ResponseError(
                f"tgId {group.tg_id} uses parameter set {group.parameter_set!r}, which is not "
                "an ML-DSA parameter set this runner recognises"
            )
        if group.external_mu:
            raise ResponseError(
                f"tgId {group.tg_id} is an externalMu group, which supplies a precomputed mu "
                "this runner does not pass to an implementation; do not register externalMu "
                "for a submission"
            )
        if group.pre_hash != "pure":
            raise ResponseError(
                f"tgId {group.tg_id} uses preHash {group.pre_hash!r}, which this runner does "
                "not answer; register only 'pure' for a submission"
            )
        cases: list[dict[str, object]] = []
        for case in group.tests:
            missing = [n for n in ("pk", "message", "signature") if n not in case.fields]
            if missing:
                raise ResponseError(
                    f"tgId {group.tg_id} tcId {case.tc_id} is missing {', '.join(missing)}"
                )
            cases.append(
                {
                    "tcId": case.tc_id,
                    "testPassed": provider.verify(
                        parameter_set=group.parameter_set,
                        public_key=case.fields["pk"],
                        message=case.fields["message"],
                        signature=case.fields["signature"],
                        context=case.fields.get("context", b""),
                        signature_interface=group.signature_interface,
                    ),
                }
            )
        groups.append({"tgId": group.tg_id, "tests": cases})
    return groups


# --------------------------------------------------------------------------- dispatch


def _builder_for(algorithm: str) -> _Builder | None:
    """The response builder for one algorithm name, if there is one."""
    if algorithm in HASHLIB_ALGORITHMS:
        return _sha2_groups
    if algorithm.removeprefix("HMAC-") in HASHLIB_ALGORITHMS:
        return _hmac_groups
    return {
        "ACVP-AES-GCM": _aes_gcm_groups,
        aes_modes.ECB: _aes_modes_groups,
        aes_modes.CMAC: _aes_modes_groups,
        aes_modes.GMAC: _aes_modes_groups,
        aes_modes.KW: _aes_modes_groups,
        aes_modes.KWP: _aes_modes_groups,
        **dict.fromkeys(aes_block.SUPPORTED, _aes_block_groups),
        **dict.fromkeys(ctr_drbg.SUPPORTED, _ctr_drbg_groups),
        kdf.ALGORITHM: _kdf_groups,
        "ECDSA": _ecdsa_groups,
        rsa.ALGORITHM: _rsa_groups,
        kas_ecc.ALGORITHM: _kas_ecc_groups,
        "ML-KEM": _ml_kem_groups,
        "ML-DSA": _ml_dsa_groups,
    }.get(algorithm)


def build_response(prompt_file: Path, *, harness: Harness | None = None) -> dict[str, object]:
    """Compute the ACVP response document for one downloaded prompt.

    With ``harness`` supplied, every value in the document comes from the
    vendor's implementation rather than from the built-in providers. The
    document itself is identical in shape either way -- the server is told what
    was computed, never how.
    """
    document = json.loads(Path(prompt_file).read_text(encoding="utf-8"))
    algorithm = str(document.get("algorithm"))
    builder = _builder_for(algorithm)
    if builder is None:
        raise ResponseError(
            f"no response builder for {algorithm!r}; "
            "the offline runner can still verify it against expected results"
        )
    try:
        groups = builder(document, harness)
    except HarnessUnsupportedError as error:
        # Offline, a declined case is reported UNSUPPORTED and the run
        # continues. There is no such verdict here: ACVP scores a missing case
        # as a wrong answer, so a partial document would be recorded as a
        # failure the implementation never earned.
        raise ResponseError(
            f"the harness declined a case in {algorithm} ({error}); a submission missing "
            "cases is scored as wrong answers, so none was built"
        ) from error
    finally:
        if harness is not None:
            harness.close()
    return {
        "vsId": document.get("vsId"),
        "algorithm": algorithm,
        "revision": document.get("revision"),
        "testGroups": groups,
    }


def supported_response_algorithms() -> tuple[str, ...]:
    """Algorithms for which a submission can be constructed.

    ML-KEM and ML-DSA are included, but only reachable with
    ``--provider-command``: there is no built-in post-quantum implementation,
    and a submission must carry values something actually computed.
    """
    names = {
        "ML-KEM",
        "ML-DSA",
        kas_ecc.ALGORITHM,
        "ACVP-AES-GCM",
        aes_modes.ECB,
        aes_modes.CMAC,
        aes_modes.GMAC,
        aes_modes.KW,
        aes_modes.KWP,
        *aes_block.SUPPORTED,
        *ctr_drbg.SUPPORTED,
        kdf.ALGORITHM,
        "ECDSA",
        rsa.ALGORITHM,
        *HASHLIB_ALGORITHMS,
        *(f"HMAC-{name}" for name in HASHLIB_ALGORITHMS),
    }
    return tuple(sorted(names))


__all__ = [
    "FIXED_DATA_BYTES",
    "ResponseError",
    "Harness",
    "build_response",
    "supported_response_algorithms",
]
