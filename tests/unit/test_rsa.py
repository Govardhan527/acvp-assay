"""RSA sigGen, sigVer and the two raw primitives.

The primitives are where the real risk is. Both are bare modular
exponentiation, and both carry a range check -- with *different* bounds. ACVP
includes out-of-range cases precisely to catch an implementation that uses one
rule for both, so those bounds are asserted directly here.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from acvp_assay.algorithms import rsa as rsa_alg
from acvp_assay.models import ResultStatus
from acvp_assay.models import TestCaseResult as CaseResult
from acvp_assay.parser import AcvpValidationError
from acvp_assay.providers.rsa import CryptographyRsaProvider

# Two real 256-bit primes. They have to be prime: the CRT identity only holds
# for a genuine factorisation, so composite stand-ins fail the comparison for
# a reason that has nothing to do with the code under test.
P = 0xE1B1E1B7C1F3D5D7C7D3E1F5B7C3D1E5F7B1C3D5E7F1B3C5D7E1F3B5C7D1E499
Q = 0xC3D5E7F1B3C5D7E1F3B5C7D1E3F5B7C1D3E5F7B1C5D7E3F1B5C7D1E3F5B7C21D


def provider() -> CryptographyRsaProvider:
    """A built-in provider instance."""
    return CryptographyRsaProvider()


def test_the_signature_primitive_admits_zero_and_one() -> None:
    """Valid messages are drawn from [0, n), so both endpoints below n are legal.

    Using the decryption primitive's stricter bounds here would wrongly reject
    two cases that NIST expects answered.
    """
    engine = provider()
    n, d = 3233, 2753

    assert engine.signature_primitive(n=n, d=d, message=0) == 0
    assert engine.signature_primitive(n=n, d=d, message=1) == 1
    assert engine.signature_primitive(n=n, d=d, message=n - 1) is not None
    assert engine.signature_primitive(n=n, d=d, message=n) is None


def test_the_decryption_primitive_excludes_the_endpoints() -> None:
    """SP 800-56B admits only 1 < c < n-1, which is stricter than the signature rule.

    Reusing the signature primitive's `c < n` here would answer four cases that
    NIST expects rejected.
    """
    engine = provider()
    n, d = 3233, 2753

    assert engine.decryption_primitive(n=n, d=d, ciphertext=0) is None
    assert engine.decryption_primitive(n=n, d=d, ciphertext=1) is None
    assert engine.decryption_primitive(n=n, d=d, ciphertext=n - 1) is None
    assert engine.decryption_primitive(n=n, d=d, ciphertext=n) is None
    assert engine.decryption_primitive(n=n, d=d, ciphertext=2) is not None


def test_the_two_primitives_disagree_on_the_endpoints() -> None:
    """The bounds genuinely differ; a single shared rule would be wrong for one."""
    engine = provider()
    n, d = 3233, 2753

    for edge in (0, 1, n - 1):
        assert engine.signature_primitive(n=n, d=d, message=edge) is not None
        assert engine.decryption_primitive(n=n, d=d, ciphertext=edge) is None


def test_the_crt_primitive_agrees_with_the_plain_one() -> None:
    """Half the upstream groups supply CRT parameters and never supply d."""
    engine = provider()
    n = P * Q
    e = 65537
    d = pow(e, -1, (P - 1) * (Q - 1))
    message = 0x1234567890ABCDEF

    plain = engine.signature_primitive(n=n, d=d, message=message)
    crt = engine.signature_primitive_crt(
        n=n,
        p=P,
        q=Q,
        dmp1=d % (P - 1),
        dmq1=d % (Q - 1),
        iqmp=pow(Q, -1, P),
        message=message,
    )

    assert crt == plain
    assert engine.signature_primitive_crt(n=n, p=P, q=Q, dmp1=1, dmq1=1, iqmp=1, message=n) is None


@pytest.mark.parametrize(
    ("signature_type", "hash_algorithm", "mask_function", "supported"),
    [
        ("pkcs1v1.5", "SHA2-256", "none", True),
        ("pss", "SHA2-256", "mgf1", True),
        ("pss", "SHA3-256", "mgf1", True),
        # FIPS 186-5 allows a SHAKE mask, signalled by maskFunction rather than
        # by hashAlg. Ignoring the field answers these groups wrongly.
        ("pss", "SHA3-256", "shake-128", False),
        ("pss", "SHAKE-128", "mgf1", False),
        ("ansx9.31", "SHA2-256", "none", False),
    ],
)
def test_support_accounts_for_the_mask_function(
    signature_type: str, hash_algorithm: str, mask_function: str, supported: bool
) -> None:
    """A SHAKE mask is unsupported even when the hash itself is one we have."""
    assert (
        provider().supports(
            signature_type=signature_type,
            hash_algorithm=hash_algorithm,
            mask_function=mask_function,
        )
        is supported
    )


def documents(
    mode: str, group: dict[str, object], expected: list[dict[str, object]]
) -> tuple[dict[str, object], dict[str, object]]:
    """Build a matching prompt and expected-results pair."""
    prompt = {
        "vsId": 1,
        "algorithm": "RSA",
        "mode": mode,
        "revision": "FIPS186-5",
        "testGroups": [group],
    }
    results = {"vsId": 1, "testGroups": [{"tgId": group["tgId"], "tests": expected}]}
    return prompt, results


def run(mode: str, group: dict[str, object], expected: list[dict[str, object]]) -> list[CaseResult]:
    """Parse and execute one group."""
    prompt, results = documents(mode, group, expected)
    return rsa_alg.run_vector_set(
        rsa_alg.parse_vector_set(prompt),
        rsa_alg.parse_expected_results(results),
        provider(),
    )


def test_siggen_checks_its_own_signature() -> None:
    """NIST's signature belongs to NIST's key, so ours is checked against ours."""
    results = run(
        "sigGen",
        {
            "tgId": 1,
            "testType": "GDT",
            "sigType": "pkcs1v1.5",
            "modulo": 2048,
            "hashAlg": "SHA2-256",
            "maskFunction": "none",
            "tests": [{"tcId": 1, "message": b"acvp".hex()}],
        },
        [{"tcId": 1, "signature": "00" * 256}],
    )

    assert [r.status for r in results] == [ResultStatus.PASS]


def test_sigver_rejects_an_invalid_signature() -> None:
    """ACVP builds deliberately invalid signatures in; rejecting one is correct."""
    results = run(
        "sigVer",
        {
            "tgId": 1,
            "testType": "GDT",
            "sigType": "pkcs1v1.5",
            "modulo": 2048,
            "hashAlg": "SHA2-256",
            "maskFunction": "none",
            "n": "C5" + "A3" * 255,
            "e": "010001",
            "tests": [{"tcId": 1, "message": b"acvp".hex(), "signature": "00" * 256}],
        },
        [{"tcId": 1, "testPassed": False}],
    )

    assert [r.status for r in results] == [ResultStatus.PASS]


def test_a_shake_masked_group_is_declared() -> None:
    """Declining is right: this build has no PSS over an extendable-output function."""
    results = run(
        "sigVer",
        {
            "tgId": 1,
            "testType": "GDT",
            "sigType": "pss",
            "modulo": 2048,
            "hashAlg": "SHA3-256",
            "saltLen": 32,
            "maskFunction": "shake-128",
            "n": "C5" + "A3" * 255,
            "e": "010001",
            "tests": [{"tcId": 1, "message": b"acvp".hex(), "signature": "00" * 256}],
        },
        [{"tcId": 1, "testPassed": False}],
    )

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "shake-128" in (results[0].diagnostic or "")


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"algorithm": "ECDSA"}, "expected 'RSA'"),
        ({"mode": "keyGen"}, "expected one of"),
        ({"testGroups": "not-a-list"}, "expected an array"),
    ],
)
def test_malformed_documents_are_rejected(mutation: dict[str, object], message: str) -> None:
    """A prompt this runner cannot trust is refused, not guessed at."""
    prompt, _ = documents(
        "sigVer",
        {
            "tgId": 1,
            "testType": "GDT",
            "sigType": "pkcs1v1.5",
            "modulo": 2048,
            "hashAlg": "SHA2-256",
            "tests": [],
        },
        [],
    )
    with pytest.raises(AcvpValidationError, match=message):
        rsa_alg.parse_vector_set(prompt | mutation)


def test_a_bad_modulus_is_rejected() -> None:
    """The modulus sizes every field length derives from must be sane."""
    prompt, _ = documents(
        "sigVer",
        {"tgId": 1, "testType": "GDT", "sigType": "pkcs1v1.5", "modulo": 2049, "tests": []},
        [],
    )
    with pytest.raises(AcvpValidationError, match="multiple of 8"):
        rsa_alg.parse_vector_set(prompt)


def test_a_non_boolean_verdict_is_rejected() -> None:
    """testPassed is a verdict, not a string."""
    _, results = documents("sigVer", {"tgId": 1, "modulo": 2048, "tests": []}, [])
    groups = results["testGroups"]
    assert isinstance(groups, list)
    groups[0]["tests"] = [{"tcId": 1, "testPassed": "yes"}]
    with pytest.raises(AcvpValidationError, match="expected a boolean"):
        rsa_alg.parse_expected_results(results)


def test_files_round_trip_through_the_loaders(tmp_path: Path) -> None:
    """The path-taking loaders parse what the document parsers accept."""
    prompt, results = documents(
        "decryptionPrimitive",
        {"tgId": 1, "testType": "AFT", "modulo": 2048, "tests": []},
        [{"tcId": 1, "testPassed": False}],
    )
    (tmp_path / "prompt.json").write_text(json.dumps(prompt), encoding="utf-8")
    (tmp_path / "expected.json").write_text(json.dumps(results), encoding="utf-8")

    vector_set = rsa_alg.load_vector_set(tmp_path / "prompt.json")
    expected = rsa_alg.load_expected_results(tmp_path / "expected.json")

    assert vector_set.mode == "decryptionPrimitive"
    assert expected.cases[1].test_passed is False


def test_provider_metadata_names_the_backend() -> None:
    """A report is only meaningful if it says what produced it."""
    metadata = provider().metadata()

    assert metadata.name == "cryptography-rsa"
    assert metadata.backend_name == "OpenSSL"
    assert metadata.library_version and metadata.backend_version


def primitive_group(mode: str, **case_fields: object) -> dict[str, object]:
    """A one-case primitive group over the small test key."""
    n = P * Q
    e = 65537
    d = pow(e, -1, (P - 1) * (Q - 1))
    modulo = (n.bit_length() + 7) // 8 * 8
    case: dict[str, object] = {
        "tcId": 1,
        "n": f"{n:0{modulo // 4}X}",
        "e": f"{e:06X}",
        "d": f"{d:0{modulo // 4}X}",
        **case_fields,
    }
    return {"tgId": 1, "testType": "AFT", "modulo": modulo, "keyMode": "standard", "tests": [case]}


def test_a_primitive_in_range_compares_its_value() -> None:
    """An in-range input is answered with the exponentiation, and compared."""
    n = P * Q
    d = pow(65537, -1, (P - 1) * (Q - 1))
    message = 0x2468ACE0
    modulo = (n.bit_length() + 7) // 8 * 8
    answer = pow(message, d, n).to_bytes(modulo // 8, "big").hex().upper()

    group = primitive_group("signaturePrimitive", message=f"{message:0{modulo // 4}X}")
    good = run("signaturePrimitive", group, [{"tcId": 1, "testPassed": True, "signature": answer}])
    bad = run(
        "signaturePrimitive", group, [{"tcId": 1, "testPassed": True, "signature": "00" * 64}]
    )

    assert good[0].status is ResultStatus.PASS
    assert bad[0].status is ResultStatus.FAIL
    assert bad[0].diagnostic == "primitive output differs"


def test_an_out_of_range_primitive_answers_with_a_verdict_alone() -> None:
    """Out of range means no value at all, only testPassed: false."""
    n = P * Q
    modulo = (n.bit_length() + 7) // 8 * 8
    group = primitive_group("decryptionPrimitive", ct=f"{1:0{modulo // 4}X}")

    agreed = run("decryptionPrimitive", group, [{"tcId": 1, "testPassed": False}])
    disagreed = run("decryptionPrimitive", group, [{"tcId": 1, "testPassed": True}])

    assert agreed[0].status is ResultStatus.PASS
    assert disagreed[0].status is ResultStatus.FAIL


@pytest.mark.parametrize(
    ("drop", "fragment"),
    [("n", "no modulus"), ("d", "no usable private key")],
)
def test_a_primitive_case_missing_key_material_is_declared(drop: str, fragment: str) -> None:
    """A case this runner cannot answer is declared, not guessed at."""
    group = primitive_group("signaturePrimitive", message="02")
    del group["tests"][0][drop]  # type: ignore[index]
    results = run("signaturePrimitive", group, [{"tcId": 1, "testPassed": True}])

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert fragment in (results[0].diagnostic or "")


def test_a_decryption_case_without_a_private_exponent_is_declared() -> None:
    """decryptionPrimitive has no CRT fallback in this runner."""
    group = primitive_group("decryptionPrimitive", ct="02")
    del group["tests"][0]["d"]  # type: ignore[index]
    results = run("decryptionPrimitive", group, [{"tcId": 1, "testPassed": True}])

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "private exponent" in (results[0].diagnostic or "")


def test_missing_expectations_are_declared() -> None:
    """No recorded verdict, and no recorded value, are both declared."""
    n = P * Q
    modulo = (n.bit_length() + 7) // 8 * 8
    group = primitive_group("signaturePrimitive", message=f"{0x99:0{modulo // 4}X}")

    absent_case = run("signaturePrimitive", group, [])
    no_verdict = run("signaturePrimitive", group, [{"tcId": 1}])
    no_value = run("signaturePrimitive", group, [{"tcId": 1, "testPassed": True}])

    assert absent_case[0].status is ResultStatus.UNSUPPORTED
    assert "no expected result" in (absent_case[0].diagnostic or "")
    assert no_verdict[0].status is ResultStatus.UNSUPPORTED
    assert "no expected verdict" in (no_verdict[0].diagnostic or "")
    assert no_value[0].status is ResultStatus.UNSUPPORTED
    assert "no expected value" in (no_value[0].diagnostic or "")


def test_sigver_without_a_verdict_is_declared() -> None:
    """A sigVer case needs a boolean to judge against."""
    results = run(
        "sigVer",
        {
            "tgId": 1,
            "testType": "GDT",
            "sigType": "pkcs1v1.5",
            "modulo": 2048,
            "hashAlg": "SHA2-256",
            "n": "C5" + "A3" * 255,
            "e": "010001",
            "tests": [{"tcId": 1, "message": b"acvp".hex(), "signature": "00" * 256}],
        },
        [{"tcId": 1}],
    )

    assert results[0].status is ResultStatus.UNSUPPORTED
    assert "no expected verdict" in (results[0].diagnostic or "")


def test_a_signature_that_does_not_verify_is_a_failure() -> None:
    """If our own signature will not verify under our own key, say so."""
    from acvp_assay.providers.rsa import RsaGroupSignatures

    class BrokenProvider(CryptographyRsaProvider):
        """Returns a signature that cannot verify, to exercise the failure path."""

        def sign_group(
            self,
            *,
            signature_type: str,
            hash_algorithm: str,
            mask_function: str = "",
            modulo: int,
            salt_length: int,
            messages: Sequence[bytes],
        ) -> RsaGroupSignatures:
            real = super().sign_group(
                signature_type=signature_type,
                hash_algorithm=hash_algorithm,
                mask_function=mask_function,
                modulo=modulo,
                salt_length=salt_length,
                messages=messages,
            )
            return RsaGroupSignatures(n=real.n, e=real.e, signatures=(b"\x00" * len(real.n),))

    prompt, expected = documents(
        "sigGen",
        {
            "tgId": 1,
            "testType": "GDT",
            "sigType": "pkcs1v1.5",
            "modulo": 2048,
            "hashAlg": "SHA2-256",
            "tests": [{"tcId": 1, "message": b"acvp".hex()}],
        },
        [{"tcId": 1, "signature": "00" * 256}],
    )
    results = rsa_alg.run_vector_set(
        rsa_alg.parse_vector_set(prompt),
        rsa_alg.parse_expected_results(expected),
        BrokenProvider(),
    )

    assert results[0].status is ResultStatus.FAIL
    assert results[0].diagnostic == "generated signature did not verify"


def test_the_crt_path_runs_through_the_runner() -> None:
    """A keyMode "crt" group is answered, not declared."""
    n = P * Q
    d = pow(65537, -1, (P - 1) * (Q - 1))
    modulo = (n.bit_length() + 7) // 8 * 8
    message = 0x2468ACE0
    answer = pow(message, d, n).to_bytes(modulo // 8, "big").hex().upper()
    group = {
        "tgId": 1,
        "testType": "AFT",
        "modulo": modulo,
        "keyMode": "crt",
        "tests": [
            {
                "tcId": 1,
                "n": f"{n:0{modulo // 4}X}",
                "e": "010001",
                "p": f"{P:064X}",
                "q": f"{Q:064X}",
                "dmp1": f"{d % (P - 1):064X}",
                "dmq1": f"{d % (Q - 1):064X}",
                "iqmp": f"{pow(Q, -1, P):064X}",
                "message": f"{message:0{modulo // 4}X}",
            }
        ],
    }

    results = run(
        "signaturePrimitive", group, [{"tcId": 1, "testPassed": True, "signature": answer}]
    )

    assert [r.status for r in results] == [ResultStatus.PASS]


def test_an_unknown_signature_type_is_refused_by_the_padding_builder() -> None:
    """ansx9.31 has no padding here, and guessing one would be a wrong answer."""
    from acvp_assay.providers.rsa import _padding

    with pytest.raises(ValueError, match="unsupported sigType"):
        _padding("ansx9.31", "SHA2-256", 0)


@pytest.mark.parametrize("hash_algorithm", ["SHA2-256", "SHA3-256"])
def test_pss_signatures_round_trip(hash_algorithm: str) -> None:
    """PSS with MGF1 is the other half of sigGen, and takes a different padding."""
    results = run(
        "sigGen",
        {
            "tgId": 1,
            "testType": "GDT",
            "sigType": "pss",
            "modulo": 2048,
            "hashAlg": hash_algorithm,
            "saltLen": 32,
            "maskFunction": "mgf1",
            "tests": [{"tcId": 1, "message": b"acvp".hex()}],
        },
        [{"tcId": 1, "signature": "00" * 256}],
    )

    assert [r.status for r in results] == [ResultStatus.PASS]
