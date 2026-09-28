# PQC coverage: what liboqs answers, and through which interface

Every case below is one of NIST's, at ACVP-Server commit
`975de31eb83d87039ec88934fdc47d8c312b892d`, answered by liboqs **0.16.0**
(`5a1a854b0dc9f2141bdc771c555ee60c37950183`) through `examples/liboqs`. The table
is generated, not maintained:

```sh
make -C examples/liboqs LIBOQS=<prefix> LIBOQS_COMMIT=5a1a854b0dc9f2141bdc771c555ee60c37950183
python3 scripts/check_liboqs_coverage.py --print-table
```

CI runs the same script without `--print-table`, and fails if any count moves.

## The headline

| | cases | PASS | FAIL | declined |
| --- | ---: | ---: | ---: | ---: |
| `--interface public` — `OQS_KEM_*` and `OQS_SIG_*` only | 855 | 285 | **0** | 570 `interface_lacks` |
| `--interface extended` — the entry points underneath | 855 | 815 | **0** | 40 `implementation_lacks` |

Nothing fails in either mode. liboqs agrees with NIST on every case it can be
asked; the whole difference between 285 and 815 is which questions its published
C API can be asked at all.

**ML-KEM is unaffected.** All 240 of its cases pass in both modes, because
`OQS_KEM_ml_kem_*_keypair_derand` takes the `d || z` ACVP supplies and
`_encaps_derand` takes `m`. A KEM whose API accepts its randomness is a KEM whose
generation cases are testable.

**ML-DSA is the entire gap.** `OQS_SIG_ml_dsa_*_keypair` derives a key pair from a
seed it draws itself and has no parameter for one. `_sign` and `_sign_with_ctx_str`
hedge with randomness they draw themselves and have no parameter for ACVP's `rnd`.
`_verify_with_ctx_str` takes neither a `mu` nor a pre-hash OID. So through the
published API:

* all 75 keyGen cases are unreachable,
* all 360 sigGen cases are unreachable, deterministic ones included — a
  deterministic signature needs `rnd` to be 32 zero bytes, and there is nowhere
  to say so,
* 135 of 180 sigVer cases are unreachable, leaving the 45 pure external ones.

That 45 is worth dwelling on: it is exactly the figure a collaborator reported
from `liboqs-python`. The binding was never the limit. The C API was.

One layer down, liboqs vendors `mldsa-native`, whose `keypair_internal`,
`signature_internal`, `signature_pre_hash_internal`, `verify_internal` and
`verify_extmu` take the seed, the `rnd`, the `mu` and the pre-hash OID. Every one
of those cases then passes.

## What is still declined, and why it is not a gap in liboqs's cryptography

The 40 `implementation_lacks` cases in extended mode are HashML-DSA cases naming
`SHA2-224`, `SHA2-512/224`, `SHA2-512/256` or `SHA3-224`. liboqs exposes
SHA2-256/384/512, SHA3-256/384/512 and SHAKE-128/256, and no others.

The harness could implement those four digests in twenty lines and answer all 40.
It deliberately does not: a digest written there would put that file under test
rather than the library, and a wrong one would report a conforming module as
broken. `examples/pqc_reference_harness.py` answers all 360 sigGen cases through
`dilithium-py` and Python's `hashlib`, which is how the OID construction and the
prefix rules were checked independently of liboqs.

## The full table

Operation × parameter set × result state, with case counts. `sigGen` and `sigVer`
rows name the four group parameters that decide the answer: the signature
interface, whether the message is pre-hashed or arrives as an external `mu`, and
for sigGen whether the randomness is deterministic or hedged.

| interface | operation | parameter set | result | cases |
| --- | --- | --- | --- | ---: |
| public | keyGen | ML-KEM-1024 | PASS | 25 |
| public | keyGen | ML-KEM-512 | PASS | 25 |
| public | keyGen | ML-KEM-768 | PASS | 25 |
| extended | keyGen | ML-KEM-1024 | PASS | 25 |
| extended | keyGen | ML-KEM-512 | PASS | 25 |
| extended | keyGen | ML-KEM-768 | PASS | 25 |
| public | decapsulation | ML-KEM-1024 | PASS | 10 |
| public | decapsulation | ML-KEM-512 | PASS | 10 |
| public | decapsulation | ML-KEM-768 | PASS | 10 |
| public | decapsulationKeyCheck | ML-KEM-1024 | PASS | 10 |
| public | decapsulationKeyCheck | ML-KEM-512 | PASS | 10 |
| public | decapsulationKeyCheck | ML-KEM-768 | PASS | 10 |
| public | encapsulation | ML-KEM-1024 | PASS | 25 |
| public | encapsulation | ML-KEM-512 | PASS | 25 |
| public | encapsulation | ML-KEM-768 | PASS | 25 |
| public | encapsulationKeyCheck | ML-KEM-1024 | PASS | 10 |
| public | encapsulationKeyCheck | ML-KEM-512 | PASS | 10 |
| public | encapsulationKeyCheck | ML-KEM-768 | PASS | 10 |
| extended | decapsulation | ML-KEM-1024 | PASS | 10 |
| extended | decapsulation | ML-KEM-512 | PASS | 10 |
| extended | decapsulation | ML-KEM-768 | PASS | 10 |
| extended | decapsulationKeyCheck | ML-KEM-1024 | PASS | 10 |
| extended | decapsulationKeyCheck | ML-KEM-512 | PASS | 10 |
| extended | decapsulationKeyCheck | ML-KEM-768 | PASS | 10 |
| extended | encapsulation | ML-KEM-1024 | PASS | 25 |
| extended | encapsulation | ML-KEM-512 | PASS | 25 |
| extended | encapsulation | ML-KEM-768 | PASS | 25 |
| extended | encapsulationKeyCheck | ML-KEM-1024 | PASS | 10 |
| extended | encapsulationKeyCheck | ML-KEM-512 | PASS | 10 |
| extended | encapsulationKeyCheck | ML-KEM-768 | PASS | 10 |
| public | keyGen | ML-DSA-44 | UNSUPPORTED / interface_lacks | 25 |
| public | keyGen | ML-DSA-65 | UNSUPPORTED / interface_lacks | 25 |
| public | keyGen | ML-DSA-87 | UNSUPPORTED / interface_lacks | 25 |
| extended | keyGen | ML-DSA-44 | PASS | 25 |
| extended | keyGen | ML-DSA-65 | PASS | 25 |
| extended | keyGen | ML-DSA-87 | PASS | 25 |
| public | sigGen (external, preHash, deterministic) | ML-DSA-44 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (external, preHash, deterministic) | ML-DSA-65 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (external, preHash, deterministic) | ML-DSA-87 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (external, preHash, hedged) | ML-DSA-44 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (external, preHash, hedged) | ML-DSA-65 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (external, preHash, hedged) | ML-DSA-87 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (external, pure, deterministic) | ML-DSA-44 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (external, pure, deterministic) | ML-DSA-65 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (external, pure, deterministic) | ML-DSA-87 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (external, pure, hedged) | ML-DSA-44 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (external, pure, hedged) | ML-DSA-65 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (external, pure, hedged) | ML-DSA-87 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (internal, externalMu, deterministic) | ML-DSA-44 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (internal, externalMu, deterministic) | ML-DSA-65 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (internal, externalMu, deterministic) | ML-DSA-87 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (internal, externalMu, hedged) | ML-DSA-44 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (internal, externalMu, hedged) | ML-DSA-65 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (internal, externalMu, hedged) | ML-DSA-87 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (internal, pure, deterministic) | ML-DSA-44 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (internal, pure, deterministic) | ML-DSA-65 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (internal, pure, deterministic) | ML-DSA-87 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (internal, pure, hedged) | ML-DSA-44 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (internal, pure, hedged) | ML-DSA-65 | UNSUPPORTED / interface_lacks | 15 |
| public | sigGen (internal, pure, hedged) | ML-DSA-87 | UNSUPPORTED / interface_lacks | 15 |
| extended | sigGen (external, preHash, deterministic) | ML-DSA-44 | PASS | 10 |
| extended | sigGen (external, preHash, deterministic) | ML-DSA-44 | UNSUPPORTED / implementation_lacks | 5 |
| extended | sigGen (external, preHash, deterministic) | ML-DSA-65 | PASS | 11 |
| extended | sigGen (external, preHash, deterministic) | ML-DSA-65 | UNSUPPORTED / implementation_lacks | 4 |
| extended | sigGen (external, preHash, deterministic) | ML-DSA-87 | PASS | 11 |
| extended | sigGen (external, preHash, deterministic) | ML-DSA-87 | UNSUPPORTED / implementation_lacks | 4 |
| extended | sigGen (external, preHash, hedged) | ML-DSA-44 | PASS | 11 |
| extended | sigGen (external, preHash, hedged) | ML-DSA-44 | UNSUPPORTED / implementation_lacks | 4 |
| extended | sigGen (external, preHash, hedged) | ML-DSA-65 | PASS | 11 |
| extended | sigGen (external, preHash, hedged) | ML-DSA-65 | UNSUPPORTED / implementation_lacks | 4 |
| extended | sigGen (external, preHash, hedged) | ML-DSA-87 | PASS | 11 |
| extended | sigGen (external, preHash, hedged) | ML-DSA-87 | UNSUPPORTED / implementation_lacks | 4 |
| extended | sigGen (external, pure, deterministic) | ML-DSA-44 | PASS | 15 |
| extended | sigGen (external, pure, deterministic) | ML-DSA-65 | PASS | 15 |
| extended | sigGen (external, pure, deterministic) | ML-DSA-87 | PASS | 15 |
| extended | sigGen (external, pure, hedged) | ML-DSA-44 | PASS | 15 |
| extended | sigGen (external, pure, hedged) | ML-DSA-65 | PASS | 15 |
| extended | sigGen (external, pure, hedged) | ML-DSA-87 | PASS | 15 |
| extended | sigGen (internal, externalMu, deterministic) | ML-DSA-44 | PASS | 15 |
| extended | sigGen (internal, externalMu, deterministic) | ML-DSA-65 | PASS | 15 |
| extended | sigGen (internal, externalMu, deterministic) | ML-DSA-87 | PASS | 15 |
| extended | sigGen (internal, externalMu, hedged) | ML-DSA-44 | PASS | 15 |
| extended | sigGen (internal, externalMu, hedged) | ML-DSA-65 | PASS | 15 |
| extended | sigGen (internal, externalMu, hedged) | ML-DSA-87 | PASS | 15 |
| extended | sigGen (internal, pure, deterministic) | ML-DSA-44 | PASS | 15 |
| extended | sigGen (internal, pure, deterministic) | ML-DSA-65 | PASS | 15 |
| extended | sigGen (internal, pure, deterministic) | ML-DSA-87 | PASS | 15 |
| extended | sigGen (internal, pure, hedged) | ML-DSA-44 | PASS | 15 |
| extended | sigGen (internal, pure, hedged) | ML-DSA-65 | PASS | 15 |
| extended | sigGen (internal, pure, hedged) | ML-DSA-87 | PASS | 15 |
| public | sigVer (external, preHash) | ML-DSA-44 | UNSUPPORTED / interface_lacks | 15 |
| public | sigVer (external, preHash) | ML-DSA-65 | UNSUPPORTED / interface_lacks | 15 |
| public | sigVer (external, preHash) | ML-DSA-87 | UNSUPPORTED / interface_lacks | 15 |
| public | sigVer (external, pure) | ML-DSA-44 | PASS | 15 |
| public | sigVer (external, pure) | ML-DSA-65 | PASS | 15 |
| public | sigVer (external, pure) | ML-DSA-87 | PASS | 15 |
| public | sigVer (internal, externalMu) | ML-DSA-44 | UNSUPPORTED / interface_lacks | 15 |
| public | sigVer (internal, externalMu) | ML-DSA-65 | UNSUPPORTED / interface_lacks | 15 |
| public | sigVer (internal, externalMu) | ML-DSA-87 | UNSUPPORTED / interface_lacks | 15 |
| public | sigVer (internal, pure) | ML-DSA-44 | UNSUPPORTED / interface_lacks | 15 |
| public | sigVer (internal, pure) | ML-DSA-65 | UNSUPPORTED / interface_lacks | 15 |
| public | sigVer (internal, pure) | ML-DSA-87 | UNSUPPORTED / interface_lacks | 15 |
| extended | sigVer (external, preHash) | ML-DSA-44 | PASS | 10 |
| extended | sigVer (external, preHash) | ML-DSA-44 | UNSUPPORTED / implementation_lacks | 5 |
| extended | sigVer (external, preHash) | ML-DSA-65 | PASS | 9 |
| extended | sigVer (external, preHash) | ML-DSA-65 | UNSUPPORTED / implementation_lacks | 6 |
| extended | sigVer (external, preHash) | ML-DSA-87 | PASS | 11 |
| extended | sigVer (external, preHash) | ML-DSA-87 | UNSUPPORTED / implementation_lacks | 4 |
| extended | sigVer (external, pure) | ML-DSA-44 | PASS | 15 |
| extended | sigVer (external, pure) | ML-DSA-65 | PASS | 15 |
| extended | sigVer (external, pure) | ML-DSA-87 | PASS | 15 |
| extended | sigVer (internal, externalMu) | ML-DSA-44 | PASS | 15 |
| extended | sigVer (internal, externalMu) | ML-DSA-65 | PASS | 15 |
| extended | sigVer (internal, externalMu) | ML-DSA-87 | PASS | 15 |
| extended | sigVer (internal, pure) | ML-DSA-44 | PASS | 15 |
| extended | sigVer (internal, pure) | ML-DSA-65 | PASS | 15 |
| extended | sigVer (internal, pure) | ML-DSA-87 | PASS | 15 |
