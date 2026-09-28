# liboqs harness

A complete acvp-assay harness in C, in one file, driving
[liboqs](https://github.com/open-quantum-safe/liboqs) through its C API. It
answers ML-KEM and ML-DSA.

It exists for a specific reason. liboqs is reachable from Python through
`liboqs-python`, and a great deal of ML-KEM and ML-DSA testing is done that way,
but the binding exposes what the C API exposes — and for ML-DSA that turns out
not to include the inputs ACVP's generation vectors are built from. This harness
goes under the binding, and then under the published C API, and reports honestly
which layer answered each case.

## Build

Needs a built liboqs. Point `LIBOQS` at an install prefix:

```sh
make LIBOQS=$HOME/liboqs-install LIBOQS_COMMIT=5a1a854b0dc9f2141bdc771c555ee60c37950183
```

The measurements below were taken against liboqs **0.16.0**, commit
`5a1a854b0dc9f2141bdc771c555ee60c37950183`, configured
`-DBUILD_SHARED_LIBS=OFF -DOQS_USE_OPENSSL=OFF -DOQS_BUILD_ONLY_LIB=ON`.

`LIBOQS_COMMIT` is recorded in the harness's `metadata` and in
`--capabilities`. It is never guessed: leave it out and the version stands
alone.

**The static archive is linked `--whole-archive`, and that is load-bearing.**
The entry points below `OQS_API` are referenced as weak symbols, and a weak
reference does not pull an object out of a static archive — so without it they
link to null, every ML-DSA operation declines, and the result looks exactly like
a liboqs that does not have them. This cost an hour before it was understood;
the Makefile does it for you.

## Probe first

```sh
./acvp_harness --capabilities
```

It prints, as JSON, what *this* build exposes: which entry points are present,
which layer each is on, which pre-hashes liboqs offers, the compiler and flags,
and the CPU dispatch in effect. Every entry point is a weak symbol that is
checked before it is called, so a null one is a fact about the library in front
of you rather than an assumption. `capabilities.json` in this directory is that
output for the pinned build.

## Two interfaces, and the measurement between them

```sh
# what a caller linking against liboqs's published API can reach
./acvp_harness --interface public

# what liboqs can answer (the default)
./acvp_harness --interface extended
```

`public` restricts the harness to `OQS_KEM_*` and `OQS_SIG_*`. `extended` also
uses the `mldsa-native` entry points that liboqs vendors underneath them. Run
one of each and diff the reports and you have measured the gap between what the
library computes and what its interface can be asked for:

| Vector set | cases | `public` | `extended` |
| --- | ---: | --- | --- |
| `ML-KEM-keyGen-FIPS203` | 75 | 75 pass | 75 pass |
| `ML-KEM-encapDecap-FIPS203` | 165 | 165 pass | 165 pass |
| `ML-DSA-keyGen-FIPS204` | 75 | 75 `interface_lacks` | 75 pass |
| `ML-DSA-sigGen-FIPS204` | 360 | 360 `interface_lacks` | 335 pass, 25 `implementation_lacks` |
| `ML-DSA-sigVer-FIPS204` | 180 | 45 pass, 135 `interface_lacks` | 165 pass, 15 `implementation_lacks` |

Not one case fails in either mode. Everything that does not pass is a decline,
and each decline names which of the two reasons it is:

- **`interface_lacks`** — liboqs computes this and the API cannot be asked for
  it. `OQS_SIG_ml_dsa_44_keypair` derives a key pair from a seed it draws
  itself and has no parameter for one; `OQS_SIG_ml_dsa_44_sign` hedges with
  randomness it draws itself and has no parameter for ACVP's `rnd`;
  `verify_with_ctx_str` takes neither a `mu` nor a pre-hash OID. The repair is
  to expose an entry point, not to write one.
- **`implementation_lacks`** — liboqs genuinely does not offer it. All 40 of
  these are HashML-DSA cases naming `SHA2-224`, `SHA2-512/224`, `SHA2-512/256`
  or `SHA3-224`; liboqs exposes SHA2-256/384/512, SHA3-256/384/512 and
  SHAKE-128/256 and no others.

**This harness computes nothing liboqs does not.** It could implement the four
missing digests in twenty lines and answer those 40 cases, and then a
disagreement would be between NIST and this file rather than between NIST and
the library. Declining them by name is the honest measurement.

## What it answers

| Operation | Through |
| --- | --- |
| `metadata` | `OQS_VERSION_TEXT`, the CPU dispatch, a hash of this executable |
| `ml-kem-keygen` | `OQS_KEM_ml_kem_*_keypair_derand`, seeded with `d \|\| z` |
| `ml-kem-encapsulate` | `OQS_KEM_ml_kem_*_encaps_derand`, seeded with `m` |
| `ml-kem-decapsulate` | `OQS_KEM_decaps` |
| `ml-kem-key-check` | encapsulating or decapsulating under the key |
| `ml-dsa-keygen` | `…_keypair_internal(pk, sk, seed)` |
| `ml-dsa-sign` | `…_signature_internal` or `…_signature_pre_hash_internal` |
| `ml-dsa-verify` | `verify_with_ctx_str` (public), else `…_verify_internal` / `…_verify_pre_hash_internal` |

Three details are worth copying if you adapt this:

- **The 64-byte ML-KEM keypair seed is `d || z`**, in that order. It was checked
  against NIST's recorded `ek` and `dk` rather than read off a header, because
  the other order produces a perfectly valid key pair that matches nothing.
- **A deterministic ML-DSA case signs with 32 zero bytes.** The other reading of
  an absent `rnd` — choose your own — yields a valid signature that matches
  nothing either. The runner sends `deterministic` as its own boolean so the
  question never arises.
- **The external interface signs `00 || len(ctx) || ctx || M`** and the internal
  interface signs `M` with no prefix at all. An empty context still produces a
  two-byte prefix, so "no context" and "empty context" are different answers.

## The identity it reports

`buildId` is a SHA3-256 of this executable. The harness is statically linked
against liboqs, so that hash moves whenever either of them does — which is what
a build identity is for, and is stronger than a version that every build of a
release shares. It needs nothing from the vendor, which is the point
`docs/harness-protocol.md` makes about where a `buildId` can come from.

`build` reports the compiler, the flags, the CPU and the OS. On a library that
dispatches at run time this is not decoration: liboqs picks its ML-DSA backend
from AVX2, BMI2 and POPCNT, so the same binary on two machines runs different
code, and this harness mirrors that dispatch exactly rather than calling the
portable entry point liboqs itself would not have called.

## What it is not

It is a test harness, not a validated module, and running it produces test
evidence rather than any kind of certification. liboqs itself states that it is
not for production use without review; nothing here changes that.
