# Findings

What driving an implementation through NIST's vectors turned up, with enough
detail to reproduce each one. Everything here is about **liboqs 0.16.0**, commit
`5a1a854b0dc9f2141bdc771c555ee60c37950183`, built
`-DBUILD_SHARED_LIBS=OFF -DOQS_USE_OPENSSL=OFF -DOQS_BUILD_ONLY_LIB=ON`, against
NIST's vectors at ACVP-Server `975de31eb83d87039ec88934fdc47d8c312b892d`.

## The headline is a non-finding, and it is the important one

**liboqs agrees with FIPS 203 and FIPS 204 on every case it can be asked.** 815
of 855 pinned ML-KEM and ML-DSA cases pass, byte for byte against NIST's own
recorded answers, and **not one fails**. The 40 that do not pass are declined,
for the reason in Finding 3.

Nothing below is a conformance defect. All four findings are about what an
interface can be asked for, which is a different question from whether the
answer is right — and one that only shows up when something tries to ask.

---

## Finding 1 — the ML-DSA C API cannot be given the inputs FIPS 204 defines

**Severity: this is what stops liboqs being testable against ML-DSA keyGen and
sigGen at all.** Not a bug; an interface that omits a parameter.

FIPS 204 defines `ML-DSA.KeyGen_internal(ξ)` on a 32-byte seed and
`ML-DSA.Sign_internal(sk, M′, rnd)` on a 32-byte `rnd`. ACVP supplies both,
because that is what makes a generated answer comparable at all. liboqs's
published API takes neither:

```c
OQS_STATUS OQS_SIG_ml_dsa_44_keypair(uint8_t *pk, uint8_t *sk);
OQS_STATUS OQS_SIG_ml_dsa_44_sign(uint8_t *sig, size_t *siglen,
                                  const uint8_t *m, size_t mlen, const uint8_t *sk);
OQS_STATUS OQS_SIG_ml_dsa_44_sign_with_ctx_str(/* … */ const uint8_t *ctx, size_t ctxlen,
                                               const uint8_t *sk);
```

### Reproduction

```c
/* cc -I<prefix>/include repro.c <prefix>/lib/liboqs.a */
#include <oqs/oqs.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    uint8_t pk1[OQS_SIG_ml_dsa_44_length_public_key], sk1[OQS_SIG_ml_dsa_44_length_secret_key];
    uint8_t pk2[OQS_SIG_ml_dsa_44_length_public_key], sk2[OQS_SIG_ml_dsa_44_length_secret_key];
    OQS_SIG_ml_dsa_44_keypair(pk1, sk1);
    OQS_SIG_ml_dsa_44_keypair(pk2, sk2);
    printf("two calls agree: %s\n", memcmp(pk1, pk2, sizeof pk1) == 0 ? "yes" : "no");
    return 0;
}
```

```text
two calls agree: no
```

There is no second entry point that takes a seed, so there is no call that can
produce NIST's `pk` and `sk` for a given `seed`. The same holds for signing:
`_sign` hedges with randomness it draws itself, so a hedged sigGen case cannot be
reproduced and a deterministic one cannot be requested.

### Consequence, measured

Restricted to `OQS_KEM_*` and `OQS_SIG_*`, the harness reaches **285 of 855**
cases: all 240 ML-KEM ones, and 45 of 180 ML-DSA sigVer. The other 570 are
declined `interface_lacks`.

That 45 is the same figure a collaborator reported from `liboqs-python`, which
confirms what this finding says: the limit was never the binding. Any caller of
the published C API has the same ceiling.

### Why ML-KEM is unaffected

`OQS_KEM_ml_kem_*_keypair_derand(pk, sk, seed)` takes the 64-byte `d || z`, and
`_encaps_derand(ct, ss, pk, seed)` takes `m`. The KEM API accepts its randomness
and the signature API does not, which is the whole difference between 240 of 240
and 45 of 615.

### The code is there

liboqs vendors `mldsa-native`, whose `…_keypair_internal(pk, sk, seed)`,
`…_signature_internal(sig, &len, m, mlen, pre, prelen, rnd, sk, externalmu)` and
`…_signature_pre_hash_internal(…)` take exactly those inputs, and are exported
from the static archive. Called directly, they reproduce **75 of 75** keyGen and
**335 of 360** sigGen answers exactly. This is why the decline is
`interface_lacks` and not `implementation_lacks`: the repair is to expose an
entry point, not to write one.

**Suggested upstream change:** add `OQS_SIG_ml_dsa_*_keypair_derand(pk, sk, seed)`
and a signing entry point taking `rnd`, mirroring what the KEM side already does.
Every ACVP generation case becomes answerable through the published API, and
`liboqs-python` inherits it for free.

---

## Finding 2 — liboqs's installed headers do not declare its own hash functions

`OQS_SHA2_sha256`, `OQS_SHA3_shake256` and their siblings are exported from the
library. The installed `sha2_ops.h` and `sha3_ops.h` declare only the *callback
structs* that point at them, so a consumer calling one directly has no prototype.

### Reproduction

```c
#include <oqs/oqs.h>
int main(void) { unsigned char md[32]; OQS_SHA2_sha256(md, (const unsigned char *)"abc", 3); return md[0]; }
```

```text
warning: implicit declaration of function 'OQS_SHA2_sha256' [-Wimplicit-function-declaration]
```

```console
$ nm -g --defined-only liboqs.a | grep -c "T OQS_SHA2_sha256$"
1
$ grep -rl "OQS_SHA2_sha256(" <prefix>/include/ | wc -l
0
```

The symbol is present and usable; only the declaration is missing. On a 64-bit
platform the implicit declaration happens to produce a working call, which is
worse than a hard error: it compiles, it runs, and it is undefined behaviour in
C99 and a hard error in C23.

`examples/liboqs/acvp_harness.c` declares the eight prototypes it needs, with a
comment saying why. **Suggested upstream change:** install the prototypes beside
the callback structs.

---

## Finding 3 — only 8 of HashML-DSA's 12 hash algorithms are reachable

FIPS 204 §5.4 allows twelve pre-hashes and ACVP's sigGen and sigVer sets exercise
all twelve. liboqs exposes SHA2-256/384/512, SHA3-256/384/512, SHAKE-128 and
SHAKE-256 — and not `SHA2-224`, `SHA2-512/224`, `SHA2-512/256` or `SHA3-224`.

### Consequence, measured

40 of 855 cases are declined `implementation_lacks`: 25 in sigGen, 15 in sigVer.
They are spread across every parameter set, because ACVP distributes hash
algorithms within a group rather than by group.

The harness could implement those four digests in twenty lines and answer all 40.
It deliberately does not, and the reason is worth stating: a digest implemented
in the harness puts *the harness* under test rather than the library, and a wrong
one reports a conforming module as broken. `examples/pqc_reference_harness.py`
answers all 360 sigGen cases through `dilithium-py` and Python's `hashlib`, which
is how the pre-hash prefix and OID construction were checked independently.

---

## Finding 4 — a weak reference does not pull an object out of a static archive

A trap rather than a defect, recorded because it produces a convincing wrong
answer. `examples/liboqs/acvp_harness.c` declares every entry point below
`OQS_API` `__attribute__((weak))` and checks it before calling, so that a liboqs
without them declines instead of failing to link. Linked against `liboqs.a` the
ordinary way, **every one of those symbols resolves to null** — not because
liboqs lacks them, but because the linker only extracts an archive member to
satisfy a *strong* undefined reference.

### Reproduction

Link the harness without `--whole-archive` and probe:

```console
$ ./acvp_harness --capabilities | grep keypairFromSeed
    "ML-DSA-44": {"keypairFromSeed": "absent", …
```

With `-Wl,--whole-archive liboqs.a -Wl,--no-whole-archive`:

```console
    "ML-DSA-44": {"keypairFromSeed": "internal", …
```

The first output is indistinguishable, from the outside, from a liboqs built
without the mldsa-native backend — and it would have been reported as one. The
Makefile links `--whole-archive` and says why; the cost is about 800 KB of
binary.

Anyone writing a harness that probes for optional symbols with weak references
needs the same flag, or `-u <symbol>`, or a shared library.
