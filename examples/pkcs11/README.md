# PKCS#11 reference harness

A complete acvp-assay harness in C, in one file, dispatching to a PKCS#11
token. It exists because the case this runner is built for — an HSM that
cannot be linked against — is usually reached through PKCS#11, and because a
claim that "a harness can be written in any language" is worth more with a
non-Python example beside it.

## Build

```sh
make
# or, against your vendor's headers:
make PKCS11_INCLUDE=/opt/vendor/include
```

No dependencies beyond `libdl` and a PKCS#11 header. The JSON handling is in
the file, so there is nothing to vendor and no license to reconcile — copy
`acvp_harness.c` into your tree and edit it.

## Run

```sh
acvp-assay run prompt.json --provider-command \
    "./acvp_harness --module /usr/lib/softhsm/libsofthsm2.so --pin-file /run/user/1000/acvp.pin"
```

**There is no `--pin` option.** argv is readable by every local user through
`/proc/PID/cmdline`, and the runner keeps a harness alive for the whole run rather than
spawning it per case, so a PIN there is exposed for the length of the measurement. Three
ways to supply one, in the order this harness looks for them:

- `--pin-fd N` reads it from a descriptor the caller already opened, which keeps it out of
  the filesystem as well. Name it with `acvp-assay --provider-pass-fd N` so the runner keeps
  it open across the spawn, since Python's `subprocess` closes descriptors above 2. Without
  that option the child must open it itself, which still works:
  `"sh -c 'exec ./acvp_harness --module MODULE --pin-fd 3 3</run/user/1000/acvp.pin'"`.
- `--pin-file PATH` reads it from a file, and refuses one that is readable or writable
  beyond its owner, naming the mode it found. `chmod 600` it.
- `PKCS11_PIN` in the environment still works. `/proc/PID/environ` is owner-only, so it is
  closed to other local users, and it is inherited by every child the harness spawns.

The PIN buffer is zeroed once `C_Login` returns, on the failure path too. `--module` may
also come from `PKCS11_MODULE`, and `--slot ID` picks a slot; without it the first slot
holding a token is used. `docs/harness-protocol.md` tabulates what each method closes.

## What it answers

| Operation | Mechanism |
| --- | --- |
| `metadata` | `C_GetInfo` |
| `digest` | `CKM_SHA_1`, `CKM_SHA224/256/384/512` |
| `digest-mct` | the SHA-2 Monte Carlo chain, run in the harness |
| `mac` | `CKM_SHA*_HMAC`, truncated to the group's `macLen` |
| `block-transform` | `CKM_AES_ECB`, `CKM_AES_CBC` |
| `encrypt` / `decrypt` | `CKM_AES_GCM` |
| `key-wrap` | `CKM_AES_KEY_WRAP`, `CKM_AES_KEY_WRAP_KWP`, through `C_Encrypt` / `C_Decrypt` |
| `ml-dsa-sign` / `ml-dsa-verify` | `CKM_ML_DSA`; preHash through `CKM_HASH_ML_DSA_<hash>`, or `CKM_HASH_ML_DSA` on PH(M) from the token's `C_Digest` for SHA2-512/224 and SHA2-512/256 |

Everything else returns `{"error": "unsupported"}`. That is a first-class
answer, not a stub: the runner records it as UNSUPPORTED rather than as a
failure, because capability belongs to the implementation. Extending the
harness means adding a case to the dispatch in `main` and one `op_` function.

## Verified

Against pinned NIST vectors through SoftHSM 2.6.1:

| Set | Passed | Failed | Unsupported |
| --- | ---: | ---: | ---: |
| `ACVP-AES-GCM-1.0` | 60 | 0 | 0 |
| `ACVP-AES-ECB-1.0` | 2,138 | 0 | 6 |
| `SHA2-256-1.0` | 513 | 0 | 4 |
| `HMAC-SHA2-256-1.0` | 750 | 0 | 225 |

**3,461 cases, no failures.** The unsupported counts are honest and worth
reading: the AES-ECB six and the SHA-2 four are Monte Carlo and large-data
groups this harness does not implement, and the HMAC 225 are keys shorter than
SoftHSM's minimum for those mechanisms. A different token would decline a
different set — which is the point of asking the implementation rather than
assuming.

`key-wrap` was measured separately, through the offline pilot in
`docs/harness-protocol.md`, against FreeHSM `6c54700` (a signed module running
on the OpenSSL 3.5.7 FIPS provider) on the pinned sets:

| Set | Passed | Failed | Declined by the runner |
| --- | ---: | ---: | ---: |
| `ACVP-AES-KW-1.0` | 3,600 | 0 | 3,600 |
| `ACVP-AES-KWP-1.0` | 3,600 | 0 | 3,600 |

The declined half is every group with `kwCipher: inverse`, which the runner
does not answer; none of it is a harness gap. Of the cases that pass, 370 (KW)
and 384 (KWP) are deliberately corrupt wrappings the token refused with
`CKR_ENCRYPTED_DATA_INVALID`, reported as `authentication failed`. The same
run through this harness before `key-wrap` existed passed none and declined
3,600 of each set as `implementation_lacks`.

KWP is `CKM_AES_KEY_WRAP_KWP` (`0x210B`), which PKCS#11 v3.2 defines to give
the same results as RFC 5649. `CKM_AES_KEY_WRAP_PAD` (`0x210A`) is not a
substitute: v3.2 deprecates it in favour of `CKM_AES_KEY_WRAP_KWP` and
`CKM_AES_KEY_WRAP_PKCS7` and gives it no definition of its own, so what a token
computes under it is that token's choice.

A token that offers the wrap mechanisms only through `C_WrapKey` /
`C_UnwrapKey` refuses `C_EncryptInit`, and this harness reports that as
unsupported rather than as a failure. FreeHSM offers both halves, so that path
was measured on SoftHSM 2.6.1 instead, on the same pinned sets:

| Set | Passed | Failed | Declined by the harness | Declined by the runner |
| --- | ---: | ---: | ---: | ---: |
| `ACVP-AES-KW-1.0` | 0 | 0 | 3,600 | 3,600 |
| `ACVP-AES-KWP-1.0` | 0 | 0 | 3,600 | 3,600 |

In each set `C_EncryptInit` and `C_DecryptInit` return `CKR_MECHANISM_INVALID`
1,800 times apiece, and nothing fails or errors. `C_GetMechanismInfo` says why:
SoftHSM lists `CKM_AES_KEY_WRAP` with `CKF_WRAP` and `CKF_UNWRAP` and with
neither `CKF_ENCRYPT` nor `CKF_DECRYPT`, and does not list
`CKM_AES_KEY_WRAP_KWP` at all.

Each of those declines says which of the two it met, in its `detail`:

| Set | `detail` on the harness's 3,600 declines |
| --- | --- |
| `ACVP-AES-KW-1.0` | the token lists CKM_AES_KEY_WRAP for C_WrapKey and C_UnwrapKey only, and this harness asks through C_Encrypt and C_Decrypt |
| `ACVP-AES-KWP-1.0` | the token does not list CKM_AES_KEY_WRAP_KWP |

The reason code is `implementation_lacks` in both, and for `CKM_AES_KEY_WRAP`
it is the detail that keeps it accurate. SoftHSM does have AES-KW, on key
objects; what it does not offer is the byte-level form this harness asks for,
and the harness has no `C_WrapKey` path to fall back on. So a report tells a
token without AES-KW from one that offers it only that way by the detail, not
by the code.

## ML-DSA

PKCS#11 v3.2 section 6.67 decides what this harness can ask, so each of
`ml-dsa-sign`'s switches maps to a mechanism or to a decline:

| Case | Answered with, or declined because |
| --- | --- |
| external interface, pure | `CKM_ML_DSA` with `CK_SIGN_ADDITIONAL_CONTEXT` carrying the context |
| external interface, preHash | `CKM_HASH_ML_DSA_<hash>` on the message; for SHA2-512/224 and SHA2-512/256, which have no mechanism of their own, `CKM_HASH_ML_DSA` on PH(M) computed by the token's `C_Digest` |
| deterministic signing | `hedgeVariant` `CKH_DETERMINISTIC_REQUIRED` |
| hedged signing | `interface_lacks`: `CK_SIGN_ADDITIONAL_CONTEXT` carries no `rnd`, so the token's own randomness matches nothing NIST recorded |
| internal interface | `interface_lacks`: no v3.2 mechanism signs or verifies M′ as given |
| external mu | `interface_lacks`: no v3.2 mechanism takes mu |

Keys come from the vector and are imported with `C_CreateObject`, `CKA_VALUE`
and `CKA_PARAMETER_SET`, which v3.2 Tables 280 and 281 require on creation. A
token that refuses the import or the mechanism is `implementation_lacks`, with
the `CK_RV` in the detail. A verification the token rejects with
`CKR_SIGNATURE_INVALID` or `CKR_SIGNATURE_LEN_RANGE` is `testPassed: false`:
a verdict, not a fault. keyGen is not answered: v3.2 creates a key from its
seed only through `CKA_SEED`, which tokens may refuse.

Measured against FreeHSM `main` at `9a64b77` (the HashML-DSA mechanisms of its
2.4.0, before that release's version bump; a signed `nist-approved-only` module
on the OpenSSL 3.5.7 FIPS provider), on the pinned sets:

| Set | Passed | Failed | Declined by the harness | Declined by the runner |
| --- | ---: | ---: | ---: | ---: |
| `ML-DSA-sigGen-FIPS204` | 90 | 0 | 270 | 0 |
| `ML-DSA-sigVer-FIPS204` | 90 | 0 | 90 | 0 |

The 90 in each are the 45 pure and the 45 preHash cases of the external,
deterministic groups, compared with NIST's answers; in sigVer, 72 of the 90
-- 36 in each group of 45, preHash as well as pure -- are signatures the token
had to reject, and did. Every decline is `interface_lacks`, naming the
standard: external mu in 135 cases (90 sigGen, 45 sigVer), the internal
interface in the other internal-interface groups, and hedged signing in
sigGen. Nothing is `implementation_lacks`, so FreeHSM took every
import and every mechanism.

## Three things worth keeping if you adapt it

**A rejected GCM tag is `{"error": "authentication failed"}`**, never a crash
or a non-zero exit. Roughly a third of NIST's decrypt cases are deliberate
forgeries where rejecting is the correct answer, and a harness that dies on
them scores a conforming module as broken.

**Some `CK_RV` values are capability statements, not faults.**
`CKR_KEY_SIZE_RANGE`, `CKR_MECHANISM_INVALID` and their neighbours mean the
token does not offer something, so they map to `unsupported`. Reporting them
as errors would fail a module that is behaving correctly.

**The Monte Carlo chain is run here, not driven case by case.** At 100,000
inner iterations a round trip per hash would take hours. The `alternate`
variant truncates or zero-pads every message to the width of the *original*
seed, captured once before the loop — not to the digest length, and not
recomputed as the chain's values shrink.

## Diagnostics

Failures print the `CK_RV` to stderr, which the runner passes through to your
terminal but never places in a report — a failing module often quotes key
material, and reports get shared as evidence.

## Testing without an HSM

SoftHSM is enough to exercise the whole path:

```sh
export SOFTHSM2_CONF=$PWD/softhsm2.conf
printf 'directories.tokendir = %s/tokens\n' "$PWD" > softhsm2.conf
mkdir -p tokens
softhsm2-util --init-token --slot 0 --label acvp --so-pin 1234 --pin 1234
```
