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
    "./acvp_harness --module /usr/lib/softhsm/libsofthsm2.so --pin 1234"
```

`--module` may also come from `PKCS11_MODULE`, and `--pin` from `PKCS11_PIN`.
`--slot ID` picks a slot; without it the first slot holding a token is used.

## What it answers

| Operation | Mechanism |
| --- | --- |
| `metadata` | `C_GetInfo` |
| `digest` | `CKM_SHA_1`, `CKM_SHA224/256/384/512` |
| `digest-mct` | the SHA-2 Monte Carlo chain, run in the harness |
| `mac` | `CKM_SHA*_HMAC`, truncated to the group's `macLen` |
| `block-transform` | `CKM_AES_ECB`, `CKM_AES_CBC` |
| `encrypt` / `decrypt` | `CKM_AES_GCM` |

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
