# ACVP Assay

[![CI](https://github.com/Govardhan527/acvp-assay/actions/workflows/ci.yml/badge.svg)](https://github.com/Govardhan527/acvp-assay/actions/workflows/ci.yml)
[![Verified against NIST ACVTS](https://img.shields.io/badge/NIST%20ACVTS%20Demo-40%2F40%20algorithms%20passed-2ea44f)](#verified-against-nists-own-server)
[![Coverage](https://img.shields.io/badge/coverage-99.7%25-2ea44f)](#development-commands)

> ## ✅ Judged by NIST's own server
>
> **All 40 supported algorithm names** have been run against **vectors NIST generated live** and
> submitted back for NIST to judge. On `demo.acvts.nist.gov`, **45 vector sets, covering 32,674
> test cases, each came back `"passed"`**, and that verdict is the server's, not this project's.
> [Exactly which, per algorithm](#coverage).
>
> Read those two numbers precisely: ACVP returns one verdict **per vector set**, so 45 is the
> count of verdicts NIST issued and 32,674 is the number of cases inside them. The server never
> issued 32,674 separate verdicts, and this project does not claim it did.
>
> **What this does and does not say about ML-KEM and ML-DSA.** Those two sessions were answered
> by `examples/pqc_reference_harness.py`, which is backed by `kyber-py` and `dilithium-py` —
> educational implementations that are **not constant-time and make no side-channel claims**.
> The passing verdict is evidence that *this runner* parses, routes and answers PQC vector sets
> correctly. It is emphatically **not** evidence that any implementation is fit to ship, and
> there is no built-in PQC provider here: for post-quantum work the implementation under test is
> yours, supplied through `--provider-command`.
>
> Most tools of this kind are checked against static files only. Being checked by the system
> that issues the vectors is what caught the four defects listed under
> [What this caught that fixtures did not](#what-this-caught-that-fixtures-did-not).
>
> **This is test evidence, not a certificate.** It confers no validation status: only an
> accredited CST or 17ACVT laboratory performs CAVP or FIPS 140-3 validation, and Demo is not
> the production ACVTS.

Run NIST ACVP test vectors against any implementation — including ones you cannot link against — and catch conformance regressions between runs.

An *assay* measures composition, it does not certify it. This tool produces reproducible test evidence: it parses ACVP vector sets, executes them through a replaceable provider boundary, compares results case by case, and diffs one run against the next. It does **not** perform or substitute for CAVP algorithm validation or FIPS 140-3 cryptographic-module validation — only accredited CST and 17ACVT laboratories can do that.

Two things distinguish it from `libacvp` and ACVP Proxy, which cover more algorithms and speak the live protocol:

- **It reaches implementations they cannot.** A harness reads one JSON request on stdin and writes one on stdout, so an HSM, a smartcard, an embedded device over a serial link, or a library in any language can be tested without linking anything.
- **It answers "are we *still* conformant?"** `acvp-assay diff` compares two runs and reports regressions, including coverage that silently disappeared. With re-validation running well over a year, that is the failure mode that costs a cycle.

## Scope

Implemented today:

- **40 algorithm names across 22 families** — AES in GCM, ECB, CBC, CTR, OFB, CFB128, GMAC,
  KW and KWP; CMAC-AES; all three SP 800-90A DRBGs; KDF SP 800-108; SHA-1, SHA-2 and SHA-3;
  HMAC over each; RSA; ECDSA; ML-KEM and ML-DSA
- a replaceable provider boundary, in-process or an external harness over JSON — **all 40
  names reach a harness**, so nothing silently tests this project's OpenSSL binding when you
  asked for your own implementation
- **live ACVTS submission from your implementation**: `acvts_client.py submit
  --provider-command ...` answers NIST-generated vectors from your code and returns NIST's
  verdict — all 40 names, ML-KEM and ML-DSA included
- run-over-run regression diffing, including coverage that silently disappeared
- typed parsing that preserves `vsId`, `tgId`, and `tcId`
- deterministic tests on Linux, verified against pinned NIST vectors, and for **all 40 names
  against vectors generated live by NIST's ACVTS server** — see [Coverage](#coverage)

Deliberately out of scope: a general-purpose ACVP protocol client (`libacvp` and
ACVP Proxy already do that well), an HTML dashboard, performance benchmarking,
and redistribution of upstream vectors whose licensing is unconfirmed. There is
also no built-in ML-KEM or ML-DSA implementation — for post-quantum work the
implementation under test is yours, supplied through `--provider-command`.

The one piece of protocol code in the repository, `scripts/acvts_client.py`, is
not an exception to that: it exists so the runner can be checked against NIST's
live server rather than against a fixture, and it implements only what that
needs — register, fetch, submit, results. See
[Verified against NIST's own server](#verified-against-nists-own-server).

Versions before 1.0.0 do not promise a stable provider API; the protocols are
still settling as algorithm families are added.

## Requirements

- Python 3.12 or newer
- Internet access during setup to download pinned dependency ranges
- A Python installation with `venv` support

On Debian or Ubuntu, `venv` may be a separate package such as `python3.12-venv`.

## Quick start

```bash
python3.12 scripts/dev.py setup
python3.12 scripts/dev.py test
python3.12 scripts/dev.py demo
.venv/bin/python -m acvp_assay run fixtures/aes-gcm-valid-encrypt/prompt.json
```

The demo prints machine-readable runtime metadata, including the `cryptography` and OpenSSL versions that identify the provider. The last command executes a tiny local fixture end to end and prints a JSON report.

## Running vectors

```bash
acvp-assay run VECTOR_FILE [--output RESULT_FILE] [--strict]
```

The algorithm is read from the vector file itself and routed automatically.

`VECTOR_FILE` is an ACVP-shaped `prompt.json`; an `expectedResults.json` must sit next to it in the same directory (every directory under `fixtures/` already follows this layout). Without `--output`, the JSON report is printed to stdout; with it, the report is written to `RESULT_FILE` instead. `--strict` also fails the run if any case is `SKIPPED` or `UNSUPPORTED`. See `docs/architecture.md` for the full exit-code table.

## Coverage

Three questions a vendor actually needs answered, in one table:

- **Offline** — can this runner execute the family against an ACVP vector file?
- **Harness** — can *your* implementation answer it over `--provider-command`?
- **Live NIST verdict** — has NIST itself generated vectors for it, scored our answers, and
  said `passed`? The session ids are ours on `demo.acvts.nist.gov`; with your own credentials
  the same flow produces your own. Session state is gitignored, so nothing here is a claim you
  have to take on trust about *your* module — you run it yourself.

| Algorithm | Test types | Offline | Harness | Live NIST verdict |
| --- | --- | :---: | :---: | --- |
| `ACVP-AES-GCM` | AFT | ✅ | ✅ | `passed` — 765343 |
| `ACVP-AES-ECB` | AFT, MCT | ✅ | ✅ | `passed` — 765342 |
| `ACVP-AES-CBC`, `-CTR`, `-OFB`, `-CFB128` | AFT, MCT, CTR | ✅ | ✅ | `passed` — 765353 |
| `ACVP-AES-KW`, `ACVP-AES-KWP` | AFT | ✅ | ✅ | `passed` — 765342 |
| `ACVP-AES-GMAC` | AFT | ✅ | ✅ | `passed` — 765518 |
| `CMAC-AES` | AFT (gen and ver) | ✅ | ✅ | `passed` — 765342 |
| `SHA-1` | AFT, MCT | ✅ | ✅ | `passed` — 765345 |
| `SHA2-224` | AFT, MCT | ✅ | ✅ | `passed` — 765508 |
| `SHA2-256` | AFT, MCT | ✅ | ✅ | `passed` — 765339, 765342 |
| `SHA2-384`, `SHA2-512` | AFT, MCT | ✅ | ✅ | `passed` — 765508 |
| `SHA2-512/224`, `SHA2-512/256` | AFT, MCT | ✅ | ✅ | `passed` — 765508 |
| `SHA3-224`, `SHA3-384` | AFT, MCT | ✅ | ✅ | `passed` — 765508 |
| `SHA3-256`, `SHA3-512` | AFT, MCT | ✅ | ✅ | `passed` — 765345 |
| `HMAC-SHA-1` | AFT | ✅ | ✅ | `passed` — 765345 |
| `HMAC-SHA2-256` | AFT | ✅ | ✅ | `passed` — 765342 |
| `HMAC-SHA2-224/384/512`, `-512/224`, `-512/256` | AFT | ✅ | ✅ | `passed` — 765508 |
| `HMAC-SHA3-256` | AFT | ✅ | ✅ | `passed` — 765345 |
| `HMAC-SHA3-224`, `-384`, `-512` | AFT | ✅ | ✅ | `passed` — 765508 |
| `ctrDRBG` | AFT | ✅ | ✅ | `passed` — 765342 |
| `hashDRBG`, `hmacDRBG` | AFT | ✅ | ✅ | `passed` — 765354 |
| `KDF` (SP 800-108) | AFT | ✅ | ✅ | `passed` — 765343 |
| `ECDSA` | sigGen, sigVer | ✅ | ✅ | `passed` — 765343 |
| `RSA` | sigGen, sigVer, signaturePrimitive, decryptionPrimitive | ✅ | ✅ | `passed` — 765356 |
| `ML-KEM` | encap, decap, key checks | harness only | ✅ | `passed` — 765724 ¹ |
| `ML-DSA` | sigVer (pure, external) | harness only | ✅ | `passed` — 765727 ¹ |

¹ Answered by the educational reference harness, not a shippable implementation — see the banner.

**40 algorithm names across 22 families. All 40 reach a harness, all 40 can be submitted to a
live session, and all 40 have been.**

The harness path is checked against the built-in one by answering each pinned NIST prompt both
ways and comparing: **24,048 cases across ten families, byte-identical wherever the answer is
deterministic**. Where it cannot be, because the implementation invents part of the input, the
answers were checked for self-consistency instead — 10,950 KDF cases re-derived from the
`fixedData` the harness reported, and 800 signatures verified under the `qx`/`qy` it reported.
Groups the *reference* harness itself declines (`kwCipher: inverse`, SHAKE with ECDSA, TDES,
LDT) are excluded from that count rather than counted as passes, and PQC is not in it at all,
having no built-in side to compare against.

### Per-family notes

| Family | Detail |
| --- | --- |
| SHA-1, SHA-2 | Both `standard` and `alternate` Monte Carlo chains; LDT is reported UNSUPPORTED |
| SHA-3 | Chains a single digest per iteration, not SHA-2's three |
| HMAC | Honours per-group `macLen` truncation |
| AES chaining modes | Both directions of every Monte Carlo chain; CTR defines none. The IV advance differs per mode — see `docs/limitations.md` |
| AES-ECB | The 100 × 1000 chain, including the 192/256-bit key shuffle |
| AES-GMAC | Tag generation, and verification including deliberate forgeries |
| AES-KW/KWP | `kwCipher: cipher`; the `inverse` variant is reported UNSUPPORTED |
| RSA | PKCS#1 v1.5 and PSS over SHA-1/SHA-2/SHA-3; SHAKE masks reported UNSUPPORTED. `keyGen` is out of scope |
| ECDSA | P-224/256/384/521; sigVer is verdict-only, sigGen is verified against its own key |
| ctrDRBG | Both revisions; AES-128/192/256, with and without the derivation function. TDES reported UNSUPPORTED |
| hashDRBG, hmacDRBG | SHA-1, the SHA-2 family and both truncated SHA-512 variants |
| KDF SP 800-108 | Counter, feedback and double-pipeline modes over 14 PRFs. CMAC-TDES reported UNSUPPORTED |
| ML-KEM, ML-DSA | Require `--provider-command`: no built-in PQC implementation |

PQC has no built-in provider on purpose. `cryptography` 50.0.1 implements neither ML-KEM nor ML-DSA, and in a real engagement the implementation under test is the customer's — OpenSSL 3.5+, liboqs, an HSM, or their own module. `examples/pqc_reference_harness.py` drives the pinned NIST ML-KEM and ML-DSA sets end to end using `kyber-py` and `dilithium-py`, which are educational, **not constant-time**, and exist here to verify this runner and to demonstrate it, never as an implementation to ship or validate.

### Not covered

Named plainly so you can tell before you install whether this fits. None of these are
implemented, and none are silently mis-reported — an unrecognised algorithm exits with an
error rather than a pass:

AES-CCM, AES-XTS, AES-XPN and the FPE modes; every TDES family; SHAKE, cSHAKE, KMAC,
ParallelHash and TupleHash; the KAS/KTS and KDA families; the protocol KDFs (TLS, SSH, IKE,
SRTP, ANSI X9.42/X9.63) and PBKDF; DSA, EdDSA, safe primes, and key generation for RSA or
ECDSA; LMS/HSS and SLH-DSA; ML-KEM and ML-DSA key generation and signature generation.

`acvp-assay run` on any of these reports the algorithm as unsupported and exits non-zero.

## How vendors use this

The built-in provider exercises OpenSSL through Python's `cryptography`, which is only useful
for checking the runner itself. **Testing *your* product means supplying it as a harness.**
Four stages, each independently useful — most vendors stop after stage 2:

### Stage 1 — see it work, no integration (5 minutes)

```bash
python3.12 scripts/dev.py setup
.venv/bin/python -m acvp_assay run fixtures/aes-gcm-valid-encrypt/prompt.json
```

Nothing of yours is involved yet. This confirms the tool runs and shows the report shape.

### Stage 2 — run NIST vectors against your implementation

Write a harness: a program that reads one JSON request per line on stdin and writes one JSON
response per line on stdout. That is the entire contract, so it can be a C binary talking to an
HSM, a shell script with `jq`, a Go service in front of a network appliance, or a Python script
driving a serial port. Nothing links against this project.

```bash
acvp-assay run vectors/SHA2-256-1.0/prompt.json \
    --provider-command "./my-harness --device /dev/hsm0" \
    --provider-timeout 30
```

Start from `examples/reference_harness.py` — a complete worked implementation of the 20
non-PQC operations, which imports nothing from this package. (`examples/pqc_reference_harness.py`
covers the four ML-KEM and ML-DSA operations separately, since it needs different dependencies.)
Implement only the families you are testing; decline the rest with `{"error": "unsupported"}`
and they are reported UNSUPPORTED rather than as failures.

You supply the vectors. Either use your own ACVTS-issued prompt files, or run
`python3 scripts/fetch_vectors.py` to pull the pinned upstream sets this project tests against.

### Stage 3 — submit your answers to NIST and let NIST judge

With ACVTS Demo credentials, the same harness answers vectors NIST generated for your session,
and NIST returns the verdict. See
[Submitting *your* implementation's answers](#submitting-your-implementations-answers).

```bash
python3 scripts/acvts_client.py submit --provider-command "./my-harness" --dry-run
```

### Stage 4 — keep it from breaking

`acvp-assay diff` compares two runs and fails CI on regressions, including coverage that
silently disappeared. See [Catching regressions between runs](#catching-regressions-between-runs).
With re-validation running well over a year, that is the failure mode that costs a cycle.

### The harness contract

**`docs/harness-protocol.md` is the full specification** — every operation, the reserved errors,
and worked integration patterns for HSMs, serial devices and network appliances.

```json
→ {"operation": "encrypt", "key": "000102…", "iv": "1011…", "aad": "", "pt": "4865…", "tagLen": 128}
← {"ct": "8C4B6FC3606396AE548B0DD4", "tag": "CEA4303CA9132112C1D14AE589AD15AF"}

→ {"operation": "decrypt", "key": "F0F1…", "iv": "A0A1…", "aad": "696E…", "ct": "8997…", "tag": "5333…"}
← {"pt": "646563727970742D6D65"}
← {"error": "authentication failed"}
```

```json
→ {"operation": "encrypt", "key": "000102…", "iv": "1011…", "aad": "", "pt": "4865…", "tagLen": 128}
← {"ct": "8C4B6FC3606396AE548B0DD4", "tag": "CEA4303CA9132112C1D14AE589AD15AF"}

→ {"operation": "decrypt", "key": "F0F1…", "iv": "A0A1…", "aad": "696E…", "ct": "8997…", "tag": "5333…"}
← {"pt": "646563727970742D6D65"}
← {"error": "authentication failed"}
```

The 24 operations, by family — implement only the rows you are testing:

| Family | Operations |
| --- | --- |
| Always | `metadata` |
| AES-GCM | `encrypt`, `decrypt` |
| Hashes | `digest`, `digest-mct` |
| HMAC | `mac` |
| AES block modes, ECB | `block-transform`, `block-mct` |
| CMAC, GMAC, KW/KWP | `cmac`, `gmac`, `key-wrap` |
| ECDSA | `ecdsa-sign`, `ecdsa-verify`, `ecdsa-sign-group` |
| RSA | `rsa-sign-group`, `rsa-verify`, `rsa-primitive-sign`, `rsa-primitive-decrypt` |
| DRBGs | `drbg` |
| KDF SP 800-108 | `kdf-108` |
| ML-KEM, ML-DSA | `ml-kem-encapsulate`, `ml-kem-decapsulate`, `ml-kem-key-check`, `ml-dsa-verify` |

`ecdsa-sign-group` and `rsa-sign-group` are needed only if you intend to *submit* sigGen to a
live session: ACVP reports the public key once per group, so every case in a group must share
one key, which per-case signing cannot express.

Two error values are reserved. `{"error": "unsupported"}` declines a case the implementation does not offer — a curve, a parameter set, a mode — and is reported UNSUPPORTED rather than as a failure, because capability is yours to declare, not ours to assume. (An HSM's binary curves are not "unsupported" merely because Python's `cryptography` lacks them.)

A rejected authentication tag is reported as `{"error": "authentication failed"}`, **not** as a crash or a non-zero exit. This matters: roughly a third of NIST's own AES-GCM decrypt cases are deliberate failures where rejecting the tag is the correct answer, and a harness that dies on them will score a conforming implementation as broken.

The Monte Carlo chain is delegated whole via `digest-mct`: at 100,000 inner iterations, one round trip per hash would take hours, and running the chain is what a real implementation under test does anyway.

`examples/reference_harness.py` is a complete worked implementation that imports nothing from this package. `--provider-timeout SECONDS` bounds each call, so a wedged device cannot hang the run. Its stderr passes through to your terminal for debugging but never enters the JSON report, since a crashing harness may print key material.

**The harness is started once and kept alive** for the whole run, so expensive
setup — a PKCS#11 login, a serial port, an SSH session — happens once rather
than once per case. That is worth about fifty times the run time: 239 SHA3-256
cases take 0.5 s against a persistent harness and 17.9 s against one spawned per
case. A one-shot harness that reads stdin to end still works and is detected
automatically, because a shell script with `jq` naturally takes that shape and
reach matters more than the speed lost.

### Sample output — PASS

```bash
$ acvp-assay run fixtures/aes-gcm-valid-encrypt/prompt.json; echo "exit: $?"
```

```json
{
  "cases": [
    {
      "actual": { "ct": "8C4B6FC3606396AE548B0DD4", "tag": "CEA4303CA9132112C1D14AE589AD15AF" },
      "expected": { "ct": "8C4B6FC3606396AE548B0DD4", "tag": "CEA4303CA9132112C1D14AE589AD15AF" },
      "status": "PASS",
      "tcId": 1,
      "tgId": 1
    }
  ],
  "provider": { "name": "cryptography-aes-gcm", "...": "..." },
  "summary": { "total": 1, "passed": 1, "failed": 0, "errored": 0, "skipped": 0, "unsupported": 0 }
}
```
```text
exit: 0
```

### Sample output — failure

```bash
$ acvp-assay run fixtures/aes-gcm-invalid-decrypt-tag/prompt.json; echo "exit: $?"
```

```json
{
  "cases": [
    {
      "actual": null,
      "diagnostic": "authentication failed",
      "expected": {},
      "status": "ERROR",
      "tcId": 1,
      "tgId": 1
    }
  ],
  "provider": { "name": "cryptography-aes-gcm", "...": "..." },
  "summary": { "total": 1, "passed": 0, "failed": 0, "errored": 1, "skipped": 0, "unsupported": 0 }
}
```
```text
exit: 1
```

This second fixture's tag is deliberately corrupted (see `fixtures/README.md`); it exists to prove the tool surfaces a real, deterministic failure instead of swallowing it.

## Verified against NIST's own server

Static vector files tell you whether a runner agrees with a snapshot. They cannot tell you whether
it agrees with the system that issues the vectors. So all 40 supported algorithm names have been
through a live test session on NIST's ACVTS Demo server:
register capabilities, fetch vectors NIST generated for this client, compute answers, submit them,
and read back the verdict.

Two qualifications, both of which a reader should have without asking. These were **sample**
sessions, so NIST supplies the expected results alongside the prompt — but the answers submitted
were computed from the prompt by the same providers the offline runner uses, never read out of
NIST's answer key; `responder.py` does not open `expectedResults.json` at all. And Demo is not the
production ACVTS, which is available to accredited laboratories rather than to tool authors.

| Session | Algorithms | Sets | Cases | Verdict |
| ---: | --- | ---: | ---: | --- |
| 765339 | SHA2-256 | 1 | 513 | `passed` |
| 765342 | SHA2-256, HMAC-SHA2-256, AES-ECB, CMAC-AES, AES-KW, AES-KWP, ctrDRBG | 7 | 8,966 | `passed` |
| 765343 | AES-GCM, KDF SP 800-108, ECDSA sigGen, ECDSA sigVer | 4 | 647 | `passed` |
| 765345 | SHA-1, SHA3-256, SHA3-512, HMAC-SHA-1, HMAC-SHA3-256 | 5 | 2,877 | `passed` |
| 765346 | AES-CBC, AES-CTR, AES-OFB, AES-CFB128 | 4 | — | **abandoned**, see below |
| 765353 | AES-CBC, AES-CTR, AES-OFB, AES-CFB128 | 4 | 6,016 | `passed` |
| 765354 | hashDRBG, hmacDRBG | 2 | 120 | `passed` |
| 765356 | RSA sigGen, sigVer, signaturePrimitive, decryptionPrimitive | 4 | 98 | `passed` |
| 765508 | SHA2-224/384/512, SHA2-512/224, SHA2-512/256, SHA3-224, SHA3-384, and the eight remaining HMACs | 15 | 12,867 | `passed` ¹ |
| 765518 | AES-GMAC | 1 | 360 | `passed` |
| 765724 | ML-KEM encapDecap | 1 | 165 | `passed` ² |
| 765727 | ML-DSA sigVer | 1 | 45 | `passed` ² |
| | **Completed** | **45** | **32,674** | **all `passed`** |

² Answered through `examples/pqc_reference_harness.py`. `cryptography` implements neither
ML-KEM nor ML-DSA, so there is nothing built in to answer with; the harness is backed by
`kyber-py` and `dilithium-py`, which are educational and not constant-time. These two verdicts
say the runner handles PQC vector sets correctly, and say nothing about any shippable
implementation. Both sessions registered narrowly — ML-DSA `pure`/`external` only — because
`preHash` and `externalMu` groups are refused by design rather than answered.

¹ Session 765508 registered a sixteenth algorithm, AES-GMAC, whose vector set NIST's generator
refused with `min must be less than max` — the registration declared a zero-width `payloadLen`,
and GMAC has no payload to describe. That is a bug in the capability file, not in the runner: no
vectors were ever produced, so there was nothing to answer. The set is excluded from the 43, the
session therefore reports `passed: false` overall, and GMAC was re-registered correctly as 765518.

**Session 765346 is listed because it failed.** It is where the Monte Carlo decrypt bug below
was found: the AES-CTR set was submitted, the other three were not, and the session was
abandoned rather than finished around a known-wrong answer. 765353 is the re-run after the fix.
Its cases are excluded from the total — a run that was abandoned is not evidence, and dropping
it from the table without saying so would make the total flattering rather than true.

**On evidence.** `acvts_client.py results` now writes the server's reply to `results.json` beside
the vector sets it judges, so 765508 and 765518 are backed by the stored verdict. The seven
earlier sessions are not: `results` used to print the reply and discard it, and ACVP scopes a
session's token to its registration, so re-reading them now returns 403. Those verdicts are
recorded here from the runs themselves and cannot be re-fetched — which is exactly why they are
now written down.

### What this caught that fixtures did not

Each of these passed the offline suite and would have shipped:

- **The AES-GCM parser rejected every real vector set.** It required `ivGenMode`, which qualifies
  *internal* IV construction — so the live server omits it whenever `ivGen` is `external`. The
  pinned upstream sample file happens to include it, which is exactly why this survived.
- **The chaining-mode Monte Carlo chains were wrong for decryption.** The specification writes the
  inner loop as a cipher that "continues" from the previous call without saying what that does to
  the IV. Read literally it reproduces the encrypt arrays exactly and disagrees from the first
  block when decrypting. The rules came from NIST's generator, not the prose.
- **RSA-PSS ignored `maskFunction`.** FIPS 186-5 lets PSS use SHAKE as its mask generation
  function, signalled by a field separate from `hashAlg`. Six sigVer cases failed while their
  group looked perfectly supported.
- **ECDSA and RSA sigGen generated a fresh key per case.** ACVP reports the public key once per
  *group*, so a key per case cannot be expressed in the response document at all.

### Reproducing it

Credentials are yours to obtain — write to `acvts-demo@nist.gov` — and never live in this
repository. The client reads them from the environment:

```bash
export ACVTS_CERT=/path/to/your.cer ACVTS_KEY=/path/to/your.key ACVTS_SEED=/path/to/totp.txt

python3 scripts/acvts_client.py check                              # credentials, no network
python3 scripts/acvts_client.py register acvts-capabilities/drbg.json
python3 scripts/acvts_client.py fetch                              # prompts, and expected results
acvp-assay run .acvts/session-765354/4032194/prompt.json           # verify offline
python3 scripts/acvts_client.py submit                             # let NIST judge
python3 scripts/acvts_client.py results
```

### Submitting *your* implementation's answers

Without `--provider-command` the built-in providers answer, which tests this runner rather
than your product. Point it at your harness and every value NIST scores comes from your code:

```bash
python3 scripts/acvts_client.py submit \
    --provider-command "./my-acvp-harness --device /dev/hsm0" \
    --dry-run                                       # writes response.json, sends nothing
```

Drop `--dry-run` once the documents look right. Two behaviours differ from an offline run,
both deliberate:

- **A case your harness declines refuses the whole submission.** Offline, UNSUPPORTED is a
  useful verdict. Here there is no such verdict — ACVP scores a missing case as a *wrong
  answer* — so a partial document would record a failure you never earned. The error names
  the operation that was declined, so you can either implement it or narrow your
  registration.
- **Capability is yours to declare.** Modes the built-in provider lacks, such as DRBG `TDES`
  or KDF `CMAC-TDES`, are sent to your harness rather than refused on your behalf.

Session state, downloaded vectors and tokens land in a gitignored `.acvts/`. NIST's vectors are
theirs to distribute, and the certificate, key and TOTP seed are secrets.

One detail the public documentation gets wrong, in case it saves you an afternoon: the TOTP is
**HMAC-SHA-256 with eight digits**, not the SHA-1 and six digits the ACVP wiki and issue #297
imply. A wrong guess returns a bare 401 naming neither factor.

## Catching regressions between runs

Getting a certificate is one question; *staying* conformant is another, and with re-validation
running well over a year a silent break can survive to the next cycle. Compare two reports:

```bash
acvp-assay run vectors/ACVP-AES-GCM-1.0/prompt.json --output baseline.json
# ... upgrade a library, change firmware, bump a container base image ...
acvp-assay run vectors/ACVP-AES-GCM-1.0/prompt.json --output current.json

acvp-assay diff baseline.json current.json
```

```text
verdict: REGRESSED
provider changed between runs:
  baseline: cryptography-aes-gcm, cryptography 50.0.1, OpenSSL OpenSSL 4.0.2 25 Aug 2026
  current : cryptography-aes-gcm, cryptography 50.0.1, OpenSSL OpenSSL 3.5.0 8 Apr 2025
regressed: 1
  tgId 1 tcId 1: PASS -> FAIL (tag mismatch)
coverage lost: 10
  tgId 2 tcId 16: PASS -> UNSUPPORTED (ivGen 'internal' is not supported)
  ... and 5 more
```

Exit codes: 0 when nothing got worse, 1 on a regression, 2 when a report cannot be read — so
`acvp-assay diff` drops straight into CI. `--output` writes the machine-readable diff.

**Coverage loss counts as a regression.** A case that used to run and is now `UNSUPPORTED`,
`SKIPPED`, or simply absent is reported as loudly as an outright failure, because that is the
failure mode that hides: the totals still look clean, since the case has stopped being counted.
Provider identity is diffed alongside the cases, since a changed library or backend is usually the
cause rather than a detail.

## Development commands

```bash
# Install the package and development dependencies into .venv
python3.12 scripts/dev.py setup

# Run formatting checks, lint, static typing, and tests
python3.12 scripts/dev.py test

# Run all checks and build wheel/sdist artifacts
python3.12 scripts/dev.py verify

# Print provider/runtime metadata
python3.12 scripts/dev.py demo
```

## Repository map

- `src/acvp_assay/`: application package
- `scripts/dev.py`: the setup, test and verify gate
- `scripts/acvts_client.py`: live ACVTS client — register, fetch, submit, results
- `scripts/fetch_vectors.py`: downloads and hash-verifies the pinned upstream vectors
- `acvts-capabilities/`: capability registrations used for the live sessions
- `examples/`: worked reference harnesses that import nothing from the package
- `tests/unit/`: focused unit tests
- `tests/integration/`: subprocess and full-path tests
- `fixtures/`: small, rights-safe local test vectors
- `docs/architecture.md`: component boundaries and data flow
- `docs/harness-protocol.md`: the full harness specification for vendors
- `docs/limitations.md`: security and assurance boundaries
- `docs/vector-sources.md`: pinned upstream source, hashes, licensing, and redistribution policy
- `docs/decisions/`: committed design decisions
- `docs/backlog.md`: what is built and what is next
- `CHANGELOG.md`: release history
- `BUILDLOG.md`: running record of how each family was built and verified

## Safety

Do not add credentials, employer code or data, proprietary vectors, or confidential screenshots. Use only vectors whose source and redistribution terms have been recorded.

## License

MIT; see `LICENSE`.
