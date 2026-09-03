# ACVP Assay

[![CI](https://github.com/Govardhan527/acvp-assay/actions/workflows/ci.yml/badge.svg)](https://github.com/Govardhan527/acvp-assay/actions/workflows/ci.yml)

Run NIST ACVP test vectors against any implementation — including ones you cannot link against — and catch conformance regressions between runs.

An *assay* measures composition, it does not certify it. This tool produces reproducible test evidence: it parses ACVP vector sets, executes them through a replaceable provider boundary, compares results case by case, and diffs one run against the next. It is **not** an ACVP protocol client, and it does **not** perform or substitute for CAVP algorithm validation or FIPS 140-3 cryptographic-module validation — only accredited CST and 17ACVT laboratories can do that.

Two things distinguish it from `libacvp` and ACVP Proxy, which cover more algorithms and speak the live protocol:

- **It reaches implementations they cannot.** A harness reads one JSON request on stdin and writes one on stdout, so an HSM, a smartcard, an embedded device over a serial link, or a library in any language can be tested without linking anything.
- **It answers "are we *still* conformant?"** `acvp-assay diff` compares two runs and reports regressions, including coverage that silently disappeared. With re-validation running well over a year, that is the failure mode that costs a cycle.

## Scope

Implemented today:

- nineteen algorithm families — AES-GCM, AES-ECB, AES-GMAC, AES-KW/KWP,
  CMAC-AES, CTR_DRBG, KDF SP 800-108, SHA-1, SHA-2, SHA-3, HMAC, ECDSA,
  ML-KEM, ML-DSA
- a replaceable provider boundary, in-process or an external harness over JSON
- run-over-run regression diffing, including coverage that silently disappeared
- typed parsing that preserves `vsId`, `tgId`, and `tcId`
- deterministic tests on Linux, verified against pinned NIST vectors

Deliberately out of scope: a live ACVP protocol client (`libacvp` and ACVP Proxy
already do that well), an HTML dashboard, performance benchmarking, and
redistribution of upstream vectors whose licensing is unconfirmed. There is also
no built-in ML-KEM or ML-DSA implementation — for post-quantum work the
implementation under test is yours, supplied through `--provider-command`.

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

The algorithm is read from the vector file itself and routed automatically. Currently implemented:

| Family | Test types | Notes |
| --- | --- | --- |
| `ACVP-AES-GCM` | AFT | Encrypt and decrypt, including ACVP's deliberate authentication-failure cases |
| `SHA-1`, `SHA2-224/256/384/512`, `SHA2-512/224`, `SHA2-512/256` | AFT, MCT | Both `standard` and `alternate` Monte Carlo chains; LDT is reported UNSUPPORTED |
| `SHA3-224/256/384/512` | AFT, MCT | SHA-3 chains a single digest per iteration, not SHA-2's three |
| `HMAC-SHA-1`, `HMAC-SHA2-*`, `HMAC-SHA3-*` | AFT | Honours per-group `macLen` truncation |
| `ECDSA` | sigGen, sigVer | P-224/256/384/521; sigVer is verdict-only, sigGen is verified against its own key |
| `ML-KEM` | encap, decap, key checks | Requires `--provider-command`: no built-in PQC implementation |
| `ML-DSA` | sigVer | Requires `--provider-command`; external and internal interfaces |
| `ACVP-AES-ECB` | AFT, MCT | The 100 x 1000 Monte Carlo chain, including the 192/256-bit key shuffle |
| `ACVP-AES-GMAC` | AFT | Tag generation, and verification including deliberate forgeries |
| `ACVP-AES-KW`, `ACVP-AES-KWP` | AFT | `kwCipher: cipher`; the `inverse` variant is reported UNSUPPORTED |
| `CMAC-AES` | AFT (gen and ver) | Honours per-group `macLen` truncation |
| `ACVP-AES-CBC`, `ACVP-AES-CTR`, `ACVP-AES-OFB`, `ACVP-AES-CFB128` | AFT, MCT, CTR | CTR defines no MCT; CBC/CFB128 encrypt chains are verified, the rest are declared (see `docs/limitations.md`) |
| `ctrDRBG` | AFT | Both revisions; AES-128/192/256, with and without the derivation function. TDES is reported UNSUPPORTED |
| `KDF` (SP 800-108) | AFT | Counter, feedback and double-pipeline modes over 14 PRFs. CMAC-TDES is reported UNSUPPORTED |

The five AES mode families, `ctrDRBG` and `KDF` run in process only. They are `cryptography`-backed
and have no harness operations yet, so `--provider-command` is refused for them
rather than silently ignored.

PQC has no built-in provider on purpose. `cryptography` 50.0.1 implements neither ML-KEM nor ML-DSA, and in a real engagement the implementation under test is the customer's — OpenSSL 3.5+, liboqs, an HSM, or their own module. `examples/pqc_reference_harness.py` drives the pinned NIST ML-KEM and ML-DSA sets end to end using `kyber-py` and `dilithium-py`, which are educational, **not constant-time**, and exist here to verify this runner and to demonstrate it, never as an implementation to ship or validate.

`VECTOR_FILE` is an ACVP-shaped `prompt.json`; an `expectedResults.json` must sit next to it in the same directory (every directory under `fixtures/` already follows this layout). Without `--output`, the JSON report is printed to stdout; with it, the report is written to `RESULT_FILE` instead. `--strict` also fails the run if any case is `SKIPPED` or `UNSUPPORTED`. See `docs/architecture.md` for the full exit-code table.

## Testing your own implementation

The built-in provider exercises OpenSSL through Python's `cryptography`. To test something else — an HSM behind PKCS#11, a smartcard, an embedded device over a serial link, or a library in another language — write a small harness program and point the runner at it:

```bash
acvp-assay run VECTOR_FILE --provider-command "python3 examples/reference_harness.py"
```

The harness reads one JSON request on stdin and writes one JSON response on stdout. That is the whole contract, so it can be written in any language, and **every algorithm family goes through it** — AES-GCM, SHA-2 (including the Monte Carlo chain), HMAC, ECDSA, ML-KEM and ML-DSA:

```json
→ {"operation": "encrypt", "key": "000102…", "iv": "1011…", "aad": "", "pt": "4865…", "tagLen": 128}
← {"ct": "8C4B6FC3606396AE548B0DD4", "tag": "CEA4303CA9132112C1D14AE589AD15AF"}

→ {"operation": "decrypt", "key": "F0F1…", "iv": "A0A1…", "aad": "696E…", "ct": "8997…", "tag": "5333…"}
← {"pt": "646563727970742D6D65"}
← {"error": "authentication failed"}
```

Operations: `metadata`, `encrypt`, `decrypt`, `digest`, `digest-mct`, `mac`, `ecdsa-sign`, `ecdsa-verify`, `ml-kem-encapsulate`, `ml-kem-decapsulate`, `ml-kem-key-check`, `ml-dsa-verify`. A harness need only implement the families you are testing.

Two error values are reserved. `{"error": "unsupported"}` declines a case the implementation does not offer — a curve, a parameter set, a mode — and is reported UNSUPPORTED rather than as a failure, because capability is yours to declare, not ours to assume. (An HSM's binary curves are not "unsupported" merely because Python's `cryptography` lacks them.)

A rejected authentication tag is reported as `{"error": "authentication failed"}`, **not** as a crash or a non-zero exit. This matters: roughly a third of NIST's own AES-GCM decrypt cases are deliberate failures where rejecting the tag is the correct answer, and a harness that dies on them will score a conforming implementation as broken.

The Monte Carlo chain is delegated whole via `digest-mct`: at 100,000 inner iterations, one round trip per hash would take hours, and running the chain is what a real implementation under test does anyway.

`examples/reference_harness.py` is a complete worked implementation that imports nothing from this package. `--provider-timeout SECONDS` bounds each call, so a wedged device cannot hang the run. The harness is invoked once per case; its stderr passes through to your terminal for debugging but never enters the JSON report, since a crashing harness may print key material.

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
- `tests/unit/`: focused unit tests
- `tests/integration/`: subprocess and full-path tests
- `fixtures/`: small, rights-safe local test vectors
- `docs/architecture.md`: component boundaries and data flow
- `docs/limitations.md`: security and assurance boundaries
- `docs/vector-sources.md`: pinned upstream source, hashes, licensing, and redistribution policy
- `docs/decisions/`: committed design decisions
- `CHANGELOG.md`: release history

## Safety

Do not add credentials, employer code or data, proprietary vectors, or confidential screenshots. Use only vectors whose source and redistribution terms have been recorded.

## License

MIT; see `LICENSE`.
