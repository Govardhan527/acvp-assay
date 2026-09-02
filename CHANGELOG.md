# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0 the
provider protocols may change between minor versions.

## [0.4.0] - 2026-09-02

Broadens algorithm coverage toward what a real module actually validates.

### Added

- Five AES mode families: `ACVP-AES-ECB`, `ACVP-AES-GMAC`, `ACVP-AES-KW`,
  `ACVP-AES-KWP` and `CMAC-AES`. AES-GCM alone covers very few real
  validations; a module that validates GCM almost always validates a key wrap
  and a CMAC beside it, and reviewing published CAVP certificates showed those
  four names recurring far more often than anything still missing.
- The AES Monte Carlo chain, whose key shuffle differs by key length — 128-bit
  keys are refreshed from the final ciphertext block alone, while 192- and
  256-bit keys reach back into the previous block because one 128-bit output is
  not enough material. Verified against the pinned NIST set, all 2,144 cases.
- Twelve more pinned vector files in `scripts/fetch_vectors.py`, covering the
  five new families and — a pre-existing gap — the ECDSA, ML-KEM and ML-DSA
  sets, which had been fetched by hand but never pinned. All 25 files are now
  verified by size and SHA-256 before use.

### Notes

- `kwCipher: inverse` is reported UNSUPPORTED rather than guessed at. It is
  half of the pinned KW and KWP sets, so the honest total is 3,600 executed and
  3,600 declared per set, not a quiet 7,200.
- Counter DRBG (SP 800-90A) and KDF SP 800-108 remain uncovered. Both need a
  new result shape rather than a new provider method, and are next.

## [0.3.0] - 2026-09-02

Closes the gap between what the project claimed and what it shipped.

### Added

- Every algorithm family is now reachable through `--provider-command`. SHA-2,
  HMAC and ECDSA previously refused an external harness, so the central claim —
  that an implementation which cannot be linked against can still be tested —
  held only for AES-GCM and PQC. SHA-2 and HMAC are in essentially every
  cryptographic module, so the gap hit the most common case first.
- Wire contract operations `digest`, `digest-mct`, `mac`, `ecdsa-sign` and
  `ecdsa-verify`, all implemented by `examples/reference_harness.py`. The Monte
  Carlo chain is delegated whole: 100,000 round trips would take hours, and
  running the chain is what an implementation under test does anyway.
- `{"error": "unsupported"}` lets a harness decline a case it does not
  implement. It is reported UNSUPPORTED rather than as a failure — telling a
  customer their module is broken when it simply lacks a curve is the worst
  output this tool can produce.

### Fixed

- ECDSA capability was filtered against what Python's `cryptography` exposes,
  which would have wrongly declared an HSM's binary curves unsupported.
  Capability now belongs to the provider via `supports()`.

### Verified

Through the external harness against pinned NIST vectors: AES-GCM 60/60,
SHA2-256 513 passed, HMAC-SHA2-256 975/975, ECDSA sigVer 140 passed. The
harness and in-process providers produce identical summaries.

## [0.2.0] - 2026-09-02

Five more algorithm families, a provider boundary that reaches implementations
this project cannot link against, and regression diffing between runs.

### Added

- **SHA-2** (`SHA2-224/256/384/512`, `SHA2-512/224`, `SHA2-512/256`) with both
  the standard and `alternate` Monte Carlo chains. Large data tests (LDT) are
  reported UNSUPPORTED rather than approximated; upstream cases expand to 8 GiB.
- **HMAC** over every supported SHA-2 variant, honouring per-group `macLen`
  truncation.
- **ECDSA** `sigGen` and `sigVer` on P-224/256/384/521. This introduced two
  result shapes the project previously lacked: *verdict-only*, where the
  expected result is a boolean rather than bytes, and *produce-and-verify*,
  where the output is randomised and must be verified rather than compared.
- **ML-KEM** (encapsulation, decapsulation, and both key checks) and **ML-DSA**
  `sigVer`. These require `--provider-command`: there is deliberately no
  built-in post-quantum implementation, because for PQC the implementation
  under test is the customer's.
- **External harness provider** (`--provider-command`, `--provider-timeout`).
  A harness reads one JSON request on stdin and writes one on stdout, so an
  HSM, a smartcard, an embedded device, or a library in any language can be
  tested without linking anything. Worked examples in `examples/`.
- **`acvp-assay diff BASELINE CURRENT`** compares two run reports. Coverage
  loss counts as a regression: a case that used to run and is now UNSUPPORTED,
  SKIPPED, or absent is reported as loudly as an outright failure, because the
  totals still look clean once it stops being counted. Provider identity is
  diffed alongside the cases, since a changed library version is usually the
  cause.
- **`scripts/fetch_vectors.py`** downloads and SHA-256-verifies the pinned
  upstream NIST vectors into a git-ignored directory, refusing to write
  anything whose size or hash differs.

### Fixed

- Deliberate authentication-failure cases were scored wrongly. ACVP marks them
  `testPassed: false` and roughly a third of NIST's AES-GCM decrypt cases are
  of this kind; a correct implementation rejecting a forged tag was reported as
  an ERROR, and an implementation *wrongly accepting* one was not distinguished
  at all. Rejection is now a PASS and acceptance a loud FAIL.
- ML-DSA's `internal` signature interface was treated as external with an empty
  context. It omits the domain separator and context prefix, so nine valid
  signatures in NIST's own set were reported as rejected.
- A misconfigured harness reported every case as an error and then crashed on
  the report. Provider metadata is now probed once before any case runs, so the
  run stops with a single clear message.
- `TestCaseResult` now enforces the closed ERROR-diagnostic vocabulary itself,
  rather than relying on convention at one call site, so raw exception text
  cannot reach a report.

### Changed

- Renamed from `acvp-runner` to **`acvp-assay`**. An assay measures
  composition; it does not certify it.
- Algorithm dispatch reads the algorithm from the vector file and routes it, so
  one command serves every family.

## [0.1.0] - 2026-09-02

Initial release: an offline AES-GCM vector runner.

### Added

- ACVP AES-GCM vector and expected-results parsing with typed models that
  preserve `vsId`, `tgId`, and `tcId`.
- A replaceable provider boundary with one implementation backed by the OpenSSL
  behind Python's `cryptography`.
- Encrypt and decrypt execution, per-case PASS/FAIL/ERROR comparison with
  non-secret diagnostics, and deterministic JSON reporting including provider
  and backend versions.
- `acvp-assay run VECTOR_FILE [--output] [--strict]` with documented exit codes.
- Clean-checkout Linux CI, and a pinned, hash-verified upstream vector source
  that is referenced rather than redistributed.

[0.3.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.3.0
[0.2.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.2.0
[0.1.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.1.0
