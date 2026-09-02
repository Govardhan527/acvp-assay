# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0 the
provider protocols may change between minor versions.

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

[0.2.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.2.0
[0.1.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.1.0
