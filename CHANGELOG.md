# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0 the
provider protocols may change between minor versions.

## [0.8.0] - 2026-09-03

### Added

- The AES chaining modes: `ACVP-AES-CBC`, `ACVP-AES-CTR`, `ACVP-AES-OFB` and
  `ACVP-AES-CFB128`. CBC and CTR appear on very nearly every certificate ever
  issued, which made this the largest remaining commercial gap.
- 6,008 cases executed against vectors the live server generated, zero
  failures, with 8 declared.

### Notes

- `ACVP-AES-CTR` has **no Monte Carlo test**. ACVP gives it a `CTR` test type,
  but that is a server-side distinction: the server back-computes the IVs from
  an ordinary functional answer. All 1,742 CTR cases pass.
- The Monte Carlo chains are fully supported in both directions, and were the
  hard part. The specification's pseudocode writes the inner loop as a cipher
  that "continues" from the previous call without saying what continuing does
  to the IV, and each mode answers differently: CBC and CFB128 advance it to
  the ciphertext just *produced* when encrypting and to the ciphertext just
  *consumed* when decrypting, while OFB advances it to the raw keystream block
  in both directions. Reading the specification's "replace all PT with CT"
  instruction literally reproduces the encrypt arrays exactly and disagrees
  from the first block when decrypting.
- The correct rules came from NIST's own generator, `MonteCarloAesCbc.cs` and
  its siblings in `usnistgov/ACVP-Server`, where encrypt and decrypt are
  structurally identical and the asymmetry lives inside the cipher object.
  `docs/limitations.md` carries the table. All twelve group combinations
  reproduce the live server's arrays on every field of all 100 iterations.
- `CFB` and `OFB` are read from `cryptography.hazmat.decrepit`, which is where
  they move in version 49.

## [0.7.0] - 2026-09-03

### Added

- `SHA-1` and the `SHA3-224/256/384/512` family, and `HMAC-SHA-1` and
  `HMAC-SHA3-*` beside them. Ten new algorithm names, taking the runner from
  23 to 33 of the 97 the live ACVTS Demo registry offers.
- Live validation against `demo.acvts.nist.gov`. Session 765345 returned
  `"passed": true` across SHA-1, SHA3-256, SHA3-512, HMAC-SHA-1 and
  HMAC-SHA3-256.

### Fixed

- **SHA-3 has its own Monte Carlo chain**, and reusing SHA-2's would have been
  silently wrong on every SHA-3 MCT case. SHA-2 hashes three digests
  concatenated (`A || B || C`); SHA-3 hashes a single one
  (`MD[i] = SHA3(MD[i-1])`). The two families share the `MCT` test type name
  and nothing else, so the mistake looks structurally correct and fails
  completely. Taken from the specification's pseudocode, then confirmed
  against server-generated vectors.
- The SHA parser accepted only revision `1.0`. SHA-3 is registered at `2.0`,
  so the accepted revision now follows the algorithm family.

## [0.6.0] - 2026-09-02

### Added

- `KDF` (SP 800-108), revision 1.0: counter, feedback and double-pipeline
  modes across 14 PRFs — HMAC over SHA-1, the SHA-2 family and the SHA-3
  family, plus CMAC-AES128/192/256.
- 10,950 cases executed against the pinned upstream set, zero failures, with a
  further 806 CMAC-TDES cases declared UNSUPPORTED.

### Notes

- This is the only set here whose *expected results file carries an input*. The
  prompt gives only `keyIn`, because a conforming implementation chooses its own
  `fixedData`; the runner reads NIST's choice back out of `expectedResults.json`
  and derives against it. A pass therefore shows the derivation is correct for
  that fixed data — it does not exercise an implementation's freedom to
  construct fixed data of its own, which the ACVP server checks and no
  file-based runner can. `docs/vector-sources.md` says so plainly.
- `breakLocation` is a **bit** offset, not a byte offset. Upstream values run 1
  to 127 against 128-bit fixed data, so the counter splices mid-byte. Treating
  it as bytes passes 10,092 cases and fails 858 — the kind of near-miss that
  looks like success on a summary line.
- `keyOutLength` is frequently not a multiple of 8 (67, 331, 1003), so the last
  byte's padding bits must be cleared.

## [0.5.0] - 2026-09-02

### Added

- `ctrDRBG`, revisions `1.0` and `SP800-90Ar1`. A DRBG sits in effectively every
  FIPS module, which made it the widest remaining single gap. It is also the
  first algorithm here that needed a genuinely new provider shape: a case
  instantiates a state machine, optionally reseeds it, and generates twice,
  rather than performing one transform.
- 450 cases executed against both pinned upstream sets, zero failures, covering
  AES-128/192/256, the derivation function both ways, prediction resistance both
  ways, and counter field widths of 128 and 64 bits.
- `optional_integer` in the parser, for fields like `counterFieldLen` that exist
  in one revision of an algorithm and not the other.

### Notes

- Two details in the operation sequence are silently wrong if you get them
  wrong, and both are now covered by tests. Prediction resistance turns a
  `generate` carrying entropy into a reseed followed by a generation, with the
  additional input consumed by the reseed rather than the generation. And every
  case generates twice while only the second output is compared — comparing the
  first would pass a DRBG that never updates its state.
- Three-key TDES is reported UNSUPPORTED rather than answered. SP 800-131A
  disallowed it for this use after 2023, so 150 of the 750 upstream cases are
  declared rather than executed.
- KDF SP 800-108 is now the last gap on the reference certificate this work has
  been tracking.

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
