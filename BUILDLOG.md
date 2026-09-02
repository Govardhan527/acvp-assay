# Build log

## 2026-09-02 - A01 repository baseline

- Project and task ID: ACVP Assay - A01 (R01-R07)
- Done condition: a clean Python 3.12 checkout can install, run checks and tests, build artifacts, and execute the smallest demo; the AES-GCM-only MVP and non-goals are documented.
- Evidence produced: documented scope and architecture, pinned dependency ranges, source/test/fixture/docs layout, Linux CI, installable package, runtime metadata command, wheel, and source distribution.
- Tests run and result: `scripts/dev.py verify` passed Ruff formatting/lint, strict mypy, 5 pytest tests with 100% branch coverage, and package builds. The same setup, verification, build, and demo passed from a separate clean clone.
- Commit/link/path: initial implementation commit `fc356ec`; repository root is this directory.
- Blocker, if any: none.
- Next unchecked ID: A02 - select and document the vector source, revision, retrieval date, and license.

## 2026-09-02 - A02 vector-source decision

- Project and task ID: ACVP Assay - A02
- Done condition: the official AES-GCM vector source, immutable revision, retrieval date, integrity hashes, licensing terms, and redistribution decision are documented.
- Evidence produced: `docs/vector-sources.md` pins NIST `ACVP-Server` commit `975de31eb83d87039ec88934fdc47d8c312b892d`, three exact source files, Git blob IDs, SHA-256 hashes, schema coverage, and source-handling policy.
- Tests run and result: upstream files were decoded directly from the GitHub API and their structure, case counts, identifiers, sizes, and SHA-256 hashes were independently inspected. Local Ruff, strict mypy, 5 pytest tests with 100% coverage, and wheel/sdist builds all passed.
- Commit/link/path: `docs/vector-sources.md` in this repository.
- Blocker, if any: none; upstream JSON will be fetched and hash-checked rather than redistributed.
- Next unchecked ID: A03 - add one tiny independently generated valid encrypt fixture and one valid decrypt fixture.

## 2026-09-02 - A03 tiny valid fixtures

- Project and task ID: ACVP Assay - A03
- Done condition: one tiny valid encrypt fixture and one tiny valid decrypt fixture exist under `fixtures/`, use ACVP-shaped prompt/result pairs, and are cryptographically checked.
- Evidence produced: independently generated fixture pairs in `fixtures/aes-gcm-valid-encrypt/` and `fixtures/aes-gcm-valid-decrypt/`, plus provenance and execution instructions in `fixtures/README.md`.
- Tests run and result: 4 fixture-specific checks passed for identifiers, declared lengths, ciphertext/tag generation, and authenticated plaintext recovery. The full gate passed Ruff, strict mypy, 9 pytest tests with 100% application coverage, and wheel/sdist builds.
- Commit/link/path: the two fixture directories and `tests/unit/test_fixtures.py` in this repository.
- Blocker, if any: none.
- Next unchecked ID: A04 - define typed internal models for vector set, test group, test case, and result while preserving ACVP IDs.

## 2026-09-02 - A04 typed internal models

- Project and task ID: ACVP Assay - A04
- Done condition: immutable typed models represent vector sets, test groups, test cases, comparable values, and classified results while retaining `vsId`, `tgId`, and `tcId`.
- Evidence produced: `src/acvp_assay/models.py` defines explicit direction, test-type, and result-status wire values plus frozen, slotted dataclasses for the AES-GCM domain.
- Tests run and result: model tests passed for ID preservation, immutability, hashability, result values, diagnostics, and stable enum wire values. The full gate passed Ruff, strict mypy, 13 pytest tests with 100% coverage, and wheel/sdist builds without warnings.
- Commit/link/path: `src/acvp_assay/models.py` and `tests/unit/test_models.py`.
- Blocker, if any: none.
- Next unchecked ID: A05 - validate required fields, types, invalid hexadecimal values, and unsupported directions.

## 2026-09-02 - A05 input validation

- Project and task ID: ACVP Assay - A05
- Done condition: required top-level, group, and case fields are checked with safe paths; wrong JSON types, malformed hexadecimal data, unsupported direction/test type, algorithm, and revision are rejected.
- Evidence produced: `src/acvp_assay/parser.py` separates boundary validation from immutable domain models and raises `AcvpValidationError` with an exact JSON-style path and non-secret diagnostic.
- Tests run and result: 35 negative validation cases cover missing fields at every level, booleans masquerading as integers, wrong scalar/container types, non-object nodes, odd/invalid/separated hex, direction-specific fields, and unsupported contract values. The full gate passed Ruff, strict mypy, 48 pytest tests with 98.95% coverage, and wheel/sdist builds.
- Commit/link/path: `src/acvp_assay/parser.py` and `tests/unit/test_parser_validation.py`.
- Blocker, if any: none.
- Next unchecked ID: A06 - load and parse one complete group without losing `vsId`, `tgId`, or `tcId`.

## 2026-09-02 - A06 lossless group parsing

- Project and task ID: ACVP Assay - A06
- Done condition: an ACVP-shaped JSON file is loaded and normalized through validation into the internal model without losing vector, group, or case IDs.
- Evidence produced: `load_vector_set()` performs UTF-8 JSON loading with bounded parse diagnostics; integration tests load both tiny prompt files and assert IDs, metadata, direction, declared lengths, and normalized direction-specific byte fields.
- Tests run and result: both encrypt and decrypt fixtures passed end-to-end loading and normalization checks; malformed JSON produced a bounded location-only diagnostic. The full gate passed Ruff, strict mypy, 52 pytest tests with 100% coverage, and wheel/sdist builds.
- Commit/link/path: `src/acvp_assay/parser.py` and `tests/integration/test_parser.py`.
- Blocker, if any: none.
- Next unchecked ID: A07 - define a provider interface for encrypt, decrypt, and provider/version metadata.

## 2026-09-02 - A07 provider boundary

- Project and task ID: ACVP Assay - A07
- Done condition: parsing does not invoke OpenSSL; a replaceable typed interface defines encrypt, decrypt, and provider/backend metadata.
- Evidence produced: `AesGcmProvider` is a runtime-checkable structural protocol, `ProviderMetadata` records both library and backend versions, and a non-cryptographic stub proves the boundary is implementation-independent.
- Tests run and result: a non-OpenSSL stub satisfied the runtime protocol and exercised metadata, encrypt, and decrypt signatures. The full gate passed Ruff, strict mypy, 53 pytest tests with 100% coverage, and wheel/sdist builds.
- Commit/link/path: `src/acvp_assay/providers/base.py`, `src/acvp_assay/models.py`, and `tests/unit/test_provider_contract.py`.
- Blocker, if any: none.
- Next unchecked ID: A08 - implement AES-GCM encrypt through the OpenSSL-backed `cryptography` binding and compare ciphertext/tag separately.

## 2026-09-02 - A08 OpenSSL-backed encryption

- Project and task ID: ACVP Assay - A08
- Done condition: the first concrete provider encrypts AES-GCM through `cryptography`'s OpenSSL binding, identifies both versions, returns ciphertext/tag separately, and covers empty plaintext and AAD.
- Evidence produced: `CryptographyAesGcmProvider.encrypt()` uses the GCM cipher API, emits byte-separated ciphertext and a requested 32-128-bit tag, and retains the provider boundary defined in A07.
- Tests run and result: the stored encrypt fixture matched ciphertext and tag separately; three empty plaintext/AAD combinations matched the independent high-level API; 32-bit tag truncation and invalid tag lengths were covered. The full gate passed Ruff, strict mypy, 64 pytest tests with 100% coverage, and wheel/sdist builds.
- Commit/link/path: `src/acvp_assay/providers/cryptography_aesgcm.py` and `tests/unit/test_cryptography_provider.py`.
- Blocker, if any: none.
- Next unchecked ID: A09 - implement authenticated decryption and negative cases for modified inputs and wrong keys.

## 2026-09-02 - A09 authenticated decryption

- Project and task ID: ACVP Assay - A09
- Done condition: valid AES-GCM ciphertext/tag decrypts through the OpenSSL-backed provider; modified tag, wrong key, wrong IV, and modified ciphertext fail authentication.
- Evidence produced: `CryptographyAesGcmProvider.decrypt()` configures GCM with the supplied tag and an explicit 32-128-bit minimum, authenticates AAD, and exposes plaintext only after finalization succeeds.
- Tests run and result: the valid decrypt fixture recovered the expected plaintext; modified tag, wrong key, wrong IV, and modified ciphertext each raised `InvalidTag`; supported truncated tags and invalid tag lengths were covered. The full gate passed Ruff, strict mypy, 72 pytest tests with 100% coverage, and wheel/sdist builds.
- Commit/link/path: `src/acvp_assay/providers/cryptography_aesgcm.py` and `tests/unit/test_cryptography_provider.py`.
- Blocker, if any: none.
- Next unchecked ID: A10 - implement per-case PASS/FAIL/ERROR comparison output with expected and actual values plus a safe diagnostic.

## 2026-09-02 - A10 per-case comparison

- Project and task ID: ACVP Assay - A10
- Done condition: every compared case retains its IDs, expected/actual values, PASS/FAIL/ERROR status, and a safe diagnostic that does not echo secrets or raw exceptions.
- Evidence produced: `compare_values()` names only mismatched output fields; `error_result()` accepts a closed `SafeDiagnostic` enum and never receives an exception object or free-form exception text.
- Tests run and result: exact matches, each individual output mismatch, combined ciphertext/tag mismatch, and all closed error diagnostics were covered. The full gate passed Ruff, strict mypy, 80 pytest tests with 100% coverage, and wheel/sdist builds.
- Commit/link/path: `src/acvp_assay/comparator.py` and `tests/unit/test_comparator.py`.
- Blocker, if any: none.
- Next unchecked ID: A11 - generate JSON totals for passed, failed, errored, skipped/unsupported, and provider version.

## 2026-09-02 - A11 JSON report and summary

- Project and task ID: ACVP Assay - A11
- Done condition: deterministic JSON contains every case, total/passed/failed/errored/skipped/unsupported counts, and the binding plus backend versions.
- Evidence produced: `reporter.py` serializes expected/actual AES-GCM values using ACVP field names, includes bounded diagnostics, and emits an explicit zero-preserving summary schema and provider identity.
- Tests run and result: `scripts/dev.py verify` passed Ruff, strict mypy, 85 pytest tests with 100% branch coverage, and wheel/sdist builds.
- Commit/link/path: `src/acvp_assay/reporter.py` and `tests/unit/test_reporter.py`.
- Blocker, if any: none.
- Next unchecked ID: A12 - implement the `run` command, output file, strict mode, and documented exit codes.

## 2026-09-02 - Code review fixes on A10/A11

- Project and task ID: ACVP Assay - review follow-up (A10/A11)
- Done condition: `TestCaseResult` itself rejects ERROR diagnostics outside the closed safe vocabulary instead of relying on convention at `comparator.error_result()`; `_values_document` reaches 100% branch coverage; `build_report`'s summary is derived from `ReportSummary` instead of hand-duplicated; the A11 log entry above records its actual verified gate result instead of "pending".
- Evidence produced: `SafeDiagnostic` moved to `models.py` (re-exported from `comparator.py`); `TestCaseResult.__post_init__` raises `ValueError` for an ERROR result whose diagnostic is not a `SafeDiagnostic` value; `reporter.build_report` now builds `"summary"` via `dataclasses.asdict(summary)`; new tests cover independent ciphertext/tag presence and the diagnostic-rejection/acceptance behavior.
- Tests run and result: `scripts/dev.py verify` passed Ruff, strict mypy, 88 pytest tests with 100% branch coverage, and wheel/sdist builds.
- Commit/link/path: `src/acvp_assay/models.py`, `src/acvp_assay/comparator.py`, `src/acvp_assay/reporter.py`, `tests/unit/test_models.py`, `tests/unit/test_reporter.py`.
- Blocker, if any: none.
- Next unchecked ID: A12 - implement the `run` command, output file, strict mode, and documented exit codes.

## 2026-09-02 - A12 the `run` command

- Project and task ID: ACVP Assay - A12
- Done condition: `acvp-assay run VECTOR_FILE [--output RESULT_FILE] [--strict]` parses a vector file and its sibling `expectedResults.json`, executes every case through the OpenSSL-backed provider, writes the JSON report to stdout or a file, and returns a documented exit code (0 hard-pass, 1 case failures or `--strict` soft failures, 2 the run could not start).
- Evidence produced: `parser.py` gained `parse_expected_results`/`load_expected_results` (typed `ExpectedResultCase`/`Group`/`Set` models in `models.py`, preserving `tgId`/`tcId`); `runner.py` is the new orchestration layer matching cases by `(tgId, tcId)`, classifying groups with non-`external` `ivGen` as UNSUPPORTED, and turning `InvalidTag`/`ValueError` provider exceptions into bounded ERROR results instead of exposing raw exception text; `cli.py` wires parser+runner+reporter behind the `run` subcommand and owns exit-code semantics.
- Tests run and result: `scripts/dev.py verify` passed Ruff, strict mypy, 118 pytest tests with 100% branch coverage, and wheel/sdist builds.
- Commit/link/path: `src/acvp_assay/{parser,models,runner,cli}.py`, `tests/unit/test_expected_results_parser.py`, `tests/unit/test_runner.py`, `tests/unit/test_cli.py`.
- Blocker, if any: none.
- Next unchecked ID: A13 - deterministic unit tests and one integration test executing the complete CLI against the tiny fixtures.

## 2026-09-02 - A13 CLI integration coverage

- Project and task ID: ACVP Assay - A13
- Done condition: deterministic unit tests cover the runner and the `run` subcommand (pass, error, `--output`, `--strict`, a load error), and one integration test invokes the installed CLI end to end through a subprocess against the tiny fixtures.
- Evidence produced: `tests/integration/test_run_command.py` runs `python -m acvp_assay run ...` as a subprocess against `aes-gcm-valid-encrypt` (PASS, stdout), `aes-gcm-valid-decrypt` (PASS, `--output`), and the new `aes-gcm-invalid-decrypt-tag` fixture (ERROR, non-zero exit); `tests/unit/test_runner.py` and `tests/unit/test_cli.py` cover the same paths in-process plus the missing-file and mismatched-identity cases.
- Tests run and result: included in the A12 gate above (118 pytest tests, 100% branch coverage); no additional source changes were needed beyond the A12 commit.
- Commit/link/path: `tests/integration/test_run_command.py`, `tests/unit/test_runner.py`, `tests/unit/test_cli.py`.
- Blocker, if any: none.
- Next unchecked ID: A14 - add one intentionally bad fixture that produces a visible, deterministic CI failure signal.

## 2026-09-02 - A14 intentionally bad fixture

- Project and task ID: ACVP Assay - A14
- Done condition: one fixture is deliberately corrupted so the runner produces a genuine, reproducible failure, and a test asserts on it without making the CI job itself flaky or red.
- Evidence produced: `fixtures/aes-gcm-invalid-decrypt-tag/` reuses `aes-gcm-valid-decrypt/`'s key/IV/AAD/ciphertext but flips the final hex digit of the tag, so `InvalidTag` is deterministic (verified independently against `cryptography`'s high-level `AESGCM` API, not just this project's own provider); `expectedResults.json` has no `pt` field, which `parse_expected_results`/`runner.py` treat as "authentication is expected to fail." `test_run_command_fails_visibly_on_the_intentionally_bad_fixture` asserts exit code 1 and an `ERROR`/`authentication failed` case — a passing pytest assertion that the CI job (`.github/workflows/ci.yml`) already runs on every push.
- Tests run and result: included in the A12 gate above; the CI workflow requires no changes since `scripts/dev.py verify` already runs the full pytest suite.
- Commit/link/path: `fixtures/aes-gcm-invalid-decrypt-tag/`, `fixtures/README.md`, `tests/integration/test_run_command.py`.
- Blocker, if any: none.
- Next unchecked ID: A15 - publish v0.1.0 with a five-minute quick start, architecture, sample pass/failure output, and security limitations.

## 2026-09-02 - A15 publish v0.1.0

- Project and task ID: ACVP Assay - A15
- Done condition: the version is tagged 0.1.0; the README documents the `run` command with real sample PASS and failure output; `docs/architecture.md` documents the `run` command, its exit codes, and the expected-results sibling-file convention; `docs/limitations.md` reflects the shipped v0.1.0 feature set (not the stale pre-MVP text) and keeps the FIPS 140-3 non-validation statement.
- Evidence produced: `pyproject.toml` and `src/acvp_assay/__init__.py` bumped to `0.1.0`; README gained "Running vectors" plus real PASS/ERROR sample output captured from an actual run against the fixtures; `docs/architecture.md` and `docs/limitations.md` rewritten for the complete v0.1.0 pipeline; `docs/backlog.md` A12-A15 checked off.
- Tests run and result: `scripts/dev.py verify` passed Ruff, strict mypy, 118 pytest tests with 100% branch coverage, and `wheel`/`sdist` built as `acvp_assay-0.1.0`. A from-scratch venv re-creation in a separate clean copy of the tree was attempted but blocked by this sandbox's missing `python3.12-venv` system package (a pre-existing environment gap, not caused by this change); as a substitute, the new/changed files were grep-checked for absolute or `/tmp` paths (none found) to confirm no hidden local-state dependency was introduced.
- Commit/link/path: `pyproject.toml`, `src/acvp_assay/__init__.py`, `README.md`, `docs/architecture.md`, `docs/limitations.md`, `docs/backlog.md`.
- Blocker, if any: a genuine clean-room (`python -m venv` from scratch) verification is still owed once `python3.12-venv` is installed on a verification host; noted here rather than silently claimed.
- Next unchecked ID: none - the v0.1.0 AES-GCM MVP backlog is complete.

## 2026-09-02 - M01 pinned upstream vectors, and the bug they exposed

- Project and task ID: ACVP Assay - M01 (market roadmap)
- Done condition: the three pinned NIST AES-GCM files download reproducibly, verify by size and SHA-256 before being written, stay out of version control, and the full sixty-case set runs end to end through the CLI.
- Evidence produced: `scripts/fetch_vectors.py` holds the pins and refuses to write a file whose size or hash differs; `vectors/` is git-ignored per the existing no-redistribution decision; `scripts/dev.py vectors` wires it into the task runner. All three upstream hashes recorded in `docs/vector-sources.md` back in A02 were confirmed byte-for-byte correct against the live repository, so that document is trustworthy.
- Defect found and fixed: real NIST data revealed that ten of the sixty cases (groups 3 and 4) are deliberate authentication-failure tests encoded as `"testPassed": false` with no `pt`. The runner classified every `InvalidTag` as ERROR, so a *correct* implementation rejecting a forged tag was scored as an error, and the security-critical inverse - an implementation wrongly accepting a forged tag - was not distinguished at all. `ExpectedResultCase` now carries `test_passed`, the parser reads `testPassed`, and `runner.py` inverts the verdict for those cases: rejection is a PASS, acceptance is a loud FAIL. This shape was invisible to the three hand-written fixtures and only surfaced against real vectors.
- Tests run and result: `scripts/dev.py test` passed Ruff, strict mypy, 130 pytest tests with 100% branch coverage. The full upstream set now reports 60/60 passed with exit code 0, including the ten expected-rejection cases. `tests/integration/test_nist_vectors.py` skips automatically when the vectors are absent, so CI stays network-free and deterministic.
- Commit/link/path: `scripts/fetch_vectors.py`, `scripts/dev.py`, `src/acvp_assay/{models,parser,runner}.py`, `fixtures/aes-gcm-decrypt-auth-failure/`, `tests/unit/test_fetch_vectors.py`, `tests/integration/test_nist_vectors.py`.
- Blocker, if any: none.
- Next unchecked ID: M02 - subprocess provider speaking JSON on stdin/stdout.

## 2026-09-02 - M02 external harness provider

- Project and task ID: ACVP Assay - M02 (market roadmap)
- Done condition: a customer can test an implementation this project cannot link against, by writing a program that reads one JSON request on stdin and writes one JSON response on stdout; the report attributes results to their implementation rather than to the built-in provider.
- Evidence produced: `providers/subprocess_harness.py` implements the existing `AesGcmProvider` protocol over a subprocess, so nothing upstream of the provider boundary changed. `--provider-command` and `--provider-timeout` expose it on the CLI. `examples/reference_harness.py` is a complete worked harness that deliberately imports nothing from `acvp_assay`, which is what actually proves the A07 boundary is replaceable rather than merely typed. The full sixty-case pinned NIST set passes through the external process in about 3.8s, reported as provider `reference-harness`.
- Design decisions: a rejected tag is signalled as `{"error": "authentication failed"}` and translated into the same `InvalidTag` the in-process provider raises, so the `testPassed` verdict logic from M01 works identically for every provider - a harness that instead crashed on those cases would score a conforming implementation as broken. Harness stderr is inherited rather than captured, so developers see diagnostics live while nothing from a crashing harness can reach a shared report; harness error text is never echoed for the same reason. One invocation per operation keeps the contract trivial to implement, at roughly 60ms per spawn; a persistent mode can be added later without changing the wire format.
- Defect found and fixed: the first integration test exposed that a missing harness command reported every case as INVALID_CASE and then crashed with a traceback, because `provider.metadata()` ran at report time outside the handled exception set. Provider metadata is now fetched once, before any case runs, so a misconfigured harness stops the run with a single clear message and exit code 2 - and the report no longer costs an extra spawn.
- Tests run and result: `scripts/dev.py verify` passed Ruff, strict mypy, 152 pytest tests with 100% branch coverage, and wheel/sdist builds. Coverage includes the timeout, non-executable, missing-command, non-zero-exit, malformed-JSON, non-object, missing-field, invalid-hex, and error-not-echoed paths.
- Commit/link/path: `src/acvp_assay/providers/subprocess_harness.py`, `src/acvp_assay/cli.py`, `examples/reference_harness.py`, `tests/unit/test_subprocess_harness.py`, `tests/integration/test_run_command.py`.
- Blocker, if any: none.
- Next unchecked ID: M03 - SHA2 with Monte Carlo test support, then HMAC.

## 2026-09-02 - M03 SHA-2 and HMAC

- Project and task ID: ACVP Assay - M03 (market roadmap)
- Done condition: a second and third algorithm family run end to end from the same CLI, with the algorithm read from the vector file and routed automatically; SHA-2 covers the Monte Carlo test type, which is structurally unlike anything the AES-GCM path handles.
- Evidence produced: `algorithms/` is the new dispatch seam - `sha2.py` and `hmac_mac.py` own their models, parsers and runners, while everything downstream of execution (`TestCaseResult`, comparator vocabulary, reporter, exit codes) is shared unchanged. `providers/digest.py` adds `HashProvider`/`MacProvider` boundaries with hashlib-backed implementations. `models.py` gained a `CaseValues` protocol so a result can carry AES-GCM values or digests without the reporter growing isinstance chains. Parser primitives are now shared so every algorithm reports the same `$.testGroups[0].tests[0].field` paths.
- Verified against real NIST data: SHA2-256 runs 512 AFT cases plus one MCT group to 513 passed with 4 LDT cases correctly UNSUPPORTED; HMAC-SHA2-256 runs 975/975 including the 80/88/96-bit truncated-MAC groups. The MCT case matches NIST's full 100-entry `resultsArray`.
- Design decisions taken from the spec rather than assumed: NIST's SHA-2 set declares `mctVersion: "alternate"`, which normalises every inner message to the *original* seed length by truncation or zero-padding, rather than hashing three concatenated digests. The seed length is captured once before the loop, so later iterations pad up to it after the seed shrinks to one digest. Implementing the standard chain here would have failed the MCT case, and both variants are now implemented and tested to differ. LDT cases expand to as much as 8 GiB and are declared UNSUPPORTED rather than approximated; bit-oriented message lengths are likewise declared. `--provider-command` is refused for hash and MAC families with a clear message, because the harness wire contract still covers AES-GCM only and a Monte Carlo group would otherwise mean 100,000 process spawns.
- Defect found and fixed: exporting a parser helper named `string` shadowed `import string` inside `parser.py`, which `_hex_value` uses for `string.hexdigits` - a latent break of every hex validation in the project. Renamed to `string_field`.
- Tests run and result: `scripts/dev.py verify` passed Ruff, strict mypy, 204 pytest tests with 100% branch coverage, and wheel/sdist builds. Local fixtures use published known answers - FIPS 180-4 for SHA-256 and RFC 4231 case 1 for HMAC - so CI has independent assurance without network access.
- Commit/link/path: `src/acvp_assay/algorithms/`, `src/acvp_assay/providers/digest.py`, `src/acvp_assay/models.py`, `scripts/fetch_vectors.py`, `fixtures/sha2-256-known-answers/`, `fixtures/hmac-sha2-256-known-answers/`, `tests/unit/test_algorithms.py`, `tests/unit/test_digest_providers.py`.
- Blocker, if any: none.
- Next unchecked ID: M04 - the produce-and-verify and verdict-only result paths (ECDSA sigGen/sigVer).

## 2026-09-02 - M04 the two result shapes AES-GCM never needed

- Project and task ID: ACVP Assay - M04 (market roadmap)
- Done condition: ECDSA runs end to end in both modes, using result shapes the compare-output path cannot express.
- Evidence produced: `algorithms/ecdsa.py` and `providers/ecdsa.py`; `models.py` gained `VerdictValues` and `SignatureValues`, and `CaseValues.as_document()` widened to `dict[str, object]` so a verdict serializes as a real JSON boolean rather than a string.
- Verified against real NIST data: ECDSA sigVer over the pinned FIPS186-5 set is 140 passed / 0 failed / 56 unsupported, and the expected verdicts split 120 false to 20 true - so 120 deliberately invalid signatures were correctly rejected and 20 valid ones correctly accepted. ECDSA sigGen is 800 passed / 0 failed / 2080 unsupported (1600 binary and Koblitz curves OpenSSL does not offer here, 480 SHAKE hashes).
- The finding that justified the task: sigGen prompt cases carry only `{tcId, message}`. The implementation under test generates its own key, so the `qx`/`qy`/`r`/`s` recorded in `expectedResults` are NIST's own. Ours differ completely (NIST `BDF3EF47...` against our `90EBE377...`), exactly as randomized signing requires. Comparing against them would have failed all 800 conforming cases, so `parse_expected_results` deliberately discards those fields and keeps only verdicts, and sigGen passes by verifying its own signature under its own public key.
- Second correctness point: an off-curve public key or out-of-range scalar in a sigVer case produces a *verdict* of false, not an error. ACVP sets are full of such cases on purpose; raising there would turn a correct rejection into a failure.
- Tests run and result: `scripts/dev.py verify` passed Ruff, strict mypy, 247 pytest tests with 100% branch coverage, and wheel/sdist builds.
- Commit/link/path: `src/acvp_assay/algorithms/ecdsa.py`, `src/acvp_assay/providers/ecdsa.py`, `src/acvp_assay/models.py`, `fixtures/ecdsa-p256-sigver/`, `tests/unit/test_ecdsa.py`.
- Blocker, if any: none.
- Next unchecked ID: M05 - ML-KEM and ML-DSA.

## 2026-09-02 - M05 ML-KEM and ML-DSA

- Project and task ID: ACVP Assay - M05 (market roadmap)
- Done condition: ML-KEM and ML-DSA vector sets parse, route, execute, and report; every function is matched to the comparison its shape requires.
- Evidence produced: `algorithms/pqc.py` and `providers/pqc.py`. Real NIST files parse into the expected shapes: ML-KEM encapDecap is 165 cases across four functions (105 comparable-bytes, 60 verdict-only) and ML-DSA sigVer is 180 verdict-only cases. `HarnessClient` was extracted from the AES-GCM subprocess provider so every family shares one transport, timeout, and error-to-diagnostic rule.
- Payoff from M04: no new result shape was needed. ML-KEM encapsulation supplies the random `m` in the prompt, so it is deterministic and its `c`/`k` compare directly; decapsulation compares `k`; the encapsulation and decapsulation key checks are verdict-only, as is ML-DSA sigVer - the shape ECDSA introduced.
- **There is deliberately no built-in PQC provider.** The pinned `cryptography` 50.0.1 exposes neither ML-KEM nor ML-DSA, and the system OpenSSL is 3.0.13 while PQC landed in 3.5. Rather than add an unvetted dependency or hand-roll post-quantum primitives, these families require `--provider-command`, and the CLI says so explicitly. This is the correct outcome for the business case as well: for PQC the implementation under test is the customer's - OpenSSL 3.5+, liboqs, or their own module - which is precisely what the provider boundary exists for.
- Honest limits recorded: ML-DSA `externalMu` groups (a precomputed mu instead of a message) and `preHash` groups are declared UNSUPPORTED rather than misinterpreted, as are unknown parameter sets and cases missing required inputs. Cryptographic correctness of ML-KEM/ML-DSA is **not** claimed here: with no local implementation, the tests verify parsing, routing, comparison, and reporting using a stub that replays NIST's own expected values keyed by input, plus a deliberately corrupted stub proving every function's failures surface rather than pass.
- Tests run and result: `scripts/dev.py verify` passed Ruff, strict mypy, 247 pytest tests with 100% branch coverage, and wheel/sdist builds.
- Commit/link/path: `src/acvp_assay/algorithms/pqc.py`, `src/acvp_assay/providers/pqc.py`, `src/acvp_assay/providers/subprocess_harness.py`, `tests/unit/test_pqc.py`.
- Blocker, if any: end-to-end PQC verification against NIST vectors awaits an ML-KEM/ML-DSA implementation to drive - OpenSSL 3.5+ or liboqs behind a harness. Recorded rather than silently claimed.
- Next unchecked ID: M06 - run-over-run regression diffing between two reports.

## 2026-09-02 - M05 follow-up: PQC verified end to end, and the bug that found

- Project and task ID: ACVP Assay - M05 (follow-up)
- Done condition: the PQC path is verified against real NIST vectors rather than only against stubs, and can be demonstrated, without adding a runtime dependency or hand-rolling post-quantum primitives.
- Evidence produced: `examples/pqc_reference_harness.py` drives ML-KEM and ML-DSA through the existing subprocess boundary using `kyber-py` and `dilithium-py` - development-only references that already pass NIST's own ACVP known-answer tests from the same `usnistgov/ACVP-Server` repository this project pins. The runtime dependency set is unchanged: PQC is still reached through `--provider-command`, which is what a customer engagement uses.
- Results against the pinned NIST sets: ML-KEM encapDecap **165/165 passed** across encapsulation, decapsulation, and both key-check functions. ML-DSA sigVer **90/90 executable cases passed**, with 90 declared UNSUPPORTED (45 preHash, 45 externalMu).
- Defect found and fixed: the first ML-DSA run reported 9 failures, all "rejected a signature ACVP declares valid", and all in `signatureInterface: internal` groups. The runner was treating the internal interface as external-with-empty-context, but the internal interface omits the domain separator and context prefix the external one applies, so a valid internal signature is correctly rejected when checked externally. `signatureInterface` now crosses the provider boundary, and a regression test asserts it reaches the harness. Only real vectors surfaced this: every stub-based test passed while the bug was present, and against a customer's conforming implementation it would have reported nine spurious failures.
- Honest limits unchanged: these references are pure-Python and not constant-time; they verify this runner's parsing, routing, and comparison, and make no claim about the security of any implementation. ML-DSA preHash and externalMu groups remain declared UNSUPPORTED.
- Tests run and result: `scripts/dev.py verify` passed Ruff, strict mypy, 248 pytest tests with 100% branch coverage, and wheel/sdist builds.
- Commit/link/path: `examples/pqc_reference_harness.py`, `src/acvp_assay/algorithms/pqc.py`, `src/acvp_assay/providers/pqc.py`, `tests/unit/test_pqc.py`.
- Blocker, if any: none. The earlier blocker - no implementation available to verify PQC end to end - is cleared.
- Next unchecked ID: M06 - run-over-run regression diffing between two reports.

## 2026-09-02 - M06 run-over-run regression diffing

- Project and task ID: ACVP Assay - M06 (market roadmap)
- Done condition: two reports from `acvp-assay run` can be compared, regressions are reported with the identifiers and diagnostics needed to act on them, and the exit code makes the comparison usable as a CI gate.
- Evidence produced: `src/acvp_assay/diff.py` plus an `acvp-assay diff BASELINE CURRENT [--output FILE]` subcommand. Changes are classified as regressed, coverage lost, fixed, still failing, or added; the verdict is REGRESSED, IMPROVED, or UNCHANGED; exit codes follow the existing scheme (0 nothing worse, 1 regression, 2 unreadable input).
- The design decision that carries the value: **coverage loss counts as a regression**. A case that used to be executed and is now UNSUPPORTED, SKIPPED, or absent entirely is reported as loudly as an outright failure. That is the failure mode that hides - totals still look clean because the case simply stops being counted - and it is what silently drops an algorithm from a test set between validation cycles. Provider identity is diffed alongside the cases, because a changed library or backend version is usually the cause rather than a detail.
- Verified against a realistic scenario: a baseline over the pinned 60-case NIST AES-GCM set compared against a run with one broken case, five groups turned UNSUPPORTED, five cases silently dropped, and an OpenSSL downgrade. The diff reported verdict REGRESSED, 1 regression with its diagnostic, 10 cases of lost coverage, the provider change at the top, and exit code 1. A report compared with itself reports UNCHANGED and exits 0.
- Why this before the remaining PQC coverage: algorithm breadth is the axis where `libacvp` and ACVP Proxy already win and cannot be caught by a solo effort. Regression diffing is the item in the roadmap that neither offers, it converts one-off engagements into recurring work, and it cost roughly one build block against several for the PQC gaps.
- Tests run and result: `scripts/dev.py verify` passed Ruff, strict mypy, 268 pytest tests with 100% branch coverage, and wheel/sdist builds.
- Commit/link/path: `src/acvp_assay/diff.py`, `src/acvp_assay/cli.py`, `tests/unit/test_diff.py`.
- Blocker, if any: none.
- Next unchecked ID: M07 - publish to PyPI, deferred until the version reflects six algorithm families and there is someone to install it.
