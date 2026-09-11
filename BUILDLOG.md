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
- Next unchecked ID: M07 - the AES mode families surrounding GCM. (Publishing to PyPI was M07 at the time of writing; inserting the algorithm-coverage milestones renumbered it, and it is M13 below.)

## 2026-09-02 - M07 the AES mode families a real module validates beside GCM

- Project and task ID: ACVP Assay - M07
- Done condition: the AES names that recur on published CAVP certificates alongside GCM are runnable - `ACVP-AES-ECB`, `ACVP-AES-GMAC`, `ACVP-AES-KW`, `ACVP-AES-KWP` and `CMAC-AES`.
- Why these five: AES-GCM alone covers very few real validations. Reviewing published certificates showed a module that validates GCM almost always validates a key wrap and a CMAC beside it, so these four names recur far more often than anything else still missing.
- Evidence produced: `src/acvp_assay/algorithms/aes_modes.py` and `src/acvp_assay/providers/aes_modes.py`, plus twelve more pinned files in `scripts/fetch_vectors.py` covering the five new families and - a pre-existing gap - the ECDSA, ML-KEM and ML-DSA sets, which had been fetched by hand but never pinned.
- The detail that carries the work: the AES Monte Carlo key shuffle differs by key length. A 128-bit key is refreshed from the final ciphertext block alone; 192- and 256-bit keys reach back into the previous block, because one 128-bit output is not enough key material. All 2,144 ECB cases reproduce the pinned arrays.
- Honest total: `kwCipher: inverse` is reported UNSUPPORTED rather than guessed at. It is half of each pinned KW and KWP set, so the honest figure is 3,600 executed and 3,600 declared per set, not a quiet 7,200.
- Tests run and result: `scripts/dev.py verify` passed the full gate - Ruff, strict mypy, pytest with branch coverage, and wheel/sdist builds.
- Commit/link/path: released as v0.4.0.
- Blocker, if any: none.
- Next unchecked ID: M08 - Counter DRBG.

## 2026-09-02 - M08 Counter DRBG, and the first stateful provider shape

- Project and task ID: ACVP Assay - M08
- Done condition: `ctrDRBG` runs at both revisions, `1.0` and `SP800-90Ar1`.
- Why here: a DRBG sits in effectively every FIPS module, which made it the widest remaining single gap. It is also the first algorithm needing a genuinely new provider shape - a case instantiates a state machine, optionally reseeds it, and generates twice, rather than performing one transform.
- Evidence produced: 450 cases against both pinned sets, zero failures, covering AES-128/192/256, the derivation function both ways, prediction resistance both ways, and counter widths of 128 and 64 bits. `optional_integer` was added to the parser for fields like `counterFieldLen` that exist in one revision and not the other.
- Two details that are silently wrong if you get them wrong, both now covered by tests: prediction resistance turns a `generate` carrying entropy into a reseed followed by a generation, with the additional input consumed by the *reseed* rather than the generation; and every case generates twice while only the second output is compared - comparing the first would pass a DRBG that never updates its state.
- Three-key TDES is reported UNSUPPORTED rather than answered: SP 800-131A disallowed it for this use after 2023, so 150 of the 750 pinned cases are declared.
- Tests run and result: `scripts/dev.py verify` passed the full gate.
- Commit/link/path: released as v0.5.0.
- Blocker, if any: none.
- Next unchecked ID: M09 - KDF SP 800-108.

## 2026-09-02 - M09 KDF SP 800-108, and a bit offset mistaken for a byte offset

- Project and task ID: ACVP Assay - M09
- Done condition: `KDF` revision 1.0 runs in counter, feedback and double-pipeline modes across the 14 PRFs - HMAC over SHA-1, the SHA-2 family and the SHA-3 family, plus CMAC-AES128/192/256.
- Evidence produced: 10,950 cases executed against the pinned set with zero failures, and a further 806 CMAC-TDES cases declared UNSUPPORTED.
- What this set uniquely exposes: it is the only pinned set whose *expected results file carries an input*. The prompt gives only `keyIn`, because a conforming implementation chooses its own `fixedData`; the runner reads NIST's choice back out of `expectedResults.json` and derives against it. A pass therefore shows the derivation is correct for that fixed data - it does not exercise an implementation's freedom to construct fixed data of its own, which the ACVP server checks and no file-based runner can. `docs/vector-sources.md` says so plainly.
- Defect the vectors caught: `breakLocation` is a **bit** offset, not a byte offset. Upstream values run 1 to 127 against 128-bit fixed data, so the counter splices mid-byte. Treating it as bytes passes 10,092 cases and fails 858 - the kind of near-miss that looks like success on a summary line. Also, `keyOutLength` is frequently not a multiple of 8 (67, 331, 1003), so the last byte's padding bits must be cleared.
- Tests run and result: `scripts/dev.py verify` passed the full gate.
- Commit/link/path: released as v0.6.0.
- Blocker, if any: none.
- Next unchecked ID: live validation against NIST's own server.

## 2026-09-03 - Live validation against NIST's ACVTS Demo server

- Project and task ID: ACVP Assay - interleaved with M07-M12, not a numbered milestone
- Done condition: the runner is checked by the system that *issues* ACVP vectors, not only against static snapshots of them.
- Evidence produced: `scripts/acvts_client.py` - register, fetch, submit, results - and eight test sessions on `demo.acvts.nist.gov`. Seven completed: 27 vector sets, covering 19,237 cases, each returning a `"passed"` disposition. The eighth (765346) was abandoned once the Monte Carlo decrypt bug surfaced, and its cases are excluded from that total rather than quietly folded in. Credentials live outside the repository and are read from `ACVTS_CERT`, `ACVTS_KEY` and `ACVTS_SEED`; `.acvts/` is git-ignored.
- Precision that matters when quoting these numbers: ACVP issues **one disposition per vector set**, not per case. 27 is the count of verdicts NIST returned; 19,237 is the number of cases inside them. `results` now writes the server's reply to `results.json` beside the vector sets it judges, because the verdict is the one part of a live run this project cannot reproduce on its own, and printing it to a terminal left the claim resting on memory.
- Four defects this caught that the offline suite did not, each of which would have shipped:
  - **The AES-GCM parser rejected every real vector set.** It required `ivGenMode`, which qualifies *internal* IV construction, so the live server omits it whenever `ivGen` is `external`. The pinned sample file happens to include it, which is exactly why this survived. The test asserting the field was required was encoding the bug.
  - **The chaining-mode Monte Carlo chains were wrong for decryption.** Read literally, the specification reproduces the encrypt arrays exactly and disagrees from the first block when decrypting. The rules came from `MonteCarloAesCbc.cs` in `usnistgov/ACVP-Server`, where encrypt and decrypt are structurally identical and the asymmetry lives inside the cipher object.
  - **RSA-PSS ignored `maskFunction`.** FIPS 186-5 lets PSS use SHAKE as its mask generation function, signalled by a field separate from `hashAlg`. Six sigVer cases failed while their group looked perfectly supported.
  - **ECDSA and RSA sigGen generated a fresh key per case.** ACVP reports the public key once per *group*, so a key per case cannot be expressed in the response document at all.
- Practical detail worth recording: the ACVTS TOTP is **HMAC-SHA-256 with eight digits**, not the SHA-1 and six digits the public wiki implies. A wrong guess returns a bare 401 naming neither factor. The source of truth is `app/totp/totp.c` in `cisco/libacvp`.
- Method this established, and kept since: **read NIST's generator source first, the specification second.** Every ambiguity above was settled by the generator, and none of them by the prose.
- Blocker, if any: none. Production ACVTS remains lab-only and out of reach by design.
- Next unchecked ID: M10 - keep the harness process alive.

## 2026-09-03 - M10 a persistent harness, and a specification for vendors

- Project and task ID: ACVP Assay - M10
- Done condition: the harness process is started once and kept alive for a whole run, and the wire contract is written down well enough for a vendor to implement against without reading this project's source.
- Evidence produced: `HarnessClient` rewritten around a persistent process with polled reads and a bounded reap, plus `docs/harness-protocol.md` - the operations, the reserved errors, the Monte Carlo traps, and worked integration patterns for HSMs, serial devices and network appliances.
- Measured benefit: 239 SHA3-256 cases take 0.5 s against a persistent harness and 17.9 s against one spawned per case - roughly fifty times.
- Compatibility kept deliberately: a one-shot harness that reads stdin to end still works and is detected on the first exchange, because a shell script with `jq` naturally takes that shape and reach matters more than the speed lost.
- Defect fixed in passing: `Popen.wait()` with no timeout defeated `--provider-timeout` entirely - one test took 61 s. A bounded `_reap` took the suite from 129 s to 15.5 s.
- Tests run and result: `scripts/dev.py verify` passed the full gate.
- Commit/link/path: `737cd5c`, `src/acvp_assay/providers/subprocess_harness.py`, `docs/harness-protocol.md`.
- Blocker, if any: none.
- Next unchecked ID: M11 - harness operations for every family.

## 2026-09-03 - M11 every family reaches a harness

- Project and task ID: ACVP Assay - M11
- Done condition: all 40 algorithm names accept `--provider-command`. Until this landed, the project's central claim - that an implementation which cannot be linked against can still be tested - held for some families and not others, which is the difference between a coverage number and a claim a vendor can rely on.
- Evidence produced, in the order it was built: the AES families (`block-transform`, `block-mct`, `cmac`, `gmac`, `key-wrap`) at **13,282 cases, zero failures, Monte Carlo chains included**; RSA in all four modes (`rsa-sign-group`, `rsa-verify`, `rsa-primitive-sign`, `rsa-primitive-decrypt`) with decryptionPrimitive 90/90 and sigVer 126 passed with 144 declined; then the DRBGs and KDF.
- Design decisions that shaped the wire: a Monte Carlo chain is delegated **whole** rather than driven case by case, because 100 x 1000 round trips per case would take hours and running the chain is what a real implementation does anyway. A DRBG case crosses in **one exchange** carrying its whole `otherInput` sequence, because putting a state machine on a wire makes the two sides agree about a sequence of calls rather than about an answer. An RSA or ECDSA sigGen **group** is signed in one exchange, because ACVP reports the public key once per group.
- Defect the full vector set caught: `HMAC_FOR_KDF` in the reference harness was hand-listed at five hashes and declined 5,486 of 11,756 pinned KDF cases. Derived from `HASHLIB`, the harness path matches the built-in exactly - 10,950 passed, 806 unsupported, 0 failed.
- Tests run and result: `scripts/dev.py verify` passed the full gate; 544 pytest tests at the close of the milestone.
- Commit/link/path: `b5deb61`, `06a1993`, `e8a73b0`, `38a52d0`; `examples/reference_harness.py`, `tests/unit/test_harness_families.py`.
- Process note worth keeping: an edit addressed by line number ran after the formatter had already shifted the lines and silently broke an import block, and I reported a green gate from a stale task-output file before catching it. Both are why the string-anchored edits with an asserted match count are used now, and why a gate result is read from the file that run wrote.
- Blocker, if any: none.
- Next unchecked ID: M12 - the live responder.

## 2026-09-03 - M12 a vendor's own answers reach NIST

- Project and task ID: ACVP Assay - M12
- Done condition: `scripts/acvts_client.py submit --provider-command ...` answers a live ACVTS session from the vendor's implementation rather than from this project's OpenSSL binding, which is the configuration that says anything about their product.
- Evidence produced: `Harness` in `responder.py`, threaded through every response builder, plus `--provider-command`, `--provider-timeout` and `--dry-run` on the submit subcommand. The submitted document is identical in shape either way - the server is told what was computed, never how.
- Two rules this forced, which verification never had to decide:
  - **A declined case refuses the whole document.** Offline, UNSUPPORTED is a verdict worth recording. In a submission there is no such verdict - ACVP scores a missing case as a wrong answer - so a partial document would record a failure the implementation never earned. The error names the operation declined.
  - **Capability belongs to the implementation.** The responder was raising the built-in provider's limits - ctrDRBG `TDES`, KDF `CMAC-TDES` - on the vendor's behalf, which would make a submission impossible for a product that offers them. Both already travel on the wire, so the implementation now answers or declines them itself. This is the rule `supports()` states everywhere else; the responder was the one place not following it.
- Gap this exposed: `SubprocessEcdsaProvider` had only per-case `sign`, which generates a fresh key each time, so ECDSA sigGen could not be submitted through a harness at all. `ecdsa-sign-group` mirrors `rsa-sign-group`.
- Verified: each pinned prompt answered both ways and compared - **24,048 cases across ten families, byte-identical wherever the answer is deterministic**. Where it cannot be, because the implementation invents part of the input, the answers were checked for self-consistency: 10,950 KDF cases re-derived from the `fixedData` the harness reported, and 800 signatures verified under the `qx`/`qy` it reported. Groups the reference harness itself declines are excluded rather than counted as passes.
- Tests run and result: `scripts/dev.py verify` - 557 pytest tests, 99.73% branch coverage, wheel and sdist built.
- Commit/link/path: `924c197`, `src/acvp_assay/responder.py`, `scripts/acvts_client.py`, `tests/unit/test_responder_harness.py`.
- Blocker, if any: none.
- Next unchecked ID: M13 - publish to PyPI.

## 2026-09-03 - Live coverage from 22 to 38 of 40 algorithm names

- Project and task ID: ACVP Assay - improving NIST coverage
- Done condition: every algorithm name that *can* be submitted to ACVTS has been, and NIST has returned a verdict on it. The README's headline claim stops being "22 of 40" and becomes the ceiling the code allows.
- Why this before implementing new families: the 18 unjudged names were already implemented and already passing pinned vectors. Submitting them costs two sessions and converts "agrees with a snapshot" into "judged by the system that issues the vectors" for nearly half the coverage table. Adding a new family buys one more name at many times the cost.
- Evidence produced: session **765508** - the seven remaining hash names and the eight remaining HMACs, 15 vector sets, 12,867 cases, every one `passed`. Session **765518** - `ACVP-AES-GMAC`, 360 cases, `passed`. Running total across all sessions: **43 vector sets, 32,464 cases, every verdict `passed`**, taking live coverage to **38 of 40 names**. The two that remain, ML-KEM and ML-DSA, have no response builder, so they cannot be submitted at all - that is now the only reason the column is incomplete.
- Order kept deliberately: every set was verified offline against NIST's expected results *before* submission. All 15 passed locally first, which is why nothing had to be withdrawn.
- Defect found in my own registration: the GMAC entry declared `payloadLen` as a zero-width range and NIST's generator refused it with `min must be less than max`. GMAC is AAD-only and has no payload to describe. No vectors were generated, so there was nothing to answer; the set is excluded from the 43 and session 765508 therefore reports `passed: false` overall. Re-registered correctly as 765518. Recorded rather than dropped, on the same principle as 765346.
- Defect found in the new results command, on its first contact with a real reply: it read a `disposition` field and reported every verdict as `unknown`. The Demo server names the field `status`. Both are accepted now. This is precisely the class of bug that only shows up against the live server, and it was visible only because the reply is now saved instead of printed and discarded.
- Gap closed, and one that cannot be: a session's scoped token was only ever written to the single current-session file, so each registration orphaned the previous session. ACVP answers 403 to any token but the one issued at registration, which means the verdicts from the first seven sessions can never be re-fetched - they are recorded from the runs themselves and that is all the evidence there will be. The record is now written beside each session's own vector sets, and `results --session <id>` reads it back.
- Tests run and result: `scripts/dev.py verify` - full gate.
- Commit/link/path: `scripts/acvts_client.py`, `acvts-capabilities/remaining-digests-gmac.json`, `acvts-capabilities/gmac.json`, `README.md`.
- Blocker, if any: ML-KEM and ML-DSA need a response builder in `responder.py` before they can be submitted. That is the remaining item for live coverage.
- Next unchecked ID: M13 - publish to PyPI.

## 2026-09-04 - Every supported algorithm judged by NIST: 40 of 40

- Project and task ID: ACVP Assay - closing the live-coverage gap
- Done condition: no algorithm the runner supports is left without a verdict from NIST's own server.
- Evidence produced: response builders for ML-KEM and ML-DSA in `responder.py`, then two sessions on `demo.acvts.nist.gov` - **765724** (ML-KEM encapDecap, 165 cases, `passed`) and **765727** (ML-DSA sigVer, 45 cases, `passed`). Running total: **45 vector sets, 32,674 cases, every verdict `passed`, 40 of 40 algorithm names**. `supported_response_algorithms()` now equals `supported_algorithms()`, and a test asserts they stay equal.
- These were the first submissions answered **entirely by a harness** rather than by the built-in providers, which is precisely the configuration M12 existed to enable. The mechanism a vendor would use is now the mechanism that produced two of the verdicts.
- The honesty that has to travel with the number: both PQC sessions were answered by `examples/pqc_reference_harness.py`, backed by `kyber-py` and `dilithium-py` - educational, pure-Python, **not constant-time**. A passing verdict is evidence that this runner handles PQC vector sets correctly. It is not evidence that any implementation is fit to ship, and there is still no built-in PQC provider. That statement sits in the README banner rather than in a footnote, because "40 of 40 judged by NIST" invites exactly the wrong reading if it stands alone.
- Registering narrowly is the point, not a workaround: the ML-DSA builder refuses `preHash` and `externalMu` groups, so the registration declares `pure`/`external` only and NIST generated exactly the three groups the runner supports - 45 cases, all answerable. Registering for a capability you refuse produces a document that cannot be completed.
- Four rejected registrations preceded the accepted one, each corrected by the server's own validation text rather than by guessing: `capabilities` must be a non-empty array; `externalMu` is rejected when only the external signature interface is declared; `messageLength` and `contextLength` are required; and `preHash` belongs at the top level rather than inside a capability. Reading the error is faster than reading the spec, and it is authoritative.
- Also hit and worth remembering: two logins inside one 30-second TOTP step return `403 TOTP Window has already been used`. Wait for the next window rather than retrying immediately.
- Tests run and result: `scripts/dev.py verify` - 572 passed, 99.74% branch coverage, `responder.py` at 100%.
- Commit/link/path: `src/acvp_assay/responder.py`, `acvts-capabilities/ml-kem.json`, `acvts-capabilities/ml-dsa.json`, `tests/unit/test_responder_harness.py`.
- Blocker, if any: none. Live coverage is complete for the current algorithm set; raising it further means implementing new families.
- Next unchecked ID: none outstanding. M13 shipped to PyPI on 2026-09-04.

## 2026-09-06 - The first families chosen by measurement, and the defect one hid

- Project and task ID: ACVP Assay - M21, the AES modes the measurement rescued
- Done condition: the five names M25 put at the top of what was missing are implemented, reach a harness, and have a verdict from NIST.
- Why these five: not judgement. `docs/algorithm-frequency.md` counted every algorithm across the 690 active FIPS 140-3 certificates that list one, and CFB8 (36%), CBC-CS3 (27%), CS1 (24%), CS2 (23%) and CFB1 (21%) came out on top of what was unimplemented. The previous, reasoned ranking had dismissed **all five as niche** and put cSHAKE first, which measures 7%. This is the first family selected by counting rather than by reasoning about what modules probably validate.
- Evidence produced: session **766208** - five vector sets, **17,656 cases, every verdict `passed`**. Running total: **56 vector sets, 56,468 cases**, all `passed`, **51 of 51 algorithm names**.
- Order kept deliberately, and it paid: the session was registered and the vectors fetched *before any module code was written*, and every rule was derived by reproducing NIST's own arrays. The segment Monte Carlo chain was right the first time it executed because it was read off the answers rather than off the prose.
- What the vectors settled that prose would not have: CFB8 and CFB1 need a **different** Monte Carlo algorithm from the whole-block modes, not a parameterisation of one. A segment mode feeds back one segment per inner step, so a block's worth of feedback takes 16 steps for CFB8 and 128 for CFB1, and the input for step *j* comes from the IV while the register still holds it and from the output a block's worth of segments back once it does not. Reusing the CFB128 chain returns 100 plausible outer iterations that disagree with NIST from the first.
- Defect found in my own first implementation, by the vectors rather than by review: the key shuffle takes the last **keyLen bits** of output, not the last block. At 128 bits those are the same thing and the 128-bit group passed; the 192-bit group raised `zip() argument 2 is shorter than argument 1`. Verifying against one group is not verifying.
- Defect found by the live server that the offline suite could not find: the **response builder never passed CFB1's `payloadLen`**. CFB1 is the only mode whose payload is measured in bits, and the hex pads to a byte boundary, so without the bit count a submission answers over the padding too. The offline runner *does* pass it, so all 2,144 cases agreed with NIST's own sample file and passed. The submission path is a different function. Session **766207** returned `fail` for the CFB1 vector set while the offline run was green - both paths checked against the same file, only one checked by NIST. 766207 is listed in the README results table marked failed, on the same principle as 765346.
- The regression test watches the **call**, not the answer: `tests/unit/test_responder_payload_bits.py` records what reaches the provider, because what went wrong was an argument that was never passed in a path no fixture exercised. Asserting on output would have passed against the built-in provider either way.
- CS1, CS2 and CS3 are one algorithm and three orderings - CS3 always reverses the last two ciphertext blocks, CS2 only when the final block is partial, CS1 never - and the tests pin them against each other rather than against hardcoded answers, because reading them as three algorithms is the expensive mistake. A payload of exactly one block has nothing to steal from and is plain CBC.
- Wire change, scoped deliberately: `payloadLen` is sent on `block-transform` and `block-mct` for **CFB1 only**. Sending it for every mode would change the input of every harness already written against the byte-oriented contract, for a field that says nothing new there. `cbc-cs` is a new operation.
- Tests run and result: `scripts/dev.py verify` - full gate.
- Commit/link/path: `src/acvp_assay/providers/aes_block.py`, `src/acvp_assay/providers/aes_cs.py`, `src/acvp_assay/algorithms/aes_cs.py`, `src/acvp_assay/responder.py`, `examples/reference_harness.py`, `acvts-capabilities/aes-cfb-segments-cs.json`.
- Blocker, if any: none.
- Next unchecked ID: M22 - PBKDF, 42% of modules and second on the unlock table.

## 2026-09-06 - PBKDF, and the family whose password is not hex

- Project and task ID: ACVP Assay - M22, PBKDF (SP 800-132)
- Done condition: PBKDF implemented, reaching a harness, with a verdict from NIST.
- Why this next: measurement, not judgement. `docs/algorithm-frequency.md` puts PBKDF on **42%** of the 690 active FIPS 140-3 modules and **second on the unlock table** - adding it alone completes 26 modules that are otherwise one name away. It is also one name on a provider that already existed, which is the best rate on the list after M21.
- Evidence produced: session **766210** - one vector set, **110 cases, `passed`**. Running total: **57 vector sets, 56,578 cases**, all `passed`, **52 of 52 algorithm names**.
- Order kept, and it is now the habit rather than the exception: registered, fetched, and reproduced all 110 of NIST's answers with a throwaway script *before* any module code existed. The implementation was then written against a settled question.
- The one real trap, and it is a quiet one: **ACVP sends `password` as text**, while every other byte string in a vector set arrives hex-encoded. Reading it as hex fails loudly on any password containing a letter past `f` - but silently *succeeds* on one that happens to be hex-shaped, deriving perfectly correctly from the wrong bytes. That is the failure mode worth fearing, so the decode happens once in the parser and the harness wire carries hex like everything else on it.
- `keyLen` is in bits and `hashlib` wants bytes. Stated here because it is the kind of thing that is obvious once wrong and invisible until then.
- **The M21 lesson was applied rather than remembered:** the response document was built and compared against NIST's expected results *before* submitting, not after. In M21 that check did not exist and the live server found a CFB1 defect the offline suite could not. Here it ran clean, 110/110, and the submission passed first time.
- Tests run and result: `scripts/dev.py verify` - full gate; both new modules at 100%.
- Commit/link/path: `src/acvp_assay/providers/pbkdf.py`, `src/acvp_assay/algorithms/pbkdf.py`, `src/acvp_assay/responder.py`, `examples/reference_harness.py`, `acvts-capabilities/pbkdf.json`.
- Also fixed, and overdue: the README's "Not covered" list still named AES-CCM, AES-XTS, SHAKE, the KDA and KAS families, ML-KEM and ML-DSA as unimplemented. All of those shipped releases ago. A prospective user reading that list would have concluded the tool did roughly half of what it does.
- Blocker, if any: none.
- Next unchecked ID: M23 - safePrimes and KAS-FFC-SSC, 47% and 46%, one cluster.

## 2026-09-06 - safePrimes and KAS-FFC-SSC, and a defect no local check could see

- Project and task ID: ACVP Assay - M23, the FFC key-agreement cluster
- Done condition: both names implemented, reaching a harness, with a verdict from NIST.
- Why together: the measurement said so. `docs/algorithm-frequency.md` puts safePrimes on 47% of the 690 active FIPS 140-3 modules and KAS-FFC-SSC on 46%, and **278 of safePrimes' 322 modules validate both** - building either alone leaves most of them still untestable. The code turned out to bracket them too: ACVP names the group with the same strings in both families, so one table of domain parameters serves both.
- Evidence produced: session **766221** - three vector sets, **98 cases, `passed`**. Running total: **60 vector sets, 56,676 cases**, all `passed`, **54 of 54 algorithm names**.
- The domain parameters were computed, not transcribed. RFC 3526 gives MODP as `p = 2^n - 2^(n-64) - 1 + 2^64 * (floor(2^(n-130) * pi) + offset)` and RFC 7919 gives FFDHE the same shape over *e*. Deriving them from the formula and then checking against the server's own keyVer answers - all 60 verdicts across six groups, 42 true and 18 false - is a better guarantee than retyping 4096-bit constants, because a wrong prime fails *every* case in its group rather than some of them.
- **The defect, and it is the subtlest this project has produced.** keyGen drew its private key from [1, p-2]. It must come from [1, q-1] where q = (p-1)/2. Generator 2 has order q, so `g^x == g^(x mod q)`: an out-of-range x produces a **perfectly valid public key**. The obvious test - generate a pair, verify the pair - passed every single time. `key_ver` was correct. `key_gen` was incorrect. They agreed with each other, which is exactly why nothing local complained.
- Nor could any vector have caught it: **all 60 of NIST's keyVer cases use a private key already inside the range**, so that mode never exercises the constraint at all. Checked, rather than assumed - the count is in the session data.
- It is also precisely the case the runner *declines by design*. keyGen produces a fresh key, so the offline run reported all 18 cases UNSUPPORTED with the reason "submit to ACVTS, which recomputes it". Session **766220** did, and ACVTS said no. Where the CFB1 defect in M21 was two code paths with one unchecked, this was a single path, wholly self-consistent, and still wrong.
- What changed as a result, beyond the three-line fix: `tests/unit/test_generated_key_ranges.py` asserts the **domain constraint** rather than the round trip; keeps the round trip but labels it the weaker claim; and pins the blind spot itself - a public key derived from an out-of-range private key still verifies - so that nobody later "simplifies" the range test back into the test that missed it. Restoring the original defect fails 6 of its 36 tests; that was verified rather than assumed.
- The rule this generalises to, and it is checkable: the exposure is exactly those generators whose modular arithmetic this project does **by hand**. Where `cryptography` generates the key - ECDSA, RSA, KAS-ECC-SSC - the library enforces its own ranges.
- Tests run and result: `scripts/dev.py verify` - full gate.
- Commit/link/path: `src/acvp_assay/providers/safe_primes.py`, `src/acvp_assay/providers/kas_ffc.py`, `src/acvp_assay/algorithms/safe_primes.py`, `src/acvp_assay/algorithms/kas_ffc.py`, `src/acvp_assay/responder.py`, `examples/reference_harness.py`, `acvts-capabilities/safeprimes-kas-ffc.json`.
- Blocker, if any: none.
- Next unchecked ID: M24 - kdf-components (56%), TLS-v1.2 (41%), TLS-v1.3 (28%).

## 2026-09-07 - The protocol KDFs, and a defect made structurally impossible

- Project and task ID: ACVP Assay - M24, kdf-components (ssh), TLS-v1.2, TLS-v1.3
- Done condition: three registry names implemented, reaching a harness, with a verdict from NIST.
- Why these: `kdf-components` is the most common name this project was missing - 56% of the 690 active FIPS 140-3 modules - and TLS-v1.2 (41%) and TLS-v1.3 (28%) travel with it, 256 of the 281 TLS-v1.2 modules also carrying kdf-components.
- **Which of the nine kdf-components modes to build was also measured.** Re-counting the cached certificates by mode gave `ssh` 46%, `ans9.63` 24%, `tls` 20%, `ikev2` 18%, `ans9.42` 17%, `snmp` 17%, `srtp` 8%, `ikev1` 5%, `tpm` 0.1%. Building `ssh` covers the registry name for nearly half of all modules; the other eight are declined **by name** so a report says which mode is missing rather than reporting the algorithm as unsupported.
- Evidence produced: session **766249** - three vector sets, **410 cases, `passed`, on the first submission**. Running total: **63 vector sets, 57,086 cases**, all `passed`, **57 of 57 algorithm names**.
- Three details settled from the server's own answers before any module code existed, each of which changes every output byte if taken the other way:
  - **SSH's `k` arrives already mpint-encoded**, four-byte length prefix included, and is hashed exactly as received. RFC 4253 describes K as an mpint, so *adding* the prefix is the natural reading and is wrong here.
  - **TLS 1.2 is RFC 7627**: the master secret derives from the session hash, not the randoms. The key block seed is server random *then* client random - the reverse of the order it is usually written in.
  - **TLS 1.3's missing input is zeros, not absent**: a PSK-only case has no `dhe` and a DHE-only case no `psk`, each replaced by zeros as long as the hash, and all eight secrets are produced in every running mode.
- **The M21 defect class was closed structurally rather than tested against.** The response builder calls `kdf_tls.derive`, the same function `run_vector_set` uses, instead of repeating the derivation. CFB1 failed because the two paths were separate implementations of one thing and only one carried `payloadLen`; sharing the function means they cannot disagree at all.
- The M21 *practice* also held: the response document was diffed against NIST's expected results before submitting - 2,320 individual output values, none mismatched - and the session passed first time. M21 and M23 both needed a second session.
- The M22 documentation guard fired again, on `kdf-components` appearing in the README's "Not covered" list. That mention is legitimate - it scopes a partial gap, as `KAS-ECC-SSC` does - so the exemption was made explicit with a reason attached, plus a test that every exemption still names an implemented algorithm, so the allow-list cannot quietly become a way to silence the check.
- Tests run and result: `scripts/dev.py verify` - full gate; both new modules at 100%.
- Commit/link/path: `src/acvp_assay/providers/kdf_tls.py`, `src/acvp_assay/algorithms/kdf_tls.py`, `src/acvp_assay/responder.py`, `examples/reference_harness.py`, `acvts-capabilities/kdf-ssh-tls.json`.
- Blocker, if any: none.
- Next unchecked ID: M26 - the measured tail, starting with KTS-IFC (31%) and KAS-IFC-SSC (17%).

## 2026-09-09 - The IFC families, and what five sessions caught that one would not

- Project and task ID: ACVP Assay - M26 first pair, KAS-IFC-SSC and KTS-IFC
- Done condition: both names implemented, reaching a harness, with a verdict from NIST.
- Why together: KTS-IFC is on 31% of the 690 active FIPS 140-3 modules and KAS-IFC-SSC on 17%, and **114 modules carry both**. They also share the RSA primitives, so one provider serves them.
- Evidence produced: session **766758** - two vector sets, **30 cases, `passed`, first submission**. Running total: **65 vector sets, 57,116 cases**, all `passed`, **59 of 59 algorithm names**.
- **These are not like the ECC and FFC siblings, and it changes what an offline run means.** There, an AFT case has the implementation generate an ephemeral key and only the server can check it. Here most cases hand the implementation *its own RSA private key*, so recovery is deterministic and the offline runner checks it in full. Only the originating cases - KAS1 as initiator, either KAS2 role, KTS-IFC as initiator - are server-only.
- **The defect five sessions caught and one would have shipped.** KAS2 concatenates the two contributions, and the order follows the **role**, not ownership: the initiator's contribution always comes first, so an initiator emits `own || recovered` and a responder `recovered || own`. Derived from a KAS2 *initiator* group alone it reads as "own first" and is silently wrong for every responder case. Sessions 766250 and 766251 both passed clean with that version; **766252's KAS2 responder group failed four of five cases**, which is what exposed it. The user's instruction to validate against what NIST actually tests, rather than one sample, is the only reason this was found before submission rather than by a rejected one.
- **A VAL failure never isolates one condition**, and that is now measured rather than assumed: across five sessions, nine failing VAL cases, six of which carry two independent checks, **not one failed only one of them**. NIST's generator corrupts the underlying Z, which breaks every derived check at once. Both conditions are checked anyway - it agrees with every vector the server issues, and is correct for one it has not yet generated. The second condition has its own test, since the server's vectors never exercise it alone.
- **A defect the tests caught before NIST could:** the harness wire wrote RSA integers with `format(value, "X")`. For 65537 - the commonest public exponent there is - that yields `"10001"`, five digits, and `bytes.fromhex` refuses odd-length input. Every harness parsing the obvious way would have crashed on almost every case. There is now a test asserting every integer on that wire has an even hex length.
- Also fixed this session, from a careful read of the README rather than from any check: six stale numbers, all the same failure - correct when written, never re-read as the results table grew. The banner counted four defects where the section listed six; a footnote said "excluded from the 43" when the total had reached 63; the CI badge claimed 46/46 against a body claiming 57; a paragraph said two sessions had stored verdicts when fifteen did, understating the evidence; and the sample `diff` announced ten lost cases and accounted for six.
- **That class now fails the build.** `tests/unit/test_readme_arithmetic.py` checks the badge against the code, the banner's defect count against the bullets it refers to, the results table's totals against the rows above them, every reference to the table total, the sample diff's internal arithmetic, and the stored-verdict sentence against the session list. It caught a real inconsistency on its first run - the code had 59 names while the README said 57, because M26 was sitting half-finished in the tree.
- Tests run and result: `scripts/dev.py verify` - full gate; both new modules at 100%.
- Commit/link/path: `src/acvp_assay/providers/kas_ifc.py`, `src/acvp_assay/algorithms/kas_ifc.py`, `src/acvp_assay/responder.py`, `examples/reference_harness.py`, `acvts-capabilities/kas-kts-ifc.json`, `acvts-capabilities/kas-ifc-broad.json`.
- Blocker, if any: none.
- Next unchecked ID: M26 continues - KMAC-128/256 (22%) and KAS-ECC non-SSC (22%).

## 2026-09-11 - Claims that did not carry what determines them

- Project and task ID: ACVP Assay - five corrections, one commit each, all breaking one rule the README argues for: a claim that does not carry what determines it is not a claim.
- Done condition: each place that breaks the rule either carries what determines the claim, or is reworded so there is nothing left to go stale.
- **The runner did not pin itself.** `runtime_metadata()` reported `runner_version` and nothing that identifies the code. A version is a claim about the instrument, not its identity: two runs a commit apart report the same one, so two result sets can name the same runner and not be comparable. It now carries `runner_commit`, the full hash of HEAD, because an abbreviated one is not fetchable and collides as history grows, and `runner_tree_clean`, from `git status --porcelain` being empty.
- Where there is no commit, `runner_commit` is null and `runner_commit_absent_reason` names which of three states applies: `no_checkout` for an installed wheel, `not_a_repository` for a source tree outside version control, `vcs_unavailable` when git could not be run. They have three different remedies, so one bare null for all three would have been the same defect one level up.
- Each branch was run rather than reasoned about. The wheel built from this tree and installed into a fresh virtualenv reports `no_checkout`, through `acvp-assay info` as well as the function; the tree copied outside git reports `not_a_repository`; the checkout itself, with git removed from PATH, reports `vcs_unavailable`.
- Two cases turned up while writing it that would have named the **wrong** commit rather than none, which is worse than either. A wheel installed into a virtualenv inside a checkout would have borrowed the checkout's HEAD, so a checkout is recognised by its layout before git is asked anything. A copy of the tree dropped inside an unrelated repository would have been given that repository's HEAD, so the tree must be tracked by the repository git finds. Both have tests.
- Still open: `acvp-assay run` records the provider's identity in its report but not the runner's, so a result set does not yet say which commit produced it. The metadata exists; the report does not carry it.
- **UNSUPPORTED collapsed four states into one word.** The reason strings already told them apart in English; nothing told them apart in the data. They are properties of different things with different repairs: the implementation under test (the vendor repairs it), this runner (built here), the method (submitted to ACVTS, or structurally not at all) and the vector (a different registration, or NIST). That is the test for whether a vocabulary has finished splitting: two members sharing a repair are one state under two names, and each of these points somewhere different. `DeclineReason` carries them as `implementation_lacks`, `runner_lacks`, `offline_undecidable` and `vector_incomplete`, and `TestCaseResult` refuses UNSUPPORTED without one and a reason on any other status, on the model rather than by convention.
- Session 766220 is why it matters. safePrimes keyGen reported UNSUPPORTED offline with "submit to ACVTS, which recomputes it", was submitted, and failed: a limitation of the method was concealing a defect in the implementation, and the two printed identically. That test now asserts `offline_undecidable` and nothing else.
- The 115 `_unsupported(...)` calls across 19 modules were given their code by a script keyed on the exact source text of each reason, which stopped on any reason it had no code for rather than guessing. The English stays beside every code: the code is for aggregation and filtering, the sentence for a person reading one case. Each was classified by what the code checks, not by what the sentence says. XTS `keyLen N is not supported` is `runner_lacks`, not `implementation_lacks`, because the check is against this runner's table and the implementation is never asked.
- Two handlers held two owners each and were split. KDA's "a VAL case needs a dkm and a verdict" is the vector's gap when the dkm is missing and the answer key's when the verdict is. The protocol KDFs' "this case cannot be answered" is the vector's on a missing field and the implementation's on a refused parameter.
- The run summary counts each reason under `unsupportedByReason`. `acvp-assay diff` lists a case whose reason changed even when its status did not, under `decline reason changed`, because a gap that moved from `runner_lacks` to `implementation_lacks` has a different owner and the totals cannot show it. A baseline written before reasons existed is not reported as changed: that is missing evidence, not a different world.
- Found while classifying, and left as it was. AES-KW reports UNSUPPORTED when unwrapping fails and no verdict is recorded, but NIST's pinned KW and KWP sets record every valid unwrap as a plaintext with no `testPassed` (2,863 and 2,885 cases) and every invalid one as `testPassed: false` (737 and 715). A failed unwrap on such a case is a failure reported as a decline. It is coded `implementation_lacks`, so that it points at the vendor rather than at ACVTS; making it FAIL is a separate change.
- **The headline total did not say how unevenly it falls.** 65 vector sets and 57,116 cases are both correct, and a reader takes 57,116 as a measure of breadth when it is substantially two sessions: 766208 has 17,656 cases and 765508 has 12,867, together 53.4% of the cases across 21 completed sessions, where a flat split would give two sessions 9.5%. The headline now says so in the same sentence as the totals, so that quoting one quotes the other, and names the partition: cases by session.
- The partition is part of the figure, not a detail of it. The same two sessions are 53.4% of the cases and 30.8% of the vector sets, because cases and sets divide a run differently. It is easy to get wrong: 33.8% is the share of sets held by the two largest sessions *by sets*, 765508 and 765342, which is a different pair.
- `test_the_concentration_figures_match_the_table` computes the share, the flat baseline and the session count from the rows, so the sentence moves with the table. It replaces the check on "covering N test cases", which the reworded headline would otherwise have let pass by matching nothing.
- `acvp-assay run` reports the same three values for a run, partitioned by test group: `concentration` in the summary carries the partition, how many groups there are and the two largest groups' share. NIST's pinned SHA2-256 set is 517 cases, and 99.8% of them are in two of its three groups.
- Tests run and result: `scripts/dev.py test` - format, lint, strict mypy, 1,008 passed and 9 skipped.
- Commit/link/path: `README.md`, `src/acvp_assay/reporter.py`, `tests/unit/test_readme_arithmetic.py`.
- Blocker, if any: none.
- Next unchecked ID: `docs/algorithm-frequency.md`, where three entries have a caveat that contradicts their rank and only the prose says so.
