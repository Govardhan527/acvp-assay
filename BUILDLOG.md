# Build log

## 2026-09-02 - A01 repository baseline

- Project and task ID: ACVP Runner/Adapter - A01 (R01-R07)
- Done condition: a clean Python 3.12 checkout can install, run checks and tests, build artifacts, and execute the smallest demo; the AES-GCM-only MVP and non-goals are documented.
- Evidence produced: documented scope and architecture, pinned dependency ranges, source/test/fixture/docs layout, Linux CI, installable package, runtime metadata command, wheel, and source distribution.
- Tests run and result: `scripts/dev.py verify` passed Ruff formatting/lint, strict mypy, 5 pytest tests with 100% branch coverage, and package builds. The same setup, verification, build, and demo passed from a separate clean clone.
- Commit/link/path: initial implementation commit `fc356ec`; repository root is this directory.
- Blocker, if any: none.
- Next unchecked ID: A02 - select and document the vector source, revision, retrieval date, and license.

## 2026-09-02 - A02 vector-source decision

- Project and task ID: ACVP Runner/Adapter - A02
- Done condition: the official AES-GCM vector source, immutable revision, retrieval date, integrity hashes, licensing terms, and redistribution decision are documented.
- Evidence produced: `docs/vector-sources.md` pins NIST `ACVP-Server` commit `975de31eb83d87039ec88934fdc47d8c312b892d`, three exact source files, Git blob IDs, SHA-256 hashes, schema coverage, and source-handling policy.
- Tests run and result: upstream files were decoded directly from the GitHub API and their structure, case counts, identifiers, sizes, and SHA-256 hashes were independently inspected. Local Ruff, strict mypy, 5 pytest tests with 100% coverage, and wheel/sdist builds all passed.
- Commit/link/path: `docs/vector-sources.md` in this repository.
- Blocker, if any: none; upstream JSON will be fetched and hash-checked rather than redistributed.
- Next unchecked ID: A03 - add one tiny independently generated valid encrypt fixture and one valid decrypt fixture.

## 2026-09-02 - A03 tiny valid fixtures

- Project and task ID: ACVP Runner/Adapter - A03
- Done condition: one tiny valid encrypt fixture and one tiny valid decrypt fixture exist under `fixtures/`, use ACVP-shaped prompt/result pairs, and are cryptographically checked.
- Evidence produced: independently generated fixture pairs in `fixtures/aes-gcm-valid-encrypt/` and `fixtures/aes-gcm-valid-decrypt/`, plus provenance and execution instructions in `fixtures/README.md`.
- Tests run and result: 4 fixture-specific checks passed for identifiers, declared lengths, ciphertext/tag generation, and authenticated plaintext recovery. The full gate passed Ruff, strict mypy, 9 pytest tests with 100% application coverage, and wheel/sdist builds.
- Commit/link/path: the two fixture directories and `tests/unit/test_fixtures.py` in this repository.
- Blocker, if any: none.
- Next unchecked ID: A04 - define typed internal models for vector set, test group, test case, and result while preserving ACVP IDs.

## 2026-09-02 - A04 typed internal models

- Project and task ID: ACVP Runner/Adapter - A04
- Done condition: immutable typed models represent vector sets, test groups, test cases, comparable values, and classified results while retaining `vsId`, `tgId`, and `tcId`.
- Evidence produced: `src/acvp_runner/models.py` defines explicit direction, test-type, and result-status wire values plus frozen, slotted dataclasses for the AES-GCM domain.
- Tests run and result: model tests passed for ID preservation, immutability, hashability, result values, diagnostics, and stable enum wire values. The full gate passed Ruff, strict mypy, 13 pytest tests with 100% coverage, and wheel/sdist builds without warnings.
- Commit/link/path: `src/acvp_runner/models.py` and `tests/unit/test_models.py`.
- Blocker, if any: none.
- Next unchecked ID: A05 - validate required fields, types, invalid hexadecimal values, and unsupported directions.

## 2026-09-02 - A05 input validation

- Project and task ID: ACVP Runner/Adapter - A05
- Done condition: required top-level, group, and case fields are checked with safe paths; wrong JSON types, malformed hexadecimal data, unsupported direction/test type, algorithm, and revision are rejected.
- Evidence produced: `src/acvp_runner/parser.py` separates boundary validation from immutable domain models and raises `AcvpValidationError` with an exact JSON-style path and non-secret diagnostic.
- Tests run and result: 35 negative validation cases cover missing fields at every level, booleans masquerading as integers, wrong scalar/container types, non-object nodes, odd/invalid/separated hex, direction-specific fields, and unsupported contract values. The full gate passed Ruff, strict mypy, 48 pytest tests with 98.95% coverage, and wheel/sdist builds.
- Commit/link/path: `src/acvp_runner/parser.py` and `tests/unit/test_parser_validation.py`.
- Blocker, if any: none.
- Next unchecked ID: A06 - load and parse one complete group without losing `vsId`, `tgId`, or `tcId`.

## 2026-09-02 - A06 lossless group parsing

- Project and task ID: ACVP Runner/Adapter - A06
- Done condition: an ACVP-shaped JSON file is loaded and normalized through validation into the internal model without losing vector, group, or case IDs.
- Evidence produced: `load_vector_set()` performs UTF-8 JSON loading with bounded parse diagnostics; integration tests load both tiny prompt files and assert IDs, metadata, direction, declared lengths, and normalized direction-specific byte fields.
- Tests run and result: both encrypt and decrypt fixtures passed end-to-end loading and normalization checks; malformed JSON produced a bounded location-only diagnostic. The full gate passed Ruff, strict mypy, 52 pytest tests with 100% coverage, and wheel/sdist builds.
- Commit/link/path: `src/acvp_runner/parser.py` and `tests/integration/test_parser.py`.
- Blocker, if any: none.
- Next unchecked ID: A07 - define a provider interface for encrypt, decrypt, and provider/version metadata.
