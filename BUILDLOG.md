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
