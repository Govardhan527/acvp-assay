# ACVP Runner/Adapter

ACVP Runner/Adapter is a small, offline command-line tool for executing AES-GCM test vectors through a provider boundary and reporting case-level results. It is intended to make parsing, execution, comparison, and diagnostics reproducible without claiming ACVP protocol conformance or cryptographic-module validation.

## MVP scope

The frozen v0.1.0 MVP contains:

- Python 3.12 and pytest;
- offline AES-GCM vector files only;
- one adapter backed by the OpenSSL used by Python's `cryptography` package;
- typed parsing models that preserve `vsId`, `tgId`, and `tcId` values when present;
- input validation, encrypt/decrypt execution, comparison, JSON reporting, and a CLI;
- deterministic unit and end-to-end tests on Linux.

Explicit non-goals for v0.1.0 are live ACVP server sessions, a second algorithm or provider, full FIPS 140-3 validation, vector redistribution without confirmed rights, an HTML dashboard, and performance benchmarking.

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
```

The demo prints machine-readable runtime metadata, including the `cryptography` and OpenSSL versions that will identify the first provider implementation.

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

- `src/acvp_runner/`: application package
- `tests/unit/`: focused unit tests
- `tests/integration/`: subprocess and full-path tests
- `fixtures/`: small, rights-safe local test vectors
- `docs/architecture.md`: component boundaries and data flow
- `docs/limitations.md`: security and assurance boundaries
- `docs/vector-sources.md`: pinned upstream source, hashes, licensing, and redistribution policy
- `docs/decisions/`: committed design decisions

## Safety

Do not add credentials, employer code or data, proprietary vectors, or confidential screenshots. Use only vectors whose source and redistribution terms have been recorded.

## License

MIT; see `LICENSE`.
