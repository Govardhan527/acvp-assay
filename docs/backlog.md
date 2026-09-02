# Build backlog

- [x] A01 / R01-R06: freeze the MVP and establish the repository baseline.
- [x] A01 / R07: verify setup, tests, demo, and build from a clean checkout.
- [x] A02: select and document the exact AES-GCM vector source, revision, retrieval date, and license.
- [x] A03: add one tiny valid encrypt fixture and one valid decrypt fixture.
- [x] A04: define typed vector-set, group, case, value, and result models that preserve ACVP IDs.
- [x] A05: validate required fields, types, hexadecimal values, and supported directions.
- [x] A06: parse one group end to end without losing IDs.
- [x] A07: define a provider interface for encrypt, decrypt, and implementation metadata.
- [x] A08: implement and verify OpenSSL-backed AES-GCM encryption.
- [x] A09: implement and verify OpenSSL-backed AES-GCM decryption and authentication failures.
- [x] A10: compare cases into PASS/FAIL/ERROR with expected, actual, and safe diagnostics.
- [x] A11: produce JSON totals and provider-version summaries.
- [x] A12: add `run VECTOR_FILE`, `--output`, `--strict`, and meaningful exit codes.
- [x] A13: add deterministic unit tests and one integration test executing the complete CLI against the tiny fixtures.
- [x] A14: add one intentionally corrupted fixture and verify it produces a visible, deterministic failure in the existing test gate.
- [x] A15: publish v0.1.0 with a five-minute quick start, architecture, sample pass/failure output, and security limitations.

The frozen v0.1.0 AES-GCM MVP is complete.

## Market roadmap (post-v0.1.0)

Aimed at demand rather than portfolio scope; supersedes the v0.1.0 non-goals where they conflict.

- [~] M00: request ACVTS Demo credentials from `acvts-demo@nist.gov` — sent 2026-09-02,
      awaiting CSR requirements. See `docs/acvts-demo-access-request.md`.
- [x] M01: fetch and SHA-256-verify the pinned upstream NIST vectors, and run them end to end.
- [x] M02: add a subprocess provider that speaks JSON on stdin/stdout, so any language or device can be tested.
- [x] M03: add SHA2 with Monte Carlo test support, then HMAC.
- [x] M04: add the produce-and-verify and verdict-only result paths (ECDSA sigGen/sigVer).
- [x] M05: add ML-KEM and ML-DSA ahead of the CNSA 2.0 January 2027 requirement (parsing and
      execution complete; requires an external implementation, see BUILDLOG).
- [x] M06: add run-over-run regression diffing between two reports.
- [ ] M07: publish to PyPI.

Still out of scope: a full ACVP protocol client, algorithm count as a goal, an HTML dashboard, and any hosted service.
