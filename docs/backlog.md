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
- [x] M07: add the AES mode families that surround GCM in a real module — ECB (with the
      Monte Carlo key shuffle), GMAC, CMAC-AES, and KW/KWP. Chosen by reading published
      CAVP certificates rather than by guessing: these four names recur far more often
      than anything else still missing.
- [x] M08: Counter DRBG (SP 800-90A), both revisions. Effectively every FIPS module
      contains an approved DRBG, so this was the widest remaining single gap. It needed a
      new provider shape — a state machine with reseed and prediction resistance rather
      than a one-shot transform. TDES is declared UNSUPPORTED: SP 800-131A disallowed it
      for this use after 2023.
- [x] M09: KDF SP 800-108 (counter, feedback, double-pipeline). 5,878 groups and 11,756
      cases. The IUT supplies its own `fixedData`, so the runner reads it back from the
      expected results and derives against it — which bounds what a pass means, and the
      limitation is documented rather than glossed.
- [x] M10: keep the harness process alive across cases, and detect a one-shot
      harness rather than deadlocking on it. Spawning per case cost ~75 ms, about
      fifty times the cryptography, and forced a PKCS#11 harness to log in once per
      case. See `docs/harness-protocol.md`.
- [~] M11: harness operations for the fourteen families that are in-process only.
      The ten AES families are done and verified through the wire against NIST's
      vectors — 13,282 cases, zero failures. The DRBGs, KDF and RSA remain.
      This is what makes the coverage claim true for a *vendor's* module rather than
      for this project's OpenSSL binding, so it is the highest-value item left.
      Planned operations, in the order they are worth building:
      - `block-encrypt` / `block-decrypt` / `block-mct` — ECB, CBC, CTR, OFB, CFB128.
        The Monte Carlo chain is delegated whole and returns each outer iteration's
        key, IV, input and output.
      - `cmac`, `gmac`, `key-wrap` — the remaining AES mode families.
      - `rsa-sign-group` (one key per group, returning `n` and `e`), `rsa-verify`,
        `rsa-primitive-sign`, `rsa-primitive-decrypt`.
      - `drbg` — one call per case carrying the whole `otherInput` sequence, rather
        than a stateful instantiate/reseed/generate conversation over the wire.
      - `kdf-108` — returns `keyOut` *and* the `fixedData` the implementation chose.
- [ ] M12: `--provider-command` for the live responder, so a vendor's own answers
      can be submitted to ACVTS rather than this project's.
- [ ] M13: publish to PyPI.

Still out of scope: a full ACVP protocol client, algorithm count as a goal, an HTML dashboard, and any hosted service.
