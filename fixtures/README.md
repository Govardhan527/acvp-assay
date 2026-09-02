# Fixtures

Only tiny, deterministic, rights-safe AES-GCM fixtures belong here. Each imported fixture must record its source URL, exact repository revision or document version, retrieval date, and license before vector data is committed.

## Local AES-GCM fixtures

| Directory | Direction | Vector-set ID | Group/case ID | Purpose |
| --- | --- | ---: | --- | --- |
| `aes-gcm-valid-encrypt/` | encrypt | 900001 | 1/1 | Nonempty plaintext and AAD with a 128-bit tag |
| `aes-gcm-valid-decrypt/` | decrypt | 900002 | 1/1 | Valid ciphertext/tag recovery with nonempty AAD |
| `aes-gcm-invalid-decrypt-tag/` | decrypt | 900003 | 1/1 | Corrupted tag with an expectation that says it should succeed; the A14 CI-visible-failure gate |
| `aes-gcm-decrypt-auth-failure/` | decrypt | 900004 | 1/1 | Corrupted tag correctly declared `testPassed: false`; rejection is the pass |

Each directory contains an ACVP-shaped `prompt.json` and matching `expectedResults.json`. Prompt and result data remain separate, mirroring the pinned NIST example-set layout.

Both invalid-tag fixtures reuse `aes-gcm-valid-decrypt/`'s key, IV, AAD, and ciphertext but flip the final hex digit of the tag (`...9FFA` to `...9FFB`), so authentication deterministically fails on every run. What differs is the *expectation*, and that difference is the point:

- **`aes-gcm-decrypt-auth-failure/`** declares `"testPassed": false`, the encoding NIST itself uses for decrypt cases that must fail. Rejecting the tag is correct behaviour, so the runner reports **PASS**. Ten of the sixty cases in the pinned upstream set are of exactly this kind.
- **`aes-gcm-invalid-decrypt-tag/`** instead claims a recoverable `pt`, which is a false expectation. The runner therefore reports **ERROR / authentication failed** and exits non-zero. `tests/integration/test_run_command.py::test_run_command_fails_visibly_on_the_intentionally_bad_fixture` asserts that reproducible failure — proving the tool surfaces a real problem instead of swallowing it, without making CI itself flaky.

## Upstream NIST vectors

The pinned NIST set is *not* committed here. Run `python scripts/dev.py vectors` to download and SHA-256-verify it into the git-ignored `vectors/` directory; `tests/integration/test_nist_vectors.py` then exercises all sixty cases and is skipped automatically when the files are absent.

These values were independently generated on 2026-09-02 from manually selected deterministic inputs using `cryptography` 50.0.1 backed by OpenSSL 4.0.2. They are original local test data, not copied or derived from the pinned NIST JSON files. They are suitable for deterministic repository tests but are not validation vectors and do not provide independent assurance of the cryptographic implementation.

Run the fixture checks with:

```bash
.venv/bin/python -m pytest --no-cov tests/unit/test_fixtures.py
```

The tests verify declared bit lengths, identifier pairing, AES-GCM encryption outputs, and successful authenticated decryption.
