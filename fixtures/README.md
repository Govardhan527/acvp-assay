# Fixtures

Only tiny, deterministic, rights-safe AES-GCM fixtures belong here. Each imported fixture must record its source URL, exact repository revision or document version, retrieval date, and license before vector data is committed.

## Local AES-GCM fixtures

| Directory | Direction | Vector-set ID | Group/case ID | Purpose |
| --- | --- | ---: | --- | --- |
| `aes-gcm-valid-encrypt/` | encrypt | 900001 | 1/1 | Nonempty plaintext and AAD with a 128-bit tag |
| `aes-gcm-valid-decrypt/` | decrypt | 900002 | 1/1 | Valid ciphertext/tag recovery with nonempty AAD |

Each directory contains an ACVP-shaped `prompt.json` and matching `expectedResults.json`. Prompt and result data remain separate, mirroring the pinned NIST example-set layout.

These values were independently generated on 2026-09-02 from manually selected deterministic inputs using `cryptography` 50.0.1 backed by OpenSSL 4.0.2. They are original local test data, not copied or derived from the pinned NIST JSON files. They are suitable for deterministic repository tests but are not validation vectors and do not provide independent assurance of the cryptographic implementation.

Run the fixture checks with:

```bash
.venv/bin/python -m pytest --no-cov tests/unit/test_fixtures.py
```

The tests verify declared bit lengths, identifier pairing, AES-GCM encryption outputs, and successful authenticated decryption.
