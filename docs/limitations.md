# Limitations

This is the frozen v0.1.0 MVP: it parses one ACVP-shaped vector/expected-results file pair, executes AES-GCM encrypt or decrypt through the OpenSSL-backed `cryptography` provider, compares results, and reports case-level and summary JSON with a process exit code.

The tool:

- exercises the OpenSSL backend exposed by `cryptography`, and does not validate OpenSSL itself;
- runs offline vector files and does not communicate with a live ACVP server;
- supports only AES-GCM, `ACVP-AES-GCM` revision `1.0`, `AFT` test type, and externally supplied IVs (`ivGen: external`) — groups with internally generated IVs are reported as UNSUPPORTED, not silently skipped or approximated;
- requires the expected-results file to sit next to the vector file and to identify the same `vsId`/`algorithm`/`revision`;
- provides test evidence, not FIPS 140-3 validation, certification, or a complete security assessment;
- treats malformed, unsupported, failed, and errored cases as distinct outcomes, and never places raw exception text in a report (`ERROR` diagnostics are drawn from a closed, non-secret vocabulary);
- avoids redistributing third-party vectors unless their license permits it.

Do not use this tool as evidence that a cryptographic module is production-ready, FIPS 140-3 validated, or otherwise compliant.

## AES chaining-mode Monte Carlo tests

`ACVP-AES-CBC`, `ACVP-AES-OFB` and `ACVP-AES-CFB128` are fully supported in both
directions. `ACVP-AES-CTR` defines no Monte Carlo test at all: ACVP gives it a
`CTR` test type, but the server back-computes the IVs from an ordinary
functional answer, so the client runs no chain.

These chains are worth a note because the specification's pseudocode is not
sufficient to implement them. It writes the inner loop as a cipher that
"continues" from the previous call, without saying what continuing does to the
IV -- and each mode answers that differently:

| Mode | How the IV advances between inner iterations |
| --- | --- |
| CBC, CFB128, encrypting | to the ciphertext just **produced** |
| CBC, CFB128, decrypting | to the ciphertext just **consumed** (the input) |
| OFB, either direction | to the raw keystream block, which is neither |

The payload chain is shared by all of them: `payload[0]` is the case's input,
`payload[1]` is the IV, and `payload[j]` is `output[j-2]` thereafter.

Reading the specification's "replace all PT with CT" instruction literally
produces a chain that reproduces the encrypt arrays exactly and disagrees with
NIST from the first block when decrypting. The correct rules were taken from
NIST's own generator, `MonteCarloAesCbc.cs` and its siblings in
`usnistgov/ACVP-Server`, where the encrypt and decrypt routines are
structurally identical and the asymmetry lives entirely inside the cipher
object. All twelve group combinations now reproduce the live server's arrays on
every field of all 100 iterations.
