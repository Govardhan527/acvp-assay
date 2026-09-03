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

## AES chaining-mode Monte Carlo tests (v0.8.0)

`ACVP-AES-CBC`, `ACVP-AES-OFB` and `ACVP-AES-CFB128` each define a Monte Carlo
test. This runner answers **only the combinations it has reproduced against
NIST's own answers**:

| Algorithm | encrypt MCT | decrypt MCT |
| --- | --- | --- |
| `ACVP-AES-CBC` | verified | **declared** |
| `ACVP-AES-CFB128` | verified | **declared** |
| `ACVP-AES-OFB` | **declared** | **declared** |
| `ACVP-AES-CTR` | no MCT — none defined | no MCT |

The specification gives the encryption chain as pseudocode and describes
decryption as "the encryption pseudocode with all PT's replaced by CT's and all
CT's replaced by PT's". Implemented exactly that way, the chain reproduces the
live server's CBC and CFB128 *encrypt* arrays field for field — key, IV, input
and output, across all 100 outer iterations. The same code matches nothing for
decryption, and nothing for OFB in either direction, diverging at the very first
output.

A search over 36 candidate feedback rules — every combination of what becomes
the next IV and the next input, drawn from the current and previous IV, input
and output — produced no chain that reaches NIST's answer, at any iteration
count up to 1200. So the real chain is something this runner has not yet
established.

Those groups are therefore reported UNSUPPORTED, and the responder refuses to
submit them. That costs 8 cases out of 6,016 in the session that established
this. Answering them with a plausible-looking chain would cost far more: a
Monte Carlo chain that runs to completion and disagrees is scored as a wrong
answer, and looks like a working implementation until a laboratory says
otherwise.
