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
