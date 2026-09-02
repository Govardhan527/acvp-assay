# Limitations

This repository is pre-MVP. It currently reports runtime/provider metadata but does not parse vectors, perform AES-GCM operations, compare results, or implement ACVP protocol behavior.

Even after v0.1.0, the tool will:

- exercise the OpenSSL backend exposed by `cryptography`, not validate OpenSSL itself;
- run offline vector files and not communicate with a live ACVP server;
- support only the documented AES-GCM subset;
- provide test evidence, not FIPS 140-3 validation, certification, or a complete security assessment;
- treat malformed, unsupported, failed, and errored cases as distinct outcomes;
- avoid redistributing third-party vectors unless their license permits it.

Do not use this tool as evidence that a cryptographic module is production-ready or compliant.
