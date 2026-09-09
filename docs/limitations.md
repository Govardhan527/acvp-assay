# Limitations

What this tool does **not** tell you, stated plainly. The README's
[Coverage](../README.md#coverage) section says what it does.

## It is evidence, not validation

This produces reproducible test evidence. It does not perform, substitute for, or confer
CAVP algorithm validation or FIPS 140-3 module validation — only accredited CST and 17ACVT
laboratories do that. Passing every vector here is necessary, not sufficient:

- it exercises the algorithm implementation, not the module boundary, its self-tests, its
  key management, its entropy source, or its physical security;
- the live sessions used NIST's **Demo** server (`demo.acvts.nist.gov`), which is for
  development. Production ACVTS access is granted to laboratories, not to tool authors;
- a passing run says the implementation agreed with NIST's vectors on the cases NIST sent.
  It says nothing about constant-time behaviour, side channels, or fault resistance.

Do not cite a report from this tool as evidence that a module is FIPS 140-3 validated,
production-ready, or otherwise compliant.

## The built-in provider is a reference, not a subject

Without `--provider-command`, the runner exercises the OpenSSL backend exposed by Python's
`cryptography`. That checks the *runner*, not your product, and it does not validate OpenSSL
either. Any result meant to say something about a vendor's implementation must come from a
harness.

## Coverage boundaries

- 59 algorithm names are implemented; the README lists what is [not covered](../README.md#not-covered).
  An unrecognised algorithm exits non-zero rather than reporting a pass.
- `kdf-components` is one registry name covering nine component KDFs, and only `ssh` is built.
  The other eight are declined by name, so a report says which mode is missing.
- All 59 have been judged by NIST's live ACVTS Demo server — 65 vector sets, 57,116 cases,
  every verdict `passed`. That is the server's verdict on answers this runner produced, not
  this project's own assessment, and it is still **test evidence, not validation**: only an
  accredited CST or 17ACVT laboratory performs CAVP or FIPS 140-3 validation, and Demo is not
  the production ACVTS.
- Some cases can only be checked by the server, and are declined here rather than guessed at:
  `safePrimes` keyGen, the KAS-ECC-SSC / KAS-FFC-SSC AFT cases, and the IFC cases where the
  implementation originates secret material — KAS1 as initiator, either KAS2 role, and KTS-IFC as
  initiator — all have the implementation produce something fresh, so no recorded value can be
  compared with the answer. KAS-IFC-SSC differs from its ECC and FFC siblings here: most of its
  cases supply the IUT's own private key, so they *are* fully checkable offline. They are reported
  UNSUPPORTED offline and answered in full on submission. Treat a run that reports them as
  complete only if you have also submitted: session 766220 failed on exactly this path while
  every offline case was green.
- Within supported families, some parameters are declined rather than approximated, and are
  reported UNSUPPORTED: AES-GCM `ivGen: internal`, AES-KW/KWP `kwCipher: inverse`, SHA large
  data tests (LDT), RSA SHAKE mask functions, ctrDRBG TDES, KDF `CMAC-TDES`, and ECDSA
  component tests. With `--provider-command` the mode-capability decisions among these are
  deferred to your implementation; the ones that are not on the wire at all (LDT, `inverse`,
  internal IV generation) are declined regardless.
- `--strict` turns UNSUPPORTED and SKIPPED into a failing exit code, so a coverage gap cannot
  pass quietly in CI.

## Reporting boundaries

- Malformed, unsupported, failed and errored cases are distinct outcomes, never merged.
- Raw exception text never enters a report. `ERROR` diagnostics come from a closed,
  non-secret vocabulary, and a harness's own error text is never echoed back — a failure
  message commonly quotes the key it failed on, and reports get shared as evidence.
- A harness's stderr passes through to your terminal for debugging but never enters the
  JSON report, for the same reason.

## Vectors

Upstream NIST vectors are referenced by pinned SHA-256 and fetched on demand; they are never
redistributed here. See `vector-sources.md` for the source, hashes and licensing position.

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
