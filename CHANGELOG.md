# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0 the
provider protocols may change between minor versions.

## [0.18.0] - 2026-09-04

### Added

- **KDA** (SP 800-56C), HKDF mode, revisions Cr1 and Cr2 — the key-derivation
  half of key agreement. `KAS-ECC-SSC` produces the shared secret; this turns it
  into keying material, and a module doing TLS validates both.
- Session 765811 returned `passed` on all 300 cases. Running total:
  **51 vector sets, 38,812 cases, 46 of 46 algorithm names**.
- Harness operation `kda-hkdf`, and `acvts-capabilities/kda-hkdf.json`.

### Notes

- The derivation is the easy half. The work is assembling **`fixedInfo`**: the
  group declares a pattern, the case supplies each party's contribution
  separately, and a string built even slightly differently gives keying
  material that is wrong on *every* case rather than some of them. Only
  `uPartyInfo||vPartyInfo` under `concatenation` is built; other patterns name
  literals, algorithm identifiers or labels, and are declined with the remedy.
- `fixedInfo` reaches a harness **already assembled**. Putting the pattern on
  the wire would make every harness reimplement the same string-building and
  get it wrong in the same places; sending bytes keeps the question to "derive
  this", which is what the implementation is being tested on.
- VAL cases carry deliberately wrong keying material, so rejecting is a correct
  answer. Both directions of that inversion have a test.
- `usesHybridSharedSecret` is required in the registration for Cr2 and has no
  default — the server rejects a registration without it.

## [0.17.0] - 2026-09-04

### Added

- **SHAKE-128 and SHAKE-256**, revision FIPS202 — the extendable-output
  functions, and the first family here whose output length is an *input*.
- Session 765794 returned `passed` on both vector sets, 508 cases. Running
  total: **50 vector sets, 38,512 cases, 45 of 45 algorithm names**.
- Harness operation `xof`, and `acvts-capabilities/shake.json`.

### Notes

- An XOF needs its own boundary rather than an extra argument on the hash one.
  The same message squeezed to a different length is a different answer, and a
  fixed-length interface can only express that by inventing a digest size.
- `XOF_ALGORITHMS` holds the constructors rather than hashlib's names, because
  `hashlib.new` is typed as returning a fixed-length hash whose `digest` takes
  no argument. Going through it would not typecheck, and would hide the one
  thing that makes an XOF different.
- **Only AFT is answered.** The Demo server generates nothing else for a
  FIPS202 SHAKE registration, including when explicitly asked, so the Monte
  Carlo chain is declared rather than implemented — a chain written without
  vectors to check it against would be a guess, and a wrong one fails every
  case of a group that looks supported.
- FIPS 202 is explicit that the XOFs are **not approved as hash functions**;
  their approved uses are named in NIST Special Publications. This runner tests
  what ACVP asks for and makes no claim about where a SHAKE output may be used.

## [0.16.0] - 2026-09-04

### Added

- **ACVP-AES-CCM**, revision 1.0 — counter with CBC-MAC, the AEAD of 802.11 and
  constrained devices. 128/192/256-bit keys, 7 to 13-byte nonces, 32 to 128-bit
  tags.
- Session 765788 on `demo.acvts.nist.gov` returned `passed` on all **4,830**
  cases, the largest single vector set answered so far. Running total:
  **48 vector sets, 38,004 cases, 43 of 43 algorithm names**.
- Harness operations `ccm-encrypt` and `ccm-decrypt`, and
  `acvts-capabilities/aes-ccm.json`.

### Notes

- **613 of the decrypt cases are deliberate forgeries**, where rejecting the tag
  is the correct answer and a PASS. Getting that inversion wrong is the worst
  output this tool can produce: reported as failures it accuses a conforming
  module of hundreds of defects, and inverted the other way it stays quiet about
  a module that accepts forgeries. Both directions now have a test against real
  vectors.
- The tag is **appended to the ciphertext** rather than reported separately, so a
  zero-length payload still produces a non-empty `ct` — the tag alone. ACVP
  records it that way and so does `cryptography`.
- Tag length is a property of the cipher object rather than of the call, so
  building it with a length CCM does not define fails rather than truncating.

## [0.15.0] - 2026-09-04

### Added

- **ACVP-AES-XTS**, revision 2.0 — the mode disk and storage encryption is
  validated under, with 128 and 256-bit keys and both tweak conventions.
- Session 765786 on `demo.acvts.nist.gov` returned `passed` on all 480 cases,
  taking the running total to **47 vector sets, 33,174 cases, 42 of 42
  algorithm names**.
- Harness operation `xts-transform`, and `acvts-capabilities/aes-xts.json`.

### Notes

Three things about XTS are easy to get wrong, each fails quietly, and each was
settled against NIST's own vectors before any module code was written:

- **The key is two AES keys concatenated.** `keyLen` 128 means a 32-byte key.
  A provider validating against the usual AES sizes rejects every vector.
- **A `number` tweak is a little-endian 128-bit sequence number.** Big-endian
  reproduces exactly 240 of the 480 cases — the half where the value happens to
  be symmetric enough not to matter, which is the worst kind of near-miss.
- **A payload longer than `dataUnitLen` spans several data units, each with its
  own tweak**, advanced by one per unit. `cryptography` treats its input as a
  single unit, so the split is the provider's job. 161 of the 480 cases span
  more than one unit; encrypting the payload whole passes the other 319.

XTS also forbids the two key halves being equal, and the provider raises rather
than encrypting. That is now a bounded ERROR result carrying only
`provider error`, never the library's own message, which can quote key material.

## [0.14.0] - 2026-09-04

### Added

- **KAS-ECC-SSC**, revision `Sp800-56Ar3` — elliptic-curve shared-secret
  computation, the `ephemeralUnified` scheme on P-224/256/384/521. Key
  agreement appears wherever TLS is validated and was the last item on this
  project's own commercial priority list.
- Session 765769 on `demo.acvts.nist.gov` returned `passed` on all 20 cases,
  taking the running total to **46 vector sets, 32,694 cases, 41 of 41
  algorithm names**.
- Harness operation `kas-ecc-ssc`, and `acvts-capabilities/kas-ecc-ssc.json`.

### Notes

- **AFT and VAL are not variations on one theme.** A VAL case supplies every
  input, including the implementation's own private key, so the answer is a
  verdict and is fully checked offline. An AFT case supplies only the peer's
  public key, so the implementation generates an ephemeral pair — and Z then
  differs on every run, which cannot be compared with the value NIST recorded
  from its own. Those cases are reported UNSUPPORTED offline, with the reason,
  rather than compared against something they cannot equal.
- The live server has no such limitation: it holds the peer private key and
  recomputes Z from the public key reported back to it. So `responder.py`
  answers AFT in full, and session 765769 judged all 20 cases. That split is
  the clearest case so far of a live session checking something no file-based
  runner can.
- A peer point off the curve yields a verdict of `false` rather than an error.
  ACVP is entitled to send one, and refusing to agree a secret with an invalid
  public key is correct behaviour, not a fault.

## [0.13.0] - 2026-09-04

### Added

- **ML-KEM and ML-DSA response builders**, the last two of the forty algorithm
  names without one. Both require `--provider-command` and refuse clearly
  without it: every other family falls back to a built-in provider, PQC has
  none, and inventing a value is not an option when ACVP scores a missing case
  as a wrong answer.
- **Every supported algorithm has now been judged by NIST.** Two further
  sessions on `demo.acvts.nist.gov` took live coverage from 38 of 40 to
  **40 of 40**:
  - Session 765724: `ML-KEM` encapDecap, 165 cases, `passed`.
  - Session 765727: `ML-DSA` sigVer, 45 cases, `passed`.
  - Running total: **45 vector sets, 32,674 cases, every verdict `passed`.**
- `acvts-capabilities/ml-kem.json` and `ml-dsa.json`.

### Notes

- **What the PQC verdicts do and do not mean.** Both sessions were answered by
  `examples/pqc_reference_harness.py`, backed by `kyber-py` and `dilithium-py`
  — educational implementations that are not constant-time. The verdicts are
  evidence that this runner parses, routes and answers PQC vector sets
  correctly. They are not evidence that any implementation is fit to ship, and
  the README says so in the banner rather than in a footnote.
- These are also the first submissions answered entirely by a harness rather
  than by the built-in providers, which is the configuration M12 was built for.
- The ML-DSA registration declares `pure` and `external` only. `preHash` and
  `externalMu` groups are refused by the builder rather than answered, so
  registering for them would produce a document that could not be completed.
  NIST generated exactly the three groups the runner supports.
- Getting that registration accepted took four attempts, each corrected by the
  server's own validation message: `capabilities` must be a non-empty array;
  `externalMu` is rejected when only the external interface is declared;
  `messageLength` and `contextLength` are required; and `preHash` belongs at
  the top level rather than inside a capability.

## [0.12.0] - 2026-09-03

### Added

- **Every algorithm that can be submitted has now been judged by NIST.** Two
  new sessions on `demo.acvts.nist.gov` took the live-verified count from 22 of
  40 algorithm names to **38 of 40** — the remaining two, ML-KEM and ML-DSA,
  have no response builder and so cannot be submitted at all.
  - Session 765508: the seven remaining hash names (`SHA2-224/384/512`,
    `SHA2-512/224`, `SHA2-512/256`, `SHA3-224`, `SHA3-384`) and the eight
    remaining HMACs. 15 vector sets, 12,867 cases, all `passed`.
  - Session 765518: `ACVP-AES-GMAC`. 360 cases, `passed`.
  - Running total: **43 vector sets, 32,464 cases, every verdict `passed`.**
- `acvts-capabilities/remaining-digests-gmac.json` and `gmac.json`.
- `results --session <id>` re-reads an earlier session's verdict from its
  stored record.

### Fixed

- **`results` reported every verdict as `unknown`.** It read a `disposition`
  field; the Demo server names it `status`. Both are accepted now. This was
  caught the first time the command was run against a real reply, because the
  reply is now saved rather than printed and discarded.
- **A session's scoped token was only ever stored for the *current* session**,
  so registering the next one orphaned the last. ACVP scopes a token to its
  registration and answers 403 to any other, which is why the verdicts from the
  first seven sessions can no longer be re-fetched. The record is now written
  beside the session's own vector sets as well.

### Notes

- The GMAC registration in 765508 declared a zero-width `payloadLen` and NIST's
  generator refused it with `min must be less than max` — GMAC is AAD-only and
  has no payload to describe. No vectors were produced, so the set is excluded
  from the 43 and that session reports `passed: false` overall. Recorded in the
  README rather than quietly dropped.

## [0.11.0] - 2026-09-03

### Added

- **Every one of the 40 algorithm names now reaches an external harness.** The
  DRBGs and KDF SP 800-108 were the last holdouts, so the project's central
  claim -- that an implementation which cannot be linked against can still be
  tested -- is now true for every family rather than most of them.
- **A live ACVTS session can be answered from a vendor's implementation.**
  `scripts/acvts_client.py submit` takes `--provider-command`,
  `--provider-timeout` and `--dry-run`; with a harness, every value NIST scores
  comes from the vendor's code rather than from this project's OpenSSL binding.
  The submitted document is identical in shape either way -- the server is told
  what was computed, never how.
- Harness operations `drbg`, `kdf-108` and `ecdsa-sign-group`.

### Changed

- **A declined case now refuses a whole submission.** Offline, UNSUPPORTED is a
  verdict worth recording. In a submission there is no such verdict: ACVP scores
  a missing case as a wrong answer, so a partial document would record a failure
  the implementation never earned. Nothing is sent, and the error names the
  operation that was declined.
- **Capability decisions moved to the implementation.** The responder was
  raising the built-in provider's limits -- ctrDRBG `TDES`, KDF `CMAC-TDES` --
  on the vendor's behalf, which would make a submission impossible for a product
  that offers them. Both already travel on the wire, so with a harness the
  implementation answers or declines them itself. This is the rule `supports()`
  states everywhere else; the responder was the one place not following it.
- `run_drbg_case()` is the single driver for a DRBG case. The responder had
  grown a second copy of the same prediction-resistance and generate-twice
  logic; the duplicate is gone.

### Fixed

- `SubprocessEcdsaProvider` had only per-case `sign`, which generates a fresh
  key each time. ACVP reports the public key once per *group*, so ECDSA sigGen
  could not be submitted through a harness at all. `ecdsa-sign-group` mirrors
  `rsa-sign-group`.
- `HMAC_FOR_KDF` in the reference harness was hand-listed at five hashes and
  declined 5,486 of 11,756 pinned KDF cases. Derived from `HASHLIB` now, the
  harness path matches the built-in exactly: 10,950 passed, 806 unsupported.
- A harness failure message is no longer echoed into `HarnessProtocolError`.
  Such a message commonly quotes the key it failed on, and the error reaches
  logs and CI output; only the operation is named.
- A ctrDRBG refusal interpolated nothing, because the second fragment of the
  message was a plain string rather than an f-string, so it printed a literal
  brace expression.

### Documentation

- The README banner claimed every algorithm had been judged by NIST's live
  server. Checking the session records, **22 of the 40** were; the rest are
  digest-size variants of the same code paths, plus AES-GMAC and the two PQC
  families. A single Coverage table now carries offline, harness and live-NIST
  status per algorithm, with the session id for each live claim, followed by a
  Not-covered list naming the absent families.
- `docs/limitations.md` still described a "frozen v0.1.0 MVP" supporting "only
  AES-GCM" -- the most misleading page in the repository, given the README sends
  vendors to it. Rewritten around what the tool does not tell you.
- "Testing your own implementation" became a four-stage vendor path, and the
  harness operation list became a table by family.

### Verified

Each pinned NIST prompt answered both ways and compared: **24,048 cases across
ten families, byte-identical wherever the answer is deterministic**. Where it
cannot be -- KDF invents `fixedData`, sigGen invents a key -- the answers were
checked for self-consistency: 10,950 KDF cases re-derived from the `fixedData`
the harness reported, and 800 signatures verified under the `qx`/`qy` it
reported. Groups the reference harness itself declines are excluded rather than
counted as passes.

## [0.10.0] - 2026-09-03

### Added

- RSA `sigGen`, `sigVer`, `signaturePrimitive` and `decryptionPrimitive`. RSA
  is the single most common name on published certificates, and these are the
  four modes a module normally validates. Submitted to demo.acvts.nist.gov;
  the session returned `"passed"` on all four.
- PKCS#1 v1.5 and PSS over SHA-1, the SHA-2 family and the SHA-3 family,
  including the `keyMode: crt` half of the primitive sets.

### Notes

- **The two primitives use different range checks**, and ACVP includes
  out-of-range cases precisely to catch a runner that uses one rule for both.
  A signature primitive message is in range when `m < n`; a decryption
  primitive ciphertext only when `1 < c < n - 1`. Both bounds come from NIST's
  generator grains in usnistgov/ACVP-Server and reproduce every case of the
  pinned upstream sets exactly.
- **`maskFunction` is a separate field from `hashAlg`.** FIPS 186-5 lets PSS
  use SHAKE as its mask generation function, which ACVP signals through
  `maskFunction` rather than through the hash. Ignoring it made six upstream
  cases fail while the group looked supported; those groups are now declared.
- SHAKE-based groups are declared throughout: this binding has no PSS over an
  extendable-output function. Across the pinned upstream sets that is 196 cases
  declared and 350 executed, with no failures.
- RSA `keyGen` is deliberately absent. Several of its modes require reporting
  intermediate prime seeds this binding does not expose, and a partial answer
  to keyGen is scored as wrong rather than incomplete.

## [0.9.0] - 2026-09-03

### Added

- `hashDRBG` and `hmacDRBG`, completing the SP 800-90A trio beside `ctrDRBG`.
  Effectively every FIPS module contains one of the three, so this closes the
  mechanism rather than a corner of it. Seven hashes each: SHA-1, the SHA-2
  family and both truncated SHA-512 variants.
- Both were submitted to demo.acvts.nist.gov and the session returned
  `"passed"`. 120 cases, and they passed on the first run -- which is what
  reading NIST's generator first buys.

### Notes

- All three mechanisms now share one runner and one boundary, because all three
  have the same lifecycle: instantiate, optionally reseed, generate twice, and
  compare only the second generation. `ctrDRBG`'s derivation-function and
  counter-width options are accepted and ignored by the other two rather than
  splitting the code into three paths.
- The implementations were written from `DrbgHash.cs` and `DrbgHmac.cs` in
  usnistgov/ACVP-Server rather than from prose. Two details that reading only
  the standard makes easy to miss: Hash_DRBG folds the *reseed counter* into V
  alongside H and C after every generation, and HMAC_DRBG runs its trailing
  update even when there is no additional input -- a single pass rather than
  two, but skipping it entirely desynchronises every later generation.

## [0.8.0] - 2026-09-03

### Added

- The AES chaining modes: `ACVP-AES-CBC`, `ACVP-AES-CTR`, `ACVP-AES-OFB` and
  `ACVP-AES-CFB128`. CBC and CTR appear on very nearly every certificate ever
  issued, which made this the largest remaining commercial gap.
- 6,008 cases executed against vectors the live server generated, zero
  failures, with 8 declared.

### Notes

- `ACVP-AES-CTR` has **no Monte Carlo test**. ACVP gives it a `CTR` test type,
  but that is a server-side distinction: the server back-computes the IVs from
  an ordinary functional answer. All 1,742 CTR cases pass.
- The Monte Carlo chains are fully supported in both directions, and were the
  hard part. The specification's pseudocode writes the inner loop as a cipher
  that "continues" from the previous call without saying what continuing does
  to the IV, and each mode answers differently: CBC and CFB128 advance it to
  the ciphertext just *produced* when encrypting and to the ciphertext just
  *consumed* when decrypting, while OFB advances it to the raw keystream block
  in both directions. Reading the specification's "replace all PT with CT"
  instruction literally reproduces the encrypt arrays exactly and disagrees
  from the first block when decrypting.
- The correct rules came from NIST's own generator, `MonteCarloAesCbc.cs` and
  its siblings in `usnistgov/ACVP-Server`, where encrypt and decrypt are
  structurally identical and the asymmetry lives inside the cipher object.
  `docs/limitations.md` carries the table. All twelve group combinations
  reproduce the live server's arrays on every field of all 100 iterations.
- `CFB` and `OFB` are read from `cryptography.hazmat.decrepit`, which is where
  they move in version 49.

## [0.7.0] - 2026-09-03

### Added

- `SHA-1` and the `SHA3-224/256/384/512` family, and `HMAC-SHA-1` and
  `HMAC-SHA3-*` beside them. Ten new algorithm names, taking the runner from
  23 to 33 of the 97 the live ACVTS Demo registry offers.
- Live validation against `demo.acvts.nist.gov`. Session 765345 returned
  `"passed": true` across SHA-1, SHA3-256, SHA3-512, HMAC-SHA-1 and
  HMAC-SHA3-256.

### Fixed

- **SHA-3 has its own Monte Carlo chain**, and reusing SHA-2's would have been
  silently wrong on every SHA-3 MCT case. SHA-2 hashes three digests
  concatenated (`A || B || C`); SHA-3 hashes a single one
  (`MD[i] = SHA3(MD[i-1])`). The two families share the `MCT` test type name
  and nothing else, so the mistake looks structurally correct and fails
  completely. Taken from the specification's pseudocode, then confirmed
  against server-generated vectors.
- The SHA parser accepted only revision `1.0`. SHA-3 is registered at `2.0`,
  so the accepted revision now follows the algorithm family.

## [0.6.0] - 2026-09-02

### Added

- `KDF` (SP 800-108), revision 1.0: counter, feedback and double-pipeline
  modes across 14 PRFs — HMAC over SHA-1, the SHA-2 family and the SHA-3
  family, plus CMAC-AES128/192/256.
- 10,950 cases executed against the pinned upstream set, zero failures, with a
  further 806 CMAC-TDES cases declared UNSUPPORTED.

### Notes

- This is the only set here whose *expected results file carries an input*. The
  prompt gives only `keyIn`, because a conforming implementation chooses its own
  `fixedData`; the runner reads NIST's choice back out of `expectedResults.json`
  and derives against it. A pass therefore shows the derivation is correct for
  that fixed data — it does not exercise an implementation's freedom to
  construct fixed data of its own, which the ACVP server checks and no
  file-based runner can. `docs/vector-sources.md` says so plainly.
- `breakLocation` is a **bit** offset, not a byte offset. Upstream values run 1
  to 127 against 128-bit fixed data, so the counter splices mid-byte. Treating
  it as bytes passes 10,092 cases and fails 858 — the kind of near-miss that
  looks like success on a summary line.
- `keyOutLength` is frequently not a multiple of 8 (67, 331, 1003), so the last
  byte's padding bits must be cleared.

## [0.5.0] - 2026-09-02

### Added

- `ctrDRBG`, revisions `1.0` and `SP800-90Ar1`. A DRBG sits in effectively every
  FIPS module, which made it the widest remaining single gap. It is also the
  first algorithm here that needed a genuinely new provider shape: a case
  instantiates a state machine, optionally reseeds it, and generates twice,
  rather than performing one transform.
- 450 cases executed against both pinned upstream sets, zero failures, covering
  AES-128/192/256, the derivation function both ways, prediction resistance both
  ways, and counter field widths of 128 and 64 bits.
- `optional_integer` in the parser, for fields like `counterFieldLen` that exist
  in one revision of an algorithm and not the other.

### Notes

- Two details in the operation sequence are silently wrong if you get them
  wrong, and both are now covered by tests. Prediction resistance turns a
  `generate` carrying entropy into a reseed followed by a generation, with the
  additional input consumed by the reseed rather than the generation. And every
  case generates twice while only the second output is compared — comparing the
  first would pass a DRBG that never updates its state.
- Three-key TDES is reported UNSUPPORTED rather than answered. SP 800-131A
  disallowed it for this use after 2023, so 150 of the 750 upstream cases are
  declared rather than executed.
- KDF SP 800-108 is now the last gap on the reference certificate this work has
  been tracking.

## [0.4.0] - 2026-09-02

Broadens algorithm coverage toward what a real module actually validates.

### Added

- Five AES mode families: `ACVP-AES-ECB`, `ACVP-AES-GMAC`, `ACVP-AES-KW`,
  `ACVP-AES-KWP` and `CMAC-AES`. AES-GCM alone covers very few real
  validations; a module that validates GCM almost always validates a key wrap
  and a CMAC beside it, and reviewing published CAVP certificates showed those
  four names recurring far more often than anything still missing.
- The AES Monte Carlo chain, whose key shuffle differs by key length — 128-bit
  keys are refreshed from the final ciphertext block alone, while 192- and
  256-bit keys reach back into the previous block because one 128-bit output is
  not enough material. Verified against the pinned NIST set, all 2,144 cases.
- Twelve more pinned vector files in `scripts/fetch_vectors.py`, covering the
  five new families and — a pre-existing gap — the ECDSA, ML-KEM and ML-DSA
  sets, which had been fetched by hand but never pinned. All 25 files are now
  verified by size and SHA-256 before use.

### Notes

- `kwCipher: inverse` is reported UNSUPPORTED rather than guessed at. It is
  half of the pinned KW and KWP sets, so the honest total is 3,600 executed and
  3,600 declared per set, not a quiet 7,200.
- Counter DRBG (SP 800-90A) and KDF SP 800-108 remain uncovered. Both need a
  new result shape rather than a new provider method, and are next.

## [0.3.0] - 2026-09-02

Closes the gap between what the project claimed and what it shipped.

### Added

- Every algorithm family is now reachable through `--provider-command`. SHA-2,
  HMAC and ECDSA previously refused an external harness, so the central claim —
  that an implementation which cannot be linked against can still be tested —
  held only for AES-GCM and PQC. SHA-2 and HMAC are in essentially every
  cryptographic module, so the gap hit the most common case first.
- Wire contract operations `digest`, `digest-mct`, `mac`, `ecdsa-sign` and
  `ecdsa-verify`, all implemented by `examples/reference_harness.py`. The Monte
  Carlo chain is delegated whole: 100,000 round trips would take hours, and
  running the chain is what an implementation under test does anyway.
- `{"error": "unsupported"}` lets a harness decline a case it does not
  implement. It is reported UNSUPPORTED rather than as a failure — telling a
  customer their module is broken when it simply lacks a curve is the worst
  output this tool can produce.

### Fixed

- ECDSA capability was filtered against what Python's `cryptography` exposes,
  which would have wrongly declared an HSM's binary curves unsupported.
  Capability now belongs to the provider via `supports()`.

### Verified

Through the external harness against pinned NIST vectors: AES-GCM 60/60,
SHA2-256 513 passed, HMAC-SHA2-256 975/975, ECDSA sigVer 140 passed. The
harness and in-process providers produce identical summaries.

## [0.2.0] - 2026-09-02

Five more algorithm families, a provider boundary that reaches implementations
this project cannot link against, and regression diffing between runs.

### Added

- **SHA-2** (`SHA2-224/256/384/512`, `SHA2-512/224`, `SHA2-512/256`) with both
  the standard and `alternate` Monte Carlo chains. Large data tests (LDT) are
  reported UNSUPPORTED rather than approximated; upstream cases expand to 8 GiB.
- **HMAC** over every supported SHA-2 variant, honouring per-group `macLen`
  truncation.
- **ECDSA** `sigGen` and `sigVer` on P-224/256/384/521. This introduced two
  result shapes the project previously lacked: *verdict-only*, where the
  expected result is a boolean rather than bytes, and *produce-and-verify*,
  where the output is randomised and must be verified rather than compared.
- **ML-KEM** (encapsulation, decapsulation, and both key checks) and **ML-DSA**
  `sigVer`. These require `--provider-command`: there is deliberately no
  built-in post-quantum implementation, because for PQC the implementation
  under test is the customer's.
- **External harness provider** (`--provider-command`, `--provider-timeout`).
  A harness reads one JSON request on stdin and writes one on stdout, so an
  HSM, a smartcard, an embedded device, or a library in any language can be
  tested without linking anything. Worked examples in `examples/`.
- **`acvp-assay diff BASELINE CURRENT`** compares two run reports. Coverage
  loss counts as a regression: a case that used to run and is now UNSUPPORTED,
  SKIPPED, or absent is reported as loudly as an outright failure, because the
  totals still look clean once it stops being counted. Provider identity is
  diffed alongside the cases, since a changed library version is usually the
  cause.
- **`scripts/fetch_vectors.py`** downloads and SHA-256-verifies the pinned
  upstream NIST vectors into a git-ignored directory, refusing to write
  anything whose size or hash differs.

### Fixed

- Deliberate authentication-failure cases were scored wrongly. ACVP marks them
  `testPassed: false` and roughly a third of NIST's AES-GCM decrypt cases are
  of this kind; a correct implementation rejecting a forged tag was reported as
  an ERROR, and an implementation *wrongly accepting* one was not distinguished
  at all. Rejection is now a PASS and acceptance a loud FAIL.
- ML-DSA's `internal` signature interface was treated as external with an empty
  context. It omits the domain separator and context prefix, so nine valid
  signatures in NIST's own set were reported as rejected.
- A misconfigured harness reported every case as an error and then crashed on
  the report. Provider metadata is now probed once before any case runs, so the
  run stops with a single clear message.
- `TestCaseResult` now enforces the closed ERROR-diagnostic vocabulary itself,
  rather than relying on convention at one call site, so raw exception text
  cannot reach a report.

### Changed

- Renamed from `acvp-runner` to **`acvp-assay`**. An assay measures
  composition; it does not certify it.
- Algorithm dispatch reads the algorithm from the vector file and routes it, so
  one command serves every family.

## [0.1.0] - 2026-09-02

Initial release: an offline AES-GCM vector runner.

### Added

- ACVP AES-GCM vector and expected-results parsing with typed models that
  preserve `vsId`, `tgId`, and `tcId`.
- A replaceable provider boundary with one implementation backed by the OpenSSL
  behind Python's `cryptography`.
- Encrypt and decrypt execution, per-case PASS/FAIL/ERROR comparison with
  non-secret diagnostics, and deterministic JSON reporting including provider
  and backend versions.
- `acvp-assay run VECTOR_FILE [--output] [--strict]` with documented exit codes.
- Clean-checkout Linux CI, and a pinned, hash-verified upstream vector source
  that is referenced rather than redistributed.

[0.18.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.18.0
[0.17.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.17.0
[0.16.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.16.0
[0.15.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.15.0
[0.14.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.14.0
[0.13.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.13.0
[0.12.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.12.0
[0.11.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.11.0
[0.10.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.10.0
[0.9.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.9.0
[0.8.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.8.0
[0.7.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.7.0
[0.6.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.6.0
[0.5.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.5.0
[0.4.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.4.0
[0.3.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.3.0
[0.2.0]: https://github.com/Govardhan527/acvp-assay/releases/tag/v0.2.0
<!-- 0.1.0 was never tagged: development continued past it on the same version,
     so b174d92 is the last commit that carried it. Linked to the commit rather
     than to a release tag that does not exist. -->
[0.1.0]: https://github.com/Govardhan527/acvp-assay/commit/b174d92
