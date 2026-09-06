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

- [x] M00: request ACVTS Demo credentials from `acvts-demo@nist.gov` — sent 2026-09-02,
      granted, and used for every live session from 765339 onward. See
      `docs/acvts-demo-access-request.md`.
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
- [x] M11: harness operations for every family. All forty algorithm names implemented
      at the time reached an external implementation, verified through the wire against
      NIST's vectors with the shipped reference harness; every family added since has
      shipped with its operations, so the property still holds at forty-six. A DRBG
      case crosses in one exchange rather than as a conversation, because putting a
      state machine on a wire makes the two sides agree about a sequence of calls
      rather than about an answer.
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
- [x] M12: `--provider-command` for the live responder, so a vendor's own answers
      can be submitted to ACVTS rather than this project's. `acvts_client.py submit`
      takes `--provider-command`, `--provider-timeout` and `--dry-run`; every value in
      the submitted document then comes from the vendor's implementation, and the
      document itself is identical in shape either way — the server is told what was
      computed, never how.
      Two things this settled that the offline runner had not had to decide:
      - **A declined case refuses the whole document.** Offline, UNSUPPORTED is a
        verdict worth recording. In a submission there is no such verdict: ACVP scores
        a missing case as a wrong answer, so a partial document would record a failure
        the implementation never earned.
      - **Capability belongs to the implementation.** The built-in provider's limits
        (DRBG `TDES`, KDF `CMAC-TDES`) were being raised on the vendor's behalf, which
        would make a submission impossible for a product that offers them. Those modes
        already travel on the wire, so with a harness the implementation answers or
        declines them itself.
      Gaps left deliberately: AES `kwCipher: inverse` and SHA LDT are not merely
      capability checks — neither operation is on the wire at all — and GCM
      `ivGen: internal` needs the provider to report the IV it chose.
- [x] M13: publish to PyPI. Released 2026-09-04 as `acvp-assay`; `pip install acvp-assay`
      installs and runs vector files from a clean environment.
- [x] M14: response builders for ML-KEM and ML-DSA, taking live NIST coverage to 40 of 40
      algorithm names. Both require `--provider-command`, since there is no built-in PQC
      provider and a submission must carry values something actually computed.
- [x] M15: KAS-ECC-SSC (Sp800-56Ar3), the `ephemeralUnified` scheme. The last item on
      the commercial priority list in the coverage-gap analysis, and the family where the
      offline/live distinction is sharpest: a VAL case supplies every input and is fully
      checkable here, while an AFT case has the implementation generate an ephemeral key,
      so Z differs every run and only the server — which holds the peer private key — can
      verify it. Declined offline with the reason; answered in full by the responder.
      Session 765769 returned `passed` on all 20 cases.
- [x] M16: ACVP-AES-XTS, revision 2.0. Storage encryption, and the next family by
      commercial value after key agreement. Three details settled against NIST's own
      vectors before any module code was written: the key is two AES keys concatenated,
      a `number` tweak is a little-endian sequence number, and a payload longer than
      `dataUnitLen` spans several data units each with its own tweak. Session 765786
      returned `passed` on all 480 cases.
- [x] M17: ACVP-AES-CCM. The AEAD of 802.11 and constrained devices, and the twin of
      AES-GCM in shape: 613 of its decrypt cases are deliberate forgeries where rejecting
      the tag is the correct answer. Session 765788 returned `passed` on all 4,830 cases.
- [x] M18: SHAKE-128 and SHAKE-256. The extendable-output functions, and the first
      family whose output length is an input rather than a property of the algorithm.
      AFT only: the Demo server generates no other test type for a FIPS202 SHAKE
      registration, and a Monte Carlo chain written without vectors would be a guess.
      Session 765794 returned `passed` on both sets, 508 cases.
- [x] M19: KDA (SP 800-56C), HKDF mode. The derivation that pairs with key agreement,
      and the highest-value name remaining after the coverage analysis was re-run against
      the live registry. The work is assembling fixedInfo from the pattern the group
      declares, not the HKDF itself. Session 765811 returned `passed` on all 300 cases.
- [x] M20: state the paid half in the repository. `SERVICES.md` carries the four
      engagements — readiness assessment, harness build, regression retainer, advisory —
      and the README points at it from just after the differentiator bullets. The
      pricing rationale stays outside the repository; only the numbers are public.
      Two claims were reconciled in the same pass: Scope still said 43 algorithm names
      and 40 reaching a harness while the banner and the coverage table said 46, and a
      services page selling 46 three lines below a scope claiming 43 invites the one
      question you do not want asked.

## Open

Ranked by measurement, not judgement. `docs/algorithm-frequency.md` counts every
name across the **690 active FIPS 140-3 certificates** that list their approved
algorithms; the shares below are from that table, and `scripts/cavp_frequency.py`
reproduces it. Where two names are bracketed together it is because the
certificates bracket them — the co-occurrence is in the same document.

The median module is **84% testable today** and 112 of the 690 are fully
testable. 118 more are exactly one name away, which is what the second table in
that document ranks.

- [x] M21: the AES modes the measurement rescued — `ACVP-AES-CFB8` (36% of
      modules), `ACVP-AES-CBC-CS3` (27%), `CBC-CS1` (24%), `CBC-CS2` (23%) and
      `ACVP-AES-CFB1` (21%). All five had been written off as niche by the reasoned
      ranking. Session 766208 returned `passed` on all five vector sets, 17,656
      cases, taking the project to 51 algorithm names.
      Three things this settled that reuse did not make free:
      - **CFB8 and CFB1 need their own Monte Carlo chain.** A segment mode feeds
        back one segment per step, so a block's worth of feedback takes 16 steps
        or 128 rather than one, and the plaintext for a step comes from the IV
        until the register has shifted past it. Every rule was checked against
        the server's own 100 outer iterations, in both directions, before any
        module code was written.
      - **CFB1 is the only mode whose payload is bits.** The hex pads to a byte,
        so the declared `payloadLen` is the only thing that says where the
        payload ends. It now travels on the wire, and only for CFB1.
      - **CS1, CS2 and CS3 are one algorithm and three orderings.** CS3 always
        reverses the last two ciphertext blocks, CS2 only when the final block is
        partial, CS1 never. A payload of exactly one block has nothing to steal
        from and is plain CBC.
      And one defect only the live server could find: the response builder never
      passed CFB1's bit count, so the submission answered over the padding while
      the offline runner — a different code path — passed all 2,144 cases against
      NIST's own sample file. Session 766207 returned `fail`; the fix is pinned by
      `tests/unit/test_responder_payload_bits.py`.
- [x] M22: `PBKDF` (SP 800-132) — 42% of modules and second on the unlock table.
      Session 766210 returned `passed` on all 110 cases, taking the project to 52
      algorithm names. One vector set, eleven groups, one per approved HMAC.
      The derivation is `hashlib.pbkdf2_hmac`, so almost none of the work was
      arithmetic. Two things ACVP decides and neither is guessable:
      - **The password arrives as text, not hex.** Every other byte string in a
        vector set is hex-encoded; this one is the characters themselves. A hex
        reading fails outright on any password containing a letter past `f` and,
        worse, silently succeeds on one that happens to be hex-shaped — deriving
        correctly from the wrong bytes. It is decoded once at the parser so
        nothing downstream has to remember which convention applies, and the
        harness wire carries hex like everything else.
      - **`keyLen` counts bits**, as ACVP lengths do, while `hashlib` wants bytes.
      Verified before writing module code, as M21 established: all 110 of NIST's
      answers were reproduced from the fetched vectors first. The response
      document was then checked against those same answers *before* submission —
      the step that would have caught the CFB1 defect in M21.
- [ ] M23: `safePrimes` (47%) and `KAS-FFC-SSC` (46%). The reasoned ranking
      dismissed safePrimes as niche, which was its largest single error — 278 of
      the 322 modules validating it also validate KAS-FFC-SSC, so these are one
      cluster and building either alone leaves most of those modules still
      untestable. KAS-FFC-SSC is a sibling of the ECC variant built in M15, so
      the offline/live split settled there applies unchanged.
- [ ] M24: `kdf-components` (56%), `TLS-v1.2` (41%) and `TLS-v1.3` (28%). The
      most common missing name and the top of the unlock table, ranked below the
      three items above only because it is the most work: kdf-components is one
      registry name covering nine component KDFs — SSH, TLS, IKEv1, IKEv2,
      ANS 9.42, ANS 9.63, SNMP, SRTP and TPM. 256 of the 281 modules validating
      TLS-v1.2 also validate kdf-components, so they ship together.
- [x] M25: replace the reasoned ranking with a measured one. Done 2026-09-06:
      `scripts/cavp_frequency.py` fetches all 1,182 active CMVP certificates,
      maps each CAVP display name onto its ACVP registry name and counts them
      across modules, by frequency and by what each addition completes. Written
      up in `docs/algorithm-frequency.md`; the display-name map is the only
      judgement in it and is tested in `tests/unit/test_cavp_frequency.py`.
      It reordered everything above. `cSHAKE-128/256` had been ranked first and
      measures **7%** — it was chosen for being cheap to build, which is a claim
      about cost wearing the clothes of a claim about demand.
- [ ] M26: the tail, in measured order — `KTS-IFC` (31%) with `KAS-IFC-SSC`
      (17%), which co-occur on 114 modules; `KMAC-128/256` (22%); `KAS-ECC`
      non-SSC (22%, and fourth on the unlock table); `EDDSA` (14%);
      `ConditioningComponent` (4%, eighth on the unlock table); then
      `cSHAKE-128/256` (7%), `ParallelHash` and `TupleHash` (6%),
      `ACVP-AES-FF1` (6%), `LMS` and `DetECDSA` (2%), `ACVP-AES-XPN` (2%),
      `KAS-KC` (0.4%) and `SLH-DSA` (0.3%).
      `DSA` measures 28% and is deliberately not ranked with the rest: SP 800-131A
      disallowed DSA signature generation after 2023, so what is left on
      certificates is legacy verification and the share should decay.

Not worth building, now measured rather than assumed: `ACVP-AES-GCM-SIV`,
`Ascon`, `XECDH` and `ACVP-AES-FF3-1` appear on **no** active FIPS 140-3
certificate, and the fourteen three-key TDES names are disallowed for new
validations since 2023.

Still out of scope: a full ACVP protocol client, algorithm count as a goal, an HTML dashboard, and any hosted service.
