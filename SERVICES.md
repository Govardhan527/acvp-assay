# Commercial services

`acvp-assay` is MIT-licensed and free to use. Nothing in the repository is gated,
and you never have to talk to me to use it. What follows are paid engagements for
teams who would rather have the work done than the tool handed over.

I am Govardhan Yadava. I spent seven years owning cryptographic validation for
an enterprise HSM and key-management platform — the FIPS 140-2 and 140-3 mode
behaviour, the PKCS#11 / CNG KSP / JCE / REST / CLI client matrix, and the
Go/No-Go security release gate the product shipped behind. I submitted twelve
review comments to the OASIS KMIP Profiles v3.0 public review in August 2026. I
wrote this tool.

---

## Why this exists

FIPS 140-3 validation runs eighteen months and upwards, and $50,000–100,000+ per
module before internal effort. ACVP algorithm validation is a mandatory gate on
that path, and it is the gate where avoidable weeks get lost: a parser
disagreement or a Monte Carlo chaining bug surfaces after you have engaged a
laboratory, on their clock, at their rate.

Building this tool against NIST's live demo server surfaced four defects that
offline fixtures had not:

1. AES-GCM parsing required `ivGenMode` even where `ivGen` was external, which
   NIST omits in exactly that case.
2. Chaining-mode Monte Carlo decrypt chains were wrong, because the specification
   prose contradicts the generator's actual rules.
3. RSA-PSS ignored `maskFunction`, so the PSS-over-SHAKE cases failed while their
   group looked perfectly supported.
4. ECDSA and RSA `sigGen` generated fresh keys per case rather than per group,
   which the ACVP response format cannot represent.

Each one is written up in
[What this caught that fixtures did not](README.md#what-this-caught-that-fixtures-did-not).
Every one of them would have been found by a laboratory instead, later and more
expensively. That is the value on offer: find them before the meter starts.

**From 21 September 2026 FIPS 140-2 certificates move to Historical status.** If
you sell into federal or FedRAMP channels on a 140-2 certificate, this is now a
scheduling problem, not a roadmap item.

---

## What makes this different from the tools you already have

`libacvp` and ACVP Proxy are good, and if your implementation links cleanly
against a C library you may not need me.

This reaches the implementations that do not link: HSMs, smartcards, embedded
devices, services behind a network boundary, libraries in languages with no ACVP
client. The harness protocol is one JSON request per line on stdin and one
response per line on stdout — see
[docs/harness-protocol.md](docs/harness-protocol.md). Nothing links against the
project, the harness is started once and stays alive so PKCS#11 login or serial
setup happens once, and a reference C harness for PKCS#11 tokens ships with it,
verified through SoftHSM against 3,461 pinned NIST cases.

---

## Engagements

### 1. ACVP readiness assessment — fixed price, from **$2,500**

Before you engage a laboratory, know what will fail.

- Scoping call to establish which of the [46 supported algorithm
  names](README.md#coverage) apply.
- Your implementation exercised against NIST-generated vectors through the
  harness boundary, case by case.
- A written gap report: what passed, what failed and why, what your
  implementation declines, and which declines a laboratory will treat as a
  finding rather than a scoping decision.
- A recorded baseline you can diff future builds against.

Two to three weeks. Priced at roughly 3% of a typical validation programme.

### 2. Harness build and assessment — fixed price, from **$6,000**

For devices that need integration work before they can be tested at all: an HSM
behind PKCS#11, a smartcard, an embedded target, a service API.

- I build the harness against your interface, starting from the reference C
  PKCS#11 or Python implementations in [`examples/`](examples/).
- Everything in engagement 1, run through it.
- The harness is yours, with documentation, and it keeps working in your CI.

Four to six weeks.

### 3. Conformance regression retainer — from **$900 / month**

Validation is a point in time; conformance is not. A library upgrade, a firmware
bump or a container base image change can silently drop coverage, and coverage
loss is the failure mode that hides inside a green summary total.

- `acvp-assay diff` wired into your CI, failing the build on regression.
- Coverage loss treated as regression, not as a passing run with fewer cases.
- Quarterly re-runs against freshly NIST-generated vectors.
- A named person to read the output when it goes red.

Minimum three months.

### 4. Advisory — **$950 / day**

Cryptographic conformance strategy, PKCS#11 and KMIP interoperability, FIPS
140-3 mode behaviour and approved-algorithm enforcement, crypto-agility and PQC
migration readiness, cryptographic test-vector design, release certification
gates.

---

## What I will not tell you

This produces test evidence. It is not a certificate and confers no validation
status. Only an accredited CST or 17ACVT laboratory performs CAVP or FIPS 140-3
validation, and the demo ACVTS is not the production service. Anyone who tells
you otherwise is selling you something that does not exist.

The ML-KEM and ML-DSA verdicts in this repository came from educational
reference implementations that are not constant-time and make no side-channel
claims. They demonstrate that the runner handles PQC vector sets correctly. They
say nothing about production fitness, including yours. The full set of
assurance boundaries is in [docs/limitations.md](docs/limitations.md).

I will tell you if an engagement will not help you. That is cheaper for both of
us than discovering it in week three.

---

## Contact

Govardhan Yadava — govardhan@seccrypto.dev — Bengaluru, India (IST, routinely
overlapping US Pacific and Central European hours).

Tell me the algorithms, the interface your implementation sits behind, and your
target validation date. I will tell you within a day whether I can help and what
it costs.
