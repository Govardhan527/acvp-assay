# What FIPS 140-3 certificates actually contain

Every algorithm in this project was chosen by reasoning about what modules
probably validate. This measures it instead.

On 2026-09-06 all 1,182 active CMVP certificates were fetched and their approved
algorithm lists read, each CAVP display name mapped onto the ACVP registry name
that would have to be implemented to test it, and the names counted across
modules. `scripts/cavp_frequency.py` does the whole thing and this page is its
output; `python3.12 scripts/cavp_frequency.py fetch` then `report` reproduces it.

## Population, and what it excludes

**690 modules.** Of the 1,182 active certificates, 696 are FIPS 140-3 and 690 of
those list approved algorithms; 549 of the 690 were first validated in 2025 or
later, which is the column to read if you care about current practice rather
than the standing population.

The 486 active **FIPS 140-2** certificates are excluded, and not as a
convenience: their pages carry no machine-readable algorithm list to read. It
matters less than it sounds, because those certificates move to Historical on
21 September 2026. Six FIPS 140-3 certificates list no algorithms at all and are
excluded too.

One module counts once per registry name however many operations it validates.
A certificate naming `RSA SigGen (FIPS186-4)`, `RSA SigVer (FIPS186-4)`,
`RSA SigVer (FIPS186-5)` and `RSA KeyGen (FIPS186-5)` needs one ACVP name, `RSA`,
so it contributes one. The map from display name to registry name is the only
judgement in the method, and it is tested in
`tests/unit/test_cavp_frequency.py`; a name it cannot place is reported rather
than dropped, and at the time of writing it places all 140 display names found.

## How much of a certificate this tool can test today

Median module: 84% of its algorithm names are testable today. Fully testable: 112 modules (16%).

Half the active FIPS 140-3 population is within two names of being fully
testable: 112 modules need nothing added, 118 need exactly one more name, and 59
need two.

## Frequency

How many of the 690 modules carry each name — the chance that any given customer
needs it.

| algorithm | modules | share | 2025+ | share | status |
| --- | ---: | ---: | ---: | ---: | --- |
| `SHA2-256` | 654 | 95% | 522 | 95% | built |
| `HMAC-SHA2-256` | 604 | 88% | 490 | 89% | built |
| `RSA` | 587 | 85% | 470 | 86% | built |
| `ACVP-AES-CBC` | 583 | 84% | 469 | 85% | built |
| `SHA2-384` | 565 | 82% | 457 | 83% | built |
| `ECDSA` | 548 | 79% | 450 | 82% | built |
| `SHA2-512` | 546 | 79% | 450 | 82% | built |
| `ACVP-AES-ECB` | 523 | 76% | 421 | 77% | built |
| `ACVP-AES-GCM` | 518 | 75% | 429 | 78% | built |
| `HMAC-SHA2-384` | 516 | 75% | 421 | 77% | built |
| `HMAC-SHA2-512` | 510 | 74% | 425 | 77% | built |
| `SHA-1` | 505 | 73% | 420 | 77% | built |
| `ctrDRBG` | 495 | 72% | 408 | 74% | built |
| `HMAC-SHA-1` | 492 | 71% | 410 | 75% | built |
| `ACVP-AES-CTR` | 473 | 69% | 391 | 71% | built |
| `KAS-ECC-SSC` | 431 | 62% | 359 | 65% | built |
| `SHA2-224` | 411 | 60% | 336 | 61% | built |
| `HMAC-SHA2-224` | 391 | 57% | 326 | 59% | built |
| `kdf-components` | 383 | 56% | 324 | 59% | **missing** |
| `CMAC-AES` | 372 | 54% | 311 | 57% | built |
| `ACVP-AES-CCM` | 356 | 52% | 296 | 54% | built |
| `ACVP-AES-KW` | 344 | 50% | 288 | 52% | built |
| `ACVP-AES-CFB128` | 337 | 49% | 277 | 50% | built |
| `safePrimes` | 322 | 47% | 271 | 49% | **missing** |
| `SHA3-256` | 322 | 47% | 273 | 50% | built |
| `KAS-FFC-SSC` | 317 | 46% | 263 | 48% | **missing** |
| `KDF` | 316 | 46% | 265 | 48% | built |
| `ACVP-AES-XTS` | 303 | 44% | 245 | 45% | built |
| `hashDRBG` | 299 | 43% | 242 | 44% | built |
| `PBKDF` | 291 | 42% | 244 | 44% | **missing** |
| `SHA3-384` | 288 | 42% | 247 | 45% | built |
| `SHA3-512` | 284 | 41% | 243 | 44% | built |
| `ACVP-AES-OFB` | 283 | 41% | 233 | 42% | built |
| `TLS-v1.2` | 281 | 41% | 247 | 45% | **missing** |
| `SHA3-224` | 280 | 41% | 240 | 44% | built |
| `ACVP-AES-GMAC` | 277 | 40% | 234 | 43% | built |
| `KDA` | 272 | 39% | 234 | 43% | built |
| `hmacDRBG` | 268 | 39% | 231 | 42% | built |
| `HMAC-SHA3-256` | 256 | 37% | 223 | 41% | built |
| `HMAC-SHA3-384` | 255 | 37% | 222 | 40% | built |
| `HMAC-SHA3-512` | 254 | 37% | 221 | 40% | built |
| `ACVP-AES-CFB8` | 250 | 36% | 213 | 39% | **missing** |
| `ACVP-AES-KWP` | 250 | 36% | 214 | 39% | built |
| `HMAC-SHA3-224` | 249 | 36% | 217 | 40% | built |
| `SHA2-512/256` | 237 | 34% | 206 | 38% | built |
| `SHAKE-256` | 222 | 32% | 194 | 35% | built |
| `HMAC-SHA2-512/256` | 221 | 32% | 193 | 35% | built |
| `SHAKE-128` | 220 | 32% | 192 | 35% | built |
| `KTS-IFC` | 214 | 31% | 185 | 34% | **missing** |
| `TLS-v1.3` | 196 | 28% | 171 | 31% | **missing** |
| `DSA` | 193 | 28% | 163 | 30% | **missing** |
| `ACVP-AES-CBC-CS3` | 188 | 27% | 162 | 30% | **missing** |
| `SHA2-512/224` | 186 | 27% | 164 | 30% | built |
| `HMAC-SHA2-512/224` | 182 | 26% | 161 | 29% | built |
| `ACVP-AES-CBC-CS1` | 165 | 24% | 145 | 26% | **missing** |
| `ACVP-AES-CBC-CS2` | 161 | 23% | 140 | 26% | **missing** |
| `KAS-ECC` | 155 | 22% | 119 | 22% | **missing** |
| `KMAC-256` | 151 | 22% | 133 | 24% | **missing** |
| `KMAC-128` | 150 | 22% | 132 | 24% | **missing** |
| `ACVP-AES-CFB1` | 148 | 21% | 130 | 24% | **missing** |
| `KAS-IFC-SSC` | 117 | 17% | 100 | 18% | **missing** |
| `EDDSA` | 97 | 14% | 84 | 15% | **missing** |
| `ACVP-TDES-CBC` | 74 | 11% | 66 | 12% | dead |
| `ACVP-TDES-ECB` | 73 | 11% | 66 | 12% | dead |
| `KAS-FFC` | 50 | 7% | 46 | 8% | **missing** |
| `cSHAKE-128` | 47 | 7% | 44 | 8% | **missing** |
| `cSHAKE-256` | 47 | 7% | 44 | 8% | **missing** |
| `KAS-IFC` | 41 | 6% | 37 | 7% | **missing** |
| `TupleHash-128` | 40 | 6% | 37 | 7% | **missing** |
| `ParallelHash-256` | 40 | 6% | 37 | 7% | **missing** |
| `ACVP-AES-FF1` | 40 | 6% | 37 | 7% | **missing** |
| `ParallelHash-128` | 40 | 6% | 37 | 7% | **missing** |
| `TupleHash-256` | 40 | 6% | 37 | 7% | **missing** |
| `ConditioningComponent` | 29 | 4% | 20 | 4% | **missing** |
| `ACVP-TDES-CFB8` | 19 | 3% | 15 | 3% | dead |
| `ACVP-TDES-CFB64` | 18 | 3% | 14 | 3% | dead |
| `ACVP-TDES-OFB` | 18 | 3% | 14 | 3% | dead |
| `CMAC-TDES` | 17 | 2% | 14 | 3% | dead |
| `ACVP-TDES-CFB1` | 14 | 2% | 11 | 2% | dead |
| `LMS` | 12 | 2% | 12 | 2% | **missing** |
| `ML-KEM` | 12 | 2% | 12 | 2% | built |
| `DetECDSA` | 11 | 2% | 11 | 2% | **missing** |
| `ACVP-AES-XPN` | 10 | 1% | 10 | 2% | **missing** |
| `ACVP-TDES-CTR` | 5 | 1% | 3 | 1% | dead |
| `ACVP-TDES-KW` | 5 | 1% | 3 | 1% | dead |
| `ML-DSA` | 5 | 1% | 5 | 1% | built |
| `KAS-KC` | 3 | 0% | 3 | 1% | **missing** |
| `SLH-DSA` | 2 | 0% | 2 | 0% | **missing** |

## What to build next

Frequency answers "will a customer need this". It does not answer "what does
adding it finish". This table is greedy: at each step it adds the name that
completes the most modules that are otherwise one name away.

| # | add this name | modules it completes | cumulative | share |
| ---: | --- | ---: | ---: | ---: |
| 1 | `kdf-components` | 23 | 135 | 20% |
| 2 | `PBKDF` | 26 | 161 | 23% |
| 3 | `ACVP-AES-CFB8` | 22 | 183 | 27% |
| 4 | `KAS-ECC` | 19 | 202 | 29% |
| 5 | `TLS-v1.2` | 19 | 221 | 32% |
| 6 | `KTS-IFC` | 16 | 237 | 34% |
| 7 | `ACVP-AES-CBC-CS3` | 15 | 252 | 37% |
| 8 | `ConditioningComponent` | 13 | 265 | 38% |
| 9 | `TLS-v1.3` | 11 | 276 | 40% |
| 10 | `LMS` | 6 | 282 | 41% |
| 11 | `EDDSA` | 7 | 289 | 42% |
| 12 | `ACVP-AES-XPN` | 6 | 295 | 43% |

## What this changed

Four calls in the previous, reasoned ranking were wrong:

- **`cSHAKE-128/256` was ranked first.** It is on **7%** of modules — near the
  bottom of everything still missing. It was ranked first because it is cheap to
  build from the XOF boundary SHAKE already established, which is a statement
  about cost, not about demand.
- **`KMAC-128/256` was paired with it** for the same reason. KMAC is genuinely
  more common at 22%, but the pairing does not hold: of 150 modules validating
  KMAC-128, only 41 also validate cSHAKE-128.
- **`safePrimes` was dismissed as niche.** It is on **47%** of modules, and it
  travels with FFC key agreement — 278 of the 322 modules validating it also
  validate `KAS-FFC-SSC`. Dismissing it was the single largest error.
- **`ACVP-AES-CFB8`, `CFB1` and `CBC-CS1/2/3` were dismissed as niche.** They
  measure 36%, 21% and 23–27%, and each reuses the AES mode machinery already
  built. `CFB1` is a strict subset: all 148 modules validating it also validate
  `CFB8`.

Four names were correctly dismissed, and more firmly than expected —
`ACVP-AES-GCM-SIV`, `Ascon`, `XECDH` and `ACVP-AES-FF3-1` appear on **no** active
FIPS 140-3 certificate at all.

Two names deserve a caveat rather than a rank. `DSA` measures 28%, but SP 800-131A
disallowed DSA signature generation after 2023, so what remains on certificates is
legacy verification and the number should decay. The three-key TDES family is
excluded outright for the same reason, and is marked `dead` in the table above
rather than silently dropped.

The post-quantum names are the opposite case: `ML-KEM` is on 12 modules and
`ML-DSA` on 5. Both are already built here, ahead of the demand curve rather than
behind it, which is where CNSA 2.0 requires them to be by January 2027.

## Reproducing it

```bash
python3.12 scripts/cavp_frequency.py fetch    # ~1,180 requests, 3 at a time
python3.12 scripts/cavp_frequency.py report   # prints both tables above
```

The cache lands in `.cavp-cache/` and is gitignored: it is NIST's content, read
here and not redistributed. `report --since YEAR` moves the recent-slice cutoff.
