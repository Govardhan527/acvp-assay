# Vector sources

## Selected upstream source

Status: selected and pinned for the AES-GCM v0.1.0 MVP.

- Publisher: National Institute of Standards and Technology (NIST)
- Repository: [`usnistgov/ACVP-Server`](https://github.com/usnistgov/ACVP-Server)
- Repository commit: [`975de31eb83d87039ec88934fdc47d8c312b892d`](https://github.com/usnistgov/ACVP-Server/commit/975de31eb83d87039ec88934fdc47d8c312b892d)
- Upstream commit date: 2026-08-12
- Retrieved and reviewed: 2026-09-02 (Asia/Kolkata)
- Selected directory: [`gen-val/json-files/ACVP-AES-GCM-1.0`](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ACVP-AES-GCM-1.0)
- Protocol/schema reference: [`usnistgov/ACVP` symmetric specification at `892fd147...`](https://github.com/usnistgov/ACVP/blob/892fd14710f3a7edbea230d0aecc5511e0257f8e/src/draft-celi-acvp-symmetric.adoc)

The exact upstream inputs selected for later compatibility tests are:

| File | Purpose | Git blob ID | Size | SHA-256 |
| --- | --- | --- | ---: | --- |
| [`registration.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ACVP-AES-GCM-1.0/registration.json) | Capabilities used to generate the set | `a284b090b903cb0eb9173e4a982f9a81ddef049e` | 376 bytes | `70dbf2189f673d756013d758539fc57994c1415efa43cd1524d59ca1346c4038` |
| [`prompt.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ACVP-AES-GCM-1.0/prompt.json) | Vector-set input to an implementation under test | `16650d8ead5de4c8c5323419d2e3b3fcfb8f73e2` | 15,187 bytes | `78114cb01d1f436a1f6d0b47bf2fdb9a78f805fbae59c31a813c32edb4e00821` |
| [`expectedResults.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ACVP-AES-GCM-1.0/expectedResults.json) | Expected case results paired by `tgId` and `tcId` | `6d1338e8a752eb439ec15d2115bbbbfb40ac9b69` | 6,067 bytes | `5d4f4bfff5af3284548296f3637ed75bb92f7eb94e6fa04524d1546353e4cff8` |

`internalProjection.json` and `validation.json` are not selected as runner inputs. They are server-side generation/validation artifacts and are unnecessary for the first adapter contract.

### Additional algorithm sets (M03)

Pinned at the same commit, under the same `gen-val/json-files` root and the same licensing decision below.

| File | Purpose | Size | SHA-256 |
| --- | --- | ---: | --- |
| [`SHA2-256-1.0/prompt.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/SHA2-256-1.0/prompt.json) | 512 AFT cases, one `alternate` MCT group, four LDT cases | 948,259 bytes | `9c4ec74e526cced84cd6dfdf130f2908e2d340b45ea5d9ea0a4019987ee49dac` |
| [`SHA2-256-1.0/expectedResults.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/SHA2-256-1.0/expectedResults.json) | Expected digests and the 100-entry MCT `resultsArray` | 77,375 bytes | `776688ef7b6e4dd18ce203ee7d9ee45c6c597248f6c00ec70bdbd59176109e05` |
| [`HMAC-SHA2-256-1.0/prompt.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/HMAC-SHA2-256-1.0/prompt.json) | 975 AFT cases across 13 groups, `macLen` 80/88/96/160 | 347,221 bytes | `efb49edda31524c8fe9ffdb4fc92120f041b01ca06f6496f97939240bf1cdcf9` |
| [`HMAC-SHA2-256-1.0/expectedResults.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/HMAC-SHA2-256-1.0/expectedResults.json) | Expected MACs, truncated to each group's `macLen` | 88,459 bytes | `dae3412189dfe11a63b40780f16c6c3304b5d9c2dff5351f653711903cf09e1f` |

The SHA-2 set is the one that pinned down two behaviours guesswork would have got wrong: `mctVersion` is `alternate`, which normalises every Monte Carlo message to the *original* seed length rather than hashing three digests directly, and the LDT cases expand to as much as 8 GiB, which this runner reports UNSUPPORTED rather than approximating.

### AES mode families and public-key sets (v0.4.0)

Pinned at the same commit and under the same licensing decision. These closed a
pre-existing gap: the ECDSA and PQC sets were being used but had never been
recorded in `scripts/fetch_vectors.py`, so nothing checked they had not drifted.

| File | Size | SHA-256 |
| --- | ---: | --- |
| [`ECDSA-SigGen-FIPS186-5/prompt.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ECDSA-SigGen-FIPS186-5/prompt.json) | 987,281 bytes | `a07cfcf2e3bdbda1cbf82cefc6f38a2d0559ee8852b2f0276a200e0747b46744` |
| [`ECDSA-SigGen-FIPS186-5/expectedResults.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ECDSA-SigGen-FIPS186-5/expectedResults.json) | 1,057,697 bytes | `64ddfc8cdf1e4d693e888e40bab5d898aa4a6684812ed94371e90bb040559c6d` |
| *ECDSA-SigGen-FIPS186-5* | | P-224 to P-521; each signature verified against its own key |
| [`ECDSA-SigVer-FIPS186-5/prompt.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ECDSA-SigVer-FIPS186-5/prompt.json) | 150,759 bytes | `2547cabd9a6006943ff611d4990fad18162b51a614cd2d7986769a3e94dee7e3` |
| [`ECDSA-SigVer-FIPS186-5/expectedResults.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ECDSA-SigVer-FIPS186-5/expectedResults.json) | 16,027 bytes | `c4f2e21e9c6391a5349a81237b5c508466ce05f0d6eb6dbcecb17b458a6c5171` |
| *ECDSA-SigVer-FIPS186-5* | | Verdict-only; 16 groups of deliberate good and bad signatures |
| [`ML-KEM-encapDecap-FIPS203/prompt.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-KEM-encapDecap-FIPS203/prompt.json) | 624,189 bytes | `998e22dfb12efb14ce9fdff911ca634b13612819a1806f25da69adba7e16db91` |
| [`ML-KEM-encapDecap-FIPS203/expectedResults.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-KEM-encapDecap-FIPS203/expectedResults.json) | 190,940 bytes | `9089ec6ff2424da9f2782b89b2f831a329a3e28d6e5e24b802b78ff36ac61cdf` |
| *ML-KEM-encapDecap-FIPS203* | | Requires `--provider-command`; no built-in PQC provider |
| [`ML-DSA-sigVer-FIPS204/prompt.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json) | 3,125,947 bytes | `e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e` |
| [`ML-DSA-sigVer-FIPS204/expectedResults.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigVer-FIPS204/expectedResults.json) | 13,956 bytes | `e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6` |
| *ML-DSA-sigVer-FIPS204* | | Requires `--provider-command`; internal and external interfaces |
| [`CMAC-AES-1.0/prompt.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/CMAC-AES-1.0/prompt.json) | 4,533,505 bytes | `e2c412bbe9a63640ceb490e38fbad809259b4829b28995995994567547bd2cec` |
| [`CMAC-AES-1.0/expectedResults.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/CMAC-AES-1.0/expectedResults.json) | 61,378 bytes | `ec48d26649b963183f3ceefb4b4c74563eddb51ff3c44ef92029ca05d58b7bcf` |
| *CMAC-AES-1.0* | | 756 cases, generation and verification, per-group `macLen` |
| [`ACVP-AES-ECB-1.0/prompt.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ACVP-AES-ECB-1.0/prompt.json) | 369,982 bytes | `b4ec2a6e7011a9d7fb453aef52b32872cc7509dda07b13b28237d9b8f56076e9` |
| [`ACVP-AES-ECB-1.0/expectedResults.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ACVP-AES-ECB-1.0/expectedResults.json) | 343,166 bytes | `4893c2718529d4af5a10f10335118e5a462808a0857005440c52b1083d71da18` |
| *ACVP-AES-ECB-1.0* | | 2,144 cases including the 100 x 1000 Monte Carlo chain |
| [`ACVP-AES-GMAC-1.0/prompt.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ACVP-AES-GMAC-1.0/prompt.json) | 13,084 bytes | `6bdac25495398b2221191fb8e1cd0a8c54664b33b52984c49b6d539c5d6e2d66` |
| [`ACVP-AES-GMAC-1.0/expectedResults.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ACVP-AES-GMAC-1.0/expectedResults.json) | 4,976 bytes | `9eacc97af44ed0b58bc35217c689f49e24b9dcc3567126bd55038ebe164b1d43` |
| *ACVP-AES-GMAC-1.0* | | 60 cases including deliberate tag forgeries |
| [`ACVP-AES-KW-1.0/prompt.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ACVP-AES-KW-1.0/prompt.json) | 5,021,125 bytes | `3e0c5a5fb8da3b484e42d73528a6a6e87c9a4c5e6386bc5bb98bbfcaa27831f3` |
| [`ACVP-AES-KW-1.0/expectedResults.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ACVP-AES-KW-1.0/expectedResults.json) | 4,100,580 bytes | `ff722dcbc986252c4de5d7df10da5d74e677765524bcdcb666dfc7f4f6c08f34` |
| *ACVP-AES-KW-1.0* | | 3,600 executed; 3,600 `kwCipher: inverse` reported UNSUPPORTED |
| [`ACVP-AES-KWP-1.0/prompt.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ACVP-AES-KWP-1.0/prompt.json) | 4,869,914 bytes | `c39175c5f2eab4168c1e8d5bd6d1658ce83590499dabbf0f6f33d6533d3f7bc1` |
| [`ACVP-AES-KWP-1.0/expectedResults.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ACVP-AES-KWP-1.0/expectedResults.json) | 4,001,079 bytes | `114774bb317bc6fdb2491fa41e1c5d3b2b27f23ccb4d2b004d8610abc5689751` |
| *ACVP-AES-KWP-1.0* | | 3,600 executed; same `inverse` split |

| [`ctrDRBG-1.0/prompt.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ctrDRBG-1.0/prompt.json) | 244,292 bytes | `35a2fda242abd3e8e9c6c89a2878ee1d4d499c48c7458d67025bc8b5ff361420` |
| [`ctrDRBG-1.0/expectedResults.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ctrDRBG-1.0/expectedResults.json) | 264,148 bytes | `46608d7bbcaf0f6408a1905f81a77d3e2e90bfd5cee5a84dd78d4c51de1c6143` |
| *ctrDRBG-1.0* | | 240 cases: 180 AES executed, 60 TDES declared UNSUPPORTED |
| [`ctrDRBG-SP800-90Ar1/prompt.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ctrDRBG-SP800-90Ar1/prompt.json) | 371,608 bytes | `7ddb75bdd25bcb6183102146872c0f97a5227603b2ea64c63771ffe2daf938ae` |
| [`ctrDRBG-SP800-90Ar1/expectedResults.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ctrDRBG-SP800-90Ar1/expectedResults.json) | 42,956 bytes | `c805df470563ec6e91413cde1a29b2574b7c33b67fd3a7bf3179b7ac26c77a6e` |
| *ctrDRBG-SP800-90Ar1* | | 360 cases: 270 AES executed, 90 TDES declared; adds `counterFieldLen` |

### CTR_DRBG (v0.5.0)

Both revisions are pinned. They differ in one field that matters: `SP800-90Ar1`
adds `counterFieldLen`, which narrows the counter inside V so that only its
rightmost bits increment. Where it is 128 the two revisions agree; the upstream
set also exercises 64 and 4, and an implementation that ignores the field passes
the first and fails the rest.

| [`KDF-1.0/prompt.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/KDF-1.0/prompt.json) | 3,429,414 bytes | `a97ac943f775fc249e258bc27a189075eb11e8c4029ae8eb39fd555671c610b8` |
| [`KDF-1.0/expectedResults.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/KDF-1.0/expectedResults.json) | 3,496,097 bytes | `bdba2cbbf68679db995c47e4bc8c53aa4c39c4a54e07c367450e4f91b83329e0` |

### KDF SP 800-108 (v0.6.0)

5,878 groups and 11,756 cases, and the only set here whose *expected results
file carries an input*. The prompt gives only `keyIn`, because a conforming
implementation chooses its own `fixedData`; NIST records the choice its
reference made next to the answer, so the runner reads `fixedData` back out of
`expectedResults.json` and derives against it.

That bounds what a pass means, and the bound is worth stating: it shows the
derivation is right for that fixed data. It does not exercise an
implementation's freedom to construct fixed data of its own, which the ACVP
server checks and no file-based runner can.

Two details in this set are easy to miss. `breakLocation` is a **bit** offset —
the upstream values run 1 to 127 against 128-bit fixed data — so the counter
splices mid-byte. And `keyOutLength` is frequently not a multiple of 8 (331,
1003, 67), so the final byte's padding bits must be cleared.

Every size and SHA-256 is recorded in `scripts/fetch_vectors.py` and checked
before a file is used. Run `python3 scripts/fetch_vectors.py` to retrieve them;
`vectors/` is deliberately not committed, because NIST's vectors are theirs to
distribute, not this project's.

The AES key wrap sets are the ones worth reading the pin table for. Half of each
set is `kwCipher: inverse`, which this runner does not implement, and reporting
those 3,600 cases as UNSUPPORTED rather than quietly dropping them is the
difference between an honest total and a flattering one.

## Suitability and limits

The selected `prompt.json` identifies `ACVP-AES-GCM`, revision `1.0`. It contains four AFT groups and 60 cases covering encrypt and decrypt, 128-bit keys, externally supplied IVs, 96-bit and 120-bit IVs, zero/nonzero payload and AAD combinations, and 32-bit and 128-bit tags.

The set is useful for schema and execution compatibility, but it is not the complete AES-GCM capability space. In particular, it does not cover every permitted key, IV, payload, AAD, tag, test-type, or IV-generation combination.

The repository README describes `gen-val/json-files` as sample JSON files. The selected files themselves declare `"isSample": false`, so this project will call them the "pinned NIST example set" and preserve the field exactly. It will not rewrite the field to fit local terminology.

## License and redistribution decision

The pinned repository README contains a NIST software notice that permits use, copying, modification, and distribution, requires the notice to remain intact, asks modified works to record their changes, and requests explicit NIST attribution. It also states that software developed by NIST employees is not subject to United States copyright protection. The notice is embedded in [`README.md`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/README.md#license); the repository has no standalone license file or SPDX license identifier at this commit.

The notice discusses NIST-developed software but does not separately classify the generated JSON artifacts. Therefore this repository will not redistribute the three upstream JSON files in v0.1.0. Compatibility tests that need the full NIST set must fetch the exact pinned files and verify the SHA-256 values above. The tiny committed fixtures planned for A03 will be independently generated, clearly labeled local test data rather than copied subsets of the NIST files.

If upstream vector files or extracts are ever committed later, that requires a new decision: preserve the entire upstream notice, add NIST attribution, record the date and nature of modifications, and confirm that the notice applies to the artifacts being redistributed.

## Change control

The commit and hashes above are part of the v0.1.0 test contract. A newer upstream commit is not adopted automatically. Changing the source requires reviewing schema changes, licensing, vector coverage, and expected results, then updating this file in a dedicated commit.
