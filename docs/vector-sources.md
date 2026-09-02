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
