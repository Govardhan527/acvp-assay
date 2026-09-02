# Architecture

## Data flow

```text
prompt.json (inputs)   expectedResults.json (outputs)
          |                       |
          v                       v
   parser + validator -> typed vector / expected-result models
          |                       |
          v                       |
provider interface ------> OpenSSL-backed adapter
          |                       |
          +---- actual values ----+
                   |
                   v (runner: matches by tgId/tcId, classifies IV-generation support)
          comparator -> reporter -> JSON output + exit code
```

The parser owns external JSON interpretation for both files and must preserve ACVP identifiers (`vsId`, `tgId`, `tcId`). The provider interface owns cryptographic operations and implementation metadata; neither the parser nor comparator may call OpenSSL directly. The runner (`runner.py`) is the orchestration layer: it matches each vector-set case to its expected result by `(tgId, tcId)`, decides whether a group is executable, invokes the provider, and turns provider exceptions into bounded `TestCaseResult`s. The comparator classifies expected and actual values, while the reporter owns serialization, summaries, and process exit semantics. The CLI (`cli.py`) wires these together and owns process exit codes; it contains no cryptographic or comparison logic itself.

## The `run` command

`acvp-assay run VECTOR_FILE [--output RESULT_FILE] [--strict]` loads `VECTOR_FILE` as the prompt document and requires a sibling `expectedResults.json` in the same directory (the layout every fixture under `fixtures/` already uses). This sibling-file convention is deliberate: only offline sample vector sets that ship both files together are supported, and it avoids a second required CLI argument for the common case.

Exit codes:

| Code | Meaning |
| ---: | --- |
| 0 | Every case is a hard PASS (SKIPPED/UNSUPPORTED cases do not count against success unless `--strict` is given). |
| 1 | At least one case is FAILED or ERRORED, or (`--strict` only) SKIPPED or UNSUPPORTED. |
| 2 | The run could not start: a missing file, malformed JSON, a schema violation, or an `expectedResults.json` that does not identify the same `vsId`/`algorithm`/`revision` as the vector file. |

A group is classified UNSUPPORTED, not executed, when its `ivGen` is not `external`: this runner only supplies IVs read from the vector file and does not implement IV generation or a two-phase ACVP submission. A case present in the vector file but absent from `expectedResults.json` is classified ERROR/`invalid case` rather than silently skipped.

## Boundaries

- External vector data is untrusted input and is validated before execution.
- Provider exceptions become safe, structured case errors; raw key material is never logged. `TestCaseResult.diagnostic` enforces this for ERROR results: it can only hold one of the closed `SafeDiagnostic` values, never raw exception text.
- Expected ciphertext and authentication tags are compared as separate fields.
- Machine-readable results are the source of truth for human-readable summaries.

The baseline includes UTF-8 JSON file loading and validation for both vector and expected-results documents, immutable typed models, a replaceable provider interface, OpenSSL-backed AES-GCM operations, bounded comparison, deterministic JSON case/summary reporting with provider versions, and the `run` CLI command described above with clean-checkout Linux CI coverage, including one intentionally corrupted fixture that proves failures surface rather than get swallowed (`fixtures/README.md`).
