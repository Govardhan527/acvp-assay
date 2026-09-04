# Architecture

> Diagrams for all of this — system context, layers, and end-to-end sequences — are in
> [`design.md`](design.md). This file states the boundaries and the rules; that one shows
> the shapes.


There are two paths through this code, and they share everything below the
provider boundary.

## Verifying: prompt + expected results in, report out

```text
prompt.json (inputs)   expectedResults.json (outputs)
          |                       |
          v                       v
  algorithms/__init__.py: read the algorithm, route to its family
          |
          v
   family parser -> typed vector / expected-result models
          |                       |
          v                       |
provider boundary --> built-in adapter  OR  --provider-command harness
          |                       |
          +---- actual values ----+
                   |
                   v (family runner: matches by tgId/tcId, classifies capability)
          comparator -> reporter -> JSON output + exit code
```

`algorithms/__init__.py` is the dispatcher: it reads the algorithm name from the
vector file and routes to the family that implements it. Each family owns its own
models, parser and runner, because the group shapes differ too much to share
usefully — AES-GCM has directions and authentication failures, SHA-2 has chained
Monte Carlo groups, the DRBGs have a state machine per case. What *is* shared is
everything downstream of execution: `TestCaseResult`, the comparator vocabulary,
the reporter, and the exit-code rules. Adding a family means writing its module
and adding one entry to the dispatcher.

The parser owns external JSON interpretation and must preserve ACVP identifiers
(`vsId`, `tgId`, `tcId`). The provider boundary owns cryptographic operations and
implementation metadata; neither the parser nor comparator may call OpenSSL
directly. `runner.py` is AES-GCM's orchestration layer, and each other family has
its equivalent: match each case to its expected result by `(tgId, tcId)`, decide
whether a group is executable, invoke the provider, and turn provider exceptions
into bounded `TestCaseResult`s. The comparator classifies expected and actual
values, the reporter owns serialization and summaries, and the CLI (`cli.py`)
wires these together and owns process exit codes without containing any
cryptographic or comparison logic itself.

## Answering: prompt in, submission out

`responder.py` serves a live ACVTS session, where the shape is different: the
server sends a prompt and nothing else, and expects computed answers back.

```text
prompt.json (from ACVTS)
          |
          v
 responder.py: _builder_for(algorithm) -> the family's response builder
          |
          v
provider boundary --> built-in adapter  OR  Harness(--provider-command)
          |
          v
   response document -> scripts/acvts_client.py submit -> NIST's verdict
```

It reuses the same providers, which is the point: a response submitted from here
exercises the code path the offline runner exercises, so agreement with NIST is
evidence about the providers rather than about a second implementation written to
pass. Two rules apply here that do not apply to verification:

- **Refuse rather than half-answer.** ACVP scores a missing case as a wrong
  answer, not as an incomplete run, so a family or capability that cannot be
  answered faithfully raises instead of emitting a partial document. That
  includes a case a harness declines, which offline would be UNSUPPORTED.
- **Verification cases answer with a verdict.** Where ACVP supplies a signature,
  tag or wrapping that may be deliberately invalid, the answer is `testPassed` —
  the verdict reached, not any bytes produced.

A `Harness` owns the subprocesses it opens and closes them once the document is
built, including when the document is refused, so one vector set's harness
processes never outlive it.

## The `run` command

`acvp-assay run VECTOR_FILE [--output RESULT_FILE] [--strict]` loads `VECTOR_FILE` as the prompt document and requires a sibling `expectedResults.json` in the same directory (the layout every fixture under `fixtures/` already uses). This sibling-file convention is deliberate: `run` verifies, so it needs the answers to verify against, and requiring the sibling avoids a second CLI argument for the common case. A prompt with no expected results — what a live session hands over — is answered by `responder.py` through `scripts/acvts_client.py` instead, described above.

Exit codes:

| Code | Meaning |
| ---: | --- |
| 0 | Every case is a hard PASS (SKIPPED/UNSUPPORTED cases do not count against success unless `--strict` is given). |
| 1 | At least one case is FAILED or ERRORED, or (`--strict` only) SKIPPED or UNSUPPORTED. |
| 2 | The run could not start: a missing file, malformed JSON, a schema violation, or an `expectedResults.json` that does not identify the same `vsId`/`algorithm`/`revision` as the vector file. |

A group is classified UNSUPPORTED rather than executed when the runner cannot answer it faithfully — AES-GCM `ivGen` other than `external`, AES-KW/KWP `kwCipher: inverse`, SHA large data tests, RSA SHAKE mask functions, ctrDRBG `TDES`, KDF `CMAC-TDES`, ECDSA component tests. `docs/limitations.md` keeps the current list. With `--provider-command`, the capability decisions among these are deferred to the implementation, which declines per case with `{"error": "unsupported"}`. A case present in the vector file but absent from `expectedResults.json` is classified ERROR/`invalid case` rather than silently skipped.

## Boundaries

- External vector data is untrusted input and is validated before execution.
- Provider exceptions become safe, structured case errors; raw key material is never logged. `TestCaseResult.diagnostic` enforces this for ERROR results: it can only hold one of the closed `SafeDiagnostic` values, never raw exception text.
- Expected ciphertext and authentication tags are compared as separate fields.
- Machine-readable results are the source of truth for human-readable summaries.
- Capability belongs to the implementation. Every family is reachable through
  `--provider-command`, and a harness declines what it lacks with
  `{"error": "unsupported"}`, which is reported UNSUPPORTED rather than as a
  failure. The built-in providers declare their own capability the same way,
  through `supports()`, so no runner hard-codes what an implementation offers.

Throughout: UTF-8 JSON loading and validation for every document read, immutable typed models, a replaceable provider boundary, bounded comparison, deterministic JSON reporting that records provider and backend versions, and clean-checkout Linux CI — including one intentionally corrupted fixture that proves failures surface rather than get swallowed (`fixtures/README.md`).
