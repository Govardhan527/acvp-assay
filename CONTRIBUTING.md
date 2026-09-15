# Contributing

Pull requests are welcome, and a harness for an implementation this project has
never seen is the most useful kind there is. What follows is what a change is
reviewed against, written down so that nobody hears it for the first time in
review.

## The harness protocol is a public contract

`docs/harness-protocol.md` is what every existing harness was written against.
Widening it for one implementation is a cost paid by everyone who integrated
before: a new required field breaks their harness, and a changed meaning breaks
it silently. A protocol change needs a reason that holds for more than one
implementation, and an existing harness must keep working, with what it did not
send recorded as absent rather than failing the run. `buildId` was added that
way: a harness that does not send it still runs, and its absence is recorded as
`not_reported`.

## A claim carries its method

Every claim in documentation says how it was established in the same sentence:
the session, the vector set, the command. Not in a footnote, and not only in a
commit message, because a sentence gets quoted without its footnote.

Nothing here validates or certifies anything. Only an accredited CST or 17ACVT
laboratory performs CAVP or FIPS 140-3 validation, and what this project
produces is test evidence. Write it that way.

## Numbers are computed, and guarded

A number in documentation is computed from something checkable, never
estimated, and a test holds it to its source. `tests/unit/test_readme_arithmetic.py`
exists because six README numbers were each correct when written and went stale
as the results table grew, and no build noticed. Where a sentence can avoid
naming a number that will move, prefer that: a claim that cannot go stale is
better than one checked for staleness.

## Watch the test fail

A regression test nobody has watched fail has not been tested. Write it before
the fix, or put the defect back, and see it fail for the reason it names; then
make it pass. A variable shadowed in `aes_modes.py` once made the case after a
harness decline raise `UnboundLocalError`, and 396 tests passed with it in
place. The test that now guards it was run against the defect first, and failed
with exactly that error.

## Declines carry a reason

A new UNSUPPORTED result must carry a `DeclineReason`, and `TestCaseResult`
refuses one without it. Choose by who would repair the gap:

| Reason | Repaired by |
| --- | --- |
| `implementation_lacks` | the vendor |
| `runner_lacks` | this project |
| `offline_undecidable` | a submission to ACVTS, or nothing |
| `vector_incomplete` | a different registration, or NIST |

A harness may claim only `implementation_lacks` and `vector_incomplete`. The
other two are properties of this runner and of its method, which a harness is
never in a position to assert, so claiming either is a protocol error.

## Before opening a pull request

- `python3.12 scripts/dev.py test` is green: formatting, lint, strict mypy and
  the full suite.
- Each commit is one logical change, with a message that names what it fixes and
  why.
