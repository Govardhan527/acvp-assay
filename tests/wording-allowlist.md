# Reviewed uses of the guarded words

`tests/unit/test_wording_guard.py` fails the build on `validated`, `CAVP`,
`certified` or `FIPS approved` anywhere in this project's prose or in a report
it generates. Four words, because each is a claim this project must never make:
only an accredited CST or 17ACVT laboratory performs CAVP algorithm validation
or FIPS 140-3 module validation, and this tool produces test evidence.

Some uses are legitimate — a disclaimer has to name the thing it is disclaiming,
and a script called `cavp_frequency.py` has to be called something. Each is
listed here with the reason it was allowed, and the guard accepts **only these
exact lines**. Reword one and the build fails until someone looks at it again,
which is the point: the risk is drift, and drift arrives as a small edit.

Each entry is `<path> :: <the exact line, stripped>`, and a line whose path is
not a file in this repository is ignored, so prose like this one is not an entry.

## Disclaimers, which must name what they disclaim

README.md :: > accredited CST or 17ACVT laboratory performs CAVP or FIPS 140-3 validation, and Demo is not
README.md :: An *assay* measures composition, it does not certify it. This tool produces reproducible test evidence: it parses ACVP vector sets, executes them through a replaceable provider boundary, compares results case by case, and diffs one run against the next. It does **not** perform or substitute for CAVP algorithm validation or FIPS 140-3 cryptographic-module validation — only accredited CST and 17ACVT laboratories can do that.
SERVICES.md :: status. Only an accredited CST or 17ACVT laboratory performs CAVP or FIPS 140-3
CONTRIBUTING.md :: laboratory performs CAVP or FIPS 140-3 validation, and what this project
docs/limitations.md :: CAVP algorithm validation or FIPS 140-3 module validation — only accredited CST and 17ACVT
docs/limitations.md :: Do not cite a report from this tool as evidence that a module is FIPS 140-3 validated,
docs/limitations.md :: accredited CST or 17ACVT laboratory performs CAVP or FIPS 140-3 validation, and Demo is not
examples/liboqs/README.md :: It is a test harness, not a validated module, and running it produces test
CHANGELOG.md :: only an accredited CST or 17ACVT laboratory performs CAVP or FIPS 140-3

## Describing what CMVP and CAVP do, never what this project does

docs/algorithm-frequency.md :: algorithm lists read, each CAVP display name mapped onto the ACVP registry name
docs/algorithm-frequency.md :: those list approved algorithms; 549 of the 690 were first validated in 2025 or
docs/algorithm-frequency.md :: counting a population measures what has been validated and cannot see a mandate.
docs/backlog.md :: CAVP certificates rather than by guessing: these four names recur far more often
docs/backlog.md :: maps each CAVP display name onto its ACVP registry name and counts them

## The ordinary English sense of the word, about data rather than modules

docs/architecture.md :: - External vector data is untrusted input and is validated before execution.

## Release notes and the build log, describing CAVP rather than claiming it

CHANGELOG.md :: validated under, with 128 and 256-bit keys and both tweak conventions.
CHANGELOG.md :: agreement appears wherever TLS is validated and was the last item on this
CHANGELOG.md :: and a CMAC beside it, and reviewing published CAVP certificates showed those
BUILDLOG.md :: - Done condition: the AES names that recur on published CAVP certificates alongside GCM are runnable - `ACVP-AES-ECB`, `ACVP-AES-GMAC`, `ACVP-AES-KW`, `ACVP-AES-KWP` and `CMAC-AES`.

## Describing the guard, which has to quote the words it bans

CHANGELOG.md :: - **A wording guard that fails the build** on `validated`, `CAVP`, `certified`
CHANGELOG.md :: or `FIPS approved` in a generated report, or in published prose outside the
