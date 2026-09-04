# Design: high and low level

Diagrams are Mermaid, which GitHub renders inline. They are text, so they diff
and review like code and cannot drift out of date silently the way an exported
image does.

`architecture.md` states the boundaries and the rules. This file shows the
shapes.

---

# High-level design

## What the system is for

ACVP is NIST's protocol for validating cryptographic *algorithms*. A vendor's
module has to prove it computes AES, SHA-2, RSA and the rest exactly as the
standards define, and a laboratory eventually runs that testing for a
certificate. This project runs the same vectors earlier, against
implementations a laboratory's tooling often cannot reach, and reports what
would fail before the billable hours start.

```mermaid
flowchart LR
    subgraph sources["Where vectors come from"]
        pinned["Pinned NIST vector files<br/><i>fetched, hash-verified,<br/>never redistributed</i>"]
        acvts["NIST ACVTS Demo<br/><i>generates vectors per session</i>"]
    end

    assay["<b>acvp-assay</b>"]

    subgraph under["What is being tested"]
        builtin["Built-in provider<br/><i>OpenSSL via cryptography</i>"]
        vendor["Your implementation<br/><i>HSM, smartcard, embedded,<br/>any language</i>"]
    end

    report["JSON report<br/>+ exit code"]
    verdict["NIST's verdict<br/><i>passed / failed</i>"]

    pinned --> assay
    acvts --> assay
    assay <--> builtin
    assay <-->|"JSON over stdio"| vendor
    assay --> report
    assay -->|"submitted answers"| acvts
    acvts --> verdict
```

The two things that distinguish this from `libacvp` and ACVP Proxy are both
visible above: **nothing is linked against the implementation**, and the same
runner can answer a live session rather than only checking files.

## The two paths

Everything below the provider boundary is shared. Above it, there are two
different jobs, and they differ in what they are given and what they produce.

```mermaid
flowchart TB
    subgraph verify["Verifying — <code>acvp-assay run</code>"]
        direction TB
        v1["prompt.json<br/>+ expectedResults.json"] --> v2["compute answers"]
        v2 --> v3["compare, case by case"]
        v3 --> v4["PASS / FAIL / UNSUPPORTED / ERROR<br/>and an exit code"]
    end

    subgraph answer["Answering — <code>acvts_client.py submit</code>"]
        direction TB
        a1["prompt.json only<br/><i>no answers supplied</i>"] --> a2["compute answers"]
        a2 --> a3["build the response document"]
        a3 --> a4["submit, and NIST judges"]
    end
```

The asymmetry matters and shapes the code:

|  | Verifying | Answering |
| --- | --- | --- |
| Has the expected results | yes | no |
| A case it cannot answer | reported UNSUPPORTED, run continues | **refuses the whole document** |
| Who decides correctness | this runner | NIST's server |

A missing case in a submission is scored as a *wrong answer*, not as an
incomplete run. That single fact is why `responder.py` refuses rather than
half-answers, and it is the sharpest difference between the two paths.

## Layers

```mermaid
flowchart TB
    cli["<b>cli.py</b> — run · diff · info<br/><i>owns exit codes, no crypto</i>"]

    subgraph dispatch["algorithms/__init__.py"]
        d["read the algorithm from the file,<br/>route to the family that implements it"]
    end

    subgraph families["Families — one module each"]
        f1["sha2 · hmac_mac · aes_block<br/>aes_modes · aes_xts · ctr_drbg<br/>kdf · ecdsa · rsa · kas_ecc · pqc"]
    end

    subgraph boundary["Provider boundary — providers/"]
        p1["Built-in<br/><i>cryptography / OpenSSL</i>"]
        p2["HarnessClient<br/><i>subprocess over JSON</i>"]
    end

    subgraph shared["Shared, below the boundary"]
        s1["models · comparator<br/>reporter · diff"]
    end

    responder["<b>responder.py</b><br/><i>answers instead of checking</i>"]
    client["<b>scripts/acvts_client.py</b><br/><i>register · fetch · submit · results</i>"]

    cli --> dispatch --> families --> boundary
    families --> shared
    client --> responder --> boundary
    p2 -.->|"one JSON line each way"| ext["Your implementation"]
```

Each family owns its own models, parser and runner because the group shapes
have little in common — AES-GCM has directions and authentication failures,
SHA-2 has chained Monte Carlo groups, the DRBGs have a state machine per case.
What they share is everything *downstream* of execution: the result vocabulary,
the comparator, the reporter and the exit-code rules.

Adding a family means writing one module and adding one line to the dispatcher.

---

# Low-level design

## Verifying one vector file

```mermaid
sequenceDiagram
    autonumber
    participant U as You
    participant CLI as cli.py
    participant D as dispatch
    participant F as family module
    participant P as provider
    participant H as your harness
    participant R as reporter

    U->>CLI: acvp-assay run prompt.json --provider-command "./harness"
    CLI->>D: peek_algorithm(prompt.json)
    Note over D: reads only "algorithm" and "revision"
    D->>F: parse prompt + expected results
    F-->>D: typed models, vsId/tgId/tcId preserved
    D->>P: build provider (harness named, so subprocess)
    P->>H: {"operation": "metadata"}
    H-->>P: name, library, backend
    Note over P,H: probed once, before any case runs,<br/>so a misconfigured harness fails with<br/>one clear message rather than N errors

    loop each case
        F->>P: compute this case
        P->>H: one JSON request line
        alt implementation answers
            H-->>P: {"ct": "...", "tag": "..."}
            P-->>F: bytes
            F->>F: compare with expected
        else does not offer this parameter set
            H-->>P: {"error": "unsupported"}
            P-->>F: HarnessUnsupportedError
            Note over F: UNSUPPORTED — a coverage gap,<br/>not a failure
        else rejects an authentication tag
            H-->>P: {"error": "authentication failed"}
            P-->>F: InvalidTag
            Note over F: for a deliberate forgery this is<br/>the correct answer, so PASS
        end
    end

    F->>R: results + provider metadata
    R-->>U: JSON report and exit code
```

## How a case is classified

Getting this wrong in either direction is the worst output the tool can
produce: telling a vendor their module is broken when it merely lacks a curve,
or reporting a real defect as a coverage gap.

```mermaid
flowchart TB
    start(["a case"]) --> executable{"can this group<br/>be executed<br/>faithfully?"}
    executable -->|no| unsup["<b>UNSUPPORTED</b><br/><i>declared, with the reason</i>"]
    executable -->|yes| run["ask the provider"]

    run --> failed{"provider raised?"}
    failed -->|"unsupported"| unsup
    failed -->|"other error"| err["<b>ERROR</b><br/><i>closed diagnostic vocabulary,<br/>never raw exception text</i>"]
    failed -->|no| kind{"what does<br/>ACVP expect?"}

    kind -->|"bytes"| cmp{"match?"}
    kind -->|"a verdict"| vcmp{"verdict matches<br/>testPassed?"}

    cmp -->|yes| pass["<b>PASS</b>"]
    cmp -->|no| fail["<b>FAIL</b><br/><i>names the field</i>"]
    vcmp -->|yes| pass
    vcmp -->|no| fail
```

`--strict` makes UNSUPPORTED and SKIPPED count against the exit code, so a
coverage gap cannot pass quietly in CI.

## Answering a live session

This is the flow a vendor runs against their own implementation.

```mermaid
sequenceDiagram
    autonumber
    participant V as Vendor
    participant C as acvts_client.py
    participant N as NIST ACVTS
    participant R as responder.py
    participant H as vendor harness

    V->>C: register capabilities.json
    C->>N: POST /testSessions
    N-->>C: session id + vector set URLs<br/>+ scoped access token
    Note over C: the token is scoped to this session, and<br/>losing it orphans the session permanently

    V->>C: fetch
    C->>N: GET each vector set
    N-->>C: prompt.json (+ expected results, sample sessions)

    V->>C: submit --provider-command "./harness"
    loop each vector set
        C->>R: build_response(prompt, harness)
        loop each case
            R->>H: one JSON request
            H-->>R: the implementation's answer
        end
        alt every case answered
            R-->>C: response document
            C->>N: POST .../results
        else any case declined
            R-->>C: ResponseError
            Note over C,R: nothing is sent — a partial document<br/>is scored as wrong answers
        end
    end

    V->>C: results
    C->>N: GET /results
    N-->>C: a disposition per vector set
    Note over C: written to results.json — the verdict is<br/>the one thing this project cannot reproduce
```

## The harness contract

The entire protocol: one JSON request per line in, one JSON response per line
out, until stdin closes.

```mermaid
sequenceDiagram
    participant R as acvp-assay
    participant H as harness process

    R->>H: spawn once
    Note over R,H: every message below is one line,<br/>newline-terminated, flushed immediately
    R->>H: operation = metadata
    H-->>R: name, libraryVersion, backendName
    Note over R,H: the process is kept alive for the whole run,<br/>so a PKCS#11 login or serial handshake<br/>happens once rather than once per case
    R->>H: operation = digest, algorithm = SHA2-256, message = 616263
    H-->>R: md = BA7816BF...
    R->>H: close stdin
    H-->>R: exit 0
```

On the wire that is:

```text
→ {"operation": "digest", "algorithm": "SHA2-256", "message": "616263"}
← {"md": "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"}
```

Three rules a harness must follow, each learned from a way this goes wrong:

- **Flush after every line.** A buffered harness is indistinguishable from a
  hung one.
- **`{"error": "unsupported"}` for a parameter set you do not offer.** It is
  reported UNSUPPORTED, not as a failure. Capability belongs to the
  implementation.
- **`{"error": "authentication failed"}` for a rejected tag** — never a crash
  or a non-zero exit. Roughly a third of NIST's AES-GCM decrypt cases are
  deliberate forgeries where rejecting is correct, and a harness that dies on
  them scores a conforming module as broken.

A harness that reads stdin to end and exits also works; the transport detects
that on the first exchange, because a shell script with `jq` naturally takes
that shape.

## Catching regressions between runs

```mermaid
flowchart LR
    b["baseline.json<br/><i>before the change</i>"] --> diff["acvp-assay diff"]
    c["current.json<br/><i>after it</i>"] --> diff
    diff --> r1["regressed<br/><i>PASS → FAIL</i>"]
    diff --> r2["coverage lost<br/><i>PASS → UNSUPPORTED,<br/>SKIPPED or absent</i>"]
    diff --> r3["fixed · still failing · added"]
    diff --> prov["provider identity changed<br/><i>usually the cause</i>"]
```

**Coverage loss counts as a regression.** A case that used to run and now does
not is reported as loudly as an outright failure, because that is the failure
mode that hides: the totals still look clean once the case stops being counted.

## Adding a family

```mermaid
flowchart LR
    subgraph new["Write"]
        a["algorithms/FAMILY.py<br/><i>models · parser · runner</i>"]
        p["providers/FAMILY.py<br/><i>Protocol · built-in · Subprocess</i>"]
    end
    subgraph wire["Wire in — one line each"]
        d["algorithms/__init__.py<br/><i>dispatch + supported_algorithms</i>"]
        rp["responder.py<br/><i>builder + _builder_for</i>"]
        h["examples/reference_harness.py<br/><i>the new operation</i>"]
    end
    new --> wire --> t["tests + docs"]
```

The order that has worked every time here: **register a sample session on
ACVTS, fetch real vectors, and confirm the algorithm against NIST's own
expected results before writing any module code.** Three of the four defects
this project has found came from doing that; the specification's prose has more
than once been insufficient on its own.
