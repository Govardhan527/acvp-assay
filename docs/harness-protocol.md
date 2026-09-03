# The harness protocol

This is the contract between `acvp-assay` and *your* implementation. Write a
program that speaks it and the runner can test your module without linking
against it, without knowing what language it is in, and without it being on the
same machine.

## Why a subprocess at all

The established ACVP tools — [`libacvp`](https://github.com/cisco/libacvp) and
[`acvpparser`](https://github.com/smuellerDD/acvpparser) — reach an
implementation by **linking against it**. Their backends are C files compiled
into the tool: OpenSSL, the Linux kernel crypto API, Intel IPP, and so on. That
is efficient and it covers a great deal, and if your module is a C library that
you can link, those tools are excellent and you should consider them first.

It also draws a hard line. An HSM behind PKCS#11, a smartcard, a switch you
reach over SSH, an FPGA on a test rig, a Java or Go or Rust implementation, a
service behind an HTTP API — none of these can be linked into a C program, so
none can be tested that way without writing a C shim that fakes it.

A subprocess speaking a text protocol has no such line. If your implementation
can be driven by *anything* — a library call, a serial write, an SSH command, a
REST request — it can be driven by a small program, and that program can speak
this protocol. That is the whole design, and it is the one thing this runner
does that the alternatives do not.

BoringSSL's `acvptool` reaches the same conclusion and uses a subprocess
protocol for the same reason. It chose a length-prefixed binary framing for
speed; this project chose JSON for reach, because a JSON line can be produced by
a shell script with `jq`, and a length-prefixed binary frame cannot.

## The contract

One JSON object per line in on stdin. One JSON object per line out on stdout.
One response per request, in order.

```
→ {"operation": "digest", "algorithm": "SHA2-256", "message": "616263"}
← {"md": "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"}
```

All byte strings are uppercase hex, unpadded, without separators. Lengths are
in **bits** where the field name says so (`tagLen`, `macLen`), and in bytes
otherwise. Blank lines are ignored.

### Two shapes, both supported

**Looping (recommended).** Read lines until stdin closes, answering each:

```python
import json, sys

for line in sys.stdin:
    if line.strip():
        print(json.dumps(handle(json.loads(line))), flush=True)
```

**One-shot.** Read stdin to end, answer once, exit. The runner detects this and
starts a fresh process per request:

```bash
#!/bin/sh
jq -c '{md: (.message | mydigest)}'
```

Looping is strongly preferred and the runner will use it automatically. The
difference is not small:

| | 239 SHA3-256 cases | 975 HMAC cases |
| --- | ---: | ---: |
| one process per case | 17.9 s | ~73 s |
| one persistent process | 0.5 s | 2.8 s |

That is about 75 ms of process setup per case, roughly fifty times the
cryptography. It matters more than the numbers suggest, because the
implementations this protocol exists to reach are exactly the ones with
expensive setup: a PKCS#11 harness that logs in per case will spend the entire
run logging in.

> **`flush` is not optional.** A harness that buffers its stdout is
> indistinguishable, from the outside, from one that has hung.

### How the runner tells them apart

It sends the first request and waits a few seconds. A looping harness answers
straight away. A one-shot harness cannot answer until its input closes, so it
stays silent — and rather than deadlock, the runner then closes stdin and reads
the reply.

Silence is the only available signal, so a *slow* looping harness may be taken
for a one-shot one. That costs speed and nothing else: the answer is still
read, and later requests simply start a fresh process each time.

## Operations

Every harness must implement `metadata`. Implement only the others you need —
declining is a first-class answer, see below.

| `operation` | Request fields | Response fields |
| --- | --- | --- |
| `metadata` | — | `name`, `libraryName`, `libraryVersion`, `backendName`, `backendVersion` |
| `encrypt` | `key`, `iv`, `pt`, `aad`, `tagLen` | `ct`, `tag` |
| `decrypt` | `key`, `iv`, `ct`, `aad`, `tag` | `pt` |
| `digest` | `algorithm`, `message` | `md` |
| `digest-mct` | `algorithm`, `seed`, `alternate` | `md` — an **array** of 100 digests |
| `mac` | `algorithm`, `key`, `message`, `macLen` | `mac` |
| `ecdsa-sign` | `curve`, `hashAlg`, `message` | `qx`, `qy`, `r`, `s` |
| `ecdsa-verify` | `curve`, `hashAlg`, `message`, `qx`, `qy`, `r`, `s` | `testPassed` |
| `ml-kem-encapsulate` | `parameterSet`, `ek` | `c`, `k` |
| `ml-kem-decapsulate` | `parameterSet`, `dk`, `c` | `k` |
| `ml-kem-key-check` | `parameterSet`, `ek`, `dk` | `testPassed` |
| `ml-dsa-verify` | `parameterSet`, `pk`, `message`, `signature`, `signatureInterface`, `context` | `testPassed` |

### Monte Carlo is delegated whole

`digest-mct` runs the entire 100 × 1000 chain inside your harness and returns
all 100 outer digests. A round trip per inner hash would be 100,000 exchanges
per case.

**The chain differs by family, and getting it wrong fails silently.** SHA-1 and
SHA-2 hash three digests concatenated; SHA-3 hashes a single one:

```
SHA-1, SHA-2:   MD[i] = H(A || B || C);  A, B, C = B, C, MD[i]
SHA-3:          MD[i] = H(MD[i-1])
```

They share the `MCT` test type name and nothing else. A harness that runs the
SHA-2 chain for SHA-3 produces a plausible-looking result that disagrees with
NIST on every case. `examples/reference_harness.py` had exactly this bug.

`alternate` normalises every message to the length of the original seed; it
exists for implementations whose supported message lengths exclude the digest
size.

## Declining, and failing

Two response values are reserved.

**`{"error": "unsupported"}`** — you do not implement this case: a curve, a
parameter set, a mode. It is reported UNSUPPORTED, not as a failure. Capability
is yours to declare, not the runner's to assume; an HSM's binary curves are not
"unsupported" merely because Python's `cryptography` lacks them.

**`{"error": "authentication failed"}`** — an AEAD tag or a wrapping was
rejected. This is **not** a crash and **not** a non-zero exit. Roughly a third
of NIST's AES-GCM decrypt cases are deliberate authentication failures where
rejecting is the *correct* answer. A harness that dies on them scores a
conforming implementation as broken.

Any other `error` value is reported as a provider error. Exiting non-zero, or
printing something that is not JSON, is a protocol failure and stops the run.

Your stderr passes through to the operator's terminal for debugging and never
enters the JSON report — a crashing harness may print key material.

## Reaching your implementation

The harness is a small program in whatever language suits. Some shapes:

**A C or Rust library you can call.** Easiest case. A Python harness with
`ctypes`/`cffi`, or a small native program, or bindings you already have.

**An HSM or smartcard over PKCS#11.** Open the session and log in **once**, at
start-up, outside the request loop. This is the case where a looping harness is
not an optimisation but a requirement.

**An embedded device over serial.** Open the port once; frame each request onto
whatever the device's test firmware expects. `--provider-timeout` bounds each
exchange so a wedged device fails the case rather than the run.

**A network service, appliance or switch.** Hold one SSH or HTTPS session open
and translate each request. This is how you would drive a SONiC-based switch or
a KMS.

**Java, Go, .NET, JavaScript.** Write the harness in that language directly.
The protocol has no bindings to depend on — reading a line and writing a line is
in every standard library.

Start from `examples/reference_harness.py`. It is a complete worked
implementation that imports nothing from this package, so it can be copied out
and rewritten in another language without carrying anything with it.

## Not yet reachable through the harness

These families run against the built-in provider only, and
`--provider-command` is **refused** rather than silently ignored:

`ACVP-AES-ECB` · `ACVP-AES-CBC` · `ACVP-AES-CTR` · `ACVP-AES-OFB` ·
`ACVP-AES-CFB128` · `ACVP-AES-GMAC` · `ACVP-AES-KW` · `ACVP-AES-KWP` ·
`CMAC-AES` · `ctrDRBG` · `hashDRBG` · `hmacDRBG` · `KDF` · `RSA`

If you run one of these, you are testing this project's OpenSSL binding — not
your module. That is stated plainly because the alternative is a customer
believing their RSA implementation has been exercised when it has not.

The operations to close this are designed and tracked in `docs/backlog.md`. The
shape follows what already works here and what BoringSSL's tool settled on:
block modes delegate their Monte Carlo chain whole and return the last two
outputs the key shuffle needs; each DRBG case flattens to a single call carrying
its whole `otherInput` sequence rather than a stateful conversation; RSA signs a
whole group under one key, because ACVP reports the public key once per group.
