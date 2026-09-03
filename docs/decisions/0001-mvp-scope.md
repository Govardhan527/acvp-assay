# Decision 0001: Freeze the v0.1.0 MVP

- Status: **Superseded** by the work recorded in `../backlog.md` (M01-M12), as of v0.11.0
- Date: 2026-09-02

> This record is kept as written. The scope it froze was deliberately narrow and
> has since been widened on every axis it named: 40 algorithm names rather than
> AES-GCM alone, an external-harness provider beside the built-in one, and live
> ACVTS sessions rather than offline files only. What survives is the *shape* of
> the decision — a replaceable provider boundary, and unsupported variants
> reported explicitly rather than approximated — which every family since has
> followed. See `../architecture.md` for what the system is now.

## Context

The useful first artifact is a narrow, reproducible vertical slice. Adding providers, algorithms, networking, dashboards, or benchmarks before one complete AES-GCM path would delay evidence and multiply ambiguous failure modes.

## Decision

Use Python 3.12, pytest, and the `cryptography` AES-GCM API. The first provider records both the `cryptography` version and its OpenSSL backend version. Inputs are offline vectors, and v0.1.0 ends when a supported AES-GCM case can be parsed, executed, compared, reported, and reproduced in clean Linux CI.

## Consequences

The provider boundary must remain replaceable, but only one implementation will exist in v0.1.0. Unsupported algorithms and group variants will be reported explicitly rather than approximated. Live ACVP sessions and all stretch work remain outside the release.
