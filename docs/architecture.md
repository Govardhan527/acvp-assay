# Architecture

## Data flow

```text
offline JSON vector file
          |
          v
parser + validator -> typed vector models
          |                    |
          v                    v
provider interface ------> OpenSSL-backed adapter
          |                    |
          +-------- result <---+
                   |
                   v
          comparator -> reporter -> JSON output + exit code
```

The parser owns external JSON interpretation and must preserve ACVP identifiers. The provider interface owns cryptographic operations and implementation metadata; neither the parser nor comparator may call OpenSSL directly. The comparator classifies expected and actual values, while the reporter owns serialization, summaries, and process exit semantics.

## Boundaries

- External vector data is untrusted input and is validated before execution.
- Provider exceptions become safe, structured case errors; raw key material is never logged.
- Expected ciphertext and authentication tags are compared as separate fields.
- Machine-readable results are the source of truth for human-readable summaries.

The current baseline includes UTF-8 JSON file loading, path-specific validation, normalization into immutable typed models, a replaceable provider interface, OpenSSL-backed AES-GCM encrypt/decrypt operations, runtime/provider metadata, and bounded per-case comparison. Summary reporting and CLI execution remain isolated behind their numbered backlog tasks.
