"""Produce ACVP *responses*, for submission to a live ACVTS server.

Everything else in this package verifies: it reads a prompt beside the expected
results NIST published and reports whether they agree. That is the right shape
for regression work, and it is not the shape ACVTS asks for. A live test session
hands over a prompt and nothing else; the client computes answers, submits them,
and the server returns the verdict.

So this module answers rather than checks. It reuses the same providers, which
is the point -- a response submitted from here exercises exactly the code path
the offline runner exercises, so agreement with NIST online is evidence about
the providers rather than about a second implementation written to pass.

Only families whose responses this can construct faithfully are implemented.
Asking for one that is not raises rather than emitting a partial document: a
submission missing cases is scored as wrong answers, not as an incomplete run.
"""

from __future__ import annotations

import json
from pathlib import Path

from acvp_assay.algorithms import sha2
from acvp_assay.providers.digest import (
    HASHLIB_ALGORITHMS,
    HashlibHashProvider,
    HashProvider,
)


class UnsupportedResponseError(RuntimeError):
    """This algorithm has no response builder yet."""


def _sha2_response(vector_set: sha2.Sha2VectorSet, provider: HashProvider) -> dict[str, object]:
    """Build a SHA-2 response: a digest per AFT case, a chain per MCT case."""
    groups: list[dict[str, object]] = []
    for group in vector_set.test_groups:
        cases: list[dict[str, object]] = []
        for case in group.tests:
            # Checked before the message: an LDT case carries a size descriptor
            # rather than a message, so "no message" would be a misleading way
            # to report a capability this runner deliberately declines.
            if group.test_type is sha2.Sha2TestType.LDT or case.is_large:
                raise UnsupportedResponseError(
                    f"tgId {group.tg_id} is a large data test, which this runner declines; "
                    "do not register LDT capabilities for a submission"
                )
            # Past the LDT guard the parser guarantees a message: it rejects a
            # case without one, so this only narrows the type.
            assert case.message is not None  # noqa: S101
            if group.test_type is sha2.Sha2TestType.MCT:
                version = group.mct_version or "standard"
                if version not in sha2.SUPPORTED_MCT_VERSIONS:
                    raise UnsupportedResponseError(f"mctVersion {version!r} is not supported")
                chain = provider.digest_mct(case.message, alternate=version == "alternate")
                cases.append(
                    {
                        "tcId": case.tc_id,
                        "resultsArray": [{"md": digest.hex().upper()} for digest in chain],
                    }
                )
            else:
                cases.append(
                    {"tcId": case.tc_id, "md": provider.digest(case.message).hex().upper()}
                )
        groups.append({"tgId": group.tg_id, "tests": cases})
    return {
        "vsId": vector_set.vs_id,
        "algorithm": vector_set.algorithm,
        "revision": vector_set.revision,
        "testGroups": groups,
    }


def build_response(prompt_file: Path) -> dict[str, object]:
    """Compute the ACVP response document for one downloaded prompt."""
    document = json.loads(Path(prompt_file).read_text(encoding="utf-8"))
    algorithm = document.get("algorithm")
    if algorithm in HASHLIB_ALGORITHMS:
        vector_set = sha2.parse_vector_set(document)
        return _sha2_response(vector_set, HashlibHashProvider(str(algorithm)))
    raise UnsupportedResponseError(
        f"no response builder for {algorithm!r}; "
        "the offline runner can still verify it against expected results"
    )


def supported_response_algorithms() -> tuple[str, ...]:
    """Algorithms for which a submission can be constructed."""
    return tuple(sorted(HASHLIB_ALGORITHMS))


__all__ = [
    "UnsupportedResponseError",
    "build_response",
    "supported_response_algorithms",
]
