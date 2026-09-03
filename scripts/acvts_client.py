#!/usr/bin/env python3
"""Drive a test session against NIST's live ACVTS server.

This is the counterpart to the offline runner. `acvp_assay run` compares a
downloaded ``prompt.json`` against a downloaded ``expectedResults.json``; this
speaks to the server those files come from, so the same providers can be
exercised against vectors NIST generates fresh rather than against files pinned
months ago.

Two flows matter, and they are not the same test:

``sample``
    Register with ``isSample: true``, which entitles the client to retrieve
    NIST's expected results. The vector set then has exactly the shape the
    offline runner already understands, so this validates the runner end to end
    against freshly generated vectors.

``submit``
    The real protocol. The client computes responses, POSTs them, and the
    server returns its own verdict. Nothing local decides whether this passed.

Credentials are read from the environment and never from this repository:

    ACVTS_CERT   PEM client certificate issued by NIST
    ACVTS_KEY    its private key
    ACVTS_SEED   file holding the base64 TOTP seed
    ACVTS_STATE  directory for session state and downloads (default: .acvts)

The TOTP parameters are not what the public documentation implies. The ACVP
wiki and issue #297 suggest SHA-1 and six digits; the implementation that
actually authenticates -- cisco/libacvp, ``app/totp/totp.c`` sitting beside
``app/totp/hmac_sha256.c`` -- uses **HMAC-SHA-256 and eight digits** over a
base64-decoded seed with a 30-second step. A wrong guess returns a bare 401
naming neither factor.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
import ssl
import struct
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE_URL = os.environ.get("ACVTS_URL", "https://demo.acvts.nist.gov")
ACV_VERSION = "1.0"
TOTP_STEP_SECONDS = 30
TOTP_DIGITS = 8
TRANSPORT_ATTEMPTS = 5

STATE = Path(os.environ.get("ACVTS_STATE", ".acvts"))


class CredentialError(RuntimeError):
    """A credential was not configured or is not readable."""


def _credential(variable: str) -> Path:
    """Resolve one credential path from the environment."""
    raw = os.environ.get(variable)
    if not raw:
        raise CredentialError(
            f"{variable} is not set. Credentials live outside this repository; "
            f"export {variable} to point at the file NIST issued."
        )
    path = Path(raw).expanduser()
    if not path.is_file():
        raise CredentialError(f"{variable} points at {path}, which is not a file")
    return path


def totp(at: float | None = None) -> str:
    """Derive the current ACVTS password from the seed.

    HMAC-SHA-256 over an 8-byte big-endian counter of ``floor(now / 30)``, then
    RFC 4226 dynamic truncation, reduced to eight digits.
    """
    seed = base64.b64decode(_credential("ACVTS_SEED").read_text().strip())
    counter = int((time.time() if at is None else at) // TOTP_STEP_SECONDS)
    digest = hmac.new(seed, struct.pack(">Q", counter), hashlib.sha256).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFF_FFFF
    return str(truncated % (10**TOTP_DIGITS)).zfill(TOTP_DIGITS)


def _context() -> ssl.SSLContext:
    """A TLS context presenting the NIST-issued client certificate."""
    context = ssl.create_default_context()
    context.load_cert_chain(
        certfile=str(_credential("ACVTS_CERT")), keyfile=str(_credential("ACVTS_KEY"))
    )
    return context


def request(
    method: str,
    path: str,
    body: object | None = None,
    token: str | None = None,
    *,
    _retrying: bool = False,
    _attempt: int = 0,
) -> object:
    """Make one mutually authenticated request and decode the JSON reply."""
    payload = None if body is None else json.dumps(body).encode()
    outgoing = urllib.request.Request(  # noqa: S310 - fixed https host
        f"{BASE_URL}{path}", data=payload, method=method
    )
    outgoing.add_header("Content-Type", "application/json")
    if token:
        outgoing.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(outgoing, context=_context(), timeout=300) as response:  # noqa: S310
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")[:600]
        if error.code == 401 and token is not None and not _retrying:
            # The 30-minute session token lapsed; renew it and repeat once.
            return request(method, path, body, login(), _retrying=True)
        raise SystemExit(f"HTTP {error.code} {error.reason} for {path}\n{detail}") from error
    except (http.client.IncompleteRead, urllib.error.URLError, TimeoutError, OSError) as error:
        # Vector sets run to several megabytes over a server shared worldwide,
        # and a truncated chunked read is a transport failure, not a protocol
        # one. Retrying the whole GET is safe: these reads are idempotent.
        if _attempt >= TRANSPORT_ATTEMPTS:
            raise SystemExit(
                f"{path}: transport failed {TRANSPORT_ATTEMPTS} times ({type(error).__name__})"
            ) from error
        backoff = 2**_attempt
        print(
            f"    transport error ({type(error).__name__}); retrying in {backoff}s",
            flush=True,
        )
        time.sleep(backoff)
        return request(method, path, body, token, _retrying=_retrying, _attempt=_attempt + 1)


def _token_cache() -> Path:
    STATE.mkdir(parents=True, exist_ok=True)
    STATE.chmod(0o700)
    return STATE / "jwt"


def login() -> str:
    """Authenticate and return the session token, caching it under the state directory."""
    reply = request("POST", "/acvp/v1/login", [{"acvVersion": ACV_VERSION}, {"password": totp()}])
    for element in reply if isinstance(reply, list) else []:
        if isinstance(element, dict) and "accessToken" in element:
            token = str(element["accessToken"])
            cache = _token_cache()
            cache.write_text(token)
            cache.chmod(0o600)
            return token
    raise SystemExit("no accessToken in the login reply")


def cached_token() -> str:
    """Return a cached session token, logging in if there is not one yet."""
    cache = _token_cache()
    if cache.exists() and (token := cache.read_text().strip()):
        return token
    return login()


def body_of(reply: object) -> dict[str, object]:
    """Return the payload element of an ACVP reply, past the version preamble."""
    for element in reply if isinstance(reply, list) else []:
        if isinstance(element, dict) and set(element) != {"acvVersion"}:
            return element
    raise SystemExit(f"no payload element in reply: {json.dumps(reply)[:300]}")


def mask(secret: str) -> str:
    """Render a secret as a length and a fingerprint, never in full."""
    return f"<{len(secret)} chars, sha256:{hashlib.sha256(secret.encode()).hexdigest()[:12]}…>"


def _session_file() -> Path:
    STATE.mkdir(parents=True, exist_ok=True)
    STATE.chmod(0o700)
    return STATE / "session.json"


def save_session(record: dict[str, object]) -> None:
    """Persist a test session's identity and its scoped access token.

    ACVP issues a token scoped to the session at registration time, and the
    ordinary login token cannot reach that session's endpoints — it answers
    403. Losing the scoped token orphans the session, so it is written down the
    moment it arrives.
    """
    path = _session_file()
    path.write_text(json.dumps(record, indent=2))
    path.chmod(0o600)


def vector_urls(record: dict[str, object]) -> list[str]:
    """The session's vector set URLs, as strings."""
    raw = record.get("vectorSetUrls")
    return [str(item) for item in raw] if isinstance(raw, list) else []


def load_session() -> dict[str, object]:
    """Return the saved test session, or fail with a useful message."""
    path = _session_file()
    if not path.exists():
        raise SystemExit("no saved session; run `register` first")
    loaded: dict[str, object] = json.loads(path.read_text())
    return loaded


def groups_of(document: dict[str, object]) -> list[object]:
    """The ``testGroups`` array of an ACVP document, or an empty list."""
    raw = document.get("testGroups")
    return raw if isinstance(raw, list) else []


def poll(path: str, token: str, *, attempts: int = 40) -> dict[str, object]:
    """GET a resource, honouring ACVP's ``retry`` back-pressure.

    The server answers a not-yet-generated vector set with ``{"retry": n}``
    rather than blocking. Demo is shared worldwide, so this waits as asked
    instead of hammering.
    """
    for attempt in range(attempts):
        payload = body_of(request("GET", path, token=token))
        retry = payload.get("retry")
        if retry is None:
            return payload
        delay = min(int(str(retry)), 30)
        print(f"    server asked to retry in {delay}s (attempt {attempt + 1})", flush=True)
        time.sleep(delay)
    raise SystemExit(f"{path} still not ready after {attempts} attempts")


def _cmd_register(arguments: argparse.Namespace) -> int:
    """Register a test session from a capabilities file."""
    algorithms = json.loads(Path(arguments.capabilities).read_text())
    if isinstance(algorithms, dict):
        algorithms = [algorithms]
    registration = [
        {"acvVersion": ACV_VERSION},
        {
            "isSample": not arguments.no_sample,
            "operation": "register",
            "certificateRequest": "no",
            "debugRequest": "no",
            "production": "no",
            "encryptAtRest": "no",
            "algorithms": algorithms,
        },
    ]
    payload = body_of(request("POST", "/acvp/v1/testSessions", registration, cached_token()))
    url = str(payload["url"])
    record = {
        "url": url,
        "testSessionId": url.rsplit("/", 1)[-1],
        "vectorSetUrls": payload.get("vectorSetUrls", []),
        "isSample": payload.get("isSample"),
        "accessToken": payload["accessToken"],
        "createdOn": payload.get("createdOn"),
    }
    save_session(record)
    print(f"  test session {record['testSessionId']}  isSample={record['isSample']}")
    for vector_url in vector_urls(record):
        print(f"    vector set {vector_url}")
    print(f"  scoped token saved: {mask(str(record['accessToken']))}")
    return 0


def _cmd_fetch(arguments: argparse.Namespace) -> int:
    """Download each vector set's prompt, and its expected results when sampling."""
    record = load_session()
    token = str(record["accessToken"])
    destination = STATE / f"session-{record['testSessionId']}"
    destination.mkdir(parents=True, exist_ok=True)
    for vector_url in vector_urls(record):
        vs_id = vector_url.rsplit("/", 1)[-1]
        print(f"  vector set {vs_id}")
        # One directory per vector set, using the filenames `acvp_assay run`
        # expects: it locates expectedResults.json beside the prompt by
        # convention rather than by flag.
        folder = destination / vs_id
        folder.mkdir(parents=True, exist_ok=True)
        prompt = poll(vector_url, token)
        (folder / "prompt.json").write_text(json.dumps(prompt, indent=2))
        print(
            f"    prompt      {prompt.get('algorithm')} rev {prompt.get('revision')}"
            f"  groups={len(groups_of(prompt))}"
        )
        if record.get("isSample"):
            expected = poll(f"{vector_url}/expected", token)
            (folder / "expectedResults.json").write_text(json.dumps(expected, indent=2))
            print("    expected    downloaded")
        print(f"    run with    acvp-assay run {folder / 'prompt.json'}")
    print(f"  saved under {destination}")
    return 0


def _cmd_submit(arguments: argparse.Namespace) -> int:
    """Compute responses for each downloaded vector set and submit them."""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
    from acvp_assay.responder import UnsupportedResponseError, build_response

    record = load_session()
    token = str(record["accessToken"])
    destination = STATE / f"session-{record['testSessionId']}"
    for vector_url in vector_urls(record):
        vs_id = vector_url.rsplit("/", 1)[-1]
        prompt_file = destination / vs_id / "prompt.json"
        if not prompt_file.exists():
            raise SystemExit(f"{prompt_file} not downloaded; run `fetch` first")
        try:
            response = build_response(prompt_file)
        except UnsupportedResponseError as error:
            print(f"  vector set {vs_id}: cannot answer -- {error}")
            continue
        (destination / vs_id / "response.json").write_text(json.dumps(response, indent=2))
        cases = sum(
            len(group["tests"])
            for group in groups_of(response)
            if isinstance(group, dict) and isinstance(group.get("tests"), list)
        )
        print(f"  vector set {vs_id}: submitting {cases} cases")
        # Results are a sub-resource: the vector set URL itself answers 405.
        reply = body_of(
            request(
                "POST",
                f"{vector_url}/results",
                [{"acvVersion": ACV_VERSION}, response],
                token,
            )
        )
        print(f"    server said: {json.dumps(reply)[:300]}")
    return 0


def _cmd_results(arguments: argparse.Namespace) -> int:
    """Ask the server for its verdict on the session."""
    record = load_session()
    token = str(record["accessToken"])
    payload = poll(f"{record['url']}/results", token)
    print(json.dumps(payload, indent=2)[:4000])
    return 0


def _cmd_check(arguments: argparse.Namespace) -> int:
    """Report credential readiness without contacting NIST."""
    for variable in ("ACVTS_CERT", "ACVTS_KEY", "ACVTS_SEED"):
        try:
            path = _credential(variable)
        except CredentialError as error:
            print(f"  {variable:<12} NOT READY  {error}")
            continue
        mode = oct(path.stat().st_mode & 0o777)
        warning = "  <-- readable by others" if path.stat().st_mode & 0o077 else ""
        print(f"  {variable:<12} ready      mode {mode}  {path.name}{warning}")
    generated = totp()
    ok = len(generated) == TOTP_DIGITS and generated.isdigit()
    # Never echoed: a live password belongs in the request, not in scrollback.
    print(
        f"  TOTP         {'generates' if ok else 'MALFORMED'}  "
        f"({TOTP_DIGITS} digits, HMAC-SHA-256, {TOTP_STEP_SECONDS}s step)"
    )
    return 0


def _cmd_login(arguments: argparse.Namespace) -> int:
    print(f"session token: {mask(login())}")
    return 0


def _cmd_get(arguments: argparse.Namespace) -> int:
    print(json.dumps(request("GET", arguments.path, token=cached_token()), indent=2)[:6000])
    return 0


def _cmd_post(arguments: argparse.Namespace) -> int:
    body = json.loads(Path(arguments.body).read_text())
    print(json.dumps(request("POST", arguments.path, body, cached_token()), indent=2)[:6000])
    return 0


def main() -> int:
    """Dispatch one subcommand."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="verify credentials without contacting NIST").set_defaults(
        run=_cmd_check
    )
    sub.add_parser("login", help="authenticate and cache a session token").set_defaults(
        run=_cmd_login
    )
    get = sub.add_parser("get", help="make an authenticated GET")
    get.add_argument("path")
    get.set_defaults(run=_cmd_get)
    post = sub.add_parser("post", help="make an authenticated POST from a JSON file")
    post.add_argument("path")
    post.add_argument("body", help="path to a JSON file")
    post.set_defaults(run=_cmd_post)
    register = sub.add_parser("register", help="register a test session")
    register.add_argument("capabilities", help="JSON file holding the algorithms array")
    register.add_argument(
        "--no-sample",
        action="store_true",
        help="register a real session, where NIST does not reveal expected results",
    )
    register.set_defaults(run=_cmd_register)
    sub.add_parser("fetch", help="download the session's vector sets").set_defaults(run=_cmd_fetch)
    sub.add_parser("submit", help="compute and submit responses").set_defaults(run=_cmd_submit)
    sub.add_parser("results", help="ask the server for its verdict").set_defaults(run=_cmd_results)

    arguments = parser.parse_args()
    try:
        result: int = arguments.run(arguments)
    except CredentialError as error:
        print(f"credential error: {error}", file=sys.stderr)
        return 2
    return result


if __name__ == "__main__":
    sys.exit(main())
