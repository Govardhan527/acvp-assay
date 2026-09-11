"""Count how often each ACVP algorithm name appears on a FIPS 140-3 certificate.

The build order in `docs/backlog.md` used to be reasoned from what modules
*probably* validate. This measures it instead: every active CMVP certificate is
fetched, its approved-algorithm list is read, each CAVP display name is mapped
onto the ACVP registry name that would have to be implemented to test it, and
the names are counted across modules.

Two questions are answered, because they rank differently:

* **frequency** — how many modules carry the name at all. This is the chance a
  given customer needs it.
* **unlocks** — how many modules become *fully* testable if the name is added.
  A module one name away is worth more than a module nine names away.

Only FIPS 140-3 certificates are counted. FIPS 140-2 certificate pages carry no
machine-readable algorithm list, and those certificates move to Historical on
21 September 2026 regardless.

    python3.12 scripts/cavp_frequency.py fetch     # populate the cache
    python3.12 scripts/cavp_frequency.py report    # print the tables
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import re
import sys
import time
import urllib.request
from pathlib import Path
from typing import Final, NamedTuple

ROOT: Final = Path(__file__).resolve().parent.parent
CACHE: Final = ROOT / ".cavp-cache"
SEARCH: Final = (
    "https://csrc.nist.gov/projects/cryptographic-module-validation-program"
    "/validated-modules/search?SearchMode=Advanced&CertificateStatus=Active&ValidationYear=0"
)
CERTIFICATE: Final = (
    "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/"
)
USER_AGENT: Final = "acvp-assay-coverage-research/1.0 (+https://github.com/Govardhan527/acvp-assay)"

ROW: Final = re.compile(
    r'<tr id="cert-row-(\d+)">.*?certificate/(\d+)" id="cert-number-link-\1">\d+</a>'
    r'.*?id="cert-validation-dates-\1">(.*?)</td>',
    re.S,
)
LISTED: Final = re.compile(
    r'<div class="col-md-3">([^<]+)</div>\s*<div class="col-md-4">\s*'
    r'<a href="\.\./\.\./Cryptographic-Algorithm-Validation-Program'
)
STANDARD: Final = re.compile(r"Standard (FIPS 140-[23]) Status (\w+)")

# --- CAVP display name -> ACVP registry name -------------------------------
# A certificate names the operation ("RSA SigVer (FIPS186-5)"); the registry
# names the family ("RSA"). Several display names collapse onto one registry
# name, which is the point: a module validating four RSA operations still needs
# exactly one ACVP name implemented.

EXACT: Final = {
    "AES-CMAC": "CMAC-AES",
    "TDES-CMAC": "CMAC-TDES",
    "Counter DRBG": "ctrDRBG",
    "Hash DRBG": "hashDRBG",
    "HMAC DRBG": "hmacDRBG",
    "PBKDF": "PBKDF",
    "Ascon": "Ascon",
}
PREFIX: Final = {
    "Safe Primes": "safePrimes",
    "Conditioning Component": "ConditioningComponent",
    "Deterministic ECDSA": "DetECDSA",
    "KAS-ECC-SSC": "KAS-ECC-SSC",
    "KAS-FFC-SSC": "KAS-FFC-SSC",
    "KAS-IFC-SSC": "KAS-IFC-SSC",
    "KAS-ECC": "KAS-ECC",
    "KAS-FFC": "KAS-FFC",
    "KAS-IFC": "KAS-IFC",
    "KAS-KC": "KAS-KC",
    "KTS-IFC": "KTS-IFC",
    "KDA": "KDA",
    "KDF SP800-108": "KDF",
    "KDF KMAC": "KDF",  # SP800-108r1 added KMAC as a mode of the same name
    "TLS v1.2": "TLS-v1.2",
    "TLS v1.3": "TLS-v1.3",
    "RSA": "RSA",
    "ECDSA": "ECDSA",
    "EDDSA": "EDDSA",
    "DSA": "DSA",
    "ML-DSA": "ML-DSA",
    "ML-KEM": "ML-KEM",
    "SLH-DSA": "SLH-DSA",
    "LMS": "LMS",
    "XECDH": "XECDH",
}
SIZED: Final = {
    "cSHAKE": "cSHAKE",
    "KMAC": "KMAC",
    "ParallelHash": "ParallelHash",
    "TupleHash": "TupleHash",
}
COMPONENT: Final = re.compile(
    r"^KDF (SSH|TLS|IKEv1|IKEv2|ANS ?9\.(?:42|63)|X9\.(?:42|63)|SNMP|SRTP|TPM)", re.I
)
AES: Final = re.compile(r"^AES-([A-Za-z0-9-]+)")
TDES: Final = re.compile(r"^TDES-([A-Za-z0-9]+)")
DIGEST: Final = re.compile(r"^(?:SHA-1|SHA2-\d+(?:/\d+)?|SHA3-\d+|SHAKE-\d+)$")
HMAC: Final = re.compile(r"^HMAC-(?:SHA-1|SHA2-\d+(?:/\d+)?|SHA3-\d+)$")

# Three-key TDES, disallowed for new validations since 2023. Counted, then set
# aside: a module is not worth chasing for a name nobody may newly validate.
DEAD: Final = frozenset(
    {
        "ACVP-TDES-CBC",
        "ACVP-TDES-CBCI",
        "ACVP-TDES-CFB1",
        "ACVP-TDES-CFB64",
        "ACVP-TDES-CFB8",
        "ACVP-TDES-CFBP1",
        "ACVP-TDES-CFBP64",
        "ACVP-TDES-CFBP8",
        "ACVP-TDES-CTR",
        "ACVP-TDES-ECB",
        "ACVP-TDES-KW",
        "ACVP-TDES-OFB",
        "ACVP-TDES-OFBI",
        "CMAC-TDES",
    }
)

# --- what a count cannot see -----------------------------------------------
# A rank built by counting certificates measures what has been validated, and
# cannot see a mandate. Where a standard changes what a count means, the table
# says so in a column, because a consumer of the table reads the column and
# never the paragraph. A name not listed here is ``stable``: no known policy
# pressure. Every entry names the standard that determines it.

STABLE: Final = "stable"
#: A standard disallows new use; the count describes legacy.
DECAYING: Final = "decaying"
#: A standard requires adoption by a date; the count describes a population
#: that has not moved yet.
MANDATED: Final = "mandated"
#: Withdrawn.
WITHDRAWN: Final = "dead"
TRENDS: Final = (STABLE, DECAYING, MANDATED, WITHDRAWN)

TREND: Final[dict[str, tuple[str, str]]] = {
    "DSA": (DECAYING, "SP 800-131A: DSA signature generation disallowed after 2023"),
    "ML-KEM": (MANDATED, "CNSA 2.0: required by January 2027"),
    "ML-DSA": (MANDATED, "CNSA 2.0: required by January 2027"),
    **{
        name: (WITHDRAWN, "three-key TDES: disallowed for new validations since 2023")
        for name in DEAD
    },
}


def trend(name: str) -> str:
    """The policy trend behind a name's count: ``stable`` unless a standard says otherwise."""
    return TREND.get(name, (STABLE, ""))[0]


class Module(NamedTuple):
    """One FIPS 140-3 certificate, reduced to the registry names it needs."""

    cert: int
    year: int
    names: frozenset[str]
    unmapped: tuple[str, ...]


def registry_name(display: str) -> str | None:
    """The ACVP registry name a CAVP display name belongs to, or None."""
    display = " ".join(display.split())
    if display in EXACT:
        return EXACT[display]
    if COMPONENT.match(display):
        return "kdf-components"
    if DIGEST.match(display) or HMAC.match(display):
        return display
    if aes := AES.match(display):
        return f"ACVP-AES-{aes.group(1)}"
    if tdes := TDES.match(display):
        return f"ACVP-TDES-{tdes.group(1)}"
    for prefix in sorted(SIZED, key=len, reverse=True):
        if display.startswith(prefix):
            size = re.search(r"128|256", display)
            return f"{SIZED[prefix]}-{size.group(0)}" if size else None
    for prefix in sorted(PREFIX, key=len, reverse=True):
        if display.startswith(prefix):
            return PREFIX[prefix]
    return None


def _get(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - fixed host
        body: str = response.read().decode("utf-8", errors="replace")
    return body


def _fetch_certificate(cert: str) -> bool:
    target = CACHE / f"{cert}.html"
    if target.exists() and target.stat().st_size > 5000:
        return True
    for attempt in range(4):
        try:
            body = _get(CERTIFICATE + cert)
            if len(body) < 5000:
                raise ValueError(f"short body: {len(body)} bytes")
            target.write_text(body, encoding="utf-8")
            time.sleep(0.2)
            return True
        except Exception as error:  # noqa: BLE001 - retry anything transient
            if attempt == 3:
                print(f"  {cert}: {error}", file=sys.stderr)
                return False
            time.sleep(2 * (attempt + 1))
    return False


def fetch() -> int:
    """Download the active-module index and every certificate page it names."""
    CACHE.mkdir(exist_ok=True)
    index_html = _get(SEARCH)
    index = [
        {"cert": cert, "validated": " ".join(re.sub(r"<[^>]+>", " ", dates).split())}
        for _, cert, dates in ROW.findall(index_html)
    ]
    (CACHE / "index.json").write_text(json.dumps(index, indent=1), encoding="utf-8")
    print(f"index: {len(index)} active modules")
    failed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for ok in pool.map(_fetch_certificate, [row["cert"] for row in index]):
            failed += not ok
    print(f"cached {len(index) - failed} certificate pages, {failed} failed")
    return 1 if failed else 0


def modules() -> list[Module]:
    """Every cached FIPS 140-3 module that lists approved algorithms."""
    index_path = CACHE / "index.json"
    if not index_path.exists():
        raise SystemExit("no cache; run `cavp_frequency.py fetch` first")
    dates: dict[str, str] = {
        str(row["cert"]): str(row["validated"]) for row in json.loads(index_path.read_text())
    }
    found: list[Module] = []
    for path in sorted(CACHE.glob("*.html"), key=lambda item: int(item.stem)):
        html = path.read_text(encoding="utf-8", errors="replace")
        standard = STANDARD.search(" ".join(re.sub(r"<[^>]+>", " ", html).split()))
        listed = LISTED.findall(html)
        names = frozenset(
            name for name in (registry_name(display) for display in listed) if name is not None
        )
        if standard is None or standard.group(1) != "FIPS 140-3" or not names:
            continue
        year = re.findall(r"\d{2}/\d{2}/(\d{4})", dates.get(path.stem, ""))
        found.append(
            Module(
                cert=int(path.stem),
                year=int(year[0]) if year else 0,
                names=names,
                unmapped=tuple(sorted(d for d in listed if registry_name(d) is None)),
            )
        )
    return found


def report(since: int) -> int:
    """Print the frequency and unlock tables."""
    sys.path.insert(0, str(ROOT / "src"))
    from acvp_assay.algorithms import supported_algorithms

    built = set(supported_algorithms())
    found = modules()
    if unmapped := sorted({name for row in found for name in row.unmapped}):
        print(f"WARNING: {len(unmapped)} display names did not map: {unmapped}\n")
    every = [row.names for row in found]
    recent = [row.names for row in found if row.year >= since]
    print(
        f"{len(every)} active FIPS 140-3 modules list approved algorithms; "
        f"{len(recent)} first validated {since} or later\n"
    )

    frequency = collections.Counter(name for names in every for name in names)
    recent_frequency = collections.Counter(name for names in recent for name in names)
    print(f"| algorithm | modules | share | {since}+ | share | status | trend |")
    print("| --- | ---: | ---: | ---: | ---: | --- | --- |")
    for name, count in frequency.most_common():
        status = "built" if name in built else ("dead" if name in DEAD else "**missing**")
        print(
            f"| `{name}` | {count} | {100 * count / len(every):.0f}% "
            f"| {recent_frequency[name]} | {100 * recent_frequency[name] / len(recent):.0f}% "
            f"| {status} | {trend(name)} |"
        )

    complete = sum(1 for names in every if names - DEAD <= built)
    coverage = sorted(len(names & built) / len(names) for names in every)
    print(
        f"\nMedian module: {100 * coverage[len(coverage) // 2]:.0f}% of its algorithm names "
        f"are testable today. Fully testable: {complete} modules "
        f"({100 * complete / len(every):.0f}%).\n"
    )

    print("| # | add this name | modules it completes | cumulative | share |")
    print("| ---: | --- | ---: | ---: | ---: |")
    have = set(built)
    for step in range(1, 13):
        gain: collections.Counter[str] = collections.Counter()
        for names in every:
            missing = names - DEAD - have
            if len(missing) == 1:
                gain[next(iter(missing))] += 1
        if not gain:
            break
        name, unlocks = gain.most_common(1)[0]
        have.add(name)
        total = sum(1 for names in every if names - DEAD <= have)
        print(f"| {step} | `{name}` | {unlocks} | {total} | {100 * total / len(every):.0f}% |")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("fetch", help="download the active CMVP certificates into the cache")
    counted = sub.add_parser("report", help="print the frequency and unlock tables")
    counted.add_argument("--since", type=int, default=2025, help="recent-slice cutoff year")
    arguments = parser.parse_args(argv)
    if arguments.command == "fetch":
        return fetch()
    return report(int(arguments.since))


if __name__ == "__main__":
    raise SystemExit(main())
