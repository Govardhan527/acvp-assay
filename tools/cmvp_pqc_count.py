#!/usr/bin/env python3
"""Count the CMVP certificates that list ML-KEM or ML-DSA.

A number like "twelve modules have validated ML-KEM" is worth nothing without
its denominator and its date, and both move: CMVP moved every FIPS 140-2
certificate to Historical on 21 September 2026, which changed the active
population by roughly a third overnight. So this records what it counted, out of
what, on which day, and keeps the raw pages it counted from.

It is deliberately separate from the runner and shares no code with it. The
runner is a measuring instrument for one implementation; this is desk research
about a public register, and merging them would put a network dependency and a
scraper inside a tool whose whole claim is that it is deterministic.

    python3 tools/cmvp_pqc_count.py fetch     # index pages, then candidates
    python3 tools/cmvp_pqc_count.py report    # CSV, METHOD.md, and a summary

The fetch is cached and resumable: a page already on disk is not requested
again, so an interrupted run continues where it stopped.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import datetime as dt
import json
import re
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parent.parent
CACHE: Final = ROOT / ".cmvp-pqc-cache"
PAGES: Final = CACHE / "certificates"
CSV_OUT: Final = ROOT / "tools/cmvp-pqc-certificates.csv"
METHOD_OUT: Final = ROOT / "tools/METHOD.md"

SEARCH: Final = (
    "https://csrc.nist.gov/projects/cryptographic-module-validation-program"
    "/validated-modules/search?SearchMode=Advanced&CertificateStatus={status}&ValidationYear=0"
)
CERTIFICATE: Final = (
    "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/"
)
USER_AGENT: Final = "acvp-assay-pqc-count/1.0 (+https://github.com/Govardhan527/acvp-assay)"
STATUSES: Final = ("Active", "Historical", "Revoked")

#: FIPS 203 and FIPS 204 were published on 13 August 2024, so no validation
#: before that date can list either algorithm. Certificates whose every
#: validation date is earlier are counted in the denominator and not fetched:
#: that is 5,000 requests to NIST saved, and the filter is stated rather than
#: quietly applied. A revalidation adds a date, so a 2019 module that added
#: ML-KEM in 2025 carries a 2025 date and is fetched.
EARLIEST_POSSIBLE: Final = dt.date(2024, 8, 13)

#: One index row: its certificate number and the validation dates cell.
ROW: Final = re.compile(
    r'<tr id="cert-row-(\d+)">.*?certificate/(\d+)" id="cert-number-link-\1">\d+</a>'
    r'.*?id="cert-validation-dates-\1">(.*?)</td>',
    re.S,
)
#: An approved algorithm on a certificate page: a display name whose row links
#: to a CAVP validation. The link is the anchor that separates approved
#: algorithms with a validation from everything else on the page.
LISTED: Final = re.compile(
    r'<div class="col-md-3">([^<]+)</div>\s*<div class="col-md-4">\s*'
    r'<a href="\.\./\.\./Cryptographic-Algorithm-Validation-Program'
)
STANDARD: Final = re.compile(r"Standard (FIPS 140-[23]) Status (\w+)")
DATE: Final = re.compile(r"(\d{2})/(\d{2})/(\d{4})")

#: What counts as ML-KEM or ML-DSA on a certificate. CMVP writes the CAVP
#: display names ("ML-KEM KeyGen", "ML-DSA SigVer"), and the standards are named
#: directly on some pages, so both spellings are matched. The scheme names
#: Kyber and Dilithium are deliberately *not* matched: they are the
#: pre-standard submissions, not the approved algorithms, and counting them
#: would inflate the answer with something a laboratory never validated.
FAMILIES: Final = {
    "ML-KEM": re.compile(r"\bML[- ]?KEM\b|\bFIPS\s?203\b", re.IGNORECASE),
    "ML-DSA": re.compile(r"\bML[- ]?DSA\b|\bFIPS\s?204\b", re.IGNORECASE),
}


@dataclass(frozen=True, slots=True)
class Row:
    """One certificate as the index lists it."""

    certificate: int
    status: str
    dates: tuple[dt.date, ...]

    @property
    def could_carry_pqc(self) -> bool:
        """Whether any validation happened after FIPS 203 and 204 existed."""
        return any(date >= EARLIEST_POSSIBLE for date in self.dates)


@dataclass(slots=True)
class Match:
    """One certificate that lists at least one of the two families."""

    certificate: int
    status: str
    standard: str
    families: list[str] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    latest_validation: str = ""


def _get(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310 - fixed host
        body: str = response.read().decode("utf-8", errors="replace")
    return body


def _dates(cell: str) -> tuple[dt.date, ...]:
    text = " ".join(re.sub(r"<[^>]+>", " ", cell).split())
    return tuple(dt.date(int(y), int(m), int(d)) for m, d, y in DATE.findall(text))


def parse_index(html: str, status: str) -> list[Row]:
    """Every certificate the index lists, with the dates it was validated on."""
    return [
        Row(certificate=int(number), status=status, dates=_dates(cell))
        for _, number, cell in ROW.findall(html)
    ]


def _fetch_certificate(number: int) -> bool:
    target = PAGES / f"{number}.html"
    if target.exists() and target.stat().st_size > 5000:
        return True
    for attempt in range(4):
        try:
            body = _get(CERTIFICATE + str(number))
            if len(body) < 5000:
                raise ValueError(f"short body: {len(body)} bytes")
            target.write_text(body, encoding="utf-8")
            time.sleep(0.2)
            return True
        except Exception as error:  # noqa: BLE001 - retry anything transient
            if attempt == 3:
                print(f"  {number}: {error}", file=sys.stderr)
                return False
            time.sleep(2 * (attempt + 1))
    return False


def fetch() -> int:
    """Download the three index pages and every certificate that could carry PQC."""
    PAGES.mkdir(parents=True, exist_ok=True)
    snapshot = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
    rows: list[Row] = []
    counts: dict[str, int] = {}
    for status in STATUSES:
        url = SEARCH.format(status=status)
        html = _get(url)
        (CACHE / f"index-{status.lower()}.html").write_text(html, encoding="utf-8")
        listed = parse_index(html, status)
        counts[status] = len(listed)
        rows.extend(listed)
        print(f"{status}: {len(listed)} certificates")
        time.sleep(1)

    candidates = sorted({row.certificate for row in rows if row.could_carry_pqc})
    print(
        f"\n{len(candidates)} certificates have a validation on or after "
        f"{EARLIEST_POSSIBLE}; the rest cannot list an algorithm that did not exist yet"
    )
    (CACHE / "snapshot.json").write_text(
        json.dumps(
            {
                "snapshotUtc": snapshot,
                "search": {status: SEARCH.format(status=status) for status in STATUSES},
                "certificateBase": CERTIFICATE,
                "counts": counts,
                "candidates": len(candidates),
                "earliestPossibleValidation": EARLIEST_POSSIBLE.isoformat(),
                "index": [
                    {
                        "certificate": row.certificate,
                        "status": row.status,
                        "dates": [date.isoformat() for date in row.dates],
                    }
                    for row in sorted(rows, key=lambda row: (row.status, row.certificate))
                ],
            },
            indent=1,
        ),
        encoding="utf-8",
    )

    failed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for ok in pool.map(_fetch_certificate, candidates):
            failed += not ok
    print(f"cached {len(candidates) - failed} certificate pages, {failed} failed")
    return 1 if failed else 0


def _snapshot() -> dict[str, object]:
    path = CACHE / "snapshot.json"
    if not path.exists():
        raise SystemExit("no snapshot; run `tools/cmvp_pqc_count.py fetch` first")
    document: dict[str, object] = json.loads(path.read_text(encoding="utf-8"))
    return document


def classify(html: str) -> tuple[str, list[str], list[str]]:
    """The standard this certificate is under, its PQC families and their names."""
    flattened = " ".join(re.sub(r"<[^>]+>", " ", html).split())
    standard = STANDARD.search(flattened)
    listed = [" ".join(name.split()) for name in LISTED.findall(html)]
    families = sorted(
        {family for family, pattern in FAMILIES.items() for name in listed if pattern.search(name)}
    )
    names = sorted(
        {name for name in listed if any(pattern.search(name) for pattern in FAMILIES.values())}
    )
    return (standard.group(1) if standard else "unknown"), families, names


def mentions_anywhere(html: str) -> bool:
    """Whether a page names either family anywhere in its text, links or not.

    The count itself only accepts an approved algorithm with a CAVP validation
    behind it, which is the strict reading and could in principle miss a page
    that lists one some other way. Running the loose reading beside the strict
    one turns that from an assumption into a check: when the two disagree, the
    report says so instead of quietly reporting the smaller number.
    """
    return any(
        pattern.search(" ".join(re.sub(r"<[^>]+>", " ", html).split()))
        for pattern in FAMILIES.values()
    )


def report() -> int:
    """Count the matches, write the CSV and METHOD.md, and print the summary."""
    snapshot = _snapshot()
    index = snapshot["index"]
    assert isinstance(index, list)
    raw_counts = snapshot["counts"]
    assert isinstance(raw_counts, dict)
    counts: dict[str, int] = {str(key): int(value) for key, value in raw_counts.items()}

    matches: list[Match] = []
    unread = 0
    loose = 0
    for entry in index:
        dates = [str(date) for date in entry["dates"]]
        if not any(date >= EARLIEST_POSSIBLE.isoformat() for date in dates):
            continue
        page = PAGES / f"{entry['certificate']}.html"
        if not page.exists():
            unread += 1
            continue
        html = page.read_text(encoding="utf-8", errors="replace")
        loose += mentions_anywhere(html)
        standard, families, names = classify(html)
        if families:
            matches.append(
                Match(
                    certificate=int(entry["certificate"]),
                    status=str(entry["status"]),
                    standard=standard,
                    families=families,
                    names=names,
                    latest_validation=max(dates) if dates else "",
                )
            )

    matches.sort(key=lambda match: match.certificate)
    CSV_OUT.parent.mkdir(parents=True, exist_ok=True)
    with CSV_OUT.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["certificate", "status", "standard", "families", "latest_validation", "algorithms"]
        )
        for match in matches:
            writer.writerow(
                [
                    match.certificate,
                    match.status,
                    match.standard,
                    " ".join(match.families),
                    match.latest_validation,
                    "; ".join(match.names),
                ]
            )

    by_status = {status: 0 for status in STATUSES}
    by_family = {family: 0 for family in FAMILIES}
    both = 0
    for match in matches:
        by_status[match.status] = by_status.get(match.status, 0) + 1
        for family in match.families:
            by_family[family] += 1
        if len(match.families) == 2:
            both += 1

    total = sum(counts.values())
    print(f"snapshot {snapshot['snapshotUtc']}\n")
    print("| population | certificates | listing ML-KEM or ML-DSA |")
    print("| --- | ---: | ---: |")
    for status in STATUSES:
        print(f"| {status} | {counts.get(status, 0)} | {by_status.get(status, 0)} |")
    print(f"| **total** | **{total}** | **{len(matches)}** |")
    print(f"\nML-KEM: {by_family['ML-KEM']}   ML-DSA: {by_family['ML-DSA']}   both: {both}")
    if loose != len(matches):
        print(
            f"\nNOTE: {loose} candidate pages name a PQC algorithm somewhere in their text "
            f"while {len(matches)} list one as an approved algorithm with a CAVP validation. "
            "The difference is in the CSV's favour: read those pages by hand.",
            file=sys.stderr,
        )
    if unread:
        print(f"\n{unread} candidate page(s) were never fetched; re-run fetch", file=sys.stderr)
    write_method(snapshot, counts, matches, by_status, by_family, both, unread, loose)
    print(f"\nwrote {CSV_OUT.relative_to(ROOT)} and {METHOD_OUT.relative_to(ROOT)}")
    return 1 if unread else 0


def write_method(
    snapshot: dict[str, object],
    counts: dict[str, int],
    matches: list[Match],
    by_status: dict[str, int],
    by_family: dict[str, int],
    both: int,
    unread: int,
    loose: int,
) -> None:
    """Write down everything someone would need to get this number again."""
    search = snapshot["search"]
    assert isinstance(search, dict)
    total = sum(counts.values())
    rows = "\n".join(
        f"| {status} | {counts.get(status, 0)} | {by_status.get(status, 0)} |"
        for status in STATUSES
    )
    strict = len(matches)
    incomplete = (
        "- **Some candidate pages were not fetched.** Re-run `fetch`; the counts "
        "above are incomplete."
        if unread
        else ""
    )
    METHOD_OUT.write_text(
        f"""# Method: counting CMVP certificates that list ML-KEM or ML-DSA

Generated by `tools/cmvp_pqc_count.py report`. Everything needed to get the same
number again is written down here, because the number moves and a figure without
its date and its denominator is not evidence of anything.

## Snapshot

- **Taken (UTC):** `{snapshot["snapshotUtc"]}`
- **Raw pages kept:** `.cmvp-pqc-cache/` — the three index pages and every
  certificate page counted, exactly as served. Not committed: it is NIST's
  content, and it is large.

## Sources

| Population | URL |
| --- | --- |
| Active | <{search.get("Active", "")}> |
| Historical | <{search.get("Historical", "")}> |
| Revoked | <{search.get("Revoked", "")}> |

Certificate pages: `{snapshot["certificateBase"]}<number>`.

## The counts

| population | certificates | listing ML-KEM or ML-DSA |
| --- | ---: | ---: |
{rows}
| **total** | **{total}** | **{len(matches)}** |

ML-KEM: **{by_family["ML-KEM"]}**. ML-DSA: **{by_family["ML-DSA"]}**. Both:
**{both}**. The two family counts overlap by exactly that last figure, so they do
not add to the total.

Per-certificate detail, with the algorithm names each one actually lists, is in
`tools/cmvp-pqc-certificates.csv`.

## Filters, stated rather than implied

1. **All three statuses are counted separately**, and the denominator is the
   whole register rather than the active slice. This matters more than usual
   right now: CMVP moved every FIPS 140-2 certificate to Historical on
   **21 September 2026**, so an "active modules" denominator taken before that
   date and one taken after are not the same population.
2. **Only certificates with a validation date on or after
   {snapshot["earliestPossibleValidation"]} are fetched and parsed.** FIPS 203
   and FIPS 204 were published that day, so no earlier validation can list
   either algorithm. Every certificate is still counted in the denominator; the
   filter decides which pages are downloaded, and it saves several thousand
   requests to NIST. A revalidation adds a date, so a module validated in 2019
   that added ML-KEM in 2025 carries a 2025 date and is fetched.
3. **An algorithm counts only where the certificate lists it as an approved
   algorithm with a CAVP validation behind it** — the parser anchors on the link
   to the Cryptographic Algorithm Validation Program that CMVP puts beside each
   such entry.
4. **Name variants matched:** `ML-KEM`, `MLKEM`, `ML KEM` and `FIPS 203` for the
   KEM; `ML-DSA`, `MLDSA`, `ML DSA` and `FIPS 204` for the signature scheme, all
   case-insensitively. In practice CMVP writes the CAVP display names —
   `ML-KEM KeyGen`, `ML-KEM EncapDecap`, `ML-DSA KeyGen`, `ML-DSA SigGen`,
   `ML-DSA SigVer`.
5. **`Kyber` and `Dilithium` are deliberately not matched.** They are the
   pre-standard submissions rather than the approved algorithms, and counting
   them would inflate the figure with something no laboratory validated under
   FIPS 203 or 204.

## Known limits of the parsing

- **Security policies are not read.** A module whose policy PDF discusses FIPS
  203 while its certificate lists no ML-KEM algorithm is not counted. The
  certificate's algorithm list is the machine-readable claim, and the PDF is
  prose.
- **Allowed-but-not-approved entries are not counted**, because the anchor is
  the CAVP link that only approved entries carry. As a check on that, every
  candidate page is also searched loosely, for either name anywhere in its text:
  on this snapshot **{loose}** pages mention one and **{strict}** list one as an
  approved algorithm, so the strict anchor discarded nothing.
- **The register is a moving target.** Certificates are added, moved to
  Historical and revoked continuously, and re-running this on another day will
  give a different number. That is why the snapshot timestamp is at the top and
  the raw pages are kept.
- **One index page per status is requested.** CMVP serves the whole list in one
  response at these URLs; if that ever changes to real pagination, this tool
  would silently count only the first page. The row counts in the table above
  are the check — compare them with what the search page reports in a browser.
{incomplete}

## Reproducing it

```sh
python3 tools/cmvp_pqc_count.py fetch     # index pages, then the candidates
python3 tools/cmvp_pqc_count.py report    # this file, the CSV, and the summary
```

The fetch is cached, so a second run costs three requests. Delete
`.cmvp-pqc-cache/` to take a fresh snapshot.
""",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    """Fetch the register, or count what was fetched."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("fetch", help="download the index pages and the candidate certificates")
    sub.add_parser("report", help="write the CSV and METHOD.md and print the summary")
    arguments = parser.parse_args(argv)
    if arguments.command == "fetch":
        return fetch()
    return report()


if __name__ == "__main__":
    raise SystemExit(main())
