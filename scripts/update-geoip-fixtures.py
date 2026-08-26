#!/usr/bin/env python3
"""
update-geoip-fixtures.py — regenerate the smoke-test GeoIP fixtures from
MaxMind's own public test corpus (MaxMind-DB, dual Apache-2.0/MIT licensed,
redistributable with attribution: https://github.com/maxmind/MaxMind-DB).

Downloads GeoLite2-Country-Test.mmdb (binary database) and
GeoLite2-Country-Test.json (its source data, same 244 networks) from a pinned
commit, verifies each against a pinned sha256 digest, and writes 4 files into
tests/smoke/fixtures/ — named exactly as their on-box targets:

    GeoLite2-Country.mmdb               (byte-verbatim copy of the test mmdb)
    GeoLite2-Country-Locations-en.csv   (derived from the JSON source data)
    GeoLite2-Country-Blocks-IPv4.csv    (derived from the JSON source data)
    GeoLite2-Country-Blocks-IPv6.csv    (derived from the JSON source data)

The CSVs begin with the same dataset as the mmdb, then receive a deterministic
two-continent addendum for the continent-only GeoNames IDs that the upstream
test corpus omits. The upstream-derived rows drive both the CSV->`ugc` pipeline
and binary `mmdblookup` coverage; the CSV-only addendum exercises continent and
cc-file generation without modifying MaxMind's binary fixture.

The upstream-derived Blocks rows carry the corpus's real MaxMind test/public IP
space (67.43.156.0/24 et al.) because MMDB-backed tests need addresses the
database knows. The addendum is the deliberate RFC 5737/3849 exception: its
documentation addresses are CSV-only and never `mmdblookup` inputs. See
tests/smoke/fixtures/README.md for the full rationale; no traffic is sent to any
of these addresses.

Usage:
    python3 scripts/update-geoip-fixtures.py [--output DIR]

Re-run whenever MAXMIND_DB_COMMIT below is bumped to a newer MaxMind-DB
commit; a digest or row-count mismatch against the constants in this file is
a hard error (never silently reconciled — see the FAIL LOUD comments below).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ── Pinned source ────────────────────────────────────────────────────────────

MAXMIND_DB_COMMIT = "77c4d49493b99249ce631960a65776fae4aaa518"
RAW_URL = "https://raw.githubusercontent.com/maxmind/MaxMind-DB/{commit}/{path}"

MMDB_SRC_PATH = "test-data/GeoLite2-Country-Test.mmdb"
MMDB_SRC_SHA256 = "6996ce679243c7f719b901ebe3b490048af2fb5965163f083857533841154fd8"

JSON_SRC_PATH = "source-data/GeoLite2-Country-Test.json"
JSON_SRC_SHA256 = "444a9c27d83a4d00b6f3807d9afde3878c3502d3685fb807c1f22fe6382b4e19"

# Expected row counts for this pinned commit — a drift here means the corpus
# changed underneath us; regenerate the counts deliberately, don't patch them.
UPSTREAM_LOCATIONS_COUNT = 46
UPSTREAM_BLOCKS_V4_COUNT = 14
UPSTREAM_BLOCKS_V6_COUNT = 230
LOCATIONS_COUNT = 48
BLOCKS_V4_COUNT = 16
BLOCKS_V6_COUNT = 232

OUTPUT_FILENAMES = {
    "mmdb": "GeoLite2-Country.mmdb",
    "locations": "GeoLite2-Country-Locations-en.csv",
    "blocks_v4": "GeoLite2-Country-Blocks-IPv4.csv",
    "blocks_v6": "GeoLite2-Country-Blocks-IPv6.csv",
}

LOCATIONS_HEADER = [
    "geoname_id",
    "locale_code",
    "continent_code",
    "continent_name",
    "country_iso_code",
    "country_name",
    "is_in_european_union",
]
BLOCKS_HEADER = [
    "network",
    "geoname_id",
    "registered_country_geoname_id",
    "represented_country_geoname_id",
    "is_anonymous_proxy",
    "is_satellite_provider",
    "is_anycast",
]


class GeneratorError(Exception):
    """A hostile/drifted input the generator refuses to guess through."""


# ── Download + integrity ─────────────────────────────────────────────────────


def fetch_verified(repo_path: str, expected_sha256: str, *, timeout: float = 30.0) -> bytes:
    """Download a pinned-commit file and hard-fail on any digest mismatch."""
    url = RAW_URL.format(commit=MAXMIND_DB_COMMIT, path=repo_path)
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        data = resp.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise GeneratorError(
            f"{repo_path}: sha256 mismatch (expected {expected_sha256}, got {digest}) — "
            "MaxMind-DB content at the pinned commit changed; refusing to write any fixture"
        )
    return data


# ── JSON source-data model ───────────────────────────────────────────────────


@dataclass(frozen=True)
class LocationRow:
    geoname_id: int
    continent_code: str
    continent_name: str
    iso_code: str
    country_name: str
    is_in_eu: bool


@dataclass(frozen=True)
class BlockRow:
    network: str
    geoname_id: str
    registered_geoname_id: str
    represented_geoname_id: str
    is_anonymous_proxy: bool = False
    is_satellite_provider: bool = False
    is_anycast: bool = False


CONTINENT_ADDENDUM_LOCATIONS = (
    LocationRow(6255147, "AS", "Asia", "", "", False),
    LocationRow(6255148, "EU", "Europe", "", "", False),
)
CONTINENT_ADDENDUM_BLOCKS_V4 = (
    BlockRow("192.0.2.147/32", "6255147", "", ""),
    BlockRow("192.0.2.148/32", "6255148", "", ""),
)
CONTINENT_ADDENDUM_BLOCKS_V6 = (
    BlockRow("2001:db8:6255:147::/128", "6255147", "", ""),
    BlockRow("2001:db8:6255:148::/128", "6255148", "", ""),
)


def load_records(json_bytes: bytes) -> list[tuple[str, dict[str, Any]]]:
    """Parse the source JSON list of ``{"<network>": {<record>}}`` into pairs."""
    data = json.loads(json_bytes)
    records: list[tuple[str, dict[str, Any]]] = []
    for item in data:
        ((network, rec),) = item.items()
        records.append((network, rec))
    return records


def build_locations(records: list[tuple[str, dict[str, Any]]]) -> dict[int, LocationRow]:
    """One row per geoname that appears as a record's ``country``.

    A ``registered_country``/``represented_country`` sub-record carries no
    continent of its own — deriving a row from one would silently assign the
    wrong continent. FAIL LOUD instead of guessing when a geoname's own
    ``country`` appearances disagree with each other.
    """
    locations: dict[int, LocationRow] = {}
    for network, rec in records:
        country = rec.get("country")
        if country is None:
            continue
        try:
            gid = country["geoname_id"]
            continent = rec["continent"]
            row = LocationRow(
                geoname_id=gid,
                continent_code=continent["code"],
                continent_name=continent["names"]["en"],
                iso_code=country["iso_code"],
                country_name=country["names"]["en"],
                is_in_eu=bool(country.get("is_in_european_union", False)),
            )
        except KeyError as exc:
            raise GeneratorError(f"{network}: country record missing {exc} (iso_code/name/continent)") from exc
        existing = locations.get(gid)
        if existing is not None and existing != row:
            raise GeneratorError(
                f"{network}: geoname {gid} already has a conflicting Locations row "
                f"({existing} vs {row}) — refusing to guess a continent"
            )
        locations[gid] = row
    return locations


def _require_known(gid: int | None, network: str, role: str, locations: dict[int, LocationRow]) -> None:
    if gid is not None and gid not in locations:
        raise GeneratorError(f"{network}: {role} geoname {gid} has no Locations row")


def build_blocks(
    records: list[tuple[str, dict[str, Any]]], locations: dict[int, LocationRow]
) -> tuple[list[BlockRow], list[BlockRow]]:
    """Split records into IPv4/IPv6 Blocks rows, preserving the JSON's own order."""
    v4: list[BlockRow] = []
    v6: list[BlockRow] = []
    for network, rec in records:
        try:
            country = rec.get("country")
            gid = country["geoname_id"] if country else None
            registered = rec.get("registered_country")
            reg_gid = registered["geoname_id"] if registered else None
            represented = rec.get("represented_country")
            rep_gid = represented["geoname_id"] if represented else None
        except KeyError as exc:
            raise GeneratorError(f"{network}: country sub-record missing {exc}") from exc

        for role, g in (("country", gid), ("registered_country", reg_gid), ("represented_country", rep_gid)):
            _require_known(g, network, role, locations)

        traits = rec.get("traits") or {}
        row = BlockRow(
            network=network,
            geoname_id="" if gid is None else str(gid),
            registered_geoname_id="" if reg_gid is None else str(reg_gid),
            represented_geoname_id="" if rep_gid is None else str(rep_gid),
            is_anonymous_proxy=bool(traits.get("is_anonymous_proxy", False)),
            is_satellite_provider=bool(traits.get("is_satellite_provider", False)),
            is_anycast=bool(traits.get("is_anycast", False)),
        )
        target = v4 if ipaddress.ip_network(network).version == 4 else v6
        target.append(row)
    return v4, v6


def apply_continent_addendum(
    locations: dict[int, LocationRow], blocks_v4: list[BlockRow], blocks_v6: list[BlockRow]
) -> tuple[dict[int, LocationRow], list[BlockRow], list[BlockRow]]:
    """Add continent-only fixture rows, failing if the pinned corpus collides."""
    result_locations = dict(locations)
    result_v4 = list(blocks_v4)
    result_v6 = list(blocks_v6)
    for row in CONTINENT_ADDENDUM_LOCATIONS:
        if row.geoname_id in result_locations:
            raise GeneratorError(f"continent addendum geoname collision: {row.geoname_id}")
        result_locations[row.geoname_id] = row
    for rows, addendum in (
        (result_v4, CONTINENT_ADDENDUM_BLOCKS_V4),
        (result_v6, CONTINENT_ADDENDUM_BLOCKS_V6),
    ):
        networks = {row.network for row in rows}
        for row in addendum:
            if row.network in networks:
                raise GeneratorError(f"continent addendum network collision: {row.network}")
            rows.append(row)
            networks.add(row.network)
    return result_locations, result_v4, result_v6


# ── CSV writers (MaxMind schema: header + column order verbatim) ──────────


def write_locations_csv(path: Path, locations: dict[int, LocationRow]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(LOCATIONS_HEADER)
        for gid in sorted(locations):
            row = locations[gid]
            writer.writerow(
                [
                    row.geoname_id,
                    "en",
                    row.continent_code,
                    row.continent_name,
                    row.iso_code,
                    row.country_name,
                    "1" if row.is_in_eu else "0",
                ]
            )


def write_blocks_csv(path: Path, rows: list[BlockRow]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(BLOCKS_HEADER)
        for row in rows:
            writer.writerow(
                [
                    row.network,
                    row.geoname_id,
                    row.registered_geoname_id,
                    row.represented_geoname_id,
                    # MaxMind renders the two legacy flags 0/1 and is_anycast 1-or-empty.
                    "1" if row.is_anonymous_proxy else "0",
                    "1" if row.is_satellite_provider else "0",
                    "1" if row.is_anycast else "",
                ]
            )


def _check_counts(
    locations: dict[int, LocationRow],
    blocks_v4: list[BlockRow],
    blocks_v6: list[BlockRow],
    expected_counts: tuple[int, int, int],
) -> None:
    for label, actual, expected in (
        ("Locations", len(locations), expected_counts[0]),
        ("Blocks-IPv4", len(blocks_v4), expected_counts[1]),
        ("Blocks-IPv6", len(blocks_v6), expected_counts[2]),
    ):
        if actual != expected:
            raise GeneratorError(f"{label} count drifted: expected {expected}, got {actual}")


def check_upstream_counts(
    locations: dict[int, LocationRow], blocks_v4: list[BlockRow], blocks_v6: list[BlockRow]
) -> None:
    """Refuse a pinned upstream corpus whose row counts drifted."""
    _check_counts(
        locations,
        blocks_v4,
        blocks_v6,
        (UPSTREAM_LOCATIONS_COUNT, UPSTREAM_BLOCKS_V4_COUNT, UPSTREAM_BLOCKS_V6_COUNT),
    )


def check_counts(locations: dict[int, LocationRow], blocks_v4: list[BlockRow], blocks_v6: list[BlockRow]) -> None:
    """Refuse final fixtures whose row counts drifted."""
    _check_counts(locations, blocks_v4, blocks_v6, (LOCATIONS_COUNT, BLOCKS_V4_COUNT, BLOCKS_V6_COUNT))


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--output",
        default="tests/smoke/fixtures",
        metavar="DIR",
        help="Output directory for the 4 generated fixture files (default: tests/smoke/fixtures)",
    )
    args = parser.parse_args()
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Fetching MaxMind-DB @ {MAXMIND_DB_COMMIT[:12]} ...")
    mmdb_bytes = fetch_verified(MMDB_SRC_PATH, MMDB_SRC_SHA256)
    json_bytes = fetch_verified(JSON_SRC_PATH, JSON_SRC_SHA256)
    print(f"  {MMDB_SRC_PATH}: {len(mmdb_bytes)} bytes, sha256 verified")
    print(f"  {JSON_SRC_PATH}: {len(json_bytes)} bytes, sha256 verified")

    records = load_records(json_bytes)
    locations = build_locations(records)
    blocks_v4, blocks_v6 = build_blocks(records, locations)
    check_upstream_counts(locations, blocks_v4, blocks_v6)
    locations, blocks_v4, blocks_v6 = apply_continent_addendum(locations, blocks_v4, blocks_v6)
    check_counts(locations, blocks_v4, blocks_v6)

    (out_dir / OUTPUT_FILENAMES["mmdb"]).write_bytes(mmdb_bytes)
    write_locations_csv(out_dir / OUTPUT_FILENAMES["locations"], locations)
    write_blocks_csv(out_dir / OUTPUT_FILENAMES["blocks_v4"], blocks_v4)
    write_blocks_csv(out_dir / OUTPUT_FILENAMES["blocks_v6"], blocks_v6)

    print(
        f"Wrote {len(OUTPUT_FILENAMES)} files to {out_dir}/: "
        f"{len(locations)} locations, {len(blocks_v4)} v4 blocks, {len(blocks_v6)} v6 blocks"
    )


if __name__ == "__main__":
    try:
        main()
    except GeneratorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
