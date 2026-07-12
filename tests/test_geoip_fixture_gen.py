"""Tests for scripts/update-geoip-fixtures.py (issue #1228).

The generator turns MaxMind-DB's own public test-corpus JSON into the smoke
suite's GeoIP CSV fixtures. Every guard here pins a hard-fail the generator
must never silently work around (the continent trap chief among them: a
``registered_country``/``represented_country`` sub-record carries no continent
of its own, so deriving a Locations row from one would assign the wrong
continent).

No network, no committed-fixture reads: every test drives the pure
``build_locations`` / ``build_blocks`` / ``write_*_csv`` functions directly
against tiny hand-built record dicts shaped like MaxMind-DB's own JSON.

Loaded by path via importlib (scripts/ is not a package), same pattern as
tests/test_update_tld_lists.py.
"""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "update-geoip-fixtures.py"
_spec = importlib.util.spec_from_file_location("update_geoip_fixtures", _SCRIPT)
assert _spec is not None and _spec.loader is not None
m = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = m
_spec.loader.exec_module(m)


def _country(geoname_id: int, iso: str, name: str, *, eu: bool = False) -> dict[str, object]:
    return {"geoname_id": geoname_id, "iso_code": iso, "names": {"en": name}, "is_in_european_union": eu}


def _continent(code: str, geoname_id: int, name: str) -> dict[str, object]:
    return {"code": code, "geoname_id": geoname_id, "names": {"en": name}}


# --------------------------------------------------------------------------- #
# A normal record -> exact Locations + Blocks rows
# --------------------------------------------------------------------------- #


def test_normal_record_yields_exact_locations_and_blocks_rows() -> None:
    records = [
        (
            "81.2.69.0/24",
            {"continent": _continent("EU", 6255148, "Europe"), "country": _country(2635167, "GB", "United Kingdom")},
        ),
    ]
    locations = m.build_locations(records)
    assert locations[2635167] == m.LocationRow(
        geoname_id=2635167,
        continent_code="EU",
        continent_name="Europe",
        iso_code="GB",
        country_name="United Kingdom",
        is_in_eu=False,
    )
    v4, v6 = m.build_blocks(records, locations)
    assert v4 == [
        m.BlockRow(network="81.2.69.0/24", geoname_id="2635167", registered_geoname_id="", represented_geoname_id="")
    ]
    assert v6 == []


def test_ipv6_network_lands_in_the_v6_split() -> None:
    records = [
        (
            "2001:218::/32",
            {"continent": _continent("AS", 6255147, "Asia"), "country": _country(1861060, "JP", "Japan")},
        ),
    ]
    locations = m.build_locations(records)
    v4, v6 = m.build_blocks(records, locations)
    assert v4 == []
    assert v6 == [
        m.BlockRow(network="2001:218::/32", geoname_id="1861060", registered_geoname_id="", represented_geoname_id="")
    ]


# --------------------------------------------------------------------------- #
# write_locations_csv / write_blocks_csv -- MaxMind schema: column order, en
# locale, is_in_european_union 0/1, is_anycast empty-when-false
# --------------------------------------------------------------------------- #


def test_write_locations_csv_column_order_and_locale(tmp_path: Path) -> None:
    locations = {2635167: m.LocationRow(2635167, "EU", "Europe", "GB", "United Kingdom", False)}
    path = tmp_path / "loc.csv"
    m.write_locations_csv(path, locations)
    rows = list(csv.reader(path.open(newline="", encoding="utf-8")))
    assert rows[0] == m.LOCATIONS_HEADER
    assert rows[1] == ["2635167", "en", "EU", "Europe", "GB", "United Kingdom", "0"]


def test_write_locations_csv_is_in_eu_true_renders_1(tmp_path: Path) -> None:
    locations = {798549: m.LocationRow(798549, "EU", "Europe", "RO", "Romania", True)}
    path = tmp_path / "loc.csv"
    m.write_locations_csv(path, locations)
    rows = list(csv.reader(path.open(newline="", encoding="utf-8")))
    assert rows[1][-1] == "1"


def test_write_blocks_csv_is_anycast_empty_when_false(tmp_path: Path) -> None:
    rows_in = [
        m.BlockRow(
            network="67.43.156.0/24", geoname_id="1252634", registered_geoname_id="798549", represented_geoname_id=""
        )
    ]
    path = tmp_path / "blocks.csv"
    m.write_blocks_csv(path, rows_in)
    rows = list(csv.reader(path.open(newline="", encoding="utf-8")))
    assert rows[0] == m.BLOCKS_HEADER
    assert rows[1] == ["67.43.156.0/24", "1252634", "798549", "", "0", "0", ""]


# --------------------------------------------------------------------------- #
# A geoname referenced only as registered_country/represented_country
# (never its own record's `country`) has no continent of its own: raise,
# never guess.
# --------------------------------------------------------------------------- #


def test_registered_country_only_geoname_raises() -> None:
    # Given: a network whose `country` (GB) is known, but whose
    # `registered_country` (a made-up geoname) never appears as anyone's
    # `country` -- it has no Locations row and no continent of its own.
    records = [
        (
            "1.2.3.0/24",
            {
                "continent": _continent("EU", 6255148, "Europe"),
                "country": _country(2635167, "GB", "United Kingdom"),
                "registered_country": _country(9999001, "ZZ", "Nowhereland"),
            },
        ),
    ]
    locations = m.build_locations(records)
    assert 9999001 not in locations
    # When/Then: deriving Blocks rows refuses to guess a continent for it.
    with pytest.raises(m.GeneratorError, match="9999001"):
        m.build_blocks(records, locations)


def test_represented_country_only_geoname_raises() -> None:
    records = [
        (
            "202.196.224.0/20",
            {
                "continent": _continent("AS", 6255147, "Asia"),
                "country": _country(1694008, "PH", "Philippines"),
                "represented_country": _country(9999002, "ZZ", "Nowhereland"),
            },
        ),
    ]
    locations = m.build_locations(records)
    assert 9999002 not in locations
    with pytest.raises(m.GeneratorError, match="9999002"):
        m.build_blocks(records, locations)


def test_blocks_row_own_country_geoname_missing_from_locations_raises() -> None:
    # A generic (not just registered/represented) missing-Locations-row guard:
    # even the row's own `country` geoname must be known.
    records = [
        (
            "1.2.3.0/24",
            {"continent": _continent("EU", 6255148, "Europe"), "country": _country(555, "ZZ", "Nowhereland")},
        )
    ]
    with pytest.raises(m.GeneratorError, match="555"):
        m.build_blocks(records, locations={})


# --------------------------------------------------------------------------- #
# A country record missing iso_code / names.en / continent -> raise, naming
# the network
# --------------------------------------------------------------------------- #


def test_country_missing_iso_code_raises() -> None:
    records = [
        (
            "1.2.3.0/24",
            {"continent": _continent("EU", 6255148, "Europe"), "country": {"geoname_id": 1, "names": {"en": "X"}}},
        )
    ]
    with pytest.raises(m.GeneratorError, match="1.2.3.0/24"):
        m.build_locations(records)


def test_country_missing_names_en_raises() -> None:
    records = [
        (
            "1.2.3.0/24",
            {
                "continent": _continent("EU", 6255148, "Europe"),
                "country": {"geoname_id": 1, "iso_code": "ZZ", "names": {}},
            },
        )
    ]
    with pytest.raises(m.GeneratorError, match="1.2.3.0/24"):
        m.build_locations(records)


def test_record_missing_continent_raises() -> None:
    records = [("1.2.3.0/24", {"country": _country(1, "ZZ", "Nowhereland")})]
    with pytest.raises(m.GeneratorError, match="1.2.3.0/24"):
        m.build_locations(records)


# --------------------------------------------------------------------------- #
# Country name containing a comma -> quoted by csv.writer, round-trips
# --------------------------------------------------------------------------- #


def test_country_name_with_comma_is_quoted_and_round_trips(tmp_path: Path) -> None:
    locations = {512: m.LocationRow(512, "NA", "North America", "BQ", "Bonaire, Sint Eustatius and Saba", False)}
    path = tmp_path / "loc.csv"
    m.write_locations_csv(path, locations)
    raw = path.read_text(encoding="utf-8")
    assert '"Bonaire, Sint Eustatius and Saba"' in raw
    rows = list(csv.reader(path.open(newline="", encoding="utf-8")))
    assert rows[1][5] == "Bonaire, Sint Eustatius and Saba"


# --------------------------------------------------------------------------- #
# Non-ASCII country name -> UTF-8, unmangled
# --------------------------------------------------------------------------- #


def test_non_ascii_country_name_is_utf8_and_unmangled(tmp_path: Path) -> None:
    locations = {129: m.LocationRow(129, "NA", "North America", "CW", "Curaçao", False)}
    path = tmp_path / "loc.csv"
    m.write_locations_csv(path, locations)
    rows = list(csv.reader(path.open(newline="", encoding="utf-8")))
    assert rows[1][5] == "Curaçao"


# --------------------------------------------------------------------------- #
# Continent authority (the real corpus shape): the same geoname appears as a
# `country` under one continent AND as a `registered_country` under another
# record's DIFFERENT continent -- the country-role record wins, always.
# --------------------------------------------------------------------------- #


def test_continent_authority_country_role_wins_over_registered_country_role() -> None:
    # Given: US is the network's own `country` in one record (continent NA)
    # and merely the `registered_country` of an unrelated GB-country record
    # whose OWN continent is EU (US appears under {NA, AS, EU} in the real
    # corpus, entirely via registered_country/represented_country contexts).
    us_home = (
        "50.114.0.0/22",
        {"continent": _continent("NA", 6255149, "North America"), "country": _country(6252001, "US", "United States")},
    )
    gb_exclave_in_us = (
        "81.2.69.144/28",
        {
            "continent": _continent("EU", 6255148, "Europe"),
            "country": _country(2635167, "GB", "United Kingdom"),
            "registered_country": _country(6252001, "US", "United States"),
        },
    )
    # When: Locations rows are derived from both.
    locations = m.build_locations([us_home, gb_exclave_in_us])
    # Then: US keeps NA (its own `country` appearance) -- EU, reached only via
    # the other record's registered_country context, never leaks in. A
    # regression that folds registered_country into the derivation loop would
    # either flip this to EU or raise a spurious "conflicting row" error.
    assert locations[6252001].continent_code == "NA"
    assert locations[2635167].continent_code == "EU"


# --------------------------------------------------------------------------- #
# traits -- the flag columns come FROM the record, never from a constant. The
# pinned GeoLite2 corpus carries none (issue #1221: real GeoLite2 ships zero
# proxy/satellite rows), so a hardcoded "0,0," would look right today and go
# silently wrong the moment the pin moves to a corpus that does carry them.
# --------------------------------------------------------------------------- #


def test_traits_bearing_record_renders_its_flag_columns(tmp_path: Path) -> None:
    records = [
        (
            "212.47.235.81/32",
            {
                "continent": _continent("EU", 6255148, "Europe"),
                "country": _country(2635167, "GB", "United Kingdom"),
                "traits": {"is_anonymous_proxy": True, "is_satellite_provider": True, "is_anycast": True},
            },
        ),
    ]
    locations = m.build_locations(records)
    v4, _ = m.build_blocks(records, locations)
    assert v4[0].is_anonymous_proxy and v4[0].is_satellite_provider and v4[0].is_anycast

    path = tmp_path / "blocks.csv"
    m.write_blocks_csv(path, v4)
    rows = list(csv.reader(path.open(newline="", encoding="utf-8")))
    assert rows[1] == ["212.47.235.81/32", "2635167", "", "", "1", "1", "1"]


def test_traitless_record_renders_zero_zero_empty(tmp_path: Path) -> None:
    records = [
        (
            "67.43.156.0/24",
            {"continent": _continent("AS", 6255147, "Asia"), "country": _country(1252634, "BT", "Bhutan")},
        ),
    ]
    locations = m.build_locations(records)
    v4, _ = m.build_blocks(records, locations)
    path = tmp_path / "blocks.csv"
    m.write_blocks_csv(path, v4)
    rows = list(csv.reader(path.open(newline="", encoding="utf-8")))
    assert rows[1] == ["67.43.156.0/24", "1252634", "", "", "0", "0", ""]


# --------------------------------------------------------------------------- #
# The two FAIL-LOUD guards the script's header advertises: a download whose
# sha256 does not match the pinned digest, and a corpus whose row counts drifted
# from the pinned commit's. Both must raise -- a silently reconciled fixture is
# exactly the drift these constants exist to catch.
# --------------------------------------------------------------------------- #


def test_sha256_mismatch_raises_and_writes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Resp:
        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def read(self) -> bytes:
            return b"not the pinned bytes"

    monkeypatch.setattr(m.urllib.request, "urlopen", lambda *_a, **_k: _Resp())
    with pytest.raises(m.GeneratorError, match="sha256 mismatch"):
        m.fetch_verified(m.MMDB_SRC_PATH, m.MMDB_SRC_SHA256)


def test_sha256_match_returns_the_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = b"pinned"
    digest = hashlib.sha256(payload).hexdigest()

    class _Resp:
        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def read(self) -> bytes:
            return payload

    monkeypatch.setattr(m.urllib.request, "urlopen", lambda *_a, **_k: _Resp())
    assert m.fetch_verified("any/path", digest) == payload


@pytest.mark.parametrize(
    ("locations", "v4", "v6", "expected"),
    [
        (m.LOCATIONS_COUNT - 1, m.BLOCKS_V4_COUNT, m.BLOCKS_V6_COUNT, "Locations count drifted"),
        (m.LOCATIONS_COUNT, m.BLOCKS_V4_COUNT + 1, m.BLOCKS_V6_COUNT, "Blocks-IPv4 count drifted"),
        (m.LOCATIONS_COUNT, m.BLOCKS_V4_COUNT, m.BLOCKS_V6_COUNT - 1, "Blocks-IPv6 count drifted"),
    ],
)
def test_row_count_drift_raises_per_file(locations: int, v4: int, v6: int, expected: str) -> None:
    row = m.BlockRow(network="1.2.3.0/24", geoname_id="1", registered_geoname_id="", represented_geoname_id="")
    loc = m.LocationRow(1, "EU", "Europe", "GB", "United Kingdom", False)
    with pytest.raises(m.GeneratorError, match=expected):
        m.check_counts(dict.fromkeys(range(locations), loc), [row] * v4, [row] * v6)


def test_pinned_counts_pass_the_drift_check() -> None:
    row = m.BlockRow(network="1.2.3.0/24", geoname_id="1", registered_geoname_id="", represented_geoname_id="")
    loc = m.LocationRow(1, "EU", "Europe", "GB", "United Kingdom", False)
    m.check_counts(dict.fromkeys(range(m.LOCATIONS_COUNT), loc), [row] * m.BLOCKS_V4_COUNT, [row] * m.BLOCKS_V6_COUNT)


def test_blocks_sub_record_missing_geoname_id_raises() -> None:
    # A country/registered/represented sub-record with no geoname_id must fail loud as a
    # GeneratorError naming the network -- never the raw KeyError a direct read would throw.
    records = [
        (
            "81.2.69.0/24",
            {
                "continent": _continent("EU", 6255148, "Europe"),
                "country": _country(2635167, "GB", "United Kingdom"),
                "registered_country": {"iso_code": "US", "names": {"en": "United States"}},
            },
        ),
    ]
    locations = m.build_locations(records)
    with pytest.raises(m.GeneratorError, match=r"81\.2\.69\.0/24: country sub-record missing"):
        m.build_blocks(records, locations)
