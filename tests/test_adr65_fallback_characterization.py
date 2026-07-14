"""ADR-65 Phase 1 -- Oracle B: characterize (never equate) the legacy
py_data/py_zone interchange-file fallback.

WHY THIS FILE EXISTS
--------------------
ADR.md SS1.1 (re-derived phase 0, 2026-07-14) makes four factual claims about
the fallback that ONLY runs on a manifest-build failure -- Phase 5 removes it
entirely (fail-loud instead), so those claims need pinning BEFORE the removal,
not asserted-and-trusted:

  (a) TRIGGER   -- the legacy loaders populate the DBs ONLY when
                   ``dnsbl_build_from_manifest`` returned ``None``.
  (b) LOSSY     -- every NDJSON 'abp' row is silently skipped
                   (``_load_ndjson_row_into_db``:925); ``regexDB``/
                   ``allowRegexDB`` are populated ONLY by the manifest build.
  (c) STALE-ABLE -- the loaders read whatever ``.txt`` exists, no freshness
                   check -- serves orphaned content verbatim on a build
                   failure. This is Phase 5's RED baseline.
  (d) FRESH PLAIN-DOMAIN PARITY -- a freshly-produced interchange file agrees
                   with the manifest build's zone/data split for every PLAIN
                   domain, in BOTH toggle states (the ONLY respect in which the
                   fallback is decision-aligned with production -- ABP rows
                   are excluded, that is fact (b)).

None of these assert manifest == fallback (the fallback is lossy and
stale-able); this is a CHARACTERIZATION of what the degraded path actually
does, each fact pinned as its own test with real payload assertions (never key
presence alone -- CLAUDE.md "no coverage theater"). A failure of fact (d), or a
fallback load running while the manifest built, falsifies an ADR SS1.1 claim
-- ESCALATE, never patch the plan.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from typing import Any

import pfb_unbound

_TLD_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "dnsbl_corpus", "tld")


def _read_ndjson_domains(name: str) -> list[str]:
    """Domain names carried by a golden NDJSON fixture's 'domain' rows -- 'abp'/
    cosmetic rows excluded (fact (b) covers those on their own)."""
    domains: list[str] = []
    with open(os.path.join(_TLD_DIR, name), encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("kind") == "domain":
                domains.append(row["domain"])
    return domains


# --------------------------------------------------------------------------- #
# Fact (a) -- TRIGGER: the legacy loaders run iff the manifest did NOT build.
# --------------------------------------------------------------------------- #


class TestFactATrigger:
    """``_load_zone_and_data_dbs(dnsbl_built, ...)`` (pfb_unbound.py:1045-1055):
    ``dnsbl_built=False`` -> the seeded files populate dataDB/zoneDB;
    ``dnsbl_built=True`` -> NEITHER loader runs -- it populates nothing, and
    closes the parse-stage ledger entries the loaders would have owned
    (issue #1049). ``dnsbl_built`` is True iff ``dnsbl_build_from_manifest``
    returned non-None (init wiring, :1657-1693)."""

    def test_dnsbl_built_true_populates_nothing_and_closes_ledger(self, tmp_path: Any) -> None:
        zone_path, data_path = _seed_zone_and_data(tmp_path)
        pfb_unbound.pfb["pfb_py_zone"] = zone_path
        pfb_unbound.pfb["pfb_py_data"] = data_path
        status_path = tmp_path / "pfb_py_status.json"
        pfb_unbound.pfb["pfb_py_status"] = str(status_path)

        # Pre-open ledger entries the way a PRIOR failed load would have, so the
        # dnsbl_built=True close-path has something real to clear.
        pfb_unbound.pfb_py_status_open("dnsbl", zone_path, "parse", "prior failure")
        pfb_unbound.pfb_py_status_open("dnsbl", data_path, "parse", "prior failure")

        feed_group_db: defaultdict[str, int] = defaultdict(int)
        pfb_unbound._load_zone_and_data_dbs(True, feed_group_db, 0)

        assert dict(pfb_unbound.zoneDB) == {}
        assert dict(pfb_unbound.dataDB) == {}
        with open(status_path, encoding="utf-8") as fh:
            entries = json.load(fh)
        assert entries == []  # both parse-stage entries closed, none left open

    def test_dnsbl_built_false_populates_from_the_seeded_files(self, tmp_path: Any) -> None:
        zone_path, data_path = _seed_zone_and_data(tmp_path)
        pfb_unbound.pfb["pfb_py_zone"] = zone_path
        pfb_unbound.pfb["pfb_py_data"] = data_path

        feed_group_db: defaultdict[str, int] = defaultdict(int)
        pfb_unbound._load_zone_and_data_dbs(False, feed_group_db, 0)

        assert "seeded-zone.uuidb001.net" in pfb_unbound.zoneDB
        assert "seeded-data.uuidb001.com" in pfb_unbound.dataDB


# --------------------------------------------------------------------------- #
# Fact (b) -- LOSSY: every 'abp' NDJSON row is silently skipped by the legacy
# loaders; regexDB/allowRegexDB are populated ONLY by the manifest build. The
# SAME logical ABP content, through the REAL manifest build, DOES carry them --
# real payloads asserted (compiled regex actually matching), never key presence.
# --------------------------------------------------------------------------- #


class TestFactBLossiness:
    def test_legacy_loader_drops_every_abp_derived_rule(self, tmp_path: Any) -> None:
        rows = [
            {"kind": "domain", "domain": "legacy-plain.uuidb002.com", "log": "1", "feed": "F", "group": "G"},
            {"kind": "abp", "raw": "||legacy-abp-zone.uuidb002.net^"},
            {"kind": "abp", "raw": "/^legacy-abp-data[0-9]\\.uuidb002\\.org$/"},
            {"kind": "abp", "raw": "@@/^legacy-allow[0-9]\\.uuidb002\\.org$/"},
        ]
        pfb_unbound.pfb["pfb_py_data"] = _write_ndjson(rows, tmp_path)
        pfb_unbound.pfb["pfb_py_zone"] = str(tmp_path / "pfb_py_zone.txt")  # never written -> zone loader no-ops

        feed_group_db: defaultdict[str, int] = defaultdict(int)
        idx = pfb_unbound._load_zone_db(feed_group_db, 0)
        pfb_unbound._load_data_db(feed_group_db, idx)

        # ONLY the plain domain row landed -- an exact payload check, not membership.
        assert dict(pfb_unbound.dataDB) == {"legacy-plain.uuidb002.com": {"log": "1", "index": 0, "important": False}}
        assert dict(pfb_unbound.zoneDB) == {}
        assert dict(pfb_unbound.regexDB) == {}  # loaders never write these DBs at all
        assert dict(pfb_unbound.allowRegexDB) == {}

    def test_manifest_build_over_the_same_abp_content_carries_it(self) -> None:
        lines = [
            "legacy-plain.uuidb002.com",
            "||legacy-abp-zone.uuidb002.net^",
            "/^legacy-abp-data[0-9]\\.uuidb002\\.org$/",
            "@@/^legacy-allow[0-9]\\.uuidb002\\.org$/",
        ]
        manifest = {"feeds": [{"raw": "feed.raw", "feed": "F", "group": "G", "log_flag": "1"}]}
        config = _empty_build_config()

        result = pfb_unbound.build(manifest, config, line_reader=lambda _raw: lines)

        assert "legacy-plain.uuidb002.com" in result.data_db
        assert "legacy-abp-zone.uuidb002.net" in result.zone_db  # ABP zone, absent from any loader
        assert result.regex_db, "manifest build must carry the irreducible block regex"
        assert any(v["re"].match("legacy-abp-data7.uuidb002.org") for v in result.regex_db.values())
        assert result.allow_regex_db, "manifest build must carry the irreducible allow regex"
        assert any(v["re"].match("legacy-allow3.uuidb002.org") for v in result.allow_regex_db.values())


# --------------------------------------------------------------------------- #
# Fact (c) -- STALE-ABLE: on a build failure, the loaders serve whatever
# content sits on disk verbatim, even a domain absent from every CURRENT
# manifest input. This is Phase 5's RED baseline -- named for that intent.
# --------------------------------------------------------------------------- #


class TestFactCStaleness:
    def test_stale_interchange_served_verbatim_on_build_failure(self, tmp_path: Any) -> None:
        """Pins CURRENT pre-ADR-65 behaviour: a manifest-build failure (absent
        manifest, dnsbl_build_from_manifest:5365-5369) still runs the legacy
        loaders (dnsbl_built stays False, init wiring :1657-1698), which serve
        an ORPHANED domain -- one no current manifest input carries -- verbatim.
        Phase 5 removes this path (fail-loud instead of stale-serve, ADR.md SS2.3)."""
        manifest_path = tmp_path / "pfb_py_sources.json"  # never written -> absent manifest
        stale_row = {
            "kind": "domain",
            "domain": "stale-orphan.uuidb003.com",
            "log": "1",
            "feed": "OldFeed",
            "group": "OldGroup",
        }
        pfb_unbound.pfb["pfb_py_data"] = _write_ndjson([stale_row], tmp_path)
        pfb_unbound.pfb["pfb_py_zone"] = str(tmp_path / "pfb_py_zone.txt")  # absent
        pfb_unbound.pfb["pfb_py_status"] = str(tmp_path / "pfb_py_status.json")

        build_result = pfb_unbound.dnsbl_build_from_manifest(str(manifest_path))
        assert build_result is None  # manifest absent -> build failed
        dnsbl_built = build_result is not None

        feed_group_db: defaultdict[str, int] = defaultdict(int)
        pfb_unbound._load_zone_and_data_dbs(dnsbl_built, feed_group_db, 0)

        assert "stale-orphan.uuidb003.com" in pfb_unbound.dataDB


# --------------------------------------------------------------------------- #
# Fact (d) -- FRESH PLAIN-DOMAIN PARITY: a freshly-produced interchange file
# agrees with the manifest build's zone/data split for every plain domain, in
# BOTH toggle states. Reuses the committed golden TLD-analysis corpus
# (tests/fixtures/dnsbl_corpus/tld/), already driven through the REAL legacy
# loaders by test_issue1083's Scenario A.
# --------------------------------------------------------------------------- #


class TestFactDFreshPlainDomainParity:
    def test_fresh_files_agree_with_manifest_build_when_tld_wildcard_on(self) -> None:
        # 1) The REAL legacy loaders over the golden (freshly-produced) files.
        pfb_unbound.pfb["pfb_py_zone"] = os.path.join(_TLD_DIR, "golden_pfb_py_zone.txt")
        pfb_unbound.pfb["pfb_py_data"] = os.path.join(_TLD_DIR, "golden_pfb_py_data.txt")
        feed_group_db: defaultdict[str, int] = defaultdict(int)
        idx = pfb_unbound._load_zone_db(feed_group_db, 0)
        pfb_unbound._load_data_db(feed_group_db, idx)
        loader_zone_keys = set(pfb_unbound.zoneDB.keys())
        loader_data_keys = set(pfb_unbound.dataDB.keys())

        # 2) The manifest BUILD over the SAME plain-domain content (the 'abp'/
        # cosmetic row in pfb_dnsbl_plain.txt excluded -- fact (b)), tld oracle ON.
        domains = _read_ndjson_domains("pfb_dnsbl_plain.txt")
        with open(os.path.join(_TLD_DIR, "tld_master.txt"), encoding="utf-8") as fh:
            tld_master_lines = fh.read().splitlines()
        manifest = {
            "feeds": [{"raw": "feed.raw", "feed": "tld_plain_feed", "group": "tld_plain_feed", "log_flag": "1"}]
        }
        config = _empty_build_config()
        config["tld_wildcard_master"] = tld_master_lines
        result = pfb_unbound.build(manifest, config, line_reader=lambda _raw: domains)

        assert loader_zone_keys == set(result.zone_db.keys()) == {"twolabelzone.example", "biz.co.zzsuffix"}
        assert loader_data_keys == set(result.data_db.keys()) == {"www.biz.co.zzsuffix"}

    def test_fresh_files_agree_with_manifest_build_when_tld_wildcard_off(self, tmp_path: Any) -> None:
        # 1) Synthesize the OFF-state fresh file: pfb_dnsbl_py_swap() renames the
        # WHOLE assembled raw verbatim to pfb_py_data.txt when pfb_tld is OFF --
        # every plain domain becomes an unclassified 'domain' data row, zone
        # file absent (ADR.md SS1.2).
        domains = _read_ndjson_domains("pfb_dnsbl_plain.txt")
        rows = [
            {"kind": "domain", "domain": d, "log": "1", "feed": "tld_plain_feed", "group": "tld_plain_feed"}
            for d in domains
        ]
        pfb_unbound.pfb["pfb_py_data"] = _write_ndjson(rows, tmp_path)
        pfb_unbound.pfb["pfb_py_zone"] = str(tmp_path / "pfb_py_zone.txt")  # never written -> absent

        feed_group_db: defaultdict[str, int] = defaultdict(int)
        idx = pfb_unbound._load_zone_db(feed_group_db, 0)
        pfb_unbound._load_data_db(feed_group_db, idx)
        loader_zone_keys = set(pfb_unbound.zoneDB.keys())
        loader_data_keys = set(pfb_unbound.dataDB.keys())

        # 2) The manifest BUILD over the SAME domains, EMPTY tld oracle (OFF).
        manifest = {
            "feeds": [{"raw": "feed.raw", "feed": "tld_plain_feed", "group": "tld_plain_feed", "log_flag": "1"}]
        }
        result = pfb_unbound.build(manifest, _empty_build_config(), line_reader=lambda _raw: domains)

        assert loader_zone_keys == set(result.zone_db.keys()) == set()
        assert loader_data_keys == set(result.data_db.keys()) == set(domains)


# --------------------------------------------------------------------------- #
# Shared test-only helpers
# --------------------------------------------------------------------------- #


def _empty_build_config() -> dict[str, Any]:
    return {
        "tld_wildcard_master": [],
        "tld_wildcard_blacklist": [],
        "tld_wildcard_exclusion": [],
        "user_whitelist": [],
        "top1m_list": [],
    }


def _write_ndjson(rows: list[dict[str, Any]], tmp_path: Any, filename: str = "interchange.txt") -> str:
    """Write ``rows`` as NDJSON under ``tmp_path`` (schema v1, issue #1083);
    returns the path as a str, ready for ``pfb["pfb_py_data"]``/``pfb["pfb_py_zone"]``."""
    path = os.path.join(str(tmp_path), filename)
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    return path


def _seed_zone_and_data(tmp_path: Any) -> tuple[str, str]:
    """Seed a zone + data NDJSON pair (one domain row each) for the TRIGGER fact
    (a) tests -- returns ``(zone_path, data_path)`` as strs."""
    zone_row = {"kind": "domain", "domain": "seeded-zone.uuidb001.net", "log": "1", "feed": "F", "group": "G"}
    data_row = {"kind": "domain", "domain": "seeded-data.uuidb001.com", "log": "1", "feed": "F", "group": "G"}
    zone_path = _write_ndjson([zone_row], tmp_path, "pfb_py_zone.txt")
    data_path = _write_ndjson([data_row], tmp_path, "pfb_py_data.txt")
    return zone_path, data_path
