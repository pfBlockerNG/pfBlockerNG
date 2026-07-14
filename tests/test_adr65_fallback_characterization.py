"""ADR-65: the manifest is now the SOLE DNSBL source at Python init -- the legacy
py_data/py_zone/py_whitelist interchange-file fallback is RETIRED (ADR-65 SS2.3:
fail loud, never stale-serve). This module pins the POST-removal contract,
INVERTING the pre-removal characterization this same file carried earlier in
ADR-65 (Oracle B):

  (a) TRIGGER          -- ``_load_zone_and_data_dbs``/``_load_whitelist_and_hsts_dbs``
                          no longer read ANY interchange file for EITHER
                          ``dnsbl_built`` state; both states only close the
                          parse-stage ledger entries the retired loaders used
                          to own (issue #1049).
  (b) BUILD CARRIES ABP -- the manifest build (unaffected by this phase) still
                          carries ABP-derived zone/regex/allow-regex content
                          no interchange file ever could -- the one respect in
                          which the retired fallback was lossy.
  (c) FAIL LOUD         -- an absent manifest OPENS a loud parse-stage ledger
                          entry (never close-only) and leaves dataDB/zoneDB
                          EMPTY -- a stale orphaned interchange file on disk is
                          NEVER served.
  (d) HSTS INDEPENDENCE -- HSTS still loads regardless of the manifest build
                          outcome (Semantic 4); the python_blacklist gate that
                          used to shadow it on a build failure is dropped.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from typing import Any

import pfb_unbound

# --------------------------------------------------------------------------- #
# Fact (a) -- TRIGGER: both dnsbl_built states now only close the parse-stage
# ledger entries the retired loaders used to own; neither reads a file.
# --------------------------------------------------------------------------- #


class TestFactATrigger:
    """``_load_zone_and_data_dbs(dnsbl_built, ...)`` (pfb_unbound.py:1153): ADR-65
    retires the legacy loaders entirely -- BOTH ``dnsbl_built`` states now only
    close the parse-stage ledger entries the loaders used to own (issue #1049);
    neither state ever reads pfb_py_zone.txt/pfb_py_data.txt again."""

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

    def test_dnsbl_built_false_populates_nothing_and_closes_ledger(self, tmp_path: Any) -> None:
        """ADR-65: the fallback is RETIRED -- dnsbl_built=False no longer reads the
        seeded interchange files; it closes the same two entries the True arm does."""
        zone_path, data_path = _seed_zone_and_data(tmp_path)
        pfb_unbound.pfb["pfb_py_zone"] = zone_path
        pfb_unbound.pfb["pfb_py_data"] = data_path
        status_path = tmp_path / "pfb_py_status.json"
        pfb_unbound.pfb["pfb_py_status"] = str(status_path)

        pfb_unbound.pfb_py_status_open("dnsbl", zone_path, "parse", "prior failure")
        pfb_unbound.pfb_py_status_open("dnsbl", data_path, "parse", "prior failure")

        feed_group_db: defaultdict[str, int] = defaultdict(int)
        pfb_unbound._load_zone_and_data_dbs(False, feed_group_db, 0)

        assert dict(pfb_unbound.zoneDB) == {}
        assert dict(pfb_unbound.dataDB) == {}
        with open(status_path, encoding="utf-8") as fh:
            entries = json.load(fh)
        assert entries == []


# --------------------------------------------------------------------------- #
# Fact (b) -- the manifest BUILD (unaffected by this phase) still carries
# ABP-derived zone/regex/allow-regex content -- the one respect in which the
# now-retired interchange-file loaders were lossy.
# --------------------------------------------------------------------------- #


class TestFactBLossiness:
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
# Fact (c) -- FAIL LOUD: an absent manifest OPENS a parse-stage ledger entry
# (never close-only) and the retired loaders leave dataDB/zoneDB EMPTY -- a
# stale orphaned interchange file on disk is NEVER served (ADR-65 SS2.3).
# --------------------------------------------------------------------------- #


class TestFactCStaleness:
    def test_manifest_absent_opens_the_ledger_and_keeps_dbs_empty(self, tmp_path: Any) -> None:
        """ADR-65 SS2.3: an absent manifest is a LOUD failure -- OPENS a
        parse-stage ledger entry (never close-only) and the retired loaders
        leave dataDB/zoneDB EMPTY. A stale orphaned interchange file sitting on
        disk (from a pre-ADR-65 run) is NEVER served."""
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
        status_path = tmp_path / "pfb_py_status.json"
        pfb_unbound.pfb["pfb_py_status"] = str(status_path)

        build_result = pfb_unbound.dnsbl_build_from_manifest(str(manifest_path))
        assert build_result is None  # manifest absent -> build failed
        dnsbl_built = build_result is not None

        with open(status_path, encoding="utf-8") as fh:
            entries = json.load(fh)
        assert len(entries) == 1
        assert entries[0]["item"] == str(manifest_path)
        assert entries[0]["stage"] == "parse"

        feed_group_db: defaultdict[str, int] = defaultdict(int)
        pfb_unbound._load_zone_and_data_dbs(dnsbl_built, feed_group_db, 0)

        assert dict(pfb_unbound.dataDB) == {}
        assert dict(pfb_unbound.zoneDB) == {}
        assert "stale-orphan.uuidb003.com" not in pfb_unbound.dataDB


# --------------------------------------------------------------------------- #
# Fact (d) -- HSTS INDEPENDENCE: HSTS loads regardless of the manifest build
# outcome (Semantic 4) -- the python_blacklist gate that used to shadow it on
# a build failure is dropped (ADR-65 SS2.3).
# --------------------------------------------------------------------------- #


class TestFactDHstsIndependence:
    def test_hsts_loads_when_the_manifest_did_not_build(self, tmp_path: Any) -> None:
        pfb_unbound.pfb["python_hsts"] = True
        pfb_unbound.pfb["python_blacklist"] = False  # the dropped gate -- must not block HSTS
        hsts_path = tmp_path / "pfb_py_hsts.txt"
        hsts_path.write_text("bad.uuidb004.example\n", encoding="utf-8")
        pfb_unbound.pfb["pfb_py_hsts"] = str(hsts_path)
        pfb_unbound.pfb["pfb_py_whitelist"] = str(tmp_path / "pfb_py_whitelist.txt")  # absent
        status_path = tmp_path / "pfb_py_status.json"
        pfb_unbound.pfb["pfb_py_status"] = str(status_path)
        pfb_unbound.pfb_py_status_open("dnsbl", pfb_unbound.pfb["pfb_py_whitelist"], "parse", "prior failure")

        pfb_unbound._load_whitelist_and_hsts_dbs(False)

        assert "bad.uuidb004.example" in pfb_unbound.hstsDB
        with open(status_path, encoding="utf-8") as fh:
            entries = json.load(fh)
        assert entries == []  # whitelist parse entry closed too


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
