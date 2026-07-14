"""ADR-06 Phase 4 -- init builds the DNSBL structures from RAW + emits counts.

WHY THIS FILE EXISTS
--------------------
Phase 4 switches ``pfb_unbound`` init to BUILD the DNSBL structures from the raw
feeds via the Phase-3 ``build()`` layer (the new shell->Python boundary), assign
them into the matcher globals, and EMIT ``pfb_py_count``. This module proves the
new init-from-raw path is decision-equivalent to BOTH:

  * the Phase-2 golden oracle (the pinned current decisions), AND
  * the Phase-2 ReferencePipeline (a faithful stand-in for the OLD loader),

over the golden fixtures -- for both TOP1M scenarios, the noAAAA surface, and the
no-IP-leak guarantee. It also pins the on-box wiring:

  * ``dnsbl_build_from_manifest`` reads a per-feed manifest JSON whose feeds
    reference raw files relative to the manifest dir; the public-suffix oracle
    (issue #1255) is a SHIPPED file gated by an ini flag, not a manifest key;
  * ``top1m_enabled`` is driven by ``config["top1m_enabled"]`` in the manifest;
  * ``dnsbl_emit_count`` writes the LOADED total (len(dataDB)+len(zoneDB)) to
    ``pfb_py_count`` in the format the UI reads (pfblockerng.inc:3149); and
  * a missing/broken manifest yields ``None`` (init falls back to the legacy CSV
    load -- shell/PHP still produce those files until Phase 5).

The contract is DECISIONS, not list contents/counts (ADR.md SS2): the build's
dicts differ from today's pruned lists by design (no dedup/collapse/whitelist/
TOP1M removal), but every block/resolve/whitelist/HSTS/noAAAA/zone-subdomain
outcome is identical.
"""

from __future__ import annotations

import json
import os
import shutil
from typing import Any

import pytest

import pfb_unbound

# Reuse the Phase-2 oracle's fixtures, golden decision tables, decision driver AND
# the ReferencePipeline (the old-loader stand-in) so the new init path is validated
# against the EXACT same contract -- never a copy.
from tests.test_adr06_golden_oracle import (
    FIXTURES,
    GOLDEN_ABP_CONFORMANT_OVERRIDES,
    GOLDEN_EXTRACTED_IPS,
    GOLDEN_TOP1M_DISABLED,
    GOLDEN_TOP1M_ENABLED_OVERRIDES,
    ReferencePipeline,
    _build_cfg,
    _decision_label,
    _evaluate,
    _load_json,
)

# --------------------------------------------------------------------------- #
# Build an ON-BOX-shaped manifest JSON on disk (feeds + a ``config`` block) so the
# wiring is exercised exactly as init() will read it: ``tld_master`` is a FILE PATH
# (relative to the manifest dir), feed ``raw`` references are relative, and
# ``top1m_enabled`` lives in the config block.
# --------------------------------------------------------------------------- #


def _stage_tld_oracle(tmp_path: Any) -> None:
    """issue #1255: stage the public-suffix oracle the way dnsbl_cache_stage() does
    (a shipped file) and flip the ini flag -- the manifest no longer carries
    tld_master at all (HSTS parity)."""
    oracle = os.path.join(str(tmp_path), "pfb_py_tld.txt")
    shutil.copyfile(os.path.join(FIXTURES, "tld_master.txt"), oracle)
    pfb_unbound.pfb["python_tld_wildcard"] = True
    pfb_unbound.pfb["pfb_py_tld"] = oracle


def _write_onbox_manifest(tmp_path: Any, *, top1m_enabled: bool) -> str:
    """Write a single manifest JSON (feeds + config) with its raw files copied under
    the manifest directory.

    This mirrors the PRODUCTION shape (pfblockerng.inc): the manifest lives at the
    chroot root and every feed ``raw`` it references resolves UNDER that directory
    (the build confines manifest paths to the manifest's base dir, so an out-of-base
    reference is skipped). The committed fixtures are copied into a ``pfb_py_raw/``
    subdir of tmp_path and referenced RELATIVELY. issue #1255: the public-suffix
    oracle (formerly ``config.tld_master``) is staged as a shipped file + ini flag
    instead (``_stage_tld_oracle``) -- the manifest no longer carries it.
    """
    src_manifest = _load_json("manifest.json")
    src_config = _load_json("config.json")

    raw_dir = os.path.join(str(tmp_path), "pfb_py_raw")
    os.makedirs(raw_dir, exist_ok=True)

    feeds = []
    for row in src_manifest["feeds"]:
        rel = os.path.join("pfb_py_raw", os.path.basename(row["raw"]))
        shutil.copyfile(os.path.join(FIXTURES, row["raw"]), os.path.join(str(tmp_path), rel))
        feeds.append(
            {
                "raw": rel,  # relative -> reader resolves under the manifest dir
                "feed": row["feed"],
                "group": row["group"],
                "log_flag": row["log_flag"],
            }
        )

    _stage_tld_oracle(tmp_path)

    manifest = {
        "version": 1,
        "config": {
            "tld_wildcard_blacklist": src_config.get("tld_wildcard_blacklist", []),
            "tld_wildcard_exclusion": src_config.get("tld_wildcard_exclusion", []),
            "user_whitelist": src_config.get("user_whitelist", []),
            "top1m_list": src_config.get("top1m_list", []),
            "top1m_enabled": top1m_enabled,
        },
        "feeds": feeds,
    }

    path = os.path.join(str(tmp_path), "pfb_py_sources.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    return path


def _build_from_manifest(tmp_path: Any, *, top1m_enabled: bool) -> pfb_unbound.BuildResult:
    manifest_path = _write_onbox_manifest(tmp_path, top1m_enabled=top1m_enabled)
    result = pfb_unbound.dnsbl_build_from_manifest(manifest_path)
    assert result is not None
    return result


def _evaluate_result(result: pfb_unbound.BuildResult, config: dict[str, Any], q_name: str) -> dict[str, Any]:
    """Run the PRODUCTION ``evaluate_domain`` over the init-from-raw structures."""
    containers = {
        "dataDB": result.data_db,
        "zoneDB": result.zone_db,
        "whiteDB": result.white_db,
        "regexDB": {},
        "feedGroupIndexDB": result.feed_group_index_db,
        "hstsDB": {d: 0 for d in config.get("hsts_domains", [])},
    }
    cfg = _build_cfg(config, has_white=bool(result.white_db))
    tld = q_name.rsplit(".", 1)[-1] if "." in q_name else q_name
    decision = pfb_unbound.evaluate_domain(q_name, q_name, tld, False, cfg, containers)
    return {
        "decision": _decision_label(decision),
        "b_type": decision.b_type,
        "feed": decision.feed,
        "group": decision.group,
        "b_eval": decision.b_eval,
    }


def _old_pipeline(*, top1m_enabled: bool) -> tuple[ReferencePipeline, dict[str, Any]]:
    manifest = _load_json("manifest.json")
    config = _load_json("config.json")
    pipeline = ReferencePipeline(manifest, config, top1m_enabled=top1m_enabled)
    pipeline.run()
    return pipeline, config


# --------------------------------------------------------------------------- #
# init-from-raw == the Phase-2 DECISION oracle (the pinned current behaviour).
# --------------------------------------------------------------------------- #


class TestInitFromRawDecisionsTop1mDisabled:
    def test_decisions(self, tmp_path: Any) -> None:
        result = _build_from_manifest(tmp_path, top1m_enabled=False)
        config = _load_json("config.json")
        failures: list[str] = []
        expected_map = dict(GOLDEN_TOP1M_DISABLED)
        expected_map.update(GOLDEN_ABP_CONFORMANT_OVERRIDES)  # conformant ABP zones (#718)
        for q_name, expected in expected_map.items():
            got = _evaluate_result(result, config, q_name)
            for k, v in expected.items():
                if got[k] != v:
                    failures.append(f"{q_name}: {k} expected {v!r} got {got[k]!r}")
        assert not failures, "init-from-raw decision mismatch:\n" + "\n".join(failures)


class TestInitFromRawDecisionsTop1mEnabled:
    def test_decisions(self, tmp_path: Any) -> None:
        result = _build_from_manifest(tmp_path, top1m_enabled=True)
        config = _load_json("config.json")
        expected_map = dict(GOLDEN_TOP1M_DISABLED)
        expected_map.update(GOLDEN_TOP1M_ENABLED_OVERRIDES)
        expected_map.update(GOLDEN_ABP_CONFORMANT_OVERRIDES)  # conformant ABP zones (#718)
        failures: list[str] = []
        for q_name, expected in expected_map.items():
            got = _evaluate_result(result, config, q_name)
            for k, v in expected.items():
                if got[k] != v:
                    failures.append(f"{q_name}: {k} expected {v!r} got {got[k]!r}")
        assert not failures, "init-from-raw decision mismatch (TOP1M enabled):\n" + "\n".join(failures)

    def test_top1m_enabled_flows_from_manifest_config(self, tmp_path: Any) -> None:
        # The manifest's config.top1m_enabled drives the whiteDB load: enabled ->
        # the popular domain is un-blocked; disabled -> it blocks. ADR-07 P3 widened
        # the whiteDB value to {"wildcard", "important"} (TOP1M is a user allow ->
        # important=True); ADR-07 P6 added the numeric ``band`` (user-allow band 6).
        # The net DNS decision is unchanged (pinned by the oracle).
        enabled = _build_from_manifest(tmp_path, top1m_enabled=True)
        assert enabled.white_db.get("popularcdn.com") == {
            "wildcard": False,
            "important": True,
            "band": pfb_unbound.PRIO_USER_ALLOW,
        }
        disabled = _build_from_manifest(tmp_path, top1m_enabled=False)
        assert "popularcdn.com" not in disabled.white_db


# --------------------------------------------------------------------------- #
# init-from-raw == the OLD loader (the ReferencePipeline), decision-for-decision.
# --------------------------------------------------------------------------- #


class TestInitFromRawEqualsOldLoader:
    @pytest.mark.parametrize("top1m_enabled", [False, True])
    def test_decisions_match_old_loader(self, tmp_path: Any, top1m_enabled: bool) -> None:
        result = _build_from_manifest(tmp_path, top1m_enabled=top1m_enabled)
        pipeline, config = _old_pipeline(top1m_enabled=top1m_enabled)

        expected_map = dict(GOLDEN_TOP1M_DISABLED)
        if top1m_enabled:
            expected_map.update(GOLDEN_TOP1M_ENABLED_OVERRIDES)

        failures: list[str] = []
        for q_name in expected_map:
            if q_name in GOLDEN_ABP_CONFORMANT_OVERRIDES:
                # INTENTIONAL divergence (#718): conformant ABP deep anchors emit a
                # wildcard zone; the legacy pipeline demoted them to exact DATA.
                continue
            new = _evaluate_result(result, config, q_name)
            old = _evaluate(pipeline, config, q_name)
            if new != old:
                failures.append(f"{q_name}: new {new!r} != old {old!r}")
        assert not failures, "init-from-raw vs old-loader decision mismatch:\n" + "\n".join(failures)


# --------------------------------------------------------------------------- #
# noAAAA decisions + no-IP-leak (the firewall handoff stays in PHP).
# --------------------------------------------------------------------------- #


class TestInitFromRawNoAAAA:
    def test_noaaaa_decisions(self) -> None:
        config = _load_json("config.json")
        db = {dom: wild == "1" for dom, wild in config.get("noaaaa_domains", [])}
        assert pfb_unbound.evaluate_noaaaa("noaaaa.com", db) is True
        assert pfb_unbound.evaluate_noaaaa("host.noaaaawild.net", db) is True
        assert pfb_unbound.evaluate_noaaaa("noaaaawild.net", db) is True
        assert pfb_unbound.evaluate_noaaaa("sub.noaaaa.com", db) is False
        assert pfb_unbound.evaluate_noaaaa("totally-unrelated.com", db) is False


class TestInitFromRawNoIpLeak:
    def test_no_ip_leaked_into_block_lists(self, tmp_path: Any) -> None:
        result = _build_from_manifest(tmp_path, top1m_enabled=False)
        for ip in GOLDEN_EXTRACTED_IPS:
            assert ip not in result.data_db
            assert ip not in result.zone_db


# --------------------------------------------------------------------------- #
# Counts: pfb_py_count is the LOADED total and is written in the UI's format.
# --------------------------------------------------------------------------- #


class TestInitFromRawCounts:
    def test_counts_is_loaded_total(self, tmp_path: Any) -> None:
        result = _build_from_manifest(tmp_path, top1m_enabled=False)
        assert result.counts == len(result.data_db) + len(result.zone_db)
        assert result.counts > 0

    def test_emit_count_writes_loaded_total(self, tmp_path: Any) -> None:
        result = _build_from_manifest(tmp_path, top1m_enabled=False)
        count_path = os.path.join(str(tmp_path), "pfb_py_count")
        assert pfb_unbound.dnsbl_emit_count(count_path, result.counts) is True
        with open(count_path, encoding="utf-8") as fh:
            written = fh.read().strip()
        assert written == str(result.counts)
        # The emitted total must equal the actually-loaded entry count.
        assert int(written) == len(result.data_db) + len(result.zone_db)

    def test_count_matches_loaded_entries(self, tmp_path: Any) -> None:
        # Cross-check the emitted count against the structures the matcher will use.
        result = _build_from_manifest(tmp_path, top1m_enabled=False)
        loaded = len(result.data_db) + len(result.zone_db)
        assert result.counts == loaded


# --------------------------------------------------------------------------- #
# Wiring robustness: absent / broken manifest -> None (init falls back to legacy).
# --------------------------------------------------------------------------- #


class TestManifestFallback:
    def test_missing_manifest_returns_none(self, tmp_path: Any) -> None:
        assert pfb_unbound.dnsbl_build_from_manifest(os.path.join(str(tmp_path), "nope.json")) is None

    def test_broken_manifest_returns_none(self, tmp_path: Any) -> None:
        bad = os.path.join(str(tmp_path), "bad.json")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write("{ this is not json")
        assert pfb_unbound.dnsbl_build_from_manifest(bad) is None

    def test_missing_feed_file_is_skipped_not_fatal(self, tmp_path: Any) -> None:
        # One feed references a non-existent raw file; the build must still load the
        # OTHER feeds rather than aborting (the bad feed is logged + skipped). All
        # referenced paths live UNDER the manifest dir (the production/confined shape).
        path = os.path.join(str(tmp_path), "m.json")
        _stage_tld_oracle(tmp_path)
        shutil.copyfile(os.path.join(FIXTURES, "feed_plain.txt"), os.path.join(str(tmp_path), "feed_plain.txt"))
        manifest = {
            "version": 1,
            "config": {},
            "feeds": [
                {
                    "raw": "does_not_exist.txt",
                    "feed": "Gone",
                    "group": "Gone",
                    "log_flag": "1",
                },
                {
                    "raw": "feed_plain.txt",
                    "feed": "PlainFeed",
                    "group": "Malware",
                    "log_flag": "1",
                },
            ],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
        result = pfb_unbound.dnsbl_build_from_manifest(path)
        assert result is not None
        # The good feed's entries are present despite the missing one.
        assert "malware.com" in result.zone_db

    def test_empty_feeds_manifest_builds_empty(self, tmp_path: Any) -> None:
        # A manifest with no feeds still builds (TLD-blacklist zones + whiteDB only).
        path = os.path.join(str(tmp_path), "m.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "config": {}, "feeds": []}, fh)
        result = pfb_unbound.dnsbl_build_from_manifest(path)
        assert result is not None
        assert result.counts == 0
        assert result.data_db == {}
        assert result.zone_db == {}


# --------------------------------------------------------------------------- #
# tld_master accepted as a PATH (on-box) -- read into suffix lines by the build.
# --------------------------------------------------------------------------- #


class TestInitGlobalAssignment:
    """The init glue assigns the BuildResult into the matcher's module globals
    (dataDB/zoneDB/whiteDB/feedGroupIndexDB) -- the exact dicts ``operate()`` builds
    its ``containers`` from at query time (pfb_unbound.py:2660-2667). Mimic that
    assignment and evaluate THROUGH the globals to prove the wiring + that the
    query-time whiteDB application path is unchanged."""

    def test_decisions_through_module_globals(self, tmp_path: Any) -> None:
        result = _build_from_manifest(tmp_path, top1m_enabled=False)
        config = _load_json("config.json")

        # Exactly what init_standard does after a successful build.
        pfb_unbound.dataDB = result.data_db
        pfb_unbound.zoneDB = result.zone_db
        pfb_unbound.feedGroupIndexDB = result.feed_group_index_db
        pfb_unbound.whiteDB = result.white_db
        pfb_unbound.hstsDB = {d: 0 for d in config.get("hsts_domains", [])}

        cfg = _build_cfg(config, has_white=bool(result.white_db))
        # Build containers from the GLOBALS, mirroring operate().
        containers = {
            "dataDB": pfb_unbound.dataDB,
            "zoneDB": pfb_unbound.zoneDB,
            "whiteDB": pfb_unbound.whiteDB,
            "regexDB": pfb_unbound.regexDB,
            "feedGroupIndexDB": pfb_unbound.feedGroupIndexDB,
            "hstsDB": pfb_unbound.hstsDB,
        }
        failures: list[str] = []
        for q_name, expected in GOLDEN_TOP1M_DISABLED.items():
            tld = q_name.rsplit(".", 1)[-1] if "." in q_name else q_name
            dec = pfb_unbound.evaluate_domain(q_name, q_name, tld, False, cfg, containers)
            label = _decision_label(dec)
            if label != expected["decision"]:
                failures.append(f"{q_name}: expected {expected['decision']!r} got {label!r}")
        assert not failures, "global-assignment decision mismatch:\n" + "\n".join(failures)

    def test_whitelist_unblocks_through_globals(self, tmp_path: Any) -> None:
        # The query-time whiteDB application is unchanged: a listed domain whose
        # parent/self is in whiteDB resolves (whitelist), not blocked.
        result = _build_from_manifest(tmp_path, top1m_enabled=False)
        config = _load_json("config.json")
        pfb_unbound.dataDB = result.data_db
        pfb_unbound.zoneDB = result.zone_db
        pfb_unbound.feedGroupIndexDB = result.feed_group_index_db
        pfb_unbound.whiteDB = result.white_db

        cfg = _build_cfg(config, has_white=True)
        containers = {
            "dataDB": pfb_unbound.dataDB,
            "zoneDB": pfb_unbound.zoneDB,
            "whiteDB": pfb_unbound.whiteDB,
            "regexDB": {},
            "feedGroupIndexDB": pfb_unbound.feedGroupIndexDB,
            "hstsDB": {},
        }
        # adblock.com is BLOCKED (zone) but whiteDB un-blocks it -> resolves.
        dec = pfb_unbound.evaluate_domain("adblock.com", "adblock.com", "com", False, cfg, containers)
        assert _decision_label(dec) == "whitelist"


class TestTldWildcardOracleWiring:
    """issue #1255: the public-suffix oracle is a SHIPPED file gated by
    ``python_tld_wildcard`` (staged by ``_stage_tld_oracle``), never a manifest
    key -- end-to-end through the real ``dnsbl_build_from_manifest`` path."""

    def test_oracle_staged_and_on_classifies_public_suffix_as_zone(self, tmp_path: Any) -> None:
        # With the oracle staged and the flag on, co.uk classifies as a multi-label
        # public suffix -> shop.co.uk is a ZONE (registrable parent).
        result = _build_from_manifest(tmp_path, top1m_enabled=False)
        assert "shop.co.uk" in result.zone_db
        assert "tracker.org" in result.zone_db

    def test_oracle_off_forces_exact_data_even_when_file_is_staged(self, tmp_path: Any) -> None:
        # Before-state: ON classifies as ZONE (proven above). With the SAME staged
        # file but the flag OFF, the domain must flip to exact DATA -- the toggle
        # gates the WHOLE wildcard-blocking contribution (the bug issue #1255 fixes).
        manifest_path = _write_onbox_manifest(tmp_path, top1m_enabled=False)
        pfb_unbound.pfb["python_tld_wildcard"] = False  # override the helper's ON default
        result = pfb_unbound.dnsbl_build_from_manifest(manifest_path)
        assert result is not None
        assert "shop.co.uk" in result.data_db
        assert "shop.co.uk" not in result.zone_db


class TestUserUnlockManifest:
    """#51: config.user_unlock (the temporary per-alert unlock set) is passed through
    _dnsbl_config_from_manifest and merged into whiteDB by the on-box build path."""

    def test_user_unlock_passes_through_config_shaper(self) -> None:
        manifest = {
            "version": 1,
            "config": {
                "user_unlock": ["evil.com", ".wild.net"],
            },
            "feeds": [],
        }
        config = pfb_unbound._dnsbl_config_from_manifest(manifest, FIXTURES)
        assert config["user_unlock"] == ["evil.com", ".wild.net"]

    def test_user_unlock_defaults_empty_when_absent(self) -> None:
        config = pfb_unbound._dnsbl_config_from_manifest({"config": {}}, FIXTURES)
        assert config["user_unlock"] == []

    def test_user_unlock_merges_into_white_db(self, tmp_path: Any) -> None:
        # End-to-end through dnsbl_build_from_manifest: a feed blocks evil.com; the
        # temporary unlock makes it resolve (band-6 user allow in whiteDB).
        feed = os.path.join(str(tmp_path), "feed.raw")
        with open(feed, "w", encoding="utf-8") as fh:
            fh.write("evil.com\n")
        manifest = {
            "version": 1,
            "config": {
                "user_unlock": ["evil.com"],
            },
            "feeds": [{"raw": "feed.raw", "feed": "F", "group": "G", "log_flag": "1"}],
        }
        path = os.path.join(str(tmp_path), "pfb_py_sources.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)

        result = pfb_unbound.dnsbl_build_from_manifest(path)
        assert result is not None
        assert result.white_db["evil.com"] == {
            "wildcard": False,
            "important": True,
            "band": pfb_unbound.PRIO_USER_ALLOW,
        }
        # issue #1255: no oracle staged here -> exact DATA (not a wildcard zone); the
        # feed still records the block either way -- the allow overrides at query time.
        assert "evil.com" in result.data_db
        assert "evil.com" not in result.zone_db
        config = pfb_unbound._dnsbl_config_from_manifest(manifest, str(tmp_path))
        got = _evaluate_result(result, {**config, "hsts_domains": []}, "evil.com")
        assert got["decision"] == "whitelist"
