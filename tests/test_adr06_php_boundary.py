"""ADR-06 Phase 5 -- the PHP/shell boundary hands Python a 'plain' per-feed raw.

WHY THIS FILE EXISTS
--------------------
Phase 5 slims the shell/PHP DNSBL pipeline. The chosen boundary is:

  * PHP keeps the per-feed download + multi-format domain extraction loop (hosts /
    plain / basic-ABP / the CSV threat-feed sniffers / IDN) -- it already produces
    one cleaned, lower-cased, IP-stripped domain per line in each per-feed ``.txt``
    (the 6-col CSV's col1). The DNSBL-IP firewall pass already routes embedded IPs
    to the ``*_v4.ip`` / ``DNSBLIP_v4`` path and excludes them from ``.txt``.
  * ``pfb_unbound_python_sources()`` (pfblockerng.inc) then extracts col1 of each
    ``.txt`` into a per-feed raw file and references it in the manifest with
    ``format_hint: "plain"`` -- because PHP has ALREADY done the per-format work,
    Python's ``parse("plain")`` only has to re-validate + lower-case.

This test proves that boundary is DECISION-EQUIVALENT: it simulates exactly what
PHP writes (run the reference per-format extractor over each fixture feed to get
the bare domains, exactly as the PHP loop would, dropping embedded IPs), writes
them as ``plain`` per-feed raw files, builds a ``plain``-ONLY manifest, runs the
PRODUCTION ``dnsbl_build_from_manifest`` + ``evaluate_domain`` over it, and asserts
EVERY golden decision is reproduced -- for both TOP1M scenarios -- and that no
firewall IP leaks into the domain build.

If a future change makes PHP hand Python the ORIGINAL raw feed lines per format
instead (format_hint hosts/abp/csv:pon), the existing test_adr06_init_from_raw.py
already pins that path; this file pins the Phase-5 ``plain``-only boundary.
"""

from __future__ import annotations

import json
import os
import shutil
from typing import Any

import pfb_unbound
from tests.test_adr06_golden_oracle import (
    FIXTURES,
    GOLDEN_EXTRACTED_IPS,
    GOLDEN_TOP1M_DISABLED,
    GOLDEN_TOP1M_ENABLED_OVERRIDES,
    ReferencePipeline,
    _build_cfg,
    _decision_label,
    _load_json,
    _read_lines,
)


def _php_cleaned_feed_domains(feed_row: dict[str, Any]) -> tuple[list[str], set[str]]:
    """Reproduce the per-feed PHP '.txt' col1 = the cleaned, IP-stripped, lower-cased
    domains PHP writes for a feed, plus the firewall IPs it diverts.

    Uses the reference extractor (the authoritative model of the current PHP parse
    loop) so this test mirrors the PHP boundary EXACTLY rather than guessing.
    """
    pipeline = ReferencePipeline({"feeds": []}, _load_json("config.json"), top1m_enabled=False)
    domains: list[str] = []
    firewall_ips: set[str] = set()
    for raw_line in _read_lines(feed_row["raw"]):
        value, firewall_ip = pipeline._extract(raw_line, feed_row["format_hint"])
        if firewall_ip is not None:
            firewall_ips.add(firewall_ip)
        if value is None:
            continue
        domain = pipeline._validate_domain(value)
        if domain is None:
            continue
        domains.append(domain.lower())  # inc:8016 strtolower
    return domains, firewall_ips


def _write_plain_boundary_manifest(tmp_path: Any, *, top1m_enabled: bool) -> tuple[str, set[str]]:
    """Write per-feed PLAIN raw files (PHP-cleaned col1) + a plain-only manifest.

    Returns the manifest path and the union of firewall IPs PHP diverted (which must
    NOT appear in the domain build).
    """
    src_manifest = _load_json("manifest.json")
    src_config = _load_json("config.json")

    raw_dir = os.path.join(str(tmp_path), "pfb_py_raw")
    os.makedirs(raw_dir, exist_ok=True)

    feeds = []
    all_firewall_ips: set[str] = set()
    for row in src_manifest["feeds"]:
        domains, firewall_ips = _php_cleaned_feed_domains(row)
        all_firewall_ips |= firewall_ips
        raw_path = os.path.join(raw_dir, "{}.raw".format(row["feed"]))
        with open(raw_path, "w", encoding="utf-8") as fh:
            fh.write("".join("{}\n".format(d) for d in domains))
        feeds.append(
            {
                "raw": raw_path,
                "feed": row["feed"],
                "group": row["group"],
                "format_hint": "plain",  # ADR-06 P5: PHP already extracted the domain
                "log_flag": row["log_flag"],
            }
        )

    # tld_master must resolve UNDER the manifest dir (the build confines manifest
    # paths to their base dir) -- copy it alongside the feeds and reference by name.
    shutil.copyfile(os.path.join(FIXTURES, "tld_master.txt"), os.path.join(str(tmp_path), "tld_master.txt"))

    manifest = {
        "version": 1,
        "config": {
            "tld_master": "tld_master.txt",
            "tld_blacklist": src_config.get("tld_blacklist", []),
            "tld_exclusion": src_config.get("tld_exclusion", []),
            "user_whitelist": src_config.get("user_whitelist", []),
            "top1m_list": src_config.get("top1m_list", []),
            "top1m_enabled": top1m_enabled,
        },
        "feeds": feeds,
    }
    manifest_path = os.path.join(str(tmp_path), "pfb_py_sources.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    return manifest_path, all_firewall_ips


def _build(tmp_path: Any, *, top1m_enabled: bool) -> tuple[pfb_unbound.BuildResult, set[str]]:
    manifest_path, firewall_ips = _write_plain_boundary_manifest(tmp_path, top1m_enabled=top1m_enabled)
    result = pfb_unbound.dnsbl_build_from_manifest(manifest_path)
    assert result is not None
    return result, firewall_ips


def _evaluate(result: pfb_unbound.BuildResult, config: dict[str, Any], q_name: str) -> dict[str, Any]:
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


class TestPlainBoundaryDecisionsTop1mDisabled:
    def test_decisions(self, tmp_path: Any) -> None:
        result, _ = _build(tmp_path, top1m_enabled=False)
        config = _load_json("config.json")
        failures: list[str] = []
        for q_name, expected in GOLDEN_TOP1M_DISABLED.items():
            got = _evaluate(result, config, q_name)
            for k, v in expected.items():
                if got[k] != v:
                    failures.append(f"{q_name}: {k} expected {v!r} got {got[k]!r}")
        assert not failures, "plain-boundary decision mismatch:\n" + "\n".join(failures)


class TestPlainBoundaryDecisionsTop1mEnabled:
    def test_decisions(self, tmp_path: Any) -> None:
        result, _ = _build(tmp_path, top1m_enabled=True)
        config = _load_json("config.json")
        expected_map = dict(GOLDEN_TOP1M_DISABLED)
        expected_map.update(GOLDEN_TOP1M_ENABLED_OVERRIDES)
        failures: list[str] = []
        for q_name, expected in expected_map.items():
            got = _evaluate(result, config, q_name)
            for k, v in expected.items():
                if got[k] != v:
                    failures.append(f"{q_name}: {k} expected {v!r} got {got[k]!r}")
        assert not failures, "plain-boundary decision mismatch (TOP1M enabled):\n" + "\n".join(failures)


class TestPlainBoundaryNoIpLeak:
    def test_firewall_ips_absent_from_domain_build(self, tmp_path: Any) -> None:
        # The PHP DNSBL-IP pass diverts these to the firewall (*_v4.ip / DNSBLIP_v4)
        # and strips them from the per-feed raw -- they must never reach data/zone.
        result, firewall_ips = _build(tmp_path, top1m_enabled=False)
        assert firewall_ips == GOLDEN_EXTRACTED_IPS
        keys = set(result.data_db) | set(result.zone_db)
        leaked = firewall_ips & keys
        assert not leaked, f"firewall IPs leaked into the domain build: {sorted(leaked)}"
