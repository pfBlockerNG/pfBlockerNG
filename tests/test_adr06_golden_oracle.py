"""ADR-06 Phase 2 -- golden oracle for the CURRENT DNSBL preprocessing behaviour.

WHY THIS FILE EXISTS
--------------------
ADR-06 moves DNSBL list preprocessing (parse -> normalise -> classify data/zone
-> build dicts) out of shell/PHP into ``pfb_unbound.py``. That is the DNS
*blocking* path, so the move (Phases 3-5) must be provably equivalent **at the
level of net DNS decisions** (ADR.md §2). This module pins TODAY's decisions as a
committed golden oracle, captured while the old shell/PHP path is still
authoritative, so a silent regression in a later phase goes red here.

The contract is decisions, NOT list contents/counts. ADR-06 deliberately drops the
build-time optimisations (dedup, subdomain collapse, user-whitelist removal, TOP1M
removal), so ``dataDB``/``zoneDB`` contents and ``pfb_py_count`` change BY DESIGN.
What MUST stay invariant is every block/resolve outcome. Accordingly this oracle:

  * asserts DECISIONS (block shape / resolve / whitelist / HSTS / noAAAA /
    zone-subdomain / pass-through) via the production matcher decision functions
    ``pfb_unbound.evaluate_domain`` and ``pfb_unbound.evaluate_noaaaa`` -- the same
    pure functions the rest of ``tests/test_pfb_unbound.py`` exercises; and
  * records the **extracted-IP set** (the ``*_v4.ip`` / DNSBLIP_v4 firewall input)
    that the parse step hands off to PHP -- so the IP handoff is part of the oracle.

It does NOT assert identical dict contents or counts (those change by design).

WHAT MODELS "THE CURRENT PIPELINE"
----------------------------------
There is no live PHP/Unbound in CI (every prior ADR). So this file contains a
pure-Python *reference preprocessor* (``ReferencePipeline``) that faithfully
re-implements the CURRENT shell/PHP preprocessing semantics inventoried in
Phase 1 (``RESULTS/01_Results.txt``), with PHP-symbol anchors in the docstrings:

  * per-format parse (hosts / plain / basic-ABP), incl. the legacy basic-ABP
    token-strip (upgrade-compat only since ADR-62 -- live ABP-shaped lines now
    route verbatim to Python's richer ABP parser) and the rule that ``@@`` /
    ``##`` / ``$options`` / ``*`` / ``/`` / regex lines are IGNORED by that
    legacy strip;
  * embedded-IP extraction -> firewall handoff set (generic bare-IP, handled
    in ``sync_package_pfblockerng()``'s DNSBL download/parse loop), with IP
    lines stripped from what the domain build receives. (PHP also extracts an
    embedded IP from CSV-format feeds via ``pfb_dnsbl_collect_feed_ip()`` -- a
    separate, still-live PHP path this oracle's fixtures don't currently
    exercise, so it isn't modelled here);
  * domain validation + lower-casing (``pfb_filter()``'s ``PFB_FILTER_DOMAIN`` case);
  * data/zone classification via the public-suffix TLD master (``tld_analysis()``
    / ``tld_search()``), incl. TLD blacklist (whole-TLD zone) and TLD exclusion
    (force exact data);
  * user-whitelist normalisation (``pfb_unbound_python_whitelist()``:
    www-strip, leading-dot -> wildcard) feeding the query-time ``whiteDB``; and
  * TOP1M -> ``whiteDB`` only when enabled.

The reference preprocessor then loads the production matcher's runtime structures
(``dataDB`` / ``zoneDB`` / ``feedGroupIndexDB`` / ``whiteDB``) and the oracle drives
the production decision functions over a representative query set. Phase 3's new
pure build module must reproduce these SAME decisions even though the loaded lists
differ (un-pruned).

Fixtures live in ``tests/fixtures/adr06_golden/`` and are human-readable +
documented (each ``feed_*.txt`` header says what it encodes; ``config.json`` /
``manifest.json`` document every key).
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from typing import Any

import pfb_unbound

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "adr06_golden")


# --------------------------------------------------------------------------- #
# Fixture loading
# --------------------------------------------------------------------------- #


def _fixture_path(name: str) -> str:
    return os.path.join(FIXTURES, name)


def _read_lines(name: str) -> list[str]:
    with open(_fixture_path(name), encoding="utf-8") as fh:
        return fh.read().splitlines()


def _load_json(name: str) -> dict[str, Any]:
    with open(_fixture_path(name), encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- #
# Reference model of the CURRENT preprocessing pipeline (shell + PHP).
#
# Pure, stdlib-only. Re-implements the inventoried semantics so the oracle can run
# in CI without live PHP/Unbound. Anchors to pfblockerng.inc / .sh symbol names
# are in the method docstrings. This is the authoritative-today behaviour Phase 3
# must match at the DECISION level.
# --------------------------------------------------------------------------- #


def _is_ipv4(token: str) -> bool:
    """Mirror is_ipaddrv4: dotted-quad, each octet 0-255, no leading zeros."""
    parts = token.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255) or (len(p) > 1 and p[0] == "0"):
            return False
    return True


class ReferencePipeline:
    """Faithful pure-Python stand-in for the current shell/PHP DNSBL preprocessing.

    Produces the runtime structures the matcher consumes (``dataDB`` / ``zoneDB`` /
    ``feedGroupIndexDB`` / ``whiteDB``) plus the extracted-IP firewall set, from the
    raw feed fixtures + config. Decisions over these structures are the oracle.
    """

    def __init__(self, manifest: dict[str, Any], config: dict[str, Any], *, top1m_enabled: bool) -> None:
        self.manifest = manifest
        self.config = config
        self.top1m_enabled = top1m_enabled

        self.data_db: dict[str, Any] = {}
        self.zone_db: dict[str, Any] = {}
        self.feed_group_index_db: dict[int, Any] = {}
        self.white_db: dict[str, bool] = {}
        self.extracted_ips: set[str] = set()

        self._feed_group_db: dict[str, int] = {}
        self._next_index = 0
        # Public-suffix oracle: tlds[tld][full-suffix] = '' (mirrors PHP's
        # tld_analysis() master-list load loop), minus any TLD that is
        # blacklisted or excluded.
        self._tlds: dict[str, dict[str, str]] = defaultdict(dict)

    # -- parse layer -------------------------------------------------------- #

    @staticmethod
    def _parse_abp_line(line: str) -> str | None:
        """Legacy basic-ABP token-strip, upgrade-compat only (ADR-62).

        Keep ONLY a plain ``||domain^`` network line; strip the ``||`` and ``^``
        tokens. IGNORE everything else: ``@@`` exceptions, ``##`` element rules,
        ``$options``, ``*`` and ``/`` (path/regex). Returns the bare domain or None.
        """
        if not line.startswith("||") or not line.endswith("^"):
            return None
        if "$" in line or "*" in line or "/" in line:
            return None
        return line[2:-1]  # str_replace(['||', '.^', '^'], '', ...)

    @staticmethod
    def _strip_hosts_prefix(line: str) -> str:
        """Hosts format: "<sink-ip> <domain>" -> take the domain token (approximates
        sync_package_pfblockerng()'s 'Typical Host Feed format' pass)."""
        if " " in line:
            first, _, rest = line.partition(" ")
            rest = rest.strip()
            if _is_ipv4(first):
                return rest
            # plain "domain something" -> PHP keeps the chars before the space
            return first
        return line

    def _extract(self, raw_line: str, fmt: str) -> tuple[str | None, str | None]:
        """Return ``(domain, firewall_ip)`` for one raw line; either may be None.

        Implements the per-format dispatch + the embedded-IP firewall detection of
        the current parse loop. A generic bare-IP line yields ``(None, ip)`` -- the
        IP goes to the firewall and the line is stripped from the domain build
        (``sync_package_pfblockerng()``'s DNSBL download/parse loop).
        """
        line = raw_line.strip()
        if not line:
            return None, None

        if fmt == "abp":
            # ABP control/comment lines (header, '!', '[') are dropped first.
            if line.startswith("!") or line.startswith("["):
                return None, None
            host = self._parse_abp_line(line)
            return (host or None), None

        # hosts / plain
        if line.startswith("#") or line.startswith("!"):
            return None, None
        line = self._strip_hosts_prefix(line)
        line = line.strip().strip(".")
        if not line:
            return None, None
        # Embedded bare-IP -> firewall path (sync_package_pfblockerng()); stripped from Python.
        if _is_ipv4(line):
            return None, line
        return line, None

    @staticmethod
    def _validate_domain(host: str) -> str | None:
        """Lower-case + PFB_FILTER_DOMAIN shape gate (mirrors pfb_filter()'s PFB_FILTER_DOMAIN case)."""
        host = host.strip().strip(".").lower()
        if "." not in host:
            return None
        # Representative domain-shape gate (labels of [a-z0-9_-], underscore per
        # #723 — parity with pfb_filter()'s PFB_FILTER_DOMAIN case).
        for label in host.split("."):
            if not label or label[0] == "-" or label[-1] == "-":
                return None
            if any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in label):
                return None
        return host

    # -- classify layer ----------------------------------------------------- #

    def _load_tld_master(self) -> None:
        """Load the public-suffix master, minus blacklisted/single-label-excluded TLDs.

        Mirrors PHP's tld_analysis() master-list load loop, which builds
        tlds[tld][full-suffix]; the TLD blacklist removes entries from it. A
        single-label TLD exclusion does too (tld_analysis()'s unset($tlds[$exclude])),
        but a multi-label exclusion (e.g. "excluded.com") never matches a tld key here
        -- it stays loaded and is instead force-classified to exact DATA later, in
        _classify().
        """
        blacklist = {t.strip(".") for t in self.config.get("tld_blacklist", [])}
        exclusion_keys = {e.strip(".") for e in self.config.get("tld_exclusion", [])}
        for line in _read_lines("tld_master.txt"):
            suffix = line.strip()
            if not suffix or suffix.startswith("#"):
                continue
            tld = suffix.rsplit(".", 1)[-1]
            if tld in blacklist or tld in exclusion_keys:
                continue
            self._tlds[tld][suffix] = ""

    def _tld_search(self, tld: str, dparts: list[str], j: int, k: int) -> str | None:
        """Mirrors PHP's tld_search(): if the j-label suffix is a known public
        suffix, the registrable parent is the k-label slice."""
        tld_query = ".".join(dparts[-j:])
        if tld_query in self._tlds.get(tld, {}):
            return ".".join(dparts[-k:])
        return None

    def _classify(self, domain: str) -> tuple[str, str]:
        """Return ('zone', registrable-parent) or ('data', domain).

        Mirrors PHP's tld_analysis() zone/data split: registrable-parent -> wildcard ZONE;
        deeper sub-domain -> exact DATA; TLD-exclusion -> force exact DATA.
        """
        dparts = domain.split(".")
        dcnt = len(dparts)
        tld = dparts[-1]
        dfound = ""

        if dcnt > 5:
            pass
        elif dcnt == 5:
            dfound = self._tld_search(tld, dparts, 4, 5) or ""
        elif dcnt == 4:
            dfound = self._tld_search(tld, dparts, 3, 4) or ""
        elif dcnt == 3:
            dfound = self._tld_search(tld, dparts, 2, 3) or ""
        elif dcnt == 2:
            dfound = ".".join(dparts[-2:])

        # TLD exclusion: whole-domain in the exclusion set -> transparent (data).
        exclusion = {e.strip(".") for e in self.config.get("tld_exclusion", [])}
        if domain in exclusion:
            dfound = ""

        if dfound:
            return "zone", dfound
        return "data", domain

    # -- whitelist layer ---------------------------------------------------- #

    def _build_whitelist(self) -> None:
        """User-whitelist normalisation (mirrors PHP's pfb_unbound_python_whitelist()):
        www-strip, leading-dot -> wildcard '1' else '0'. TOP1M -> whiteDB only when
        enabled. whiteDB value is the wildcard bool pfb_unbound.py's
        _load_whitelist_db() stores from that '1'/'0' encoding."""
        for line in self.config.get("user_whitelist", []):
            line = line.strip()
            if not line:
                continue
            if line.startswith("www."):
                line = line[4:]
            if line.startswith("."):
                self.white_db[line.lstrip(".")] = True  # wildcard '1'
            else:
                self.white_db[line] = False  # exact '0'

        if self.top1m_enabled:
            for dom in self.config.get("top1m_list", []):
                dom = dom.strip()
                if dom:
                    # TOP1M entries are exact bare domains -> wildcard '0'.
                    self.white_db.setdefault(dom, False)

    # -- build -------------------------------------------------------------- #

    def _index_for(self, feed: str, group: str) -> int:
        key = feed + group
        idx = self._feed_group_db.get(key)
        if idx is None:
            idx = self._next_index
            self._feed_group_db[key] = idx
            self.feed_group_index_db[idx] = {"feed": feed, "group": group}
            self._next_index += 1
        return idx

    def _emit_tld_blacklist_zones(self) -> None:
        """Whole-TLD block: a blacklisted TLD becomes a synthetic DNSBL_TLD zone
        entry, matching the row shape PHP's tld_analysis() writes for the same
        case (``,<tld>,,1,DNSBL_TLD,DNSBL_TLD``)."""
        for tld in self.config.get("tld_blacklist", []):
            tld = tld.strip(".")
            if not tld:
                continue
            idx = self._index_for("DNSBL_TLD", "DNSBL_TLD")
            self.zone_db[tld] = {"log": "1", "index": idx}

    def run(self) -> None:
        self._load_tld_master()
        self._emit_tld_blacklist_zones()
        self._build_whitelist()

        for feed_row in self.manifest["feeds"]:
            feed = feed_row["feed"]
            group = feed_row["group"]
            fmt = feed_row["format_hint"]
            log_flag = feed_row["log_flag"]
            for raw_line in _read_lines(feed_row["raw"]):
                value, firewall_ip = self._extract(raw_line, fmt)
                if firewall_ip is not None:
                    self.extracted_ips.add(firewall_ip)  # firewall handoff
                if value is None:
                    continue
                domain = self._validate_domain(value)
                if domain is None:
                    continue
                idx = self._index_for(feed, group)
                ckind, key = self._classify(domain)
                payload = {"log": log_flag, "index": idx}
                if ckind == "zone":
                    self.zone_db[key] = payload  # last-wins (dict; ADR-06 §2)
                else:
                    self.data_db[key] = payload


# --------------------------------------------------------------------------- #
# Decision driver -- run the PRODUCTION matcher decision functions over the
# reference-built structures and reduce to a stable decision label.
# --------------------------------------------------------------------------- #


def _build_cfg(config: dict[str, Any], *, has_white: bool) -> dict[str, Any]:
    """Config blob shaped like pfb_unbound.pfb, for evaluate_domain()."""
    return {
        "python_blocking": True,
        "dataDB": True,
        "zoneDB": True,
        "whiteDB": has_white,
        "hstsDB": True,
        "regexDB": False,
        "python_tld": False,
        "python_idn": False,
        "python_tld_seg": int(config.get("python_tld_seg", 1)),
        "python_tlds": [],
        "dnsbl_ipv4": "10.10.10.1",
        "dnsbl_ipv6": "::1",
        "hsts_tlds": ("app", "dev", "page"),
    }


def _decision_label(d: pfb_unbound.DnsblDecision) -> str:
    """Reduce a DnsblDecision to a stable, human-readable outcome label.

    These are the net DNS decisions the contract pins (ADR.md §2):
      * "pass"        -> not on any list; resolves normally (pass-through).
      * "whitelist"   -> on a list but un-blocked via whiteDB (resolves).
      * "hsts"        -> on a list but bypassed via HSTS (resolves real).
      * "block-null"  -> blocked and null-routed to the DNSBL sinkhole IP
                         (log_flag '1', not HSTS -> null_blocking flips to False).
      * "block-nolog" -> blocked, but log_flag '2' (block-but-skip-log):
                         null_blocking STAYS True (only log '1' flips it), so the
                         reply is built but not null-routed and the hit is not
                         logged (get_details_dnsbl()'s log_type suppression). Still a block, distinct
                         from HSTS (which sets in_hsts) and from whitelist.
    """
    if not d.is_found:
        return "pass"
    if d.in_whitelist:
        return "whitelist"
    if d.in_hsts:
        return "hsts"
    if not d.null_blocking:
        return "block-null"
    return "block-nolog"


def _evaluate(pipeline: ReferencePipeline, config: dict[str, Any], q_name: str) -> dict[str, Any]:
    """Run evaluate_domain for q_name; return the decision label + key attributes."""
    containers = {
        "dataDB": pipeline.data_db,
        "zoneDB": pipeline.zone_db,
        "whiteDB": pipeline.white_db,
        "regexDB": {},
        "feedGroupIndexDB": pipeline.feed_group_index_db,
        "hstsDB": {d: 0 for d in config.get("hsts_domains", [])},
    }
    cfg = _build_cfg(config, has_white=bool(pipeline.white_db))
    tld = q_name.rsplit(".", 1)[-1] if "." in q_name else q_name
    decision = pfb_unbound.evaluate_domain(q_name, q_name, tld, False, cfg, containers)
    return {
        "decision": _decision_label(decision),
        "b_type": decision.b_type,
        "feed": decision.feed,
        "group": decision.group,
        "b_eval": decision.b_eval,
    }


# --------------------------------------------------------------------------- #
# Golden expected decisions (committed, human-readable).
#
# Representative query set covering: exact-block (data), zone-subdomain (wildcard),
# user-whitelisted, TOP1M-when-enabled, HSTS bypass, noAAAA, pass-through, basic-ABP
# blocked, basic-ABP IGNORED (@@/##/$options/path/regex), TLD-blacklist whole-TLD
# block, TLD-exclusion forced-exact, and a cross-feed duplicate.
#
# Each entry documents WHAT it asserts. ``b_type`` distinguishes exact DATA ("DNSBL")
# from wildcard ZONE ("TLD"). Decisions -- NOT list contents/counts -- are the oracle.
# --------------------------------------------------------------------------- #

# TOP1M DISABLED (default scenario).
#
# Classification reminder (given tld_master.txt = {com, net, org, co.uk}): a
# 2-label domain (its own registrable parent) -> wildcard ZONE (b_type "TLD"); a
# deeper sub-domain whose registrable parent is NOT a known suffix -> exact DATA
# (b_type "DNSBL"); a 3-label co.uk domain matches the multi-label public suffix
# -> ZONE on the registrable parent.
GOLDEN_TOP1M_DISABLED: dict[str, dict[str, Any]] = {
    # 2-label registrable in hosts feed -> ZONE wildcard, exact name blocks...
    "tracker.org": {"decision": "block-null", "b_type": "TLD"},
    # ...and a child of that ZONE entry stays blocked (wildcard coverage).
    "anything.tracker.org": {"decision": "block-null", "b_type": "TLD"},
    "x.y.tracker.org": {"decision": "block-null", "b_type": "TLD"},
    # another 2-label ZONE (hosts feed).
    "evilads.net": {"decision": "block-null", "b_type": "TLD"},
    # deep sub-domain in hosts feed whose parent (cleandata.com) is NOT listed ->
    # exact DATA. Only that exact name blocks; a deeper child does NOT.
    "deep.host.cleandata.com": {"decision": "block-null", "b_type": "DNSBL"},
    "cleandata.com": {"decision": "pass"},
    "deeper.deep.host.cleandata.com": {"decision": "pass"},
    # plain-feed 2-label -> ZONE.
    "malware.com": {"decision": "block-null", "b_type": "TLD"},
    # deep sub-domain in plain feed (parent cleanmal.com NOT listed) -> exact DATA.
    "deep.path.cleanmal.com": {"decision": "block-null", "b_type": "DNSBL"},
    "cleanmal.com": {"decision": "pass"},
    # multi-label public suffix co.uk: shop.co.uk is the registrable parent -> ZONE,
    # and a subdomain of it blocks via the wildcard.
    "shop.co.uk": {"decision": "block-null", "b_type": "TLD"},
    "www.shop.co.uk": {"decision": "block-null", "b_type": "TLD"},
    # user-whitelisted exact (phishing.net listed verbatim in plain feed) -> the
    # domain IS blocked but whiteDB un-blocks it -> resolves.
    "phishing.net": {"decision": "whitelist"},
    # adblock.com is BLOCKED (plain feed ZONE) but the user whitelist normalises
    # 'www.adblock.com' -> 'adblock.com' (www-strip) and un-blocks it -> resolves.
    "adblock.com": {"decision": "whitelist"},
    # ...and the www form is un-blocked via whiteDB's www-strip rule too.
    "www.adblock.com": {"decision": "whitelist"},
    # user-whitelisted wildcard ('.wildwhite.org' -> wildcard) but NOT on any
    # blocklist -> still "pass" (whitelist only un-blocks; never blocks).
    "host.wildwhite.org": {"decision": "pass"},
    # TOP1M domain, TOP1M DISABLED -> blocks normally (present in plain feed, ZONE).
    "popularcdn.com": {"decision": "block-null", "b_type": "TLD"},
    # HSTS-listed blocked domain (ZONE, feed_extra) -> resolves real (HSTS bypass).
    "hstslisted.com": {"decision": "hsts"},
    # TLD-exclusion: excluded.com forced to exact DATA -> blocks exactly, but a
    # subdomain does NOT block (transparent, not wildcard).
    "excluded.com": {"decision": "block-null", "b_type": "DNSBL"},
    "sub.excluded.com": {"decision": "pass"},
    # log_flag '2' feed (block-but-skip-log) -> blocked but NOT null-routed/logged.
    "silentblock.com": {"decision": "block-nolog", "b_type": "TLD"},
    # basic-ABP "||domain^" 2-label -> blocked ZONE.
    "abpblocked.com": {"decision": "block-null", "b_type": "TLD"},
    # basic-ABP deep "||sub.abpzone.net^" (parent abpzone.net NOT listed): the
    # LEGACY pass demoted it to exact DATA -- pinned here for the reference
    # pipeline only; production overlays GOLDEN_ABP_CONFORMANT_OVERRIDES (#718).
    "sub.abpzone.net": {"decision": "block-null", "b_type": "DNSBL"},
    "abpzone.net": {"decision": "pass"},
    # basic-ABP IGNORED lines -> NOT blocked (pass-through):
    "abpallowed.com": {"decision": "pass"},  # @@ exception ignored
    "abpoptions.com": {"decision": "pass"},  # $options line ignored
    "abpwildcard.com": {"decision": "pass"},  # * line ignored
    "abppath.com": {"decision": "pass"},  # /path line ignored
    # TLD-blacklist: any domain under blacklisted '.zip' -> whole-TLD ZONE block.
    "anything.zip": {"decision": "block-null", "b_type": "TLD", "group": "DNSBL_TLD"},
    "another.sub.zip": {"decision": "block-null", "b_type": "TLD", "group": "DNSBL_TLD"},
    # pass-through: never listed anywhere -> resolves.
    "totally-unrelated.com": {"decision": "pass"},
    "good.net": {"decision": "pass"},
}

# TOP1M ENABLED scenario: ONLY the TOP1M domain flips to whitelist; everything else
# is identical. Asserting both scenarios pins the TOP1M-when-enabled decision.
GOLDEN_TOP1M_ENABLED_OVERRIDES: dict[str, dict[str, Any]] = {
    "popularcdn.com": {"decision": "whitelist"},
}

# INTENTIONAL divergence from the legacy pipeline (#718): a conformant ABP
# "||host^" anchor covers host + ALL subdomains at ANY depth, so production emits
# a wildcard ZONE where the legacy basic-ABP pass demoted a deep anchor to exact
# DATA. The reference pipeline (and the GOLDEN dicts above) keep the legacy
# behaviour; the production-side suites (build module / init-from-raw) overlay
# these expectations, and the old-loader equivalence comparison skips exactly
# these keys.
GOLDEN_ABP_CONFORMANT_OVERRIDES: dict[str, dict[str, Any]] = {
    # the deep anchor now matches as a zone (b_type TLD); same block decision.
    "sub.abpzone.net": {"decision": "block-null", "b_type": "TLD"},
    # ...and its subdomain is now covered (the legacy pass resolved it).
    "deep.sub.abpzone.net": {"decision": "block-null", "b_type": "TLD"},
}

# The extracted-IP firewall handoff set (the *_v4.ip -> DNSBLIP_v4 input). Comes
# from generic bare-IP lines (PHP's separate CSV-feed IP extraction isn't
# modelled by this oracle's current fixtures -- see the module docstring).
# This is part of the oracle: Phase 5's independent DNSBL-IP pass must
# produce the SAME set.
GOLDEN_EXTRACTED_IPS: set[str] = {
    "198.51.100.23",  # hosts feed bare IP
    "203.0.113.45",  # plain feed bare IP
}


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


def _make_pipeline(*, top1m_enabled: bool) -> tuple[ReferencePipeline, dict[str, Any]]:
    manifest = _load_json("manifest.json")
    config = _load_json("config.json")
    pipeline = ReferencePipeline(manifest, config, top1m_enabled=top1m_enabled)
    pipeline.run()
    return pipeline, config


class TestGoldenDecisionsTop1mDisabled:
    """Every query in the representative set reproduces its golden DECISION
    (block shape / resolve / whitelist / HSTS / zone-subdomain / pass-through),
    TOP1M disabled. This is the net-DNS-decision oracle Phase 3 diffs against."""

    def test_decisions(self) -> None:
        pipeline, config = _make_pipeline(top1m_enabled=False)
        failures: list[str] = []
        for q_name, expected in GOLDEN_TOP1M_DISABLED.items():
            got = _evaluate(pipeline, config, q_name)
            for k, v in expected.items():
                if got[k] != v:
                    failures.append(f"{q_name}: {k} expected {v!r} got {got[k]!r}")
        assert not failures, "Golden decision mismatch:\n" + "\n".join(failures)


class TestGoldenDecisionsTop1mEnabled:
    """Same set with TOP1M enabled: the popular domain flips to 'whitelist'
    (un-blocked via whiteDB); all other decisions are unchanged."""

    def test_decisions(self) -> None:
        pipeline, config = _make_pipeline(top1m_enabled=True)
        expected_map = dict(GOLDEN_TOP1M_DISABLED)
        expected_map.update(GOLDEN_TOP1M_ENABLED_OVERRIDES)
        failures: list[str] = []
        for q_name, expected in expected_map.items():
            got = _evaluate(pipeline, config, q_name)
            for k, v in expected.items():
                if got[k] != v:
                    failures.append(f"{q_name}: {k} expected {v!r} got {got[k]!r}")
        assert not failures, "Golden decision mismatch (TOP1M enabled):\n" + "\n".join(failures)

    def test_top1m_disabled_blocks_popular_domain(self) -> None:
        """Guard the flip is real: with TOP1M disabled the popular domain blocks."""
        pipeline, config = _make_pipeline(top1m_enabled=False)
        got = _evaluate(pipeline, config, "popularcdn.com")
        assert got["decision"] == "block-null"


class TestGoldenNoAAAA:
    """noAAAA decisions (independent of the DNSBL blocklist): an AAAA query for a
    listed domain (exact or wildcard-parent) is blocked; others pass."""

    def _noaaaa_db(self, config: dict[str, Any]) -> dict[str, Any]:
        db: dict[str, Any] = {}
        for dom, wild in config.get("noaaaa_domains", []):
            db[dom] = wild == "1"
        return db

    def test_noaaaa_decisions(self) -> None:
        _, config = _make_pipeline(top1m_enabled=False)
        db = self._noaaaa_db(config)
        # exact listed -> blocked
        assert pfb_unbound.evaluate_noaaaa("noaaaa.com", db) is True
        # wildcard parent listed -> subdomain blocked
        assert pfb_unbound.evaluate_noaaaa("host.noaaaawild.net", db) is True
        # wildcard-parent itself is also an exact key -> blocked.
        assert pfb_unbound.evaluate_noaaaa("noaaaawild.net", db) is True
        # exact non-wildcard entry: a subdomain is NOT covered -> not blocked.
        assert pfb_unbound.evaluate_noaaaa("sub.noaaaa.com", db) is False
        # unrelated -> not blocked (AAAA resolves normally)
        assert pfb_unbound.evaluate_noaaaa("totally-unrelated.com", db) is False


class TestGoldenExtractedIPSet:
    """The embedded-IP firewall handoff (*_v4.ip -> DNSBLIP_v4 input) matches the
    golden set, from generic bare-IP lines. IP lines are stripped from the domain
    build (none leak into dataDB/zoneDB)."""

    def test_extracted_ip_set(self) -> None:
        pipeline, _ = _make_pipeline(top1m_enabled=False)
        assert pipeline.extracted_ips == GOLDEN_EXTRACTED_IPS

    def test_no_ip_leaked_into_block_lists(self) -> None:
        pipeline, _ = _make_pipeline(top1m_enabled=False)
        for ip in GOLDEN_EXTRACTED_IPS:
            assert ip not in pipeline.data_db
            assert ip not in pipeline.zone_db


class TestReferencePipelineSanity:
    """Sanity checks on the reference preprocessor itself (so a broken model is
    caught, not silently green): the data/zone split and feed/group attribution
    are populated as expected from the fixtures."""

    def test_zone_and_data_populated(self) -> None:
        pipeline, _ = _make_pipeline(top1m_enabled=False)
        # 2-label registrable domains land in zone_db
        assert "tracker.org" in pipeline.zone_db
        assert "malware.com" in pipeline.zone_db
        # multi-label public-suffix registrable parent -> zone_db
        assert "shop.co.uk" in pipeline.zone_db
        # deep sub-domains (parent not listed) land in data_db (exact)
        assert "deep.host.cleandata.com" in pipeline.data_db
        assert "deep.path.cleanmal.com" in pipeline.data_db
        # TLD-exclusion forces a would-be-zone 2-label into data_db (exact)
        assert "excluded.com" in pipeline.data_db
        assert "excluded.com" not in pipeline.zone_db
        # TLD-blacklist synthetic zone entry present, attributed to DNSBL_TLD
        assert "zip" in pipeline.zone_db
        tld_idx = pipeline.zone_db["zip"]["index"]
        assert pipeline.feed_group_index_db[tld_idx] == {"feed": "DNSBL_TLD", "group": "DNSBL_TLD"}

    def test_cross_feed_duplicate_last_wins(self) -> None:
        """tracker.org is in BOTH the hosts feed (Ads) and the plain feed (Malware);
        the dict load keeps LAST (ADR-06 §2 attribution change) -> PlainFeed/Malware."""
        pipeline, _ = _make_pipeline(top1m_enabled=False)
        idx = pipeline.zone_db["tracker.org"]["index"]
        fg = pipeline.feed_group_index_db[idx]
        assert fg == {"feed": "PlainFeed", "group": "Malware"}

    def test_whitelist_normalisation(self) -> None:
        pipeline, _ = _make_pipeline(top1m_enabled=False)
        # www. stripped, exact (wildcard False)
        assert pipeline.white_db.get("adblock.com") is False
        # leading-dot -> wildcard True
        assert pipeline.white_db.get("wildwhite.org") is True
        # plain exact entry
        assert pipeline.white_db.get("phishing.net") is False
        # TOP1M domain NOT in whiteDB when disabled
        assert "popularcdn.com" not in pipeline.white_db

    def test_top1m_loads_whitelist_when_enabled(self) -> None:
        pipeline, _ = _make_pipeline(top1m_enabled=True)
        assert pipeline.white_db.get("popularcdn.com") is False
