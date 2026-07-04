"""Issue #38 -- branch-coverage sweep: close the one-sided / negative-path gaps.

A `pytest --cov=pfb_unbound --cov-branch` audit surfaced decision branches where only
ONE side was exercised -- the exact class of omission that motivated #38 (a feature's
ENABLED path tested, its DISABLED / fall-through path not). This module pins the
*missing* side of each such branch in the pure, unit-testable matcher / build / IDN
helpers (the runtime `operate()` / `init_standard()` / DB-worker paths need the live-VM
smoke harness and are tracked as later passes).

Every test names the branch it covers; trivial branch pins stay plain (intent-named
assertion), and the few non-trivial transitions (numeric re-attribution, $badfilter
user-immunity, regex warn/evict) carry a Given/When/Then so the behaviour -- not the
mechanics -- is on record. These ASSERT the outcome, never merely execute the line.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pfb_unbound
from pfb_unbound import (
    DNSBL_CLASS_DATA,
    DNSBL_CLASS_ZONE,
    DNSBL_KIND_BLOCK,
    PRIO_FEED_ALLOW,
    PRIO_FEED_ALLOW_IMPORTANT,
    PRIO_FEED_BLOCK,
    PRIO_FEED_BLOCK_IMPORTANT,
    PRIO_USER_ALLOW,
    REGEX_EVICT_MS_DEFAULT,
    REGEX_WARN_MS_DEFAULT,
    RULE_PROV_FEED,
    RULE_PROV_USER,
    RULE_TARGET_DOMAIN,
    RULE_TARGET_REGEX,
    SEV_LEGIT,
    SEV_MALICIOUS,
    LabelVerdict,
    NameVerdict,
    Rule,
    _dnsbl_classify_options,
    _dnsbl_config_from_manifest,
    _dnsbl_load_tld_master,
    _dnsbl_normalise_whitelist,
    _dnsbl_parse_abp_regex,
    _dnsbl_reduce_regex,
    _dnsbl_strip_hosts_prefix,
    _idn_dual_form,
    _regex_should_evict,
    _regex_timed_search,
    _scan_allow_regex_band,
    _scan_block_band,
    build,
    classify,
    classify_idn,
    dnsbl_build_from_manifest,
    dnsbl_emit_count,
    dnsbl_emit_reject_stats,
    evaluate_domain,
    parse,
    parse_abp,
    reconcile,
    whitelist_lookup_band,
)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _make_rule(
    *,
    kind: str = DNSBL_KIND_BLOCK,
    target: str = RULE_TARGET_DOMAIN,
    key_or_pattern: str,
    important: bool = False,
    badfilter: bool = False,
    provenance: str = RULE_PROV_FEED,
    wildcard: bool = True,
    signature: tuple[str, tuple[str, ...]] | None = None,
) -> Rule:
    return Rule(
        kind=kind,
        target=target,
        key_or_pattern=key_or_pattern,
        important=important,
        badfilter=badfilter,
        provenance=provenance,
        feed="F",
        group="G",
        log="1",
        signature=signature if signature is not None else (key_or_pattern, ()),
        wildcard=wildcard,
    )


class _FakeClock:
    """Deterministic `time.thread_time` substitute: each call advances by the next
    queued per-match cost (ms) so a 'slow' match is simulated without a real ReDoS."""

    def __init__(self, ticks_seconds: list[float]) -> None:
        self._ticks = ticks_seconds
        self._i = 0
        self._now = 0.0

    def __call__(self) -> float:
        v = self._now
        if self._i < len(self._ticks):
            self._now += self._ticks[self._i]
            self._i += 1
        return v


def _install_clock(monkeypatch: Any, elapsed_ms_per_match: list[float]) -> None:
    # Each match reads the clock twice (start, end); the second reading must be
    # `elapsed_ms` later, so emit [delta, 0] pairs.
    ticks: list[float] = []
    for ms in elapsed_ms_per_match:
        ticks.extend([ms / 1000.0, 0.0])
    monkeypatch.setattr(pfb_unbound, "_REGEX_HAVE_THREAD_TIME", True)
    monkeypatch.setattr(pfb_unbound.time, "thread_time", _FakeClock(ticks))


def _reset_regex_runtime_state() -> None:
    pfb_unbound._regex_warned.clear()
    pfb_unbound._regex_perf_strikes.clear()


# --------------------------------------------------------------------------- #
# classify -- label-depth branches (>5, ==5, single-label fall-through)
# --------------------------------------------------------------------------- #
class TestClassifyDepthBranches:
    def test_more_than_five_labels_is_exact_data(self) -> None:
        # >5 labels: no public-suffix search runs -> exact DATA (the dcnt>5 arm).
        cls, key = classify("a.b.c.d.e.f.example", {}, set())
        assert (cls, key) == (DNSBL_CLASS_DATA, "a.b.c.d.e.f.example")

    def test_five_labels_registrable_parent_is_zone(self) -> None:
        # dcnt==5 arm: a 4-label public suffix makes the whole 5-label name the zone.
        tlds = {"com": {"b.c.d.com": ""}}
        cls, key = classify("a.b.c.d.com", tlds, set())
        assert (cls, key) == (DNSBL_CLASS_ZONE, "a.b.c.d.com")

    def test_five_labels_unknown_suffix_is_exact_data(self) -> None:
        # dcnt==5 arm, suffix NOT public -> exact DATA (the `or ""` fallthrough).
        cls, key = classify("a.b.c.d.com", {}, set())
        assert (cls, key) == (DNSBL_CLASS_DATA, "a.b.c.d.com")

    def test_single_label_falls_through_to_data(self) -> None:
        # dcnt==1: no depth arm matches -> dfound stays "" -> exact DATA.
        cls, key = classify("com", {}, set())
        assert (cls, key) == (DNSBL_CLASS_DATA, "com")


# --------------------------------------------------------------------------- #
# parse -- skip/None branches per format
# --------------------------------------------------------------------------- #
class TestParseSkipBranches:
    def test_csv_pon_malformed_line_skipped(self) -> None:
        # A field over csv's size limit makes csv.reader raise -> except returns None.
        oversized = "a," + ("x" * 200000) + ",dom.com,d,e,f,g,h,i"
        assert parse("csv:pon", oversized) is None

    def test_csv_pon_empty_domain_column_skipped(self) -> None:
        # 9 columns but col2 (domain) empty -> None.
        assert parse("csv:pon", "a,b,,d,e,f,g,h,i") is None

    def test_csv_pon_valid_row_kept(self) -> None:
        # Contrast: a well-formed 9-col row yields the col2 domain.
        entry = parse("csv:pon", "a,b,blocked.com,d,e,f,g,h,i")
        assert entry is not None and entry.value == "blocked.com"

    def test_hosts_token_empty_after_strip_skipped(self) -> None:
        # A bare "." strips to empty -> None (no zero-length domain reaches the dicts).
        assert parse("hosts", ".") is None


class TestStripHostsPrefix:
    def test_non_ip_first_token_keeps_prefix(self) -> None:
        # PHP behaviour: a non-IP first token returns the chars before the space.
        assert _dnsbl_strip_hosts_prefix("notanip domain.com") == "notanip"

    def test_ip_first_token_takes_domain(self) -> None:
        assert _dnsbl_strip_hosts_prefix("0.0.0.0 domain.com") == "domain.com"


# --------------------------------------------------------------------------- #
# _dnsbl_load_tld_master -- comment/blank skip + blacklist/exclusion drop
# --------------------------------------------------------------------------- #
class TestLoadTldMaster:
    def test_comment_blank_and_blacklisted_tld_dropped(self) -> None:
        # Comment + blank lines are skipped; a blacklisted/excluded TLD is dropped;
        # everything else loads under tlds[tld][suffix].
        tlds = _dnsbl_load_tld_master(
            ["# a comment", "", "com", "co.uk", "net"],
            tld_blacklist=["uk"],
            tld_exclusion=["net"],
        )
        assert "uk" not in tlds  # blacklisted
        assert "net" not in tlds  # excluded
        assert tlds == {"com": {"com": ""}}


# --------------------------------------------------------------------------- #
# ABP option / regex parse helpers
# --------------------------------------------------------------------------- #
class TestAbpParseHelpers:
    def test_classify_options_skips_empty_token(self) -> None:
        # A trailing comma yields an empty option token -> skipped, not rejected.
        result = _dnsbl_classify_options("important,")
        assert result == (("important",), True, False)

    def test_parse_abp_regex_empty_inner_is_none(self) -> None:
        # "//" / "@@//" have an empty inner pattern -> not a regex rule.
        assert _dnsbl_parse_abp_regex("//") is None
        assert _dnsbl_parse_abp_regex("@@//") is None

    def test_parse_abp_bare_token_failing_normalise_is_none(self) -> None:
        # A single-label bare token has no dot -> normalise() rejects -> skipped.
        assert parse_abp("nodothere") is None


# --------------------------------------------------------------------------- #
# _dnsbl_reduce_regex -- wildcard prefix matched but inner NOT a domain literal
# --------------------------------------------------------------------------- #
class TestReduceRegexIrreducible:
    def test_wildcard_prefix_with_non_literal_body_is_irreducible(self) -> None:
        # `(^|\.)` matches but the body carries a finite class `[0-9]` -> not a domain
        # literal -> None (stays a compiled pattern; we never expand classes).
        assert _dnsbl_reduce_regex(r"(^|\.)ad[0-9]\.x$") is None

    def test_reducible_wildcard_folds(self) -> None:
        # Contrast: a pure domain literal under the same prefix DOES fold to a zone.
        assert _dnsbl_reduce_regex(r"(^|\.)ads\.example\.com$") == (True, "ads.example.com")


# --------------------------------------------------------------------------- #
# reconcile -- USER irreducible regex must NOT force the numeric path
# --------------------------------------------------------------------------- #
class TestReconcileIrreducibleProvenance:
    def test_user_irreducible_regex_does_not_set_important_rules(self) -> None:
        """
        Scenario: an irreducible regex's provenance decides whether it engages the
          numeric 6-band branch (`important_rules`).
        Given a FEED irreducible block-regex and, separately, a USER one,
        When each is reconciled alone,
        Then the FEED regex sets important_rules True (it cannot be resolved by the
          fast path) while the USER regex leaves it False (a user regex is sovereign
          and already handled) -- proving the provenance branch is real, not one-sided.
        """
        irreducible = r"(a|b)+x"  # no trailing $ -> never reduces to a domain literal

        feed = reconcile([_make_rule(target=RULE_TARGET_REGEX, key_or_pattern=irreducible)], {}, set())
        assert feed.important_rules is True
        assert len(feed.block_regex_irreducible) == 1

        user = reconcile(
            [_make_rule(target=RULE_TARGET_REGEX, key_or_pattern=irreducible, provenance=RULE_PROV_USER)],
            {},
            set(),
        )
        assert user.important_rules is False
        assert len(user.block_regex_irreducible) == 1
        assert user.block_regex_irreducible[0].provenance == RULE_PROV_USER


# --------------------------------------------------------------------------- #
# _dnsbl_normalise_whitelist -- blank user line + blank TOP1M entry skipped
# --------------------------------------------------------------------------- #
class TestNormaliseWhitelistBlanks:
    def test_blank_user_whitelist_line_skipped(self) -> None:
        wdb = _dnsbl_normalise_whitelist(["", "   ", "keep.com"], [], top1m_enabled=False)
        assert set(wdb) == {"keep.com"}

    def test_blank_top1m_entry_skipped(self) -> None:
        # TOP1M enabled: a blank entry is ignored, a real one loads as a band-6 allow.
        wdb = _dnsbl_normalise_whitelist([], ["", "  ", "top.com"], top1m_enabled=True)
        assert set(wdb) == {"top.com"}
        assert wdb["top.com"]["band"] == PRIO_USER_ALLOW

    def test_top1m_disabled_loads_nothing(self) -> None:
        # Contrast (the OFF side of the toggle): TOP1M list ignored when disabled.
        wdb = _dnsbl_normalise_whitelist([], ["top.com"], top1m_enabled=False)
        assert wdb == {}


# --------------------------------------------------------------------------- #
# _regex_should_evict -- warn-band re-warn skip + perf-counter fallback warn-band
# --------------------------------------------------------------------------- #
class TestRegexShouldEvictBranches:
    def test_warn_band_warns_once_then_skips_rewarn(self) -> None:
        """
        Given a pattern matching twice in the WARN band (over warn, under evict),
        When _regex_should_evict is called for each hit,
        Then it warns on the first (recording the name) and SKIPS the re-warn on the
          second -- neither evicts. Pins the rate-limited warn branch (both sides).
        """
        _reset_regex_runtime_state()
        # thread_time present -> single-strike semantics; 50ms is between warn(10)/evict(100).
        first = _regex_should_evict("RX", 50.0, REGEX_WARN_MS_DEFAULT, REGEX_EVICT_MS_DEFAULT, "DNSBL_Regex", "RX")
        assert first is False
        assert "RX" in pfb_unbound._regex_warned
        second = _regex_should_evict("RX", 50.0, REGEX_WARN_MS_DEFAULT, REGEX_EVICT_MS_DEFAULT, "DNSBL_Regex", "RX")
        assert second is False  # already warned -> no re-warn, still not evicted

    def test_perf_fallback_warn_band_clears_strikes(self, monkeypatch: Any) -> None:
        # perf_counter fallback + a warn-band match clears any accumulated strike streak
        # (the !thread_time arm inside the warn band).
        _reset_regex_runtime_state()
        monkeypatch.setattr(pfb_unbound, "_REGEX_HAVE_THREAD_TIME", False)
        pfb_unbound._regex_perf_strikes["RX"] = 1
        out = _regex_should_evict("RX", 50.0, REGEX_WARN_MS_DEFAULT, REGEX_EVICT_MS_DEFAULT, "DNSBL_Regex", "RX")
        assert out is False
        assert "RX" not in pfb_unbound._regex_perf_strikes


class TestRegexTimedSearchFallback:
    def test_perf_counter_branch_still_returns_match(self, monkeypatch: Any) -> None:
        # When time.thread_time is absent the timer takes the perf_counter branch; it
        # must still return the match + a non-negative elapsed (the !thread_time arm).
        monkeypatch.setattr(pfb_unbound, "_REGEX_HAVE_THREAD_TIME", False)
        match, elapsed_ms = _regex_timed_search(re.compile(r"evil"), "evil.com")
        assert match is not None
        assert elapsed_ms >= 0.0


# --------------------------------------------------------------------------- #
# _scan_block_band -- max-band zone selection + numeric block-regex eviction
# --------------------------------------------------------------------------- #
class TestScanBlockBand:
    def test_deeper_zone_lower_band_does_not_lower_best(self) -> None:
        """
        Given two matching zone suffixes -- the registrable parent at the HIGHER band
          and the bare TLD at a lower band,
        When _scan_block_band walks the suffixes (specific -> general),
        Then the higher band wins and the later, lower-band suffix does NOT replace it.
        """
        cfg: dict[str, Any] = {"dataDB": False, "zoneDB": True, "regexDB": False}
        zone_db = {
            "evil.com": {"log": "1", "index": 0, "important": True, "band": PRIO_FEED_BLOCK_IMPORTANT},
            "com": {"log": "1", "index": 1, "important": False, "band": PRIO_FEED_BLOCK},
        }
        band, meta = _scan_block_band("x.evil.com", cfg, {}, zone_db, {})
        assert band == PRIO_FEED_BLOCK_IMPORTANT
        assert meta is not None and meta["kind"] == "zone" and meta["matched"] == "evil.com"

    def test_numeric_block_regex_over_evict_is_evicted(self, monkeypatch: Any) -> None:
        # A block-regex match over the evict ceiling is collected and popped AFTER the
        # scan; nothing then matches -> (0, None) and the live regexDB is emptied.
        _reset_regex_runtime_state()
        _install_clock(monkeypatch, [300.0])  # one match, 300ms > evict(100)
        regex_db: dict[str, Any] = {"RX": re.compile(r"evil")}
        cfg: dict[str, Any] = {
            "dataDB": False,
            "zoneDB": False,
            "regexDB": True,
            "regex_warn_ms": REGEX_WARN_MS_DEFAULT,
            "regex_evict_ms": REGEX_EVICT_MS_DEFAULT,
        }
        band, meta = _scan_block_band("evil.com", cfg, {}, {}, regex_db)
        assert (band, meta) == (0, None)
        assert "RX" not in regex_db  # evicted from the live DB


class TestScanAllowRegexBand:
    def test_empty_q_name_returns_zero(self) -> None:
        # The empty-name guard: no allow-regex is evaluated for a blank query.
        assert _scan_allow_regex_band("", {"R": re.compile(r"x")}) == 0


# --------------------------------------------------------------------------- #
# whitelist_lookup_band -- the www.-strip exact path
# --------------------------------------------------------------------------- #
class TestWhitelistLookupBand:
    def test_www_strip_exact_match_returns_band(self) -> None:
        # "www.x.com" misses on the literal key but hits the www-stripped exact entry.
        wdb = {"x.com": {"wildcard": False, "important": True, "band": PRIO_USER_ALLOW}}
        assert whitelist_lookup_band("www.x.com", wdb, 2) == PRIO_USER_ALLOW

    def test_www_strip_miss_falls_through_to_suffix_walk(self) -> None:
        # "www."-prefixed name whose stripped form is ALSO absent -> the www-strip
        # exact lookup misses and the suffix walk yields no match -> 0.
        assert whitelist_lookup_band("www.gone.com", {"other.com": {"band": PRIO_USER_ALLOW}}, 2) == 0

    def test_no_match_returns_zero(self) -> None:
        assert whitelist_lookup_band("nope.com", {"x.com": {"band": PRIO_USER_ALLOW}}, 2) == 0


# --------------------------------------------------------------------------- #
# evaluate_domain -- numeric scan RE-ATTRIBUTION to a higher-band DATA entry
# --------------------------------------------------------------------------- #
class TestEvaluateDomainNumericDataReattribution:
    def test_higher_band_data_reattributes_from_regex(self) -> None:
        """
        Scenario: in the numeric 6-band path the response/report must follow the rule
          that actually WON (issue #47), not the first one discovered.
        Given python_blocking OFF (so discovery happens via the block-regex, band 1)
          AND a higher-band ($important, band 3) exact DATA entry for the same name,
        When evaluate_domain runs with important_rules engaged,
        Then it re-attributes the block to the DATA entry: b_type "DNSBL", b_eval the
          query name, and feed/group taken from the data entry -- NOT the regex feed.
        """
        q = "evil.com"
        cfg: dict[str, Any] = {
            "python_blocking": False,
            "dataDB": True,
            "zoneDB": False,
            "python_tld": False,
            "python_tlds": [],
            "dnsbl_ipv4": "10.10.10.1",
            "dnsbl_ipv6": "::1",
            "python_idn": False,
            "regexDB": True,
            "whiteDB": False,
            "allowRegexDB": False,
            "important_rules": True,
            "python_tld_seg": 2,
            "hstsDB": False,
            "hsts_tlds": (),
            "regex_warn_ms": REGEX_WARN_MS_DEFAULT,
            "regex_evict_ms": REGEX_EVICT_MS_DEFAULT,
        }
        containers: dict[str, Any] = {
            "dataDB": {q: {"log": "1", "index": 0, "important": True, "band": PRIO_FEED_BLOCK_IMPORTANT}},
            "zoneDB": {},
            "whiteDB": {},
            "regexDB": {"RXFEED": {"re": re.compile(r"^evil\.com$"), "important": False, "band": PRIO_FEED_BLOCK}},
            "allowRegexDB": {},
            "feedGroupIndexDB": {0: {"feed": "DataFeed", "group": "DataGroup"}},
            "hstsDB": {},
        }
        decision = evaluate_domain(q, q, "com", False, cfg, containers)

        assert decision.is_found is True
        assert decision.in_whitelist is False
        # Re-attributed to the higher-band DATA rule, not the discovered regex.
        assert decision.b_type == "DNSBL"
        assert decision.b_eval == q
        assert decision.feed == "DataFeed"
        assert decision.group == "DataGroup"


# --------------------------------------------------------------------------- #
# build -- empty-blacklist-TLD skip, normalise-drop, feed-allow band upgrade
# --------------------------------------------------------------------------- #
def _manifest(feeds: list[dict[str, Any]], config: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"feeds": feeds, "config": config or {}}


class TestBuildBranches:
    def test_blank_blacklist_tld_is_skipped(self) -> None:
        # A "." blacklist entry strips to "" -> no synthetic zone entry, no crash.
        result = build(
            _manifest([]),
            {"tld_blacklist": ["."]},
            line_reader=lambda raw: [],
        )
        assert result.zone_db == {}

    def test_plain_feed_line_failing_normalise_dropped(self) -> None:
        # A single-label feed line parses to a token but fails normalise -> dropped.
        feed_row = {"feed": "F", "group": "G", "format_hint": "plain", "log_flag": "1", "raw": "r"}
        result = build(
            _manifest([feed_row]),
            {},
            line_reader=lambda raw: ["singlelabelnodot", "good.com"],
        )
        assert "singlelabelnodot" not in result.data_db
        assert "good.com" in result.zone_db or "good.com" in result.data_db

    def test_feed_allow_important_upgrades_lower_band_entry(self) -> None:
        """
        Given an ABP feed emitting a plain @@allow then an @@allow$important on the
          SAME domain,
        When build reconciles + emits them into whiteDB,
        Then the second (band 4) UPGRADES the first (band 2) entry rather than being
          dropped -- the `existing band < a.band` widen branch.
        """
        feed_row = {"feed": "F", "group": "G", "format_hint": "abp", "log_flag": "1", "raw": "r"}
        result = build(
            _manifest([feed_row]),
            {},
            line_reader=lambda raw: ["@@||x.com^", "@@||x.com^$important"],
        )
        entry = result.white_db["x.com"]
        assert entry["band"] == PRIO_FEED_ALLOW_IMPORTANT
        assert entry["important"] is True

    def test_same_band_exact_and_wildcard_allow_merge_widens(self) -> None:
        """
        Given an ABP feed emitting BOTH a wildcard @@||x.com^ and an exact reduced
          @@/^x\\.com$/ allow (same domain, same band 2),
        When build emits them into whiteDB,
        Then they MERGE rather than first-writer-wins: the wildcard flag survives so
          subdomain coverage is not silently dropped (the same-band widen branch).
        """
        feed_row = {"feed": "F", "group": "G", "format_hint": "abp", "log_flag": "1", "raw": "r"}
        result = build(
            _manifest([feed_row]),
            {},
            line_reader=lambda raw: ["@@||x.com^", r"@@/^x\.com$/"],
        )
        entry = result.white_db["x.com"]
        assert entry["band"] == PRIO_FEED_ALLOW
        assert entry["wildcard"] is True  # wildcard not downgraded by the exact allow

    def test_feed_allow_does_not_downgrade_user_whitelist(self) -> None:
        """
        Scenario: a feed @@ allow must never weaken a sovereign user whitelist entry.
        Given a band-6 user-whitelist entry for x.com,
        When an ABP feed also emits @@||x.com^ (band 2) for the same key,
        Then the user entry is kept (band 6) -- the feed allow neither upgrades (its
          band is lower) nor merges (bands differ), it is simply skipped.
        """
        feed_row = {"feed": "F", "group": "G", "format_hint": "abp", "log_flag": "1", "raw": "r"}
        result = build(
            _manifest([feed_row]),
            {"user_whitelist": ["x.com"]},
            line_reader=lambda raw: ["@@||x.com^"],
        )
        assert result.white_db["x.com"]["band"] == PRIO_USER_ALLOW


# --------------------------------------------------------------------------- #
# manifest I/O error branches
# --------------------------------------------------------------------------- #
class TestManifestErrorBranches:
    def test_config_from_manifest_unreadable_tld_master_yields_empty(self) -> None:
        # A tld_master FILE path that cannot be opened -> logged + empty list (no raise).
        cfg = _dnsbl_config_from_manifest({"config": {"tld_master": "/no/such/file/xyz"}}, "/tmp")
        assert cfg["tld_master"] == []

    def test_build_from_manifest_returns_none_when_build_raises(self, tmp_path: Path) -> None:
        # A feeds row missing the "feed" key makes build() raise KeyError -> the
        # except returns None (init then falls back to the legacy CSV load).
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(
            json.dumps({"feeds": [{"group": "g", "format_hint": "plain", "log_flag": "1", "raw": "x"}], "config": {}})
        )
        assert dnsbl_build_from_manifest(str(manifest_path)) is None

    def test_build_from_manifest_absent_file_returns_none(self) -> None:
        # Contrast: a missing manifest also yields None (the legacy-fallback signal).
        assert dnsbl_build_from_manifest("/no/such/manifest.json") is None

    def test_emit_count_returns_false_on_write_error(self) -> None:
        # An unwritable path -> OSError caught -> False (never raises into the build).
        assert dnsbl_emit_count("/no/such/dir/count.txt", 42) is False

    def test_emit_count_writes_value(self, tmp_path: Path) -> None:
        # Contrast: a writable path returns True and persists the count.
        out = tmp_path / "count.txt"
        assert dnsbl_emit_count(str(out), 7) is True
        assert out.read_text().strip() == "7"


# --------------------------------------------------------------------------- #
# ADR-48 Phase 4 (#789) -- dnsbl_emit_reject_stats() artifact writer.
# --------------------------------------------------------------------------- #
class TestEmitRejectStats:
    def test_writes_only_nonzero_feeds_as_json(self, tmp_path: Path) -> None:
        # Given: a tally with one all-zero row (never emitted by build() in
        # practice, but the writer must not depend on that) and one nonzero row.
        out = tmp_path / "pfb_py_reject_stats.json"
        tally = {
            ("ZeroFeed", "ZeroGroup"): {"shape": 0, "wire_cap": 0},
            ("RejFeed", "RejGroup"): {"shape": 3, "wire_cap": 5},
        }
        # When: the artifact is written.
        assert dnsbl_emit_reject_stats(str(out), tally) is True
        # Then: valid JSON, only the nonzero feed present, exact counts.
        written = json.loads(out.read_text())
        assert written == [{"feed": "RejFeed", "group": "RejGroup", "shape": 3, "wire_cap": 5}]

    def test_empty_tally_writes_empty_json_array(self, tmp_path: Path) -> None:
        # PHP must distinguish "ran, zero rejects" ("[]") from "no artifact" (absent
        # file, fresh boot / an old python module) -- an empty tally still writes.
        out = tmp_path / "pfb_py_reject_stats.json"
        assert dnsbl_emit_reject_stats(str(out), {}) is True
        assert out.read_text() == "[]"

    def test_atomic_write_leaves_no_stray_tmp_file(self, tmp_path: Path) -> None:
        # The atomic temp+os.replace pattern (mirrors _reload_write_applied) must
        # not leave a ".tmp" sibling behind on success.
        out = tmp_path / "pfb_py_reject_stats.json"
        assert dnsbl_emit_reject_stats(str(out), {("F", "G"): {"shape": 1, "wire_cap": 0}}) is True
        assert out.exists()
        assert not (tmp_path / "pfb_py_reject_stats.json.tmp").exists()

    def test_returns_false_on_write_error(self) -> None:
        # An unwritable path -> OSError caught -> False (never raises into the run).
        assert dnsbl_emit_reject_stats("/no/such/dir/pfb_py_reject_stats.json", {}) is False

    def test_reject_stats_path_key_is_chroot_relative(self) -> None:
        # ADR §3 risk: init_standard() must set a bare filename (never a
        # host-absolute path) -- a host-absolute path silently fails to load
        # inside Unbound's chroot (the exact manifest-boundary bug class this repo
        # already hit once). init_standard() needs the live Unbound env and can't
        # run in this suite, so this pins the assignment directly in the source.
        source = Path(pfb_unbound.__file__).read_text()
        match = re.search(r'pfb\["pfb_py_reject_stats"\]\s*=\s*"([^"]+)"', source)
        assert match is not None, "pfb['pfb_py_reject_stats'] assignment not found in pfb_unbound.py"
        assert not match.group(1).startswith("/"), f"expected a chroot-relative bare name, got {match.group(1)!r}"


# --------------------------------------------------------------------------- #
# IDN per-name analysis -- later-label severity + defensive dual-form fallback
# --------------------------------------------------------------------------- #
class TestIdnNameAnalysis:
    def test_later_label_more_severe_wins(self) -> None:
        # First label legit, a LATER label malicious (Latin+Cyrillic "аpple") -> the
        # name verdict takes the more-severe later label (the worst-update branch).
        verdict = classify_idn("apple.xn--pple-43d.com")
        assert verdict.labels[0].severity == SEV_LEGIT
        assert verdict.severity == SEV_MALICIOUS

    def test_dual_form_falls_back_to_name_when_no_label_matches(self) -> None:
        # Defensive: a NameVerdict whose severity matches no label -> dual-form returns
        # the whole name rather than raising/None-dereferencing.
        nv = NameVerdict(
            a_name="x.com",
            labels=(LabelVerdict("x", "x", frozenset({"Latin"}), SEV_LEGIT, frozenset(), None),),
            severity=SEV_MALICIOUS,
            offending=frozenset(),
        )
        assert _idn_dual_form(nv) == "x.com"
