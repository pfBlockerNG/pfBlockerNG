"""ADR-07 Phase 6 -- Stage-C emit + wired build() + LIVE 6-band matcher.

These tests prove the INTEGRATION: build() routes format_hint='abp' feeds through
parse_abp (Stage A) -> reconcile (Stage B) -> emit the matcher dicts + compiled
regex + the important_rules flag, and the PRODUCTION evaluate_domain resolves them
by the live 6-band precedence -- decision-equal to the Phase-2 oracle decide().

Both directions are gated here:
  * OFF (no abp feature loaded): important_rules stays False and the matcher keeps
    today's fast path (the no-regression anchor; the ADR-06 oracle is the wider
    guard, retained unchanged).
  * ON (abp @@/regex/$important/$badfilter loaded): evaluate_domain + the wired
    build agree with decide() on block / allow / regex / important / badfilter /
    provenance / sovereignty.
"""

from __future__ import annotations

from typing import Any, Iterable

import pfb_unbound as P
import tests.test_adr07_decision_spec as spec

# --------------------------------------------------------------------------- #
# Drive the REAL build() with an in-memory abp manifest + a line reader, then run
# the REAL evaluate_domain over the emitted structures.
# --------------------------------------------------------------------------- #

# A minimal public-suffix oracle: ``com``/``net``/``org`` are public suffixes, so
# ``example.com`` is the registrable parent (zone classify groups subdomains there).
_TLD_MASTER = ["com", "net", "org"]


def _build(
    feeds: dict[str, list[str]],
    *,
    user_whitelist: Iterable[str] = (),
    user_unlock: Iterable[str] = (),
    top1m_list: Iterable[str] = (),
    top1m_enabled: bool = False,
    format_hint: str = "abp",
    user_feeds: Iterable[str] = (),
    plain_feeds: Iterable[str] = (),
) -> P.BuildResult:
    """Build from an in-memory abp manifest. ``feeds`` maps a feed name -> raw lines.

    ``user_feeds`` names the feeds tagged provenance='user' (a DNSBL Group Custom_List,
    sovereign band 5); ``plain_feeds`` names those forced format_hint='plain' (the
    non-ABP path), so a mixed user-plain + downloaded-ABP manifest can be built.
    ``user_unlock`` is the temporary per-alert unlock set (#51), merged into whiteDB
    as band-6 user allows exactly like ``user_whitelist``.
    """
    raw_store = {name: lines for name, lines in feeds.items()}
    user_set = set(user_feeds)
    plain_set = set(plain_feeds)
    manifest = {
        "feeds": [
            {
                "raw": name,
                "feed": name,
                "group": name,
                "format_hint": "plain" if name in plain_set else format_hint,
                "log_flag": "1",
                "provenance": "user" if name in user_set else "feed",
            }
            for name in feeds
        ],
    }
    config = {
        "tld_master": _TLD_MASTER,
        "tld_blacklist": [],
        "tld_exclusion": [],
        "user_whitelist": list(user_whitelist),
        "user_unlock": list(user_unlock),
        "top1m_list": list(top1m_list),
    }

    def reader(raw: str) -> Iterable[str]:
        return list(raw_store.get(raw, []))

    return P.build(manifest, config, line_reader=reader, top1m_enabled=top1m_enabled)


def _cfg_from_result(result: P.BuildResult) -> dict[str, Any]:
    return {
        "python_blocking": True,
        "dataDB": bool(result.data_db),
        "zoneDB": bool(result.zone_db),
        "whiteDB": bool(result.white_db),
        "regexDB": bool(result.regex_db),
        "allowRegexDB": bool(result.allow_regex_db),
        "important_rules": result.important_rules,
        "hstsDB": False,
        "python_tld": False,
        "python_idn": False,
        "python_tld_seg": 2,
        "python_tlds": [],
        "dnsbl_ipv4": "10.10.10.1",
        "dnsbl_ipv6": "::1",
        "hsts_tlds": (),
    }


def _containers_from_result(result: P.BuildResult) -> dict[str, Any]:
    return {
        "dataDB": result.data_db,
        "zoneDB": result.zone_db,
        "whiteDB": result.white_db,
        "regexDB": result.regex_db,
        "allowRegexDB": result.allow_regex_db,
        "feedGroupIndexDB": result.feed_group_index_db,
        "hstsDB": {},
    }


def _live_label(result: P.BuildResult, q_name: str) -> str:
    """Run the PRODUCTION matcher and reduce to the spec's {block,resolve,pass}.

    Mapping (RESULTS/02 SS1): not is_found -> "pass"; is_found & in_whitelist (an
    allow won) -> "resolve"; is_found & blocked -> "block". No hstsDB is loaded, so
    in_hsts is always False and never masks a block here."""
    cfg = _cfg_from_result(result)
    containers = _containers_from_result(result)
    tld = q_name.rsplit(".", 1)[-1] if "." in q_name else q_name
    dec = P.evaluate_domain(q_name, q_name, tld, False, cfg, containers)
    if not dec.is_found:
        return "pass"
    if dec.in_whitelist:
        return "resolve"
    return "block"


def _oracle_label(feed_lines: dict[str, list[str]], user_lines: list[str], q_name: str) -> str:
    """The Phase-2 oracle decision for the same rule set (feeds=FEED, user=USER)."""
    rules: list[spec.Rule] = []
    for lines in feed_lines.values():
        rules += spec.rules_from(lines, spec.Provenance.FEED)
    rules += spec.rules_from(user_lines, spec.Provenance.USER)
    return spec.decide(rules, q_name).outcome


# --------------------------------------------------------------------------- #
# 1. EMIT shapes -- build() produces the wired structure-set
# --------------------------------------------------------------------------- #
class TestEmitShapes:
    def test_plain_block_emits_band1_not_important(self) -> None:
        res = _build({"f": ["||evil.com^"]})
        assert res.important_rules is False  # no @@/regex/important -> fast path
        entry = res.zone_db["evil.com"]
        assert entry["band"] == P.PRIO_FEED_BLOCK
        assert entry["important"] is False

    def test_important_block_sets_flag_and_band3(self) -> None:
        res = _build({"f": ["||evil.com^$important"]})
        assert res.important_rules is True
        assert res.zone_db["evil.com"]["band"] == P.PRIO_FEED_BLOCK_IMPORTANT
        assert res.zone_db["evil.com"]["important"] is True

    def test_feed_allow_emits_whitedb_and_sets_flag(self) -> None:
        res = _build({"f": ["||example.com^", "@@||safe.example.com^"]})
        assert res.important_rules is True  # a feed @@ engages the numeric path
        assert "safe.example.com" in res.white_db
        assert res.white_db["safe.example.com"]["band"] == P.PRIO_FEED_ALLOW

    def test_irreducible_block_regex_compiled_into_regexdb(self) -> None:
        res = _build({"f": [r"/ad[0-9]\.example\.com$/"]})
        assert res.important_rules is True  # feed regex engages the numeric path
        assert len(res.regex_db) == 1
        assert res.regex_count == 1
        (payload,) = res.regex_db.values()
        assert payload["re"].search("ad7.example.com")
        assert payload["band"] == P.PRIO_FEED_BLOCK

    def test_irreducible_allow_regex_compiled_into_allowregexdb(self) -> None:
        res = _build({"f": [r"/ad[0-9]\.example\.com$/", r"@@/safe[0-9]\.example\.com$/"]})
        assert len(res.allow_regex_db) == 1
        assert res.regex_count == 2  # one block + one allow regex admitted

    def test_reducible_regex_folds_no_compiled_pattern(self) -> None:
        res = _build({"f": [r"/^(.+\.)?doubleclick\.net$/"]})
        assert res.regex_db == {}  # folded to a zone block, nothing compiled
        assert "doubleclick.net" in res.zone_db

    def test_broken_regex_skipped_not_fatal(self) -> None:
        res = _build({"f": [r"/ad(unclosed/", r"/ad[0-9]\.example\.com$/"]})
        # the broken pattern is dropped; the good one is admitted
        assert len(res.regex_db) == 1
        assert res.regex_count == 1

    def test_badfilter_prunes_feed_block(self) -> None:
        res = _build({"f": ["||y.example.com^", "||y.example.com^$badfilter"]})
        assert "y.example.com" not in res.zone_db
        assert _live_label(res, "y.example.com") == "pass"


# --------------------------------------------------------------------------- #
# 2. OFF -- no abp feature loaded keeps the fast path (no-regression anchor)
# --------------------------------------------------------------------------- #
class TestFastPathOff:
    def test_plain_feed_block_stays_fast_path(self) -> None:
        res = _build({"f": ["||evil.com^", "good.com"]}, user_whitelist=[])
        assert res.important_rules is False
        assert _live_label(res, "evil.com") == "block"
        assert _live_label(res, "sub.evil.com") == "block"  # zone covers subdomains
        assert _live_label(res, "good.com") == "block"  # plain bare domain blocks
        assert _live_label(res, "unrelated.org") == "pass"

    def test_user_whitelist_overrides_feed_block_on_fast_path(self) -> None:
        # A pure user whitelist (no abp feature) stays on the fast path and still
        # un-blocks -- byte-identical to today (P3/P5: a user rule alone does not
        # force important_rules).
        res = _build({"f": ["||evil.com^"]}, user_whitelist=["evil.com"])
        assert res.important_rules is False
        assert _live_label(res, "evil.com") == "resolve"

    def test_off_matches_oracle(self) -> None:
        feeds = {"f": ["||evil.com^", "good.com"]}
        for q in ("evil.com", "sub.evil.com", "good.com", "unrelated.org"):
            assert _live_label(_build(feeds), q) == _oracle_label(feeds, [], q)


# --------------------------------------------------------------------------- #
# 2b. #51 -- the temporary per-alert unlock set (config.user_unlock) merges into
#     whiteDB as a band-6 user allow, exactly like the permanent user whitelist.
# --------------------------------------------------------------------------- #
class TestUserUnlock:
    def test_unlock_overrides_feed_block_on_fast_path(self) -> None:
        # A temporary unlock alone (no abp feature) stays on the fast path and
        # un-blocks the domain, just like a permanent user whitelist entry.
        res = _build({"f": ["||evil.com^"]}, user_unlock=["evil.com"])
        assert res.important_rules is False
        assert _live_label(res, "evil.com") == "resolve"

    def test_unlock_is_band6_important_allow(self) -> None:
        # Same whiteDB shape as the user whitelist: sovereign user allow (band 6).
        res = _build({"f": ["||evil.com^"]}, user_unlock=["evil.com"])
        assert res.white_db["evil.com"] == {
            "wildcard": False,
            "important": True,
            "band": P.PRIO_USER_ALLOW,
        }

    def test_unlock_beats_user_custom_list_block(self) -> None:
        # A DNSBL Group Custom_List block is sovereign (band 5) over feeds, but a
        # temporary unlock (band 6) still wins -- the user can unlock their own block.
        res = _build({"cust": ["||x.example.com^"]}, user_feeds=["cust"], user_unlock=["x.example.com"])
        assert _live_label(res, "x.example.com") == "resolve"

    def test_unlock_leading_dot_is_wildcard(self) -> None:
        # Normalised exactly like the whitelist: a leading dot -> wildcard allow
        # covering subdomains.
        res = _build({"f": ["||evil.com^"]}, user_unlock=[".evil.com"])
        assert res.white_db["evil.com"]["wildcard"] is True
        assert _live_label(res, "sub.evil.com") == "resolve"

    def test_empty_unlock_keeps_block(self) -> None:
        # The full-build default (empty user_unlock) leaves the feed block intact.
        res = _build({"f": ["||evil.com^"]}, user_unlock=[])
        assert _live_label(res, "evil.com") == "block"

    def test_unlock_does_not_narrow_wildcard_whitelist(self) -> None:
        # CodeRabbit #65: a permanent WILDCARD whitelist (".evil.com" -> covers
        # subdomains) must NOT be downgraded to exact when the same registrable domain
        # is temporarily unlocked (exact). The merge widens on collision, so both the
        # apex and a subdomain still resolve.
        res = _build(
            {"f": ["||evil.com^", "||sub.evil.com^"]},
            user_whitelist=[".evil.com"],
            user_unlock=["evil.com"],
        )
        assert res.white_db["evil.com"]["wildcard"] is True
        assert _live_label(res, "evil.com") == "resolve"
        assert _live_label(res, "sub.evil.com") == "resolve"


# --------------------------------------------------------------------------- #
# 3. ON -- the live 6-band matcher == the Phase-2 oracle decide()
# --------------------------------------------------------------------------- #
class TestLiveMatcherEqualsOracle:
    def test_feed_allow_unblocks_globally(self) -> None:
        feeds = {"f": ["||example.com^", "@@||safe.example.com^"]}
        res = _build(feeds)
        assert _live_label(res, "example.com") == "block"
        assert _live_label(res, "safe.example.com") == "resolve"
        for q in ("example.com", "safe.example.com", "other.example.com"):
            assert _live_label(res, q) == _oracle_label(feeds, [], q)

    def test_important_block_beats_feed_allow(self) -> None:
        # feed ||x^$important (band 3) beats feed @@x^ (band 2)
        feeds = {"f": ["||x.example.com^$important", "@@||x.example.com^"]}
        res = _build(feeds)
        assert _live_label(res, "x.example.com") == "block"
        assert res.important_rules is True
        assert _live_label(res, "x.example.com") == _oracle_label(feeds, [], "x.example.com")

    def test_important_allow_beats_feed_block(self) -> None:
        # feed @@y^$important (band 4) beats feed ||y^ (band 1)
        feeds = {"f": ["@@||y.example.com^$important", "||y.example.com^"]}
        res = _build(feeds)
        assert _live_label(res, "y.example.com") == "resolve"
        assert _live_label(res, "y.example.com") == _oracle_label(feeds, [], "y.example.com")

    def test_irreducible_block_regex_blocks_live(self) -> None:
        feeds = {"f": [r"/ad[0-9]\.example\.com$/"]}
        res = _build(feeds)
        assert _live_label(res, "ad7.example.com") == "block"
        assert _live_label(res, "adx.example.com") == "pass"
        for q in ("ad7.example.com", "adx.example.com"):
            assert _live_label(res, q) == _oracle_label(feeds, [], q)

    def test_allow_regex_unblocks_live(self) -> None:
        feeds = {"f": ["||example.com^", r"@@/safe[0-9]\.example\.com$/"]}
        res = _build(feeds)
        assert _live_label(res, "safe7.example.com") == "resolve"
        assert _live_label(res, "evil.example.com") == "block"

    def test_block_regex_vs_allow_regex_plain(self) -> None:
        # Plain block regex (band 1) vs plain allow regex (band 2): the allow wins.
        feeds = {"f": [r"/x[0-9]\.example\.com$/", r"@@/x[0-9]\.example\.com$/"]}
        res = _build(feeds)
        assert _live_label(res, "x7.example.com") == "resolve"
        assert _live_label(res, "x7.example.com") == _oracle_label(feeds, [], "x7.example.com")

    def test_important_block_regex_beats_allow_regex(self) -> None:
        # Regex now honours $options: a block regex $important (band 3) beats a plain
        # allow regex (band 2). Without $important the allow would win (test above).
        feeds = {"f": [r"/x[0-9]\.example\.com$/$important", r"@@/x[0-9]\.example\.com$/"]}
        res = _build(feeds)
        assert res.important_rules is True
        assert _live_label(res, "x7.example.com") == "block"
        assert _live_label(res, "x7.example.com") == _oracle_label(feeds, [], "x7.example.com")

    def test_badfilter_regex_prunes_feed_block_regex(self) -> None:
        # A feed /re/$badfilter removes the matching feed /re/ (same signature) -> the
        # name no longer matches the block regex and resolves.
        feeds = {"f": [r"/x[0-9]\.example\.com$/", r"/x[0-9]\.example\.com$/$badfilter"]}
        res = _build(feeds)
        assert _live_label(res, "x7.example.com") != "block"
        assert _live_label(res, "x7.example.com") == _oracle_label(feeds, [], "x7.example.com")

    def test_exact_then_wildcard_allow_keeps_subdomain_coverage(self) -> None:
        # Same key, SAME band (both feed allow): an EXACT allow (reduced @@/^d$/)
        # emitted BEFORE the wildcard allow (@@||d^) must not drop the wildcard's
        # subdomain coverage -- the whiteDB suffix-walk only honours wildcard entries,
        # so a first-writer-wins skip would leave sub.example.com blocked by the zone.
        feeds = {"f": [r"@@/^example\.com$/", "@@||example.com^", "||example.com^"]}
        res = _build(feeds)
        assert res.white_db["example.com"]["wildcard"] is True
        assert _live_label(res, "example.com") == "resolve"
        assert _live_label(res, "sub.example.com") == "resolve"
        for q in ("example.com", "sub.example.com"):
            assert _live_label(res, q) == _oracle_label(feeds, [], q)

    def test_deep_anchor_blocks_subdomains(self) -> None:
        # ABP anchor semantics: ||host^ blocks host AND every subdomain of host,
        # regardless of how many labels sit above host's own registrable parent
        # (Phase-2 oracle decide(): "rule.wildcard and q.endswith('.' + rule.key)",
        # no depth restriction). A THREE-label anchor like ||ads.example.com^ must
        # cover deep.ads.example.com exactly as a two-label anchor covers its subs.
        feeds = {"f": ["||ads.example.com^"]}
        res = _build(feeds)
        assert _live_label(res, "ads.example.com") == "block"
        assert _live_label(res, "deep.ads.example.com") == "block"
        for q in ("ads.example.com", "deep.ads.example.com", "example.com", "other.example.com"):
            assert _live_label(res, q) == _oracle_label(feeds, [], q)


# --------------------------------------------------------------------------- #
# 4. User sovereignty (fact 7) is absolute -- user rules win over feeds + $important
# --------------------------------------------------------------------------- #
class TestUserSovereignty:
    def test_user_whitelist_beats_important_feed_block(self) -> None:
        # user allow (band 6) beats feed ||z^$important (band 3)
        feeds = {"f": ["||z.example.com^$important"]}
        res = _build(feeds, user_whitelist=["z.example.com"])
        assert _live_label(res, "z.example.com") == "resolve"
        assert _live_label(res, "z.example.com") == _oracle_label(feeds, ["@@||z.example.com^"], "z.example.com")

    def test_top1m_behaves_as_user_allow(self) -> None:
        feeds = {"f": ["||cdn.example.com^$important"]}
        res = _build(feeds, top1m_list=["cdn.example.com"], top1m_enabled=True)
        assert _live_label(res, "cdn.example.com") == "resolve"

    def test_user_whitelist_not_pruned_by_feed_badfilter(self) -> None:
        # A feed $badfilter never removes the user whitelist (it isn't a feed rule).
        # Here the feed $badfilter shares the block's signature, so it prunes the FEED
        # block (feed-only); the user whitelist is untouched. Net: the name resolves
        # (live returns "pass" -- nothing blocks -- which is the same NOT-null-routed
        # outcome as the oracle's allow-wins "resolve"; RESULTS/02 SS1 maps both to
        # "resolves").
        feeds = {"f": ["@@||w.example.com^$badfilter", "||w.example.com^"]}
        res = _build(feeds, user_whitelist=["w.example.com"])
        assert _live_label(res, "w.example.com") != "block"
        assert _oracle_label(feeds, ["@@||w.example.com^"], "w.example.com") != "block"


# --------------------------------------------------------------------------- #
# 5. Both important_rules branches are exercised + the numeric block-band max
# --------------------------------------------------------------------------- #
class TestBranchCoverage:
    def test_max_block_band_over_data_and_regex(self) -> None:
        # An exact data block ($important, band 3) AND a feed allow (band 2): the
        # numeric branch must take the MAX block band (3) so the allow does NOT win.
        feeds = {"f": ["||a.example.com^$important", "@@||a.example.com^"]}
        res = _build(feeds)
        assert _live_label(res, "a.example.com") == "block"

    def test_numeric_branch_engaged_when_flag_true(self) -> None:
        res = _build({"f": ["@@||b.example.com^", "||b.example.com^"]})
        assert res.important_rules is True
        # feed allow (2) > feed block (1) -> resolves via the numeric branch.
        assert _live_label(res, "b.example.com") == "resolve"

    def test_fast_branch_when_flag_false(self) -> None:
        res = _build({"f": ["||c.example.com^"]})
        assert res.important_rules is False
        assert _live_label(res, "c.example.com") == "block"


# --------------------------------------------------------------------------- #
# 6. USER provenance -- a DNSBL Group Custom_List is sovereign over feeds
# --------------------------------------------------------------------------- #
class TestUserCustomListSovereign:
    """A Custom_List row (manifest provenance='user') bands its blocks at the user
    tier (5), so an explicit user block beats any FEED allow -- the user is the
    sovereign. The CONTRAST tests prove the provenance tag is what flips the outcome:
    the identical rules WITHOUT the user tag let the feed @@$important win.
    """

    def test_abp_custom_block_beats_feed_important_allow(self) -> None:
        # cust (user, ABP) blocks ||x^; dl (feed) allows @@||x^$important.
        res = _build(
            {"cust": ["||x.example.com^"], "dl": ["@@||x.example.com^$important"]},
            user_feeds=["cust"],
        )
        assert _live_label(res, "x.example.com") == "block"

    def test_plain_custom_block_beats_feed_important_allow(self) -> None:
        # The NON-ABP path: cust is a plain user Custom_List (bare domain), dl is an
        # ABP feed @@$important. The plain user block must still band at 5 and win.
        res = _build(
            {"cust": ["x.example.com"], "dl": ["@@||x.example.com^$important"]},
            user_feeds=["cust"],
            plain_feeds=["cust"],
        )
        assert _live_label(res, "x.example.com") == "block"

    def test_contrast_same_rules_without_user_tag_feed_allow_wins(self) -> None:
        # IDENTICAL rules, but BOTH feeds downloaded (provenance='feed'): the feed
        # block is band 1, the feed @@$important is band 4 -> the allow wins. This is
        # what makes the provenance tag load-bearing (band 5 vs 1 flips block<->resolve).
        res = _build({"dl1": ["||x.example.com^"], "dl2": ["@@||x.example.com^$important"]})
        assert _live_label(res, "x.example.com") == "resolve"

    def test_whitelist_still_beats_user_custom_block(self) -> None:
        # The whitelist (band 6) is the ultimate override -- it beats even a user
        # Custom_List block (band 5).
        res = _build({"cust": ["||x.example.com^"]}, user_feeds=["cust"], user_whitelist=["x.example.com"])
        assert _live_label(res, "x.example.com") == "resolve"

    def test_user_custom_block_bands_at_5(self) -> None:
        # Direct payload check: a plain user Custom_List entry carries band 5.
        res = _build({"cust": ["x.example.com"]}, plain_feeds=["cust"], user_feeds=["cust"])
        entry = res.zone_db.get("example.com") or res.data_db.get("x.example.com")
        assert entry is not None and entry["band"] == P.PRIO_USER_BLOCK == 5

    def test_feed_block_still_bands_at_1(self) -> None:
        # Regression: a downloaded plain feed stays band 1 (provenance default 'feed').
        res = _build({"dl": ["x.example.com"]}, plain_feeds=["dl"])
        entry = res.zone_db.get("example.com") or res.data_db.get("x.example.com")
        assert entry is not None and entry["band"] == P.PRIO_FEED_BLOCK == 1
