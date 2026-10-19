"""ADR-07 -- user regex lives in its own containers, evaluated before the feed ones.

"User regex" is both the ``MAIN.regex_list`` patterns (the DNSBL page Regex List) and the
``/re/`` / ``@@/re/`` rows of a Custom_List (manifest ``provenance: "user"``). They load into
``userRegexDB`` / ``userAllowRegexDB`` (``user_regex_db`` / ``user_allow_regex_db`` on
``BuildResult`` and ``Snapshot``), never into the feed ``regexDB`` / ``allowRegexDB``, and every
scan visits the user list first, so a feed can neither push a user rule out nor outrank it.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

import pytest

import pfb_unbound
from pfb_unbound import (
    PRIO_FEED_ALLOW,
    PRIO_FEED_ALLOW_IMPORTANT,
    PRIO_FEED_BLOCK,
    PRIO_FEED_BLOCK_IMPORTANT,
    PRIO_USER_ALLOW,
    PRIO_USER_BLOCK,
    _scan_allow_regex_band,
    _scan_block_band,
    evaluate_domain,
)
from tests.test_adr07_regex_safety import (
    KEEP_ROW,
    SLOW_LIST_LINE,
    _cfg,
    _containers,
    _Measured,
    _patterns,
    _user_regex_loads,
)


def _build(
    feeds: dict[str, list[str]], *, user_feeds: Iterable[str] = (), regex_cap: bool = False
) -> pfb_unbound.BuildResult:
    """The real ``build()`` over an in-memory manifest; ``user_feeds`` are Custom_List rows."""
    user_set = set(user_feeds)
    manifest = {
        "feeds": [
            {
                "raw": name,
                "feed": name,
                "group": name,
                "log_flag": "1",
                "provenance": "user" if name in user_set else "feed",
            }
            for name in feeds
        ]
    }
    config = {"tld_wildcard_blacklist": [], "tld_wildcard_exclusion": [], "regex_cap": regex_cap}
    return pfb_unbound.build(manifest, config, line_reader=lambda raw: list(feeds.get(raw, [])))


@pytest.fixture(autouse=True)
def _blocking_on(monkeypatch: pytest.MonkeyPatch) -> None:
    """The per-query cfg reads ``python_blocking`` from the module settings; data and zone blocks only
    apply while it is on."""
    monkeypatch.setitem(pfb_unbound.pfb, "python_blocking", True)


def _entry(pattern: str, band: int, important: bool = False) -> dict[str, Any]:
    return {"re": re.compile(pattern, re.IGNORECASE), "important": important, "band": band}


MINE = r"/^mine[0-9]+\.example$/"
MINE_ALLOW = r"@@/^ok[0-9]+\.example$/"


class TestBuildSplitsRegexByProvenance:
    def test_a_custom_list_block_and_allow_regex_land_in_the_user_containers_only(self) -> None:
        result = _build({"Custom": [MINE, MINE_ALLOW]}, user_feeds=("Custom",))
        assert _patterns(result.user_regex_db) == {"Custom#0": r"^mine[0-9]+\.example$"}
        assert _patterns(result.user_allow_regex_db) == {"Custom#0": r"^ok[0-9]+\.example$"}
        assert result.user_regex_db["Custom#0"]["band"] == PRIO_USER_BLOCK
        assert result.user_allow_regex_db["Custom#0"]["band"] == PRIO_USER_ALLOW
        assert (result.regex_db, result.allow_regex_db) == ({}, {})

    def test_a_feed_regex_lands_in_the_feed_containers_only(self) -> None:
        result = _build({"Feed": [MINE, MINE_ALLOW]})
        assert _patterns(result.regex_db) == {"Feed#0": r"^mine[0-9]+\.example$"}
        assert _patterns(result.allow_regex_db) == {"Feed#0": r"^ok[0-9]+\.example$"}
        assert (result.user_regex_db, result.user_allow_regex_db) == ({}, {})

    def test_the_regex_count_sums_all_four_containers(self) -> None:
        result = _build({"Feed": [MINE, MINE_ALLOW], "Custom": [MINE, MINE_ALLOW]}, user_feeds=("Custom",))
        sizes = (
            len(result.regex_db),
            len(result.allow_regex_db),
            len(result.user_regex_db),
            len(result.user_allow_regex_db),
        )
        assert sizes == (1, 1, 1, 1)
        assert result.regex_count == 4

    def test_a_user_regex_takes_the_admission_gate_and_the_opt_in_length_cap(self) -> None:
        long_row = "^" + "a" * 210 + "$"
        hostile = "^[a-z]{1,255}[a-z]{1,255}[a-z]{1,255}x"
        feeds = {"Custom": [f"/{hostile}/", f"/{long_row}/", "/^keep[0-9]+\\.example$/"]}
        uncapped = _build(feeds, user_feeds=("Custom",), regex_cap=False)
        assert sorted(_patterns(uncapped.user_regex_db).values()) == sorted([long_row, "^keep[0-9]+\\.example$"])
        capped = _build(feeds, user_feeds=("Custom",), regex_cap=True)
        assert list(_patterns(capped.user_regex_db).values()) == ["^keep[0-9]+\\.example$"]

    def test_a_user_rule_loads_and_blocks_after_1500_feed_rules(self) -> None:
        feeds = {"Feed": [f"/^b[0-9]+x{i}\\.example$/" for i in range(1500)], "Custom": [MINE]}
        result = _build(feeds, user_feeds=("Custom",))
        assert len(result.regex_db) == 1500
        assert len(result.user_regex_db) == 1
        assert result.regex_count == 1501
        cfg = _cfg(regexDB=True, userRegexDB=True)
        containers = _containers(regexDB=result.regex_db, userRegexDB=result.user_regex_db)
        decision = evaluate_domain("mine7.example", "mine7.example", "example", False, cfg, containers)
        assert (decision.is_found, decision.feed) == (True, "Custom#0")


class TestUserRegexIsEvaluatedFirst:
    def test_the_discovery_scan_reaches_the_user_list_before_the_feed_list(self) -> None:
        containers = _containers(
            regexDB={"F#0": _entry("evil", PRIO_FEED_BLOCK)},
            userRegexDB={"U#0": _entry("evil", PRIO_USER_BLOCK)},
        )
        cfg = _cfg(regexDB=True, userRegexDB=True)
        decision = evaluate_domain("evil.example", "evil.example", "example", False, cfg, containers)
        assert (decision.is_found, decision.feed, decision.group) == (True, "U#0", "DNSBL_Regex")

    def test_a_user_regex_blocks_with_no_feed_regex_loaded(self) -> None:
        containers = _containers(userRegexDB={"U#0": _entry("evil", PRIO_USER_BLOCK)})
        cfg = _cfg(userRegexDB=True)
        decision = evaluate_domain("evil.example", "evil.example", "example", False, cfg, containers)
        assert (decision.is_found, decision.feed) == (True, "U#0")

    def test_a_feed_regex_still_blocks_when_the_user_list_does_not_match(self) -> None:
        containers = _containers(
            regexDB={"F#0": _entry("evil", PRIO_FEED_BLOCK)},
            userRegexDB={"U#0": _entry("other", PRIO_USER_BLOCK)},
        )
        cfg = _cfg(regexDB=True, userRegexDB=True)
        decision = evaluate_domain("evil.example", "evil.example", "example", False, cfg, containers)
        assert (decision.is_found, decision.feed) == (True, "F#0")

    @pytest.mark.parametrize("allow_band", [PRIO_FEED_ALLOW, PRIO_FEED_ALLOW_IMPORTANT])
    def test_a_user_block_regex_beats_a_feed_allow_regex(self, allow_band: int) -> None:
        containers = _containers(
            userRegexDB={"U#0": _entry("evil", PRIO_USER_BLOCK)},
            allowRegexDB={"A#0": _entry("evil", allow_band, important=allow_band == PRIO_FEED_ALLOW_IMPORTANT)},
        )
        cfg = _cfg(userRegexDB=True, allowRegexDB=True, important_rules=True)
        decision = evaluate_domain("evil.example", "evil.example", "example", False, cfg, containers)
        assert (decision.is_found, decision.in_whitelist) == (True, False)

    def test_a_user_allow_regex_beats_an_important_feed_block_regex(self) -> None:
        containers = _containers(
            regexDB={"F#0": _entry("evil", PRIO_FEED_BLOCK_IMPORTANT, important=True)},
            userAllowRegexDB={"UA#0": _entry("evil", PRIO_USER_ALLOW)},
        )
        cfg = _cfg(regexDB=True, userAllowRegexDB=True, important_rules=True)
        decision = evaluate_domain("evil.example", "evil.example", "example", False, cfg, containers)
        assert (decision.is_found, decision.in_whitelist) == (True, True)

    def test_a_user_allow_regex_beats_a_user_block_regex(self) -> None:
        containers = _containers(
            userRegexDB={"U#0": _entry("evil", PRIO_USER_BLOCK)},
            userAllowRegexDB={"UA#0": _entry("evil", PRIO_USER_ALLOW)},
        )
        cfg = _cfg(userRegexDB=True, userAllowRegexDB=True, important_rules=True)
        decision = evaluate_domain("evil.example", "evil.example", "example", False, cfg, containers)
        assert (decision.is_found, decision.in_whitelist) == (True, True)

    def test_the_band_rescan_covers_both_block_lists_and_names_the_winner(self) -> None:
        feed = {"F#0": _entry("evil", PRIO_FEED_BLOCK_IMPORTANT, important=True)}
        user = {"U#0": _entry("evil", PRIO_USER_BLOCK)}
        cfg = _cfg(regexDB=True, userRegexDB=True)
        assert _scan_block_band("evil.example", cfg, {}, {}, feed, user) == (
            PRIO_USER_BLOCK,
            {"kind": "regex", "key": "U#0"},
        )
        assert _scan_block_band("evil.example", cfg, {}, {}, feed, {}) == (
            PRIO_FEED_BLOCK_IMPORTANT,
            {"kind": "regex", "key": "F#0"},
        )
        only_user = _cfg(userRegexDB=True)
        assert _scan_block_band("evil.example", only_user, {}, {}, {}, user) == (
            PRIO_USER_BLOCK,
            {"kind": "regex", "key": "U#0"},
        )

    def test_the_allow_rescan_covers_both_allow_lists(self) -> None:
        feed = {"A#0": _entry("evil", PRIO_FEED_ALLOW_IMPORTANT, important=True)}
        user = {"UA#0": _entry("evil", PRIO_USER_ALLOW)}
        assert _scan_allow_regex_band("evil.example", feed, user, 10.0) == PRIO_USER_ALLOW
        assert _scan_allow_regex_band("evil.example", {}, user, 10.0) == PRIO_USER_ALLOW
        assert _scan_allow_regex_band("evil.example", feed, {}, 10.0) == PRIO_FEED_ALLOW_IMPORTANT

    def test_a_band_tie_keeps_the_rule_that_was_scanned_first(self) -> None:
        data = {"evil.example": {"log": "1", "index": 0, "important": False, "band": PRIO_FEED_BLOCK}}
        feed = {"F#0": _entry("evil", PRIO_FEED_BLOCK)}
        user = {"U#0": _entry("evil", PRIO_FEED_BLOCK)}
        cfg = _cfg(dataDB=True, regexDB=True, userRegexDB=True)
        # a data entry and a regex rule at one band: the data entry is scanned first
        assert _scan_block_band("evil.example", cfg, data, {}, feed, {}) == (
            PRIO_FEED_BLOCK,
            {"kind": "data", "entry": data["evil.example"]},
        )
        # a user rule and a feed rule at one band: the user list is scanned first
        assert _scan_block_band("evil.example", cfg, {}, {}, feed, user) == (
            PRIO_FEED_BLOCK,
            {"kind": "regex", "key": "U#0"},
        )

    def test_the_user_and_the_feed_block_lists_report_a_slow_scan_separately(
        self, monkeypatch: Any, capsys: Any
    ) -> None:
        measured = _Measured(monkeypatch)
        containers = _containers(
            regexDB=measured.db("F", PRIO_FEED_BLOCK, [4.0, 4.0, 4.0]),
            userRegexDB=measured.db("U", PRIO_USER_BLOCK, [3.0, 4.0, 5.0]),
        )
        cfg = _cfg(regexDB=True, userRegexDB=True)
        decision = evaluate_domain("slow.example", "slow.example", "example", False, cfg, containers)
        assert decision.is_found is False
        assert capsys.readouterr().err == SLOW_LIST_LINE.format(
            label="user DNSBL_Regex", total="12.0", count=3, slowest="U#2", top="5.0"
        ) + SLOW_LIST_LINE.format(label="DNSBL_Regex", total="12.0", count=3, slowest="F#0", top="4.0")

    def test_the_user_and_the_feed_allow_lists_report_a_slow_scan_separately(
        self, monkeypatch: Any, capsys: Any
    ) -> None:
        measured = _Measured(monkeypatch)
        feed = measured.db("A", PRIO_FEED_ALLOW, [3.0, 5.0, 4.0])
        user = measured.db("UA", PRIO_USER_ALLOW, [3.0, 4.0, 5.0])
        assert _scan_allow_regex_band("slow.example", feed, user, 10.0) == 0
        assert capsys.readouterr().err == SLOW_LIST_LINE.format(
            label="user DNSBL_AllowRegex", total="12.0", count=3, slowest="UA#2", top="5.0"
        ) + SLOW_LIST_LINE.format(label="DNSBL_AllowRegex", total="12.0", count=3, slowest="A#1", top="5.0")


def _snapshot(**fields: Any) -> pfb_unbound.Snapshot:
    base: dict[str, Any] = {
        "data_db": {},
        "zone_db": {},
        "white_db": {},
        "regex_db": {},
        "allow_regex_db": {},
        "user_regex_db": {},
        "user_allow_regex_db": {},
        "feed_group_index_db": {},
        "hsts_db": {},
    }
    return pfb_unbound.Snapshot(**{**base, **fields})


class TestSnapshotCarriesTheUserContainers:
    def test_the_per_query_containers_and_flags_name_the_user_lists(self) -> None:
        user = {"U#0": _entry("evil", PRIO_USER_BLOCK)}
        snapshot = _snapshot(user_regex_db=user)
        assert snapshot.containers()["userRegexDB"] is user
        assert snapshot.containers()["userAllowRegexDB"] == {}
        cfg = pfb_unbound._evaluate_cfg(snapshot)
        assert (cfg["userRegexDB"], cfg["userAllowRegexDB"], cfg["regexDB"], cfg["allowRegexDB"]) == (
            True,
            False,
            False,
            False,
        )

    @pytest.mark.parametrize("field", ["user_regex_db", "user_allow_regex_db"])
    def test_a_swap_that_loads_only_user_regex_enables_the_master_gate(self, monkeypatch: Any, field: str) -> None:
        monkeypatch.setattr(pfb_unbound, "_open_dnsbl_stats_db_if_wanted", lambda: None)
        monkeypatch.setitem(pfb_unbound.pfb, "python_blacklist", False)
        snapshot = _snapshot(**{field: {"U#0": _entry("evil", PRIO_USER_BLOCK)}})
        assert pfb_unbound.rebuild_and_swap(lambda: snapshot, emit_counts=False) is True
        assert pfb_unbound.pfb["python_blacklist"] is True


class TestLoadSitesFillTheUserContainers:
    FEEDS = {
        "Feed": [r"/^f[0-9]+\.example$/", r"@@/^fa[0-9]+\.example$/"],
        "Custom": [r"/^c[0-9]+\.example$/", r"@@/^ca[0-9]+\.example$/"],
    }

    def test_init_and_the_swap_split_main_and_custom_list_regex_from_the_feed_regex(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        loads = _user_regex_loads(tmp_path, monkeypatch, [f"{KEEP_ROW}#keep"], feeds=self.FEEDS, user_feeds=("Custom",))
        for user, feed, user_allow in (
            (loads.initial, loads.feed_initial, loads.user_allow_initial),
            (loads.swapped, loads.feed_swapped, loads.user_allow_swapped),
        ):
            assert _patterns(user) == {"keep": KEEP_ROW, "Custom#0": r"^c[0-9]+\.example$"}
            assert _patterns(feed) == {"Feed#0": r"^f[0-9]+\.example$"}
            assert _patterns(user_allow) == {"Custom#0": r"^ca[0-9]+\.example$"}

    def test_init_and_the_swap_count_every_container(self, tmp_path: Path, monkeypatch: Any) -> None:
        loads = _user_regex_loads(tmp_path, monkeypatch, [f"{KEEP_ROW}#keep"], feeds=self.FEEDS, user_feeds=("Custom",))
        # keep + Custom block + Custom allow + Feed block + Feed allow
        assert loads.count_initial == 5
        assert loads.count_swapped == 5

    def test_init_installs_a_snapshot_that_counts_every_container(self, tmp_path: Path, monkeypatch: Any) -> None:
        loads = _user_regex_loads(tmp_path, monkeypatch, [f"{KEEP_ROW}#keep"], feeds=self.FEEDS, user_feeds=("Custom",))
        # keep + Custom block + Custom allow + Feed block + Feed allow
        assert loads.snapshot_count_initial == 5


# A leading `.*` / `.+` is compiled behind a written `^` (see pfb_regex_admission): the rules a build
# loads carry that text whichever list they come from.
LEADING_DOT_ROW = r".*[0-9]\.x\.com$"
LEADING_DOT_COMPILED = r"^(?:(?s:.*)[0-9]\.x\.com$)"


class TestBuildCompilesLeadingDotRunsBehindACaret:
    def test_a_feed_block_and_allow_rule_are_compiled_behind_a_caret(self) -> None:
        result = _build({"Feed": [f"/{LEADING_DOT_ROW}/", f"@@/{LEADING_DOT_ROW}/"]})
        assert _patterns(result.regex_db) == {"Feed#0": LEADING_DOT_COMPILED}
        assert _patterns(result.allow_regex_db) == {"Feed#0": LEADING_DOT_COMPILED}

    def test_a_custom_list_block_and_allow_rule_are_compiled_behind_a_caret(self) -> None:
        result = _build({"Custom": [f"/{LEADING_DOT_ROW}/", f"@@/{LEADING_DOT_ROW}/"]}, user_feeds=("Custom",))
        assert _patterns(result.user_regex_db) == {"Custom#0": LEADING_DOT_COMPILED}
        assert _patterns(result.user_allow_regex_db) == {"Custom#0": LEADING_DOT_COMPILED}


# A CNAME target is decoded from Latin-1 bytes and may carry a newline: a rule anchored by a leading dot run
# still blocks it, whichever list the rule is loaded from.
NEWLINE_TARGET = "evil\n7.x.com"


class TestLeadingDotRunRulesBlockANameWithANewline:
    @pytest.mark.parametrize(
        ("feeds", "user_feeds", "feed"),
        [
            ({"Feed": [f"/{LEADING_DOT_ROW}/"]}, (), "Feed#0"),
            ({"Custom": [f"/{LEADING_DOT_ROW}/"]}, ("Custom",), "Custom#0"),
        ],
        ids=["feed", "custom-list"],
    )
    def test_a_cname_target_with_a_newline_is_blocked_through_build_and_evaluate_domain(
        self, feeds: dict[str, list[str]], user_feeds: tuple[str, ...], feed: str
    ) -> None:
        result = _build(feeds, user_feeds=user_feeds)
        decision = _query(result, NEWLINE_TARGET, is_cname=True, original="alias.example.org")
        assert (decision.is_found, decision.feed, decision.in_whitelist) == (True, feed, False)
        # before-state: a name the rule does not match is left alone
        assert _query(result, "evil.example.org").is_found is False


def _query(
    result: pfb_unbound.BuildResult, name: str, *, is_cname: bool = False, original: str | None = None
) -> pfb_unbound.DnsblDecision:
    """``evaluate_domain`` over the snapshot of a real ``build()`` result, through the per-query cfg and
    containers the resolver derives from it. ``name`` is the CNAME target when ``is_cname``."""
    snapshot = _snapshot(
        data_db=result.data_db,
        zone_db=result.zone_db,
        white_db=result.white_db,
        regex_db=result.regex_db,
        allow_regex_db=result.allow_regex_db,
        user_regex_db=result.user_regex_db,
        user_allow_regex_db=result.user_allow_regex_db,
        feed_group_index_db=result.feed_group_index_db,
        important_rules=result.important_rules,
    )
    cfg = pfb_unbound._evaluate_cfg(snapshot)
    return evaluate_domain(name, original or name, name.rsplit(".", 1)[-1], is_cname, cfg, snapshot.containers())


class TestUserAllowRegexWhitelistsThroughTheQueryPath:
    def test_a_user_allow_regex_whitelists_a_feed_block_through_the_snapshot_cfg(self) -> None:
        snapshot = _snapshot(
            data_db={"ads.example.com": {"log": "1", "index": 0, "important": False, "band": PRIO_FEED_BLOCK}},
            feed_group_index_db={0: {"feed": "F", "group": "G"}},
            user_allow_regex_db={"UA#0": _entry(r"^ads\.example\.com$", PRIO_USER_ALLOW)},
            important_rules=True,
        )
        cfg = pfb_unbound._evaluate_cfg(snapshot)
        decision = evaluate_domain("ads.example.com", "ads.example.com", "com", False, cfg, snapshot.containers())
        assert (decision.is_found, decision.in_whitelist) == (True, True)

    def test_the_same_snapshot_without_that_allow_blocks(self) -> None:
        snapshot = _snapshot(
            data_db={"ads.example.com": {"log": "1", "index": 0, "important": False, "band": PRIO_FEED_BLOCK}},
            feed_group_index_db={0: {"feed": "F", "group": "G"}},
            user_allow_regex_db={"UA#0": _entry(r"^other\.example\.com$", PRIO_USER_ALLOW)},
            important_rules=True,
        )
        cfg = pfb_unbound._evaluate_cfg(snapshot)
        decision = evaluate_domain("ads.example.com", "ads.example.com", "com", False, cfg, snapshot.containers())
        assert (decision.is_found, decision.in_whitelist) == (True, False)


FEED_BLOCK = "||ads.example.com^"
USER_ALLOW_ROW = r"@@/^ads[0-9]?\.example\.com$/"


class TestUserAllowRegexOverridesAPlainFeedBlock:
    """A user rule always wins: a Custom_List ``@@/re/`` overrides a plain feed ``||domain^`` block,
    through the real ``build()`` and the real query path (no feed regex or ``$important`` present)."""

    def test_a_custom_list_allow_regex_whitelists_a_plain_feed_block(self) -> None:
        result = _build(
            {"Feed": [FEED_BLOCK, "||evil.example.com^"], "Custom": [USER_ALLOW_ROW]}, user_feeds=("Custom",)
        )
        assert result.important_rules is True
        allowed = _query(result, "ads.example.com")
        assert (allowed.is_found, allowed.in_whitelist) == (True, True)
        blocked = _query(result, "evil.example.com")
        assert (blocked.is_found, blocked.in_whitelist) == (True, False)

    def test_a_feed_allow_regex_whitelists_a_plain_feed_block_as_before(self) -> None:
        result = _build({"Feed": [FEED_BLOCK, USER_ALLOW_ROW]})
        assert result.important_rules is True  # a feed regex raises it, as before
        allowed = _query(result, "ads.example.com")
        assert (allowed.is_found, allowed.in_whitelist) == (True, True)

    @pytest.mark.parametrize(
        ("custom_rows", "raised"),
        [
            ([MINE], True),
            ([MINE_ALLOW], True),
            ([MINE, MINE_ALLOW], True),
            (["/^[a-z]{1,255}[a-z]{1,255}[a-z]{1,255}x/"], False),
            (["||x.example^", "@@||y.example^"], False),
            ([], False),
        ],
        ids=["block", "allow", "both", "refused-by-the-gate", "plain-custom-rows", "no-custom-list"],
    )
    def test_important_rules_follows_the_user_regex_that_loaded(self, custom_rows: list[str], raised: bool) -> None:
        feeds = {"Feed": [FEED_BLOCK]}
        if custom_rows:
            feeds["Custom"] = custom_rows
        result = _build(feeds, user_feeds=("Custom",))
        assert result.important_rules is raised


class TestRegexListRowsRaiseNumericPrecedenceLikeCustomListRows:
    """A Regex List row is a user rule too: it beats a plain feed block, so at both load sites the numeric
    precedence path runs and the verdict is the user regex's, with its own log and answer shape (the feed
    below logs with flag 3, an NXDOMAIN answer)."""

    @staticmethod
    def _decision(tmp_path: Path, monkeypatch: Any, rows: list[str], site: str) -> Any:
        loads = _user_regex_loads(
            tmp_path,
            monkeypatch,
            rows,
            feeds={"Feed": ["||x.example^"]},
            feed_log_flags={"Feed": "3"},
            query="x.example",
        )
        return loads.decision_initial if site == "init" else loads.decision_swapped

    @pytest.mark.parametrize("site", ["init", "swap"])
    def test_without_a_regex_list_row_the_plain_feed_block_decides_the_verdict(
        self, tmp_path: Path, monkeypatch: Any, site: str
    ) -> None:
        decision = self._decision(tmp_path, monkeypatch, [], site)
        assert (decision.is_found, decision.feed, decision.log_type, decision.nxdomain) == (True, "Feed", "3", True)

    @pytest.mark.parametrize("site", ["init", "swap"])
    def test_without_a_regex_list_row_the_fast_path_stays_on(self, tmp_path: Path, monkeypatch: Any, site: str) -> None:
        loads = _user_regex_loads(tmp_path, monkeypatch, [], feeds={"Feed": ["||x.example^"]})
        assert (loads.important_initial if site == "init" else loads.important_swapped) is False

    @pytest.mark.parametrize("site", ["init", "swap"])
    def test_a_regex_list_row_decides_the_verdict(self, tmp_path: Path, monkeypatch: Any, site: str) -> None:
        decision = self._decision(tmp_path, monkeypatch, [r"^x\.example$#mine"], site)
        assert (
            decision.is_found,
            decision.in_whitelist,
            decision.feed,
            decision.group,
            decision.log_type,
            decision.nxdomain,
        ) == (True, False, "mine", "DNSBL_Regex", "1", False)
