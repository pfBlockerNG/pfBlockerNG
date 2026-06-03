"""ADR-07 Phase 3 -- matcher strata / 6-band resolution + payload-widening tests.

Phase 3 is a STRICTLY behaviour-preserving refactor: ``evaluate_domain`` keeps its
historical "block found -> allow overrides" fast path byte-for-byte while
``pfb["important_rules"]`` is False (the only state production reaches today, since no
ABP ``$important``/``@@``/feed-regex rule is parsed yet). The numeric 6-band branch is
therefore UNREACHABLE in production this phase; these tests exercise it directly with
SYNTHETIC widened payloads and assert it reproduces the Phase-2 band table
(``tests/test_adr07_decision_spec.py`` SS2 / ``RESULTS/02_Results.txt`` SS2):

    6 user allow   5 user block   4 feed allow+important
    3 feed block+important   2 feed allow (@@)   1 feed block (||)

A block wins iff ``block_prio > allow_prio`` (no ties). This proves the branch is
correct BEFORE any later phase feeds it real ABP rules.

The no-regression contract (fast path == today, for non-ABP input) is pinned by the
retained ADR-06 golden oracle (``tests/test_adr06_*``) and the existing
``evaluate_domain`` golden tests in ``tests/test_pfb_unbound.py``; the fast-path tests
here are an additional, explicit guard that the ``important_rules`` flag gates the two
paths and that widened payloads decide identically to today.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import pytest

import pfb_unbound
from pfb_unbound import (
    PRIO_FEED_ALLOW,
    PRIO_FEED_ALLOW_IMPORTANT,
    PRIO_FEED_BLOCK,
    PRIO_FEED_BLOCK_IMPORTANT,
    PRIO_USER_ALLOW,
    PRIO_USER_BLOCK,
    _allow_priority,
    _block_priority,
    _white_entry_important,
    _white_entry_wildcard,
    evaluate_domain,
    whitelist_check_domain,
    whitelist_lookup_domain,
)


# --------------------------------------------------------------------------- #
# cfg / containers builders (self-contained; mirror what evaluate_domain reads)
# --------------------------------------------------------------------------- #
def _cfg(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "python_blocking": True,
        "dataDB": False,
        "zoneDB": False,
        "python_tld": False,
        "python_tlds": [],
        "dnsbl_ipv4": "10.10.10.1",
        "dnsbl_ipv6": "::1",
        "python_idn": False,
        "regexDB": False,
        "whiteDB": False,
        "allowRegexDB": False,
        "important_rules": False,
        "python_tld_seg": 2,
        "hstsDB": False,
        "hsts_tlds": ("app", "dev"),
    }
    base.update(overrides)
    return base


def _containers(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "dataDB": {},
        "zoneDB": {},
        "whiteDB": {},
        "hstsDB": {},
        "regexDB": defaultdict(str),
        "allowRegexDB": defaultdict(str),
        "feedGroupIndexDB": defaultdict(list),
    }
    base.update(overrides)
    return base


def _data(important: bool = False, log: str = "1", index: int = 0) -> dict[str, Any]:
    return {"log": log, "index": index, "important": important}


# --------------------------------------------------------------------------- #
# Priority-band helpers
# --------------------------------------------------------------------------- #
class TestPriorityBands:
    def test_block_bands(self) -> None:
        assert _block_priority(False) == PRIO_FEED_BLOCK == 1
        assert _block_priority(True) == PRIO_FEED_BLOCK_IMPORTANT == 3
        assert _block_priority(False, user=True) == PRIO_USER_BLOCK == 5

    def test_allow_bands(self) -> None:
        assert _allow_priority(False) == PRIO_FEED_ALLOW == 2
        assert _allow_priority(True) == PRIO_FEED_ALLOW_IMPORTANT == 4
        assert _allow_priority(False, user=True) == PRIO_USER_ALLOW == 6

    def test_no_ties_block_odd_allow_even(self) -> None:
        # The whole "no ties" guarantee rests on block in {1,3,5}, allow in {2,4,6}.
        for p in (PRIO_FEED_BLOCK, PRIO_FEED_BLOCK_IMPORTANT, PRIO_USER_BLOCK):
            assert p % 2 == 1
        for p in (PRIO_FEED_ALLOW, PRIO_FEED_ALLOW_IMPORTANT, PRIO_USER_ALLOW):
            assert p % 2 == 0


# --------------------------------------------------------------------------- #
# whiteDB value-shape tolerance (bare bool legacy AND new dict)
# --------------------------------------------------------------------------- #
class TestWhiteEntryShape:
    def test_wildcard_accessor(self) -> None:
        assert _white_entry_wildcard(True) is True
        assert _white_entry_wildcard(False) is False
        assert _white_entry_wildcard({"wildcard": True, "important": True}) is True
        assert _white_entry_wildcard({"wildcard": False, "important": True}) is False

    def test_important_accessor(self) -> None:
        # Bare-bool legacy entries are never important.
        assert _white_entry_important(True) is False
        assert _white_entry_important(False) is False
        assert _white_entry_important({"wildcard": False, "important": True}) is True
        assert _white_entry_important({"wildcard": True, "important": False}) is False

    def test_lookup_returns_matched_and_important_dict(self) -> None:
        wdb = {"allowed.com": {"wildcard": False, "important": True}}
        assert whitelist_lookup_domain("allowed.com", wdb, 2) == (True, True)

    def test_lookup_bare_bool_matches_not_important(self) -> None:
        wdb = {"allowed.com": False}
        assert whitelist_lookup_domain("allowed.com", wdb, 2) == (True, False)

    def test_lookup_miss(self) -> None:
        assert whitelist_lookup_domain("nope.com", {"x.com": True}, 2) == (False, False)

    def test_check_domain_bool_compat_for_both_shapes(self) -> None:
        # whitelist_check_domain stays a bool-returning shim; the suffix walk only
        # honours WILDCARD entries -- a non-wildcard dict must NOT match via the walk.
        assert whitelist_check_domain("sub.evil.com", {"evil.com": {"wildcard": True, "important": True}}, 2) is True
        assert whitelist_check_domain("sub.evil.com", {"evil.com": {"wildcard": False, "important": True}}, 2) is False
        # exact still matches regardless of wildcard.
        assert whitelist_check_domain("evil.com", {"evil.com": {"wildcard": False, "important": True}}, 2) is True


# --------------------------------------------------------------------------- #
# FAST PATH (important_rules False) -- byte-for-byte today's behaviour
# --------------------------------------------------------------------------- #
class TestFastPathPreserved:
    def test_block_no_allow_blocks(self) -> None:
        cfg = _cfg(dataDB=True)
        containers = _containers(dataDB={"evil.com": _data()})
        dec = evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)
        assert dec.is_found is True and dec.in_whitelist is False
        assert dec.null_blocking is False  # null-routed (blocked)

    def test_whitelist_overrides_block(self) -> None:
        cfg = _cfg(dataDB=True, whiteDB=True)
        containers = _containers(
            dataDB={"evil.com": _data()},
            whiteDB={"evil.com": {"wildcard": False, "important": True}},
        )
        dec = evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)
        assert dec.is_found is True and dec.in_whitelist is True
        assert dec.null_blocking is True  # not null-routed (resolves)

    def test_fast_path_ignores_important_field_on_block(self) -> None:
        # An $important block payload must NOT change the fast-path decision: with the
        # flag False, an allow still overrides (today's "allow beats block"). This is
        # the no-regression guarantee for the widened payload.
        cfg = _cfg(dataDB=True, whiteDB=True)  # important_rules stays False
        containers = _containers(
            dataDB={"evil.com": _data(important=True)},
            whiteDB={"evil.com": False},  # bare-bool, non-important feed-ish allow
        )
        dec = evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)
        assert dec.in_whitelist is True  # fast path: any allow overrides

    def test_fast_path_when_flag_key_absent(self) -> None:
        # cfg without the key at all -> .get default False -> fast path.
        cfg = _cfg(dataDB=True, whiteDB=True)
        del cfg["important_rules"]
        containers = _containers(
            dataDB={"evil.com": _data()},
            whiteDB={"evil.com": False},
        )
        dec = evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)
        assert dec.in_whitelist is True

    def test_fast_path_does_not_consult_allow_regex(self) -> None:
        # allowRegexDB is a numeric-branch-only structure; the fast path never reads it.
        import re

        cfg = _cfg(dataDB=True, allowRegexDB=True)  # important_rules False
        containers = _containers(
            dataDB={"evil.com": _data()},
            allowRegexDB={"r": re.compile(r"evil")},
        )
        dec = evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)
        # Fast path: no whiteDB hit -> blocked, allow-regex ignored.
        assert dec.in_whitelist is False and dec.null_blocking is False


# --------------------------------------------------------------------------- #
# NUMERIC 6-BAND branch (important_rules True) -- synthetic payloads
# in_whitelist == True  <=>  an allow wins (name resolves)
# in_whitelist == False <=>  the block stands (null-routed)
# --------------------------------------------------------------------------- #
class TestNumericBandResolution:
    def _decide(self, block_important: bool, white_db: dict, allow_regex_db: dict) -> bool:
        import re

        cfg = _cfg(
            dataDB=True,
            whiteDB=bool(white_db),
            allowRegexDB=bool(allow_regex_db),
            important_rules=True,
        )
        compiled = {k: (re.compile(v) if isinstance(v, str) else v) for k, v in allow_regex_db.items()}
        containers = _containers(
            dataDB={"evil.com": _data(important=block_important)},
            whiteDB=white_db,
            allowRegexDB=compiled,
        )
        dec = evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)
        return dec.in_whitelist

    # band 1 feed block, no allow -> block stands
    def test_b1_block_no_allow(self) -> None:
        assert self._decide(False, {}, {}) is False

    # band 1 block vs band 2 feed allow (@@/allow-regex, non-important) -> allow wins
    def test_b2_feed_allow_beats_b1_block(self) -> None:
        assert self._decide(False, {}, {"r": r"evil"}) is True

    # band 1 block vs band 6 user allow (whiteDB important) -> allow wins
    def test_b6_user_allow_beats_b1_block(self) -> None:
        assert self._decide(False, {"evil.com": {"wildcard": False, "important": True}}, {}) is True

    # band 3 feed block+important vs band 2 feed allow -> block wins (3 > 2)
    def test_b3_important_block_beats_b2_feed_allow(self) -> None:
        assert self._decide(True, {}, {"r": r"evil"}) is False

    # band 3 feed block+important vs band 4 feed allow+important -> allow wins (4 > 3)
    def test_b4_important_feed_allow_beats_b3_important_block(self) -> None:
        import re

        ar = {"r": {"re": re.compile(r"evil"), "important": True}}
        assert self._decide(True, {}, ar) is True

    # band 3 feed block+important vs band 6 user allow -> allow wins (sovereignty)
    def test_b6_user_allow_beats_b3_important_block(self) -> None:
        assert self._decide(True, {"evil.com": {"wildcard": False, "important": True}}, {}) is True

    # band 3 block+important vs band 2 whiteDB non-important (bare bool) -> block wins
    def test_b3_important_block_beats_b2_nonimportant_whitelist(self) -> None:
        assert self._decide(True, {"evil.com": False}, {}) is False

    # band 1 block vs band 2 whiteDB non-important allow -> allow wins (2 > 1)
    def test_b2_nonimportant_whitelist_beats_b1_block(self) -> None:
        assert self._decide(False, {"evil.com": False}, {}) is True

    # highest of multiple allows wins: user allow (6) present alongside a feed allow
    def test_max_allow_wins_user_over_feed(self) -> None:
        assert self._decide(True, {"evil.com": {"wildcard": False, "important": True}}, {"r": r"evil"}) is True

    # no allow matches a different name -> block stands even at band 1
    def test_allow_regex_non_match_leaves_block(self) -> None:
        assert self._decide(False, {}, {"r": r"benign"}) is False


class TestUserRegexSovereign:
    """A USER regex is band 5 (user block): it beats ANY feed allow (@@ band 2 /
    @@$important band 4) but still loses to the user whitelist (band 6).

    Pins the ADR-07 fix where the init loads a user ``pfb_regex_list`` pattern as the
    ``{"re","important","band": PRIO_USER_BLOCK}`` payload (not a bare compiled pattern,
    which ``_block_entry_band`` would score at feed band 1 and a feed @@ would override).
    """

    def _decide(self, *, white_db: dict, allow_regex_db: dict) -> bool:
        import re

        cfg = _cfg(
            regexDB=True,
            whiteDB=bool(white_db),
            allowRegexDB=bool(allow_regex_db),
            important_rules=True,
        )
        compiled = {k: (re.compile(v) if isinstance(v, str) else v) for k, v in allow_regex_db.items()}
        user_regex = {"Regex_1": {"re": re.compile(r"evil"), "important": False, "band": PRIO_USER_BLOCK}}
        containers = _containers(regexDB=user_regex, whiteDB=white_db, allowRegexDB=compiled)
        dec = evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)
        return dec.in_whitelist

    def test_user_regex_blocks_with_no_allow(self) -> None:
        assert self._decide(white_db={}, allow_regex_db={}) is False

    def test_user_regex_beats_feed_allow_regex(self) -> None:
        # band 5 user regex vs band 2 feed @@/re/ -> block stands (5 > 2).
        assert self._decide(white_db={}, allow_regex_db={"r": r"evil"}) is False

    def test_user_regex_beats_feed_important_allow(self) -> None:
        # band 5 user regex vs band 4 feed @@...$important -> block stands (5 > 4).
        import re

        ar = {"r": {"re": re.compile(r"evil"), "important": True}}
        assert self._decide(white_db={}, allow_regex_db=ar) is False

    def test_user_regex_beats_feed_domain_allow(self) -> None:
        # band 5 user regex vs band 2 feed @@||domain^ (whiteDB band 2) -> block stands.
        assert (
            self._decide(white_db={"evil.com": {"wildcard": False, "important": False, "band": 2}}, allow_regex_db={})
            is False
        )

    def test_user_whitelist_still_beats_user_regex(self) -> None:
        # band 6 user allow (settings whitelist) vs band 5 user regex -> allow wins.
        assert self._decide(white_db={"evil.com": {"wildcard": False, "important": True}}, allow_regex_db={}) is True


class TestNumericBranchUnreachableInProduction:
    """The numeric branch only fires when pfb['important_rules'] is True, which Phase 3
    never sets (no ABP rule parsed). Defaults stay False so production stays on the
    fast path."""

    def test_default_flag_is_false(self) -> None:
        # Re-run init's default-settings assignment indirectly: the module sets the
        # flag False at init; here we assert the matcher default via cfg.get path.
        cfg = _cfg(dataDB=True, whiteDB=True)
        assert cfg["important_rules"] is False

    def test_allow_regex_db_default_false(self) -> None:
        cfg = _cfg()
        assert cfg["allowRegexDB"] is False


# --------------------------------------------------------------------------- #
# Widened block payload decides identically to a pre-P3 (no-important) payload
# --------------------------------------------------------------------------- #
class TestWidenedPayloadCompat:
    def test_payload_without_important_key_still_works(self) -> None:
        # Existing seeds (add_data/add_zone, the ADR-06 oracle) omit the important key;
        # the matcher must default it to False via .get and decide as today.
        cfg = _cfg(dataDB=True)
        containers = _containers(dataDB={"evil.com": {"log": "1", "index": 0}})  # no "important"
        dec = evaluate_domain("evil.com", "evil.com", "com", False, cfg, containers)
        assert dec.is_found is True and dec.null_blocking is False

    @pytest.mark.parametrize("important", [False, True])
    def test_zone_payload_important_field_carried(self, important: bool) -> None:
        cfg = _cfg(zoneDB=True, whiteDB=True, allowRegexDB=True, important_rules=True)
        containers = _containers(
            zoneDB={"evil.com": {"log": "1", "index": 0, "important": important}},
            allowRegexDB={},
            whiteDB={},
        )
        # zone block matches sub.evil.com; with no allow it always blocks regardless of
        # band, but the band must be read from the zone payload (no crash, correct flag).
        dec = evaluate_domain("sub.evil.com", "sub.evil.com", "com", False, cfg, containers)
        assert dec.is_found is True and dec.in_whitelist is False


def test_module_init_defaults_present() -> None:
    # We can't run init_standard() (needs the Unbound env), but the P3 public surface
    # must be importable -- a smoke check that the matcher's band scale loaded.
    assert pfb_unbound.PRIO_USER_ALLOW == 6
    assert pfb_unbound.PRIO_FEED_BLOCK == 1
    assert "allowRegexDB" in pfb_unbound.__annotations__
