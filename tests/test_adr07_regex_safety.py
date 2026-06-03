"""ADR-07 Phase 7 -- regex safety: opt-in static cap + always-on runtime warn/evict.

`re` does not release the GIL during a match and a Python thread cannot be killed
(ADR.md fact 2), so a query-time timeout CANNOT interrupt a catastrophic match. The
accepted design is a bounded residual: a pathological pattern's FIRST match may block
one query, but it is then EVICTED so it cannot hang again. Two layers, both stdlib +
in-process, applied to FEED *and* user regex:

  (1) opt-in STATIC CAP -- drop over-long / nested-quantifier patterns at LOAD (no
      execution) when "Limit long/complex regex" is enabled;
  (2) always-on RUNTIME timing -- over a warn ceiling log, over a higher evict ceiling
      log + remove the pattern from the live regexDB/allowRegexDB (snapshot-iterate,
      evict-after-loop -- never mutate mid-iteration; dict.pop is atomic under the GIL).

These tests are pure (no live Unbound). The runtime tests drive a deterministic clock
by monkeypatching ``time.thread_time`` so a "slow" match is simulated without running a
genuinely catastrophic pattern (which could hang the suite -- exactly the residual the
design accepts but the tests must not pay).
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

import pfb_unbound
from pfb_unbound import (
    DNSBL_KIND_BLOCK,
    PRIO_FEED_ALLOW,
    PRIO_FEED_BLOCK,
    RegexRule,
    _dnsbl_compile_regex_rules,
    _regex_exceeds_static_cap,
    _scan_allow_regex_band,
    evaluate_domain,
)


# --------------------------------------------------------------------------- #
# cfg / containers builders (mirror what evaluate_domain reads)
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
        "regex_warn_ms": pfb_unbound.REGEX_WARN_MS_DEFAULT,
        "regex_evict_ms": pfb_unbound.REGEX_EVICT_MS_DEFAULT,
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


class _FakeClock:
    """Deterministic stand-in for ``time.thread_time``: each call advances by the next
    queued delta (seconds). ``_regex_timed_search`` calls the clock twice per match, so
    queue (start, end) pairs -- elapsed_ms = (end-start)*1000."""

    def __init__(self, ticks: list[float]) -> None:
        self._ticks = list(ticks)

    def __call__(self) -> float:
        return self._ticks.pop(0)


def _install_clock(monkeypatch: Any, elapsed_ms_per_match: list[float]) -> None:
    """Make every match report a fixed elapsed time (ms). Forces the thread_time path
    so the warn/evict policy is deterministic (no perf-fallback 2-strike interplay)."""
    ticks: list[float] = []
    for ms in elapsed_ms_per_match:
        ticks.extend([0.0, ms / 1000.0])
    monkeypatch.setattr(pfb_unbound, "_REGEX_HAVE_THREAD_TIME", True)
    monkeypatch.setattr(pfb_unbound.time, "thread_time", _FakeClock(ticks))


# --------------------------------------------------------------------------- #
# (1) STATIC CAP -- pure heuristic
# --------------------------------------------------------------------------- #
class TestStaticCapHeuristic:
    def test_normal_pattern_passes(self) -> None:
        assert _regex_exceeds_static_cap(r"^(.+\.)?doubleclick\.net$") is False
        assert _regex_exceeds_static_cap(r"ad[0-9]\.example\.com$") is False

    def test_over_length_flagged(self) -> None:
        long_pat = "a" * (pfb_unbound.REGEX_STATIC_LEN_CAP + 1)
        assert _regex_exceeds_static_cap(long_pat) is True
        # Exactly at the cap is allowed (strictly greater is the cap).
        assert _regex_exceeds_static_cap("a" * pfb_unbound.REGEX_STATIC_LEN_CAP) is False

    def test_nested_quantifier_flagged(self) -> None:
        for pat in (r"(a+)+$", r"(a*)*", r"(\w+\.)+\w+$", r"([a-z]+)*\.example$", r"(.*a){20}$"):
            assert _regex_exceeds_static_cap(pat) is True, pat

    def test_alternation_overlap_flagged(self) -> None:
        # A quantified group whose body contains `|` backtracks catastrophically yet
        # has no INNER quantifier, so the nested-quantifier heuristic misses it. These
        # PASSED the old static cap (the gap the corrected ReDoS probe exposed).
        for pat in (r"^(a|a)+$", r"(a|ab)*", r"(foo|foobar)+", r"(x|y|x){10}"):
            assert _regex_exceeds_static_cap(pat) is True, pat

    def test_benign_alternation_not_flagged(self) -> None:
        # An UNquantified alternation group is fine -- it is the quantifier on an
        # overlapping alternation that is dangerous, not `|` alone.
        assert _regex_exceeds_static_cap(r"^(www\.)?ad-?serv(er|ice)\.example$") is False
        assert _regex_exceeds_static_cap(r"^(foo|bar)\.example$") is False


# --------------------------------------------------------------------------- #
# (1) STATIC CAP -- applied at LOAD (feed regex via _dnsbl_compile_regex_rules)
# --------------------------------------------------------------------------- #
def _block_rule(pattern: str, feed: str = "F") -> RegexRule:
    return RegexRule(
        pattern=pattern,
        kind=DNSBL_KIND_BLOCK,
        band=PRIO_FEED_BLOCK,
        important=False,
        provenance="feed",
        feed=feed,
        group="DNSBL_Regex",
        log="1",
    )


class TestStaticCapAtLoad:
    def test_cap_off_keeps_nested_quantifier(self) -> None:
        rules = [_block_rule(r"(a+)+$"), _block_rule(r"^safe\.example$")]
        db, admitted = _dnsbl_compile_regex_rules(rules, static_cap=False)
        assert admitted == 2
        assert len(db) == 2

    def test_cap_on_drops_nested_quantifier(self) -> None:
        rules = [_block_rule(r"(a+)+$"), _block_rule(r"safe\.example$")]
        db, admitted = _dnsbl_compile_regex_rules(rules, static_cap=True)
        # Only the safe pattern survives.
        assert admitted == 1
        assert len(db) == 1
        compiled = next(iter(db.values()))["re"]
        assert compiled.search("x.safe.example")

    def test_cap_on_drops_over_length(self) -> None:
        long_pat = "a" * (pfb_unbound.REGEX_STATIC_LEN_CAP + 5)
        rules = [_block_rule(long_pat), _block_rule(r"keep\.example$")]
        db, admitted = _dnsbl_compile_regex_rules(rules, static_cap=True)
        assert admitted == 1

    def test_build_threads_regex_cap_from_config(self) -> None:
        # build() reads config["regex_cap"] and forwards it to the compile helper.
        manifest = {
            "feeds": [{"feed": "F", "group": "G", "format_hint": "abp", "log_flag": "1", "raw": "F"}],
            "config": {},
        }
        lines = ["/(a+)+x/", "/^irreducible-[0-9]+\\.example$/"]

        def reader(_ref: str) -> list[str]:
            return lines

        cap_on = pfb_unbound.build(manifest, {"regex_cap": True}, line_reader=reader)
        cap_off = pfb_unbound.build(manifest, {"regex_cap": False}, line_reader=reader)
        # The nested-quantifier irreducible regex is dropped only when the cap is on.
        assert cap_on.regex_count < cap_off.regex_count


# --------------------------------------------------------------------------- #
# (2) RUNTIME warn/evict -- block-regex discovery scan (feed AND user provenance)
# --------------------------------------------------------------------------- #
def _slow_pattern() -> Any:
    # A trivially-matching compiled pattern; the SLOWNESS is faked via the clock so the
    # test never actually pays catastrophic-backtracking cost.
    return re.compile(r"slow\.example$")


class TestRuntimeBlockRegexEviction:
    def test_warn_then_evict_first_hit(self, monkeypatch: Any) -> None:
        # Two queries: first reports a slow match (> evict ceiling) and is evicted;
        # the pattern is gone before the second query (cannot hang twice).
        regex_db: dict[str, Any] = {"F#0": {"re": _slow_pattern(), "important": False, "band": PRIO_FEED_BLOCK}}
        cfg = _cfg(regexDB=True)
        containers = _containers(regexDB=regex_db)

        # First query: a 150 ms match (> 100 ms evict) -> evicted, NOT counted as found.
        _install_clock(monkeypatch, [150.0])
        dec = evaluate_domain("slow.example", "slow.example", "example", False, cfg, containers)
        assert dec.is_found is False
        assert "F#0" not in regex_db  # evicted from the LIVE dict

        # Second query: the dict is empty, so no match and no hang.
        assert len(regex_db) == 0
        dec2 = evaluate_domain("slow.example", "slow.example", "example", False, cfg, containers)
        assert dec2.is_found is False

    def test_warn_only_keeps_pattern(self, monkeypatch: Any) -> None:
        regex_db: dict[str, Any] = {"F#0": {"re": _slow_pattern(), "important": False, "band": PRIO_FEED_BLOCK}}
        cfg = _cfg(regexDB=True)
        containers = _containers(regexDB=regex_db)
        # 20 ms: over warn (10) but under evict (100) -> warns, NOT evicted, still blocks.
        _install_clock(monkeypatch, [20.0])
        dec = evaluate_domain("slow.example", "slow.example", "example", False, cfg, containers)
        assert dec.is_found is True
        assert dec.group == "DNSBL_Regex"
        assert "F#0" in regex_db  # kept
        assert "F#0" in pfb_unbound._regex_warned  # rate-limited warn recorded

    def test_user_provenance_bare_pattern_evicted(self, monkeypatch: Any) -> None:
        # The un-vetted USER regex list loads as a BARE compiled pattern (not a dict).
        # It must get the same eviction treatment.
        regex_db: dict[str, Any] = {"MyUserRegex": _slow_pattern()}
        cfg = _cfg(regexDB=True)
        containers = _containers(regexDB=regex_db)
        _install_clock(monkeypatch, [200.0])
        dec = evaluate_domain("slow.example", "slow.example", "example", False, cfg, containers)
        assert dec.is_found is False
        assert "MyUserRegex" not in regex_db

    def test_eviction_does_not_corrupt_scan(self, monkeypatch: Any) -> None:
        # Many patterns; the slow one in the middle is evicted while others remain. The
        # scan iterates a SNAPSHOT, so no "dict changed size during iteration".
        regex_db: dict[str, Any] = {}
        for i in range(5):
            regex_db["P#{}".format(i)] = {"re": re.compile(r"nomatch%d\.x$" % i), "important": False, "band": 1}
        regex_db["SLOW"] = {"re": _slow_pattern(), "important": False, "band": 1}
        cfg = _cfg(regexDB=True)
        containers = _containers(regexDB=regex_db)
        # 6 entries scanned; only SLOW is slow. Order is dict-insertion; SLOW is last but
        # we assert no exception is raised and only SLOW is evicted regardless of order.
        _install_clock(monkeypatch, [1.0, 1.0, 1.0, 1.0, 1.0, 300.0])
        dec = evaluate_domain("slow.example", "slow.example", "example", False, cfg, containers)
        assert dec.is_found is False
        assert "SLOW" not in regex_db
        assert len(regex_db) == 5  # the five non-matching patterns survive


# --------------------------------------------------------------------------- #
# (2) RUNTIME warn/evict -- allow-regex scan
# --------------------------------------------------------------------------- #
class TestRuntimeAllowRegexEviction:
    def test_allow_regex_evicted_over_ceiling(self, monkeypatch: Any) -> None:
        allow_db: dict[str, Any] = {"A#0": {"re": _slow_pattern(), "important": False, "band": PRIO_FEED_ALLOW}}
        _install_clock(monkeypatch, [250.0])
        band = _scan_allow_regex_band("slow.example", allow_db, 10.0, 100.0)
        assert band == 0  # evicted before it could contribute an allow band
        assert "A#0" not in allow_db

    def test_allow_regex_kept_under_ceiling(self, monkeypatch: Any) -> None:
        allow_db: dict[str, Any] = {"A#0": {"re": _slow_pattern(), "important": False, "band": PRIO_FEED_ALLOW}}
        _install_clock(monkeypatch, [2.0])
        band = _scan_allow_regex_band("slow.example", allow_db, 10.0, 100.0)
        assert band == PRIO_FEED_ALLOW
        assert "A#0" in allow_db


# --------------------------------------------------------------------------- #
# perf_counter FALLBACK -- 2-strike guard (no false-evict on a lone spike)
# --------------------------------------------------------------------------- #
class TestPerfCounterFallback:
    def test_single_spike_does_not_evict(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(pfb_unbound, "_REGEX_HAVE_THREAD_TIME", False)
        # One over-evict crossing -> strike 1 of 2 -> NOT evicted yet.
        evict = pfb_unbound._regex_should_evict("P", 500.0, 10.0, 100.0, "DNSBL_Regex", "P")
        assert evict is False
        assert pfb_unbound._regex_perf_strikes.get("P") == 1

    def test_two_consecutive_spikes_evict(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(pfb_unbound, "_REGEX_HAVE_THREAD_TIME", False)
        assert pfb_unbound._regex_should_evict("P", 500.0, 10.0, 100.0, "DNSBL_Regex", "P") is False
        assert pfb_unbound._regex_should_evict("P", 500.0, 10.0, 100.0, "DNSBL_Regex", "P") is True

    def test_fast_match_clears_strike(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(pfb_unbound, "_REGEX_HAVE_THREAD_TIME", False)
        assert pfb_unbound._regex_should_evict("P", 500.0, 10.0, 100.0, "DNSBL_Regex", "P") is False
        # A subsequent fast match resets the streak so two spikes must be CONSECUTIVE.
        assert pfb_unbound._regex_should_evict("P", 1.0, 10.0, 100.0, "DNSBL_Regex", "P") is False
        assert "P" not in pfb_unbound._regex_perf_strikes


# --------------------------------------------------------------------------- #
# FAST PATH -- no regex / no slow pattern is unchanged (no perf regression)
# --------------------------------------------------------------------------- #
class TestFastPathUnchanged:
    def test_no_regex_no_timing(self) -> None:
        # No regexDB -> the timing path is never entered (cfg["regexDB"] False).
        cfg = _cfg(dataDB=True, regexDB=False)
        containers = _containers(dataDB={"blocked.example": {"log": "1", "index": 0, "important": False, "band": 1}})
        dec = evaluate_domain("blocked.example", "blocked.example", "example", False, cfg, containers)
        assert dec.is_found is True
        assert dec.b_type == "DNSBL"

    def test_fast_regex_not_evicted(self, monkeypatch: Any) -> None:
        # A normal (fast) regex match blocks and stays loaded; nothing warned/evicted.
        regex_db: dict[str, Any] = {"F#0": {"re": _slow_pattern(), "important": False, "band": PRIO_FEED_BLOCK}}
        cfg = _cfg(regexDB=True)
        containers = _containers(regexDB=regex_db)
        _install_clock(monkeypatch, [0.5])
        dec = evaluate_domain("slow.example", "slow.example", "example", False, cfg, containers)
        assert dec.is_found is True
        assert "F#0" in regex_db
        assert pfb_unbound._regex_warned == set()


# --------------------------------------------------------------------------- #
# Real catastrophic pattern + static cap (end-to-end, BOUNDED so it can't hang)
# --------------------------------------------------------------------------- #
class TestRealCatastrophicCapped:
    def test_static_cap_drops_real_redos_pattern(self) -> None:
        # The static cap catches the genuinely catastrophic shape WITHOUT executing it.
        rule = _block_rule(r"([a-z]+)*\.example$")
        db, admitted = _dnsbl_compile_regex_rules([rule], static_cap=True)
        assert admitted == 0
        assert db == {}

    def test_static_cap_drops_alternation_overlap_pattern(self) -> None:
        # ^(a|a)+$ PASSES the old cap but backtracks catastrophically; the broadened
        # cap drops it at load WITHOUT executing it (cap ON).
        rule = _block_rule(r"^(a|a)+$")
        db, admitted = _dnsbl_compile_regex_rules([rule], static_cap=True)
        assert admitted == 0
        assert db == {}
        # With the cap OFF the un-vetted pattern is still admitted (opt-in only).
        db_off, admitted_off = _dnsbl_compile_regex_rules([rule], static_cap=False)
        assert admitted_off == 1
        assert len(db_off) == 1
