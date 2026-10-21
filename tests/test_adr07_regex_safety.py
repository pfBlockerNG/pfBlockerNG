"""ADR-07 Phase 7 -- regex safety: always-on admission gate + opt-in length
cap + always-on runtime slow-match warning.

`re` does not release the GIL during a match and a Python thread cannot be killed
(ADR.md fact 2), so a query-time timeout CANNOT interrupt a runaway match. The
design therefore bounds every admitted rule's work at load, and a rule that still
measures slow at query time is WARNED about once and KEPT: removing it would only let
one crafted query take a rule away for good. The LOAD-time gate is split into two
DECOUPLED concerns, both stdlib + in-process, applied to FEED *and* user regex:

  (1a) always-on ADMISSION gate -- a pattern outside the bounded grammar (printable
       ASCII, an allowlist of constructs, bounded repeats and nesting) or over the
       backtracking-cost bound is dropped at LOAD UNCONDITIONALLY -- independent of any
       setting. Pure static string analysis, NO execution of the candidate;
  (1b) opt-in LENGTH ceiling -- a long-but-safe pattern is dropped at LOAD only when the
       "Limit long/complex regex" setting is enabled; length alone is a tunable
       convenience cap, NOT a safety gate, so it stays behind the flag;
  (2) always-on RUNTIME timing -- a match over the warn ceiling logs one line per rule, and a
      list scan whose rules sum over the ceiling logs one line per list; every admitted rule
      stays in the live regex containers, and there is no limit on how many rules a list holds.

These tests are pure (no live Unbound). The runtime tests drive a deterministic clock
by monkeypatching ``time.thread_time`` so a "slow" match is simulated without running a
genuinely slow pattern.
"""

from __future__ import annotations

import base64
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, NamedTuple

import pytest
import unboundmodule

import pfb_dnsbl_regex_rules
import pfb_unbound
from pfb_unbound import (
    DNSBL_KIND_ALLOW,
    DNSBL_KIND_BLOCK,
    PRIO_FEED_ALLOW,
    PRIO_FEED_BLOCK,
    PRIO_USER_ALLOW,
    PRIO_USER_BLOCK,
    RegexRule,
    _dnsbl_compile_regex_rules,
    _dnsbl_compile_user_regex,
    _scan_allow_regex_band,
    _scan_block_band,
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
        "tld_allow": False,
        "tld_allow_list": [],
        "dnsbl_ipv4": "10.10.10.1",
        "dnsbl_ipv6": "::1",
        "python_idn": False,
        "regexDB": False,
        "whiteDB": False,
        "allowRegexDB": False,
        "userRegexDB": False,
        "userAllowRegexDB": False,
        "important_rules": False,
        "regex_warn_ms": pfb_unbound.REGEX_WARN_MS_DEFAULT,
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
        "userRegexDB": defaultdict(str),
        "userAllowRegexDB": defaultdict(str),
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


def _long_benign_pattern() -> str:
    """A pattern over the opt-in length ceiling but inside the admission grammar and cost
    bound: a long concatenation of literal labels with a single optional group. Used to
    prove the LENGTH ceiling is decoupled from (and gated independently of) the admission
    gate."""
    pat = r"^(sub)?" + "verylongsubdomainlabel" * 10 + r"\.example\.com$"
    assert len(pat) > pfb_unbound.REGEX_STATIC_LEN_CAP
    return pat


def _install_clock(monkeypatch: Any, elapsed_ms_per_match: list[float]) -> None:
    """Make every match report a fixed elapsed time (ms). Forces the thread_time path
    so the warn policy is deterministic (no perf_counter interplay)."""
    ticks: list[float] = []
    for ms in elapsed_ms_per_match:
        ticks.extend([0.0, ms / 1000.0])
    monkeypatch.setattr(pfb_unbound, "_REGEX_HAVE_THREAD_TIME", True)
    monkeypatch.setattr(pfb_unbound.time, "thread_time", _FakeClock(ticks))


# --------------------------------------------------------------------------- #
# (1a) ADMISSION gate at LOAD -- ALWAYS-ON (independent of the opt-in length cap).
# The gate's own grammar and cost rows live in test_pfb_dnsbl_regex_rules.py.
# --------------------------------------------------------------------------- #
class TestAdmissionGateAtLoad:
    def test_benign_feed_patterns_are_admitted(self) -> None:
        for pat in (
            r"ads\.",
            r"ad[0-9]\.example\.com$",
            r"^x[0-9]+\.example\.com$",
            r"\.doubleclick\.net$",
            r"^(.+\.)?doubleclick\.net$",
            r"^(www\.)?ad-?serv(er|ice)\.example$",
            r"^(foo|bar)\.example$",
            r"^(.+\.)?ads?[0-9]*\.example\.(com|net|org)$",
            r"^[a-z0-9-]+\.[a-z0-9-]+\.[a-z]{2,}$",
            r"^[^.]+\.[^.]+\.[^.]+\.example$",
            r"\d+\.\d+",
            r"[a-z]+[0-9]+\.example\.com",
        ):
            assert pfb_dnsbl_regex_rules.pfb_regex_admission(pat)[1] is None, pat

    def test_gate_is_independent_of_the_opt_in_length_cap(self) -> None:
        # A long-but-safe pattern (inside the always-on admission length) is admitted:
        # the length ceiling over REGEX_STATIC_LEN_CAP is the separate opt-in cap.
        assert pfb_dnsbl_regex_rules.pfb_regex_admission(_long_benign_pattern())[1] is None
        # And a SHORT unsafe shape is refused regardless of being well under that length.
        assert pfb_dnsbl_regex_rules.pfb_regex_admission(r"(a+)+")[1] is not None

    def test_unsafe_separator_spellings_are_dropped_by_the_feed_loader_with_both_cap_modes(self) -> None:
        unsafe = (
            r"^([a-z])(?(1)[a-z]+[a-z]+[a-z]+[a-z]+|b)@x\.com$",
            r"^[a-z]+[a-z]+(?>ab)[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(a|(?:b))+[a-z]+[a-z]+@x\.com$",
        )
        safe = r"^[a-z]+\.[a-z]+\.[a-z]+$"
        for cap in (False, True):
            db, admitted = _dnsbl_compile_regex_rules(
                [*(_block_rule(pattern) for pattern in unsafe), _block_rule(safe)],
                static_cap=cap,
            )
            assert admitted == 1, cap
            assert len(db) == 1, cap
            assert next(iter(db.values()))["re"].pattern == safe


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
    def test_admission_gate_drops_a_quantified_group_even_with_cap_off(self) -> None:
        # DECOUPLING (the key change): a quantified group is dropped at load even when
        # the opt-in length cap is OFF -- the admission gate is unconditional. The benign
        # sibling is admitted, proving it is the pattern, not a blanket drop.
        rules = [_block_rule(r"(a+)+$"), _block_rule(r"^safe\.example$")]
        db, admitted = _dnsbl_compile_regex_rules(rules, static_cap=False)
        assert admitted == 1
        assert len(db) == 1
        compiled = next(iter(db.values()))["re"]
        assert compiled.search("safe.example")

    def test_admission_gate_drops_adjacent_quantified_groups_and_oversized_repeats_cap_off(self) -> None:
        # Adjacent quantified groups and an oversized stacked repeat are also dropped
        # with the cap OFF.
        rules = [
            _block_rule(r"(a+)(a+)+"),
            _block_rule(r"a{500}{500}"),
            _block_rule(r"^keep\.example$"),
        ]
        db, admitted = _dnsbl_compile_regex_rules(rules, static_cap=False)
        assert admitted == 1
        assert next(iter(db.values()))["re"].search("keep.example")

    def test_cap_off_keeps_long_but_benign(self) -> None:
        # BEFORE-state for the length-cap gating test: a long-but-structurally-safe
        # pattern is ADMITTED when the cap is OFF (length is not enforced by default).
        rules = [_block_rule(_long_benign_pattern()), _block_rule(r"^safe\.example$")]
        db, admitted = _dnsbl_compile_regex_rules(rules, static_cap=False)
        assert admitted == 2
        assert len(db) == 2

    def test_cap_on_drops_long_but_benign(self) -> None:
        # AFTER-state: the SAME long-but-benign pattern is dropped once the cap is ON,
        # proving the length ceiling stays GATED (only the length cap differs between
        # this and the previous test -- the pattern is structurally safe in both).
        rules = [_block_rule(_long_benign_pattern()), _block_rule(r"^safe\.example$")]
        db, admitted = _dnsbl_compile_regex_rules(rules, static_cap=True)
        assert admitted == 1
        assert next(iter(db.values()))["re"].search("safe.example")

    def test_build_threads_regex_cap_from_config(self) -> None:
        # build() reads config["regex_cap"] and forwards it to the compile helper. The
        # length cap (not the admission gate) is what the flag toggles, so use a long-but-
        # benign irreducible pattern to prove the flag is threaded.
        manifest = {
            "feeds": [{"feed": "F", "group": "G", "log_flag": "1", "raw": "F"}],
            "config": {},
        }
        lines = ["/" + _long_benign_pattern() + "/", "/^irreducible-[0-9]+\\.example$/"]

        def reader(_ref: str) -> list[str]:
            return lines

        cap_on = pfb_unbound.build(manifest, {"regex_cap": True}, line_reader=reader)
        cap_off = pfb_unbound.build(manifest, {"regex_cap": False}, line_reader=reader)
        # The long-but-benign irreducible regex is dropped only when the length cap is on.
        assert cap_on.regex_count < cap_off.regex_count


# --------------------------------------------------------------------------- #
# Issue #1765: the admission rules moved to pfb_dnsbl_regex_rules.py, imported
# by pfb_unbound.py -- ONE literal now, not two, so the #1688/#1711 duplication
# pins above (deleted) are unsatisfiable and their drift class cannot occur.
# This pin replaces them: pfb_unbound's imported names are the SAME objects as
# the module's, not a copy.
# --------------------------------------------------------------------------- #
def test_pfb_unbound_reexports_are_the_same_objects_as_pfb_dnsbl_regex_rules() -> None:
    # Known limit of the `is` check on REGEX_STATIC_LEN_CAP: CPython interns small ints,
    # so a re-introduced duplicate literal of the SAME value would still pass here. That
    # case is behaviourally identical, and any DIFFERING value (the drift that matters)
    # fails, as does a re-defined function -- both mutation-checked.
    for name in ("REGEX_STATIC_LEN_CAP", "pfb_regex_admission", "pfb_regex_excerpt", "pfb_split_regex_line"):
        assert getattr(pfb_unbound, name) is getattr(pfb_dnsbl_regex_rules, name), (
            f"pfb_unbound.{name} is not the same object as pfb_dnsbl_regex_rules.{name} -- single-source broken"
        )


def test_runtime_length_cap_comparator_is_strict_at_every_site() -> None:
    """Issue #1711/#1765: pin the runtime's exact-200-character admission boundary. All
    THREE REGEX_STATIC_LEN_CAP comparisons -- the two left in pfb_unbound.py (the build-time
    compile helper and the shared user-regex helper both load paths call) and the one inside
    pfb_dnsbl_regex_rules.py's save-time probe ``main()`` -- use a STRICT '>':
    a '>=' regression at any site would silently drop a pattern exactly at the cap, which
    the resolver, the probe, and the PHP DnsblRegexEntryErrorTest suite all admit."""
    unbound_path = Path(__file__).resolve().parent.parent / "src/usr/local/pkg/pfblockerng/pfb_unbound.py"
    rules_path = Path(__file__).resolve().parent.parent / "src/usr/local/pkg/pfblockerng/pfb_dnsbl_regex_rules.py"
    source = unbound_path.read_text() + "\n" + rules_path.read_text()
    strict = re.findall(r"len\([^)\n]*\)\s*>\s*REGEX_STATIC_LEN_CAP", source)
    assert len(strict) == 3, f"expected exactly 3 strict '>' comparisons, found {len(strict)}: {strict}"
    non_strict = re.findall(r"len\([^)\n]*\)\s*>=\s*REGEX_STATIC_LEN_CAP", source)
    assert non_strict == [], f"found a non-strict '>=' REGEX_STATIC_LEN_CAP comparison: {non_strict}"


def _anchored_pattern(length: int) -> str:
    """Mirror of DnsblRegexEntryErrorTest::anchoredPattern (tests/php/DnsblRegexEntryErrorTest.php):
    an anchored, structurally benign pattern (no quantifier, no alternation, no stacked
    repeat) of EXACTLY the requested length, so only the length cap -- never the admission
    gate -- can be the reason it is admitted or dropped."""
    if length < 2:
        raise ValueError("length must be >= 2 to hold both anchors")
    return "^" + "a" * (length - 2) + "$"


class TestStaticCapExactBoundary:
    """Issue #1711: pin the runtime's admission boundary at EXACTLY REGEX_STATIC_LEN_CAP
    characters -- the comparison is strict '>', so a pattern of exactly the cap length is
    the last admissible value (mirrors the PHP-side pair in DnsblRegexEntryErrorTest)."""

    def test_exactly_cap_length_is_admitted(self) -> None:
        pattern = _anchored_pattern(pfb_unbound.REGEX_STATIC_LEN_CAP)
        assert len(pattern) == pfb_unbound.REGEX_STATIC_LEN_CAP
        rules = [_block_rule(pattern)]
        db, admitted = _dnsbl_compile_regex_rules(rules, static_cap=True)
        assert admitted == 1
        assert len(db) == 1

    def test_one_over_cap_length_is_dropped(self) -> None:
        pattern = _anchored_pattern(pfb_unbound.REGEX_STATIC_LEN_CAP + 1)
        assert len(pattern) == pfb_unbound.REGEX_STATIC_LEN_CAP + 1
        rules = [_block_rule(pattern)]
        db, admitted = _dnsbl_compile_regex_rules(rules, static_cap=True)
        assert admitted == 0
        assert db == {}


# --------------------------------------------------------------------------- #
# (2) RUNTIME slow-match warning -- a slow rule is warned about ONCE and KEPT.
# Every admitted rule has a static bound on its work, so a slow measurement (a slow
# box, a busy core) is a reason to log, never to remove the rule.
# --------------------------------------------------------------------------- #
OLD_EVICT_CEILING_MS = 100.0  # the ceiling a rule used to be removed at
SLOW_MS = 150.0  # measured over both the warn ceiling and the old evict ceiling


def _slow_pattern() -> Any:
    # A trivially-matching compiled pattern; the SLOWNESS is faked via the clock so the
    # test never actually pays a slow match.
    return re.compile(r"slow\.example$")


def _slow_rule_db() -> dict[str, Any]:
    return {"F#0": {"re": _slow_pattern(), "important": False, "band": PRIO_FEED_BLOCK}}


class TestSlowRegexIsWarnedAndKept:
    def test_discovery_scan_keeps_a_rule_measured_over_the_old_evict_ceiling(
        self, monkeypatch: Any, capsys: Any
    ) -> None:
        # Given a rule whose match is measured over the old evict ceiling, a query still
        # blocks on it, the rule is still in the live dict, and the NEXT query blocks too.
        assert SLOW_MS > OLD_EVICT_CEILING_MS
        regex_db = _slow_rule_db()
        cfg = _cfg(regexDB=True)
        containers = _containers(regexDB=regex_db)
        _install_clock(monkeypatch, [SLOW_MS, SLOW_MS])
        first = evaluate_domain("slow.example", "slow.example", "example", False, cfg, containers)
        assert (first.is_found, first.group, first.feed) == (True, "DNSBL_Regex", "F#0")
        assert "F#0" in regex_db
        second = evaluate_domain("slow.example", "slow.example", "example", False, cfg, containers)
        assert (second.is_found, second.group, second.feed) == (True, "DNSBL_Regex", "F#0")
        assert "F#0" in regex_db
        # ... and exactly one warning line was written for the rule.
        assert capsys.readouterr().err.count("slow DNSBL_Regex regex [ F#0 ]") == 1

    def test_block_band_scan_keeps_a_rule_measured_over_the_old_evict_ceiling(
        self, monkeypatch: Any, capsys: Any
    ) -> None:
        regex_db = _slow_rule_db()
        cfg = _cfg(regexDB=True)
        _install_clock(monkeypatch, [SLOW_MS, SLOW_MS])
        expected = (PRIO_FEED_BLOCK, {"kind": "regex", "key": "F#0"})
        assert _scan_block_band("slow.example", cfg, {}, {}, regex_db, {}) == expected
        assert _scan_block_band("slow.example", cfg, {}, {}, regex_db, {}) == expected
        assert "F#0" in regex_db
        assert capsys.readouterr().err.count("slow DNSBL_Regex regex [ F#0 ]") == 1

    def test_allow_scan_keeps_a_rule_measured_over_the_old_evict_ceiling(self, monkeypatch: Any, capsys: Any) -> None:
        allow_db: dict[str, Any] = {"A#0": {"re": _slow_pattern(), "important": False, "band": PRIO_FEED_ALLOW}}
        _install_clock(monkeypatch, [SLOW_MS, SLOW_MS])
        assert _scan_allow_regex_band("slow.example", allow_db, {}, 10.0) == PRIO_FEED_ALLOW
        assert _scan_allow_regex_band("slow.example", allow_db, {}, 10.0) == PRIO_FEED_ALLOW
        assert "A#0" in allow_db
        assert capsys.readouterr().err.count("slow DNSBL_AllowRegex regex [ A#0 ]") == 1

    def test_a_rule_over_the_warn_ceiling_is_warned_once_and_still_blocks(self, monkeypatch: Any, capsys: Any) -> None:
        regex_db = _slow_rule_db()
        cfg = _cfg(regexDB=True)
        containers = _containers(regexDB=regex_db)
        # 20 ms: over warn (10) -> warns, still blocks, rule kept.
        _install_clock(monkeypatch, [20.0])
        dec = evaluate_domain("slow.example", "slow.example", "example", False, cfg, containers)
        assert dec.is_found is True
        assert dec.group == "DNSBL_Regex"
        assert "F#0" in regex_db  # kept
        assert capsys.readouterr().err.count("slow DNSBL_Regex regex [ F#0 ]") == 1  # warned

    def test_a_slow_user_rule_is_kept_and_blocks_when_slow(self, monkeypatch: Any) -> None:
        # A rule of the user list gets the same treatment as a feed rule: warned about, never removed.
        user_db: dict[str, Any] = {"MyUserRegex": {"re": _slow_pattern(), "important": False, "band": PRIO_USER_BLOCK}}
        cfg = _cfg(userRegexDB=True)
        containers = _containers(userRegexDB=user_db)
        _install_clock(monkeypatch, [200.0])
        dec = evaluate_domain("slow.example", "slow.example", "example", False, cfg, containers)
        assert dec.is_found is True
        assert dec.feed == "MyUserRegex"
        assert "MyUserRegex" in user_db

    def test_a_slow_rule_among_many_does_not_disturb_the_scan(self, monkeypatch: Any) -> None:
        regex_db: dict[str, Any] = {}
        for i in range(5):
            regex_db["P#{}".format(i)] = {"re": re.compile(r"nomatch%d\.x$" % i), "important": False, "band": 1}
        regex_db["SLOW"] = {"re": _slow_pattern(), "important": False, "band": 1}
        cfg = _cfg(regexDB=True)
        containers = _containers(regexDB=regex_db)
        # 6 entries scanned; only SLOW is slow (and the one that matches).
        _install_clock(monkeypatch, [1.0, 1.0, 1.0, 1.0, 1.0, 300.0])
        dec = evaluate_domain("slow.example", "slow.example", "example", False, cfg, containers)
        assert (dec.is_found, dec.feed) == (True, "SLOW")
        assert len(regex_db) == 6  # every rule is still loaded

    def test_allow_regex_under_the_warn_ceiling_is_silent_and_kept(self, monkeypatch: Any, capsys: Any) -> None:
        allow_db: dict[str, Any] = {"A#0": {"re": _slow_pattern(), "important": False, "band": PRIO_FEED_ALLOW}}
        _install_clock(monkeypatch, [2.0])
        band = _scan_allow_regex_band("slow.example", allow_db, {}, 10.0)
        assert band == PRIO_FEED_ALLOW
        assert "A#0" in allow_db
        assert capsys.readouterr().err == ""


class _Measured:
    """Replaces ``_regex_timed_search`` so each rule measures a fixed time (ms), keyed by its pattern
    text. Unlike the thread-clock fake, the answer does not depend on the order a scan visits the
    rules in."""

    def __init__(self, monkeypatch: Any) -> None:
        self.ms: dict[str, float] = {}
        monkeypatch.setattr(pfb_unbound, "_regex_timed_search", self)

    def __call__(self, pattern: Any, q_name: str) -> tuple[Any, float]:
        return pattern.search(q_name), self.ms[pattern.pattern]

    def db(self, prefix: str, band: int, ms_list: list[float], match_at: int | None = None) -> dict[str, Any]:
        """A regex DB with one rule per entry of ``ms_list``, rule ``i`` measuring ``ms_list[i]``.
        Every rule is an alternation (no required literal, so the prefilter always runs it); rule
        ``match_at`` matches ``slow.example`` and the others never do."""
        db: dict[str, Any] = {}
        for index, ms in enumerate(ms_list):
            text = rf"^(?:slow\.example|never{prefix}{index})$" if index == match_at else f"^(?:no{prefix}{index}|zz)$"
            self.ms[text] = ms
            db[f"{prefix}#{index}"] = {"re": re.compile(text), "important": False, "band": band}
        return db


SLOW_LIST_LINE = (
    "[pfBlockerNG]: slow {label} regex list scan took {total} ms over {count} rules "
    "(warn ceiling 10.0 ms); slowest [ {slowest} ] {top} ms\n"
)


class TestSlowListScanIsReported:
    """Every rule can be under the warn ceiling and the whole list scan still slow: one line per
    list per load reports the summed time, the number of rules timed and the slowest rule."""

    @staticmethod
    def _discover(cfg: dict[str, Any], containers: dict[str, Any]) -> Any:
        return evaluate_domain("slow.example", "slow.example", "example", False, cfg, containers)

    def test_a_discovery_scan_over_the_ceiling_in_total_logs_one_line_for_its_list(
        self, monkeypatch: Any, capsys: Any
    ) -> None:
        measured = _Measured(monkeypatch)
        containers = _containers(regexDB=measured.db("F", PRIO_FEED_BLOCK, [3.0, 4.0, 5.0]))
        cfg = _cfg(regexDB=True)
        assert self._discover(cfg, containers).is_found is False
        assert capsys.readouterr().err == SLOW_LIST_LINE.format(
            label="DNSBL_Regex", total="12.0", count=3, slowest="F#2", top="5.0"
        )
        # A second query over the same list adds nothing.
        assert self._discover(cfg, containers).is_found is False
        assert capsys.readouterr().err == ""

    def test_a_list_scan_under_the_ceiling_in_total_is_silent(self, monkeypatch: Any, capsys: Any) -> None:
        measured = _Measured(monkeypatch)
        containers = _containers(regexDB=measured.db("F", PRIO_FEED_BLOCK, [3.0, 3.0, 3.0]))
        assert self._discover(_cfg(regexDB=True), containers).is_found is False
        assert capsys.readouterr().err == ""

    def test_a_list_scan_summing_exactly_to_the_ceiling_is_silent(self, monkeypatch: Any, capsys: Any) -> None:
        measured = _Measured(monkeypatch)
        containers = _containers(regexDB=measured.db("F", PRIO_FEED_BLOCK, [5.0, 5.0]))
        assert self._discover(_cfg(regexDB=True), containers).is_found is False
        assert capsys.readouterr().err == ""

    def test_a_scan_that_stops_on_its_first_match_still_counts_what_it_timed(
        self, monkeypatch: Any, capsys: Any
    ) -> None:
        measured = _Measured(monkeypatch)
        containers = _containers(regexDB=measured.db("F", PRIO_FEED_BLOCK, [6.0, 7.0, 9.0], match_at=1))
        assert self._discover(_cfg(regexDB=True), containers).feed == "F#1"
        assert capsys.readouterr().err == SLOW_LIST_LINE.format(
            label="DNSBL_Regex", total="13.0", count=2, slowest="F#1", top="7.0"
        )

    def test_the_block_band_rescan_reports_the_same_list_once(self, monkeypatch: Any, capsys: Any) -> None:
        measured = _Measured(monkeypatch)
        regex_db = measured.db("F", PRIO_FEED_BLOCK, [3.0, 4.0, 5.0])
        cfg = _cfg(regexDB=True)
        assert _scan_block_band("slow.example", cfg, {}, {}, regex_db, {}) == (0, None)
        assert capsys.readouterr().err == SLOW_LIST_LINE.format(
            label="DNSBL_Regex", total="12.0", count=3, slowest="F#2", top="5.0"
        )
        assert _scan_block_band("slow.example", cfg, {}, {}, regex_db, {}) == (0, None)
        assert capsys.readouterr().err == ""

    def test_the_discovery_scan_and_the_band_rescan_share_one_line_per_list(
        self, monkeypatch: Any, capsys: Any
    ) -> None:
        measured = _Measured(monkeypatch)
        regex_db = measured.db("F", PRIO_FEED_BLOCK, [3.0, 4.0, 5.0])
        cfg = _cfg(regexDB=True)
        self._discover(cfg, _containers(regexDB=regex_db))
        _scan_block_band("slow.example", cfg, {}, {}, regex_db, {})
        assert capsys.readouterr().err.count("regex list scan took") == 1

    def test_the_allow_scan_reports_its_own_list(self, monkeypatch: Any, capsys: Any) -> None:
        measured = _Measured(monkeypatch)
        allow_db = measured.db("A", PRIO_FEED_ALLOW, [3.0, 4.0, 5.0])
        assert _scan_allow_regex_band("slow.example", allow_db, {}, 10.0) == 0
        assert capsys.readouterr().err == SLOW_LIST_LINE.format(
            label="DNSBL_AllowRegex", total="12.0", count=3, slowest="A#2", top="5.0"
        )
        assert _scan_allow_regex_band("slow.example", allow_db, {}, 10.0) == 0
        assert capsys.readouterr().err == ""

    def test_the_block_and_allow_lists_are_reported_separately(self, monkeypatch: Any, capsys: Any) -> None:
        measured = _Measured(monkeypatch)
        regex_db = measured.db("F", PRIO_FEED_BLOCK, [3.0, 4.0, 5.0])
        allow_db = measured.db("A", PRIO_FEED_ALLOW, [3.0, 5.0, 4.0])
        _scan_block_band("slow.example", _cfg(regexDB=True), {}, {}, regex_db, {})
        _scan_allow_regex_band("slow.example", allow_db, {}, 10.0)
        err = capsys.readouterr().err
        assert err == SLOW_LIST_LINE.format(
            label="DNSBL_Regex", total="12.0", count=3, slowest="F#2", top="5.0"
        ) + SLOW_LIST_LINE.format(label="DNSBL_AllowRegex", total="12.0", count=3, slowest="A#1", top="5.0")

    def test_a_swap_re_arms_the_list_report(self, monkeypatch: Any, capsys: Any) -> None:
        measured = _Measured(monkeypatch)
        containers = _containers(regexDB=measured.db("F", PRIO_FEED_BLOCK, [3.0, 4.0, 5.0]))
        cfg = _cfg(regexDB=True)
        self._discover(cfg, containers)
        assert capsys.readouterr().err.count("regex list scan took") == 1
        self._discover(cfg, containers)
        assert capsys.readouterr().err == ""
        empty = pfb_unbound.Snapshot(
            data_db={},
            zone_db={},
            white_db={},
            regex_db={},
            allow_regex_db={},
            user_regex_db={},
            user_allow_regex_db={},
            feed_group_index_db={},
            hsts_db={},
        )
        assert pfb_unbound.rebuild_and_swap(lambda: empty, emit_counts=False) is True
        self._discover(cfg, containers)
        assert capsys.readouterr().err.count("regex list scan took") == 1

    def test_a_rule_over_the_ceiling_still_gets_its_own_line_besides_the_list_line(
        self, monkeypatch: Any, capsys: Any
    ) -> None:
        measured = _Measured(monkeypatch)
        containers = _containers(regexDB=measured.db("F", PRIO_FEED_BLOCK, [20.0]))
        self._discover(_cfg(regexDB=True), containers)
        assert capsys.readouterr().err.splitlines(keepends=True) == [
            "[pfBlockerNG]: slow DNSBL_Regex regex [ F#0 ] took 20.0 ms (warn ceiling 10.0 ms)\n",
            SLOW_LIST_LINE.format(label="DNSBL_Regex", total="20.0", count=1, slowest="F#0", top="20.0"),
        ]

    def test_the_per_rule_warning_line_ends_with_a_newline(self, capsys: Any) -> None:
        pfb_unbound._regex_warn_slow("RX", 50.0, 10.0, "DNSBL_Regex")
        assert capsys.readouterr().err == (
            "[pfBlockerNG]: slow DNSBL_Regex regex [ RX ] took 50.0 ms (warn ceiling 10.0 ms)\n"
        )

    def test_same_named_rules_of_different_lists_warn_independently(self, monkeypatch: Any, capsys: Any) -> None:
        """Rule names repeat across lists (``F#0`` of a feed list and of a user list): each list warns for
        its own rule, block and allow lists alike."""
        measured = _Measured(monkeypatch)
        containers = _containers(
            regexDB=measured.db("X", PRIO_FEED_BLOCK, [20.0]),
            userRegexDB=measured.db("X", PRIO_USER_BLOCK, [20.0]),
        )
        self._discover(_cfg(regexDB=True, userRegexDB=True), containers)
        feed_allow = measured.db("X", PRIO_FEED_ALLOW, [20.0])
        user_allow = measured.db("X", PRIO_USER_ALLOW, [20.0])
        assert _scan_allow_regex_band("slow.example", feed_allow, user_allow, 10.0) == 0
        rule_lines = [line for line in capsys.readouterr().err.splitlines() if "regex [ X#0 ]" in line]
        assert rule_lines == [
            "[pfBlockerNG]: slow user DNSBL_Regex regex [ X#0 ] took 20.0 ms (warn ceiling 10.0 ms)",
            "[pfBlockerNG]: slow DNSBL_Regex regex [ X#0 ] took 20.0 ms (warn ceiling 10.0 ms)",
            "[pfBlockerNG]: slow user DNSBL_AllowRegex regex [ X#0 ] took 20.0 ms (warn ceiling 10.0 ms)",
            "[pfBlockerNG]: slow DNSBL_AllowRegex regex [ X#0 ] took 20.0 ms (warn ceiling 10.0 ms)",
        ]

    def test_every_slow_rule_of_one_list_warns_for_itself(self, monkeypatch: Any, capsys: Any) -> None:
        measured = _Measured(monkeypatch)
        containers = _containers(regexDB=measured.db("F", PRIO_FEED_BLOCK, [20.0, 30.0]))
        self._discover(_cfg(regexDB=True), containers)
        rule_lines = [line for line in capsys.readouterr().err.splitlines() if "regex [ F#" in line]
        assert rule_lines == [
            "[pfBlockerNG]: slow DNSBL_Regex regex [ F#0 ] took 20.0 ms (warn ceiling 10.0 ms)",
            "[pfBlockerNG]: slow DNSBL_Regex regex [ F#1 ] took 30.0 ms (warn ceiling 10.0 ms)",
        ]


class TestNoRuntimeEviction:
    def test_the_per_query_cfg_carries_the_warn_ceiling_and_no_evict_ceiling(self) -> None:
        snapshot = pfb_unbound.Snapshot(
            data_db={},
            zone_db={},
            white_db={},
            regex_db={},
            allow_regex_db={},
            user_regex_db={},
            user_allow_regex_db={},
            feed_group_index_db={},
            hsts_db={},
        )
        cfg = pfb_unbound._evaluate_cfg(snapshot)
        assert cfg["regex_warn_ms"] == pfb_unbound.pfb["regex_warn_ms"]
        assert "regex_evict_ms" not in cfg


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

    def test_a_fast_regex_match_blocks_and_is_not_warned(self, monkeypatch: Any) -> None:
        # A normal (fast) regex match blocks and stays loaded; nothing warned.
        regex_db = _slow_rule_db()
        cfg = _cfg(regexDB=True)
        containers = _containers(regexDB=regex_db)
        _install_clock(monkeypatch, [0.5])
        dec = evaluate_domain("slow.example", "slow.example", "example", False, cfg, containers)
        assert dec.is_found is True
        assert "F#0" in regex_db
        assert pfb_unbound._regex_warned == set()


# --------------------------------------------------------------------------- #
# A quantified group dropped UNCONDITIONALLY (end-to-end, BOUNDED so it can't
# hang -- the pattern is never executed against any input)
# --------------------------------------------------------------------------- #
class TestQuantifiedGroupRefusedAtLoad:
    def test_admission_gate_drops_a_starred_group_cap_off(self) -> None:
        # The gate refuses a quantified group WITHOUT executing it, and does so with the
        # length cap OFF (the always-on admission gate).
        rule = _block_rule(r"([a-z]+)*\.example$")
        db, admitted = _dnsbl_compile_regex_rules([rule], static_cap=False)
        assert admitted == 0
        assert db == {}

    def test_admission_gate_drops_a_repeated_alternation_cap_off(self) -> None:
        # ^(a|a)+$ PASSES a naive length cap but backtracks exponentially; the admission
        # gate drops it at load WITHOUT executing it -- regardless of the length cap.
        rule = _block_rule(r"^(a|a)+$")
        for cap in (False, True):
            db, admitted = _dnsbl_compile_regex_rules([rule], static_cap=cap)
            assert admitted == 0, cap
            assert db == {}, cap


# --------------------------------------------------------------------------- #
# Feed regex admission at load: compile isolation, no limit on the number of rules, short log excerpts
# --------------------------------------------------------------------------- #


def _allow_rule(pattern: str, feed: str = "F") -> RegexRule:
    return RegexRule(
        pattern=pattern,
        kind=DNSBL_KIND_ALLOW,
        band=PRIO_FEED_ALLOW,
        important=False,
        provenance="feed",
        feed=feed,
        group="DNSBL_Regex",
        log="1",
    )


def _compiled_patterns(db: dict[str, dict[str, Any]]) -> list[str]:
    return [entry["re"].pattern for entry in db.values()]


def _excerpt_of(pattern: str) -> str:
    """The log form of a long pattern: its first 32 characters, escaped, and its length."""
    return ascii(pattern[:32]) + f" ... ({len(pattern)} chars)"


@pytest.mark.parametrize("failure", [OverflowError, RecursionError, ValueError, MemoryError])
def test_unexpected_compile_failure_drops_only_that_rule(monkeypatch: Any, failure: type[Exception]) -> None:
    """Any exception out of ``re.compile`` costs the one rule that raised it; the lists
    around it still load and the build is not aborted."""
    first, middle, last = r"^first\.example$", r"^middle\.example$", r"^last\.example$"
    real_compile = re.compile

    def compile_or_fail(pattern: Any, flags: int = 0) -> Any:
        if pattern == middle:
            raise failure("simulated compile failure")
        return real_compile(pattern, flags)

    monkeypatch.setattr(pfb_unbound.re, "compile", compile_or_fail)
    db, admitted = _dnsbl_compile_regex_rules([_block_rule(first), _block_rule(middle), _block_rule(last)])
    assert admitted == 2
    assert _compiled_patterns(db) == [first, last]


@pytest.mark.parametrize("count", [1000, 1001, 1500])
def test_every_admitted_rule_of_a_list_loads_however_many_there_are(capsys: Any, count: int) -> None:
    rules = [_block_rule(rf"^r{i}\.example$") for i in range(count)]
    db, admitted = _dnsbl_compile_regex_rules(rules)
    assert admitted == count
    assert _compiled_patterns(db) == [rule.pattern for rule in rules]
    assert capsys.readouterr().err == ""


def _costed_rule(index: int) -> RegexRule:
    """A rule that costs exactly 65536: three digit atoms and ``x{252}`` (253 nodes), searched
    from every position (x256). Distinct text per index, equal cost for all."""
    rule = _block_rule(f"{index:03d}x{{252}}")
    assert pfb_dnsbl_regex_rules.pfb_regex_admission(rule.pattern)[:2] == (65536, None)
    return rule


def test_a_list_far_over_the_old_summed_cost_budget_loads_in_full(capsys: Any) -> None:
    """300 rules of cost 65536 sum to 19.6 million; only the per-rule bound applies to each."""
    rules = [_costed_rule(i) for i in range(300)]
    db, admitted = _dnsbl_compile_regex_rules(rules)
    assert admitted == 300
    assert _compiled_patterns(db) == [rule.pattern for rule in rules]
    assert capsys.readouterr().err == ""


def test_a_list_of_unanchored_literal_rules_loads_in_full(capsys: Any) -> None:
    """An unanchored 9-character literal costs 2304 (``analytics`` is one): 1500 of them sum to 3.4 million."""
    rules = [_block_rule(f"host{i:05d}") for i in range(1500)]
    assert pfb_dnsbl_regex_rules.pfb_regex_admission(rules[0].pattern)[:2] == (2304, None)
    db, admitted = _dnsbl_compile_regex_rules(rules)
    assert admitted == 1500
    assert capsys.readouterr().err == ""


# Per call, at most REFUSAL_LOG_MAX per-rule refusal lines are written; the rest are counted
# into one summary line.
REFUSAL_LOG_MAX = 20


def _per_rule_lines(lines: list[str]) -> list[str]:
    return [line for line in lines if "dropping" in line or "compile error" in line]


def test_refusal_log_lines_are_capped_per_list_and_the_rest_are_counted_once(capsys: Any) -> None:
    rules = [_block_rule(f"(a+)+x{i}") for i in range(50)]
    db, admitted = _dnsbl_compile_regex_rules(rules)
    assert (db, admitted) == ({}, 0)
    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == REFUSAL_LOG_MAX + 1, lines
    assert all("dropping block regex feed" in line for line in lines[:REFUSAL_LOG_MAX]), lines
    assert "30 more refused block regex rules not logged" in lines[REFUSAL_LOG_MAX], lines


@pytest.mark.parametrize(("count", "suppressed"), [(REFUSAL_LOG_MAX, 0), (REFUSAL_LOG_MAX + 1, 1)])
def test_the_refusal_log_cap_is_exact_at_its_boundary(capsys: Any, count: int, suppressed: int) -> None:
    _dnsbl_compile_regex_rules([_allow_rule(f"(a+)+x{i}") for i in range(count)])
    lines = capsys.readouterr().err.splitlines()
    assert len(_per_rule_lines(lines)) == REFUSAL_LOG_MAX, lines
    if suppressed:
        assert len(lines) == REFUSAL_LOG_MAX + 1, lines
        assert f"{suppressed} more refused allow regex rules not logged" in lines[-1], lines
    else:
        assert len(lines) == REFUSAL_LOG_MAX, lines


def test_gate_refusals_length_cap_drops_and_compile_errors_share_one_refusal_log_budget(
    capsys: Any, monkeypatch: Any
) -> None:
    real_compile = re.compile

    def compile_or_fail(candidate: Any, flags: int = 0) -> Any:
        if candidate.startswith("^boom"):
            raise ValueError("cannot compile")
        return real_compile(candidate, flags)

    monkeypatch.setattr(pfb_unbound.re, "compile", compile_or_fail)
    rules = (
        [_block_rule(f"(a+)+x{i}") for i in range(10)]  # refused by the gate
        + [_block_rule("^" + "a" * 210 + f"{i:02d}$") for i in range(10)]  # over the opt-in length cap
        + [_block_rule(f"^boom{i}$") for i in range(5)]  # admitted, then the compile raises
    )
    db, admitted = _dnsbl_compile_regex_rules(rules, static_cap=True)
    assert (db, admitted) == ({}, 0)
    lines = capsys.readouterr().err.splitlines()
    assert len(_per_rule_lines(lines)) == REFUSAL_LOG_MAX, lines
    assert len(lines) == REFUSAL_LOG_MAX + 1, lines
    assert "5 more refused block regex rules not logged" in lines[-1], lines


def test_feed_rules_with_wide_classes_are_refused_without_a_compile_attempt(capsys: Any, monkeypatch: Any) -> None:
    """Classes this wide cost milliseconds each to compile, so a full list of them is
    refused rule by rule on the gate's verdict and no pattern reaches ``re.compile``."""
    compiled: list[str] = []
    real_compile = re.compile

    def record_compile(candidate: Any, flags: int = 0) -> Any:
        compiled.append(candidate)
        return real_compile(candidate, flags)

    monkeypatch.setattr(pfb_unbound.re, "compile", record_compile)
    rules = [_block_rule("^" + "[!-~]" * 49 + f"x{i:04d}") for i in range(1000)]
    db, admitted = _dnsbl_compile_regex_rules(rules)
    assert (db, admitted) == ({}, 0)
    assert compiled == []
    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == REFUSAL_LOG_MAX + 1, lines
    assert all("character classes too wide" in line for line in lines[:REFUSAL_LOG_MAX]), lines
    assert f"{1000 - REFUSAL_LOG_MAX} more refused block regex rules not logged" in lines[-1], lines


def test_refusals_do_not_stop_the_rest_of_the_list_loading_and_the_one_summary_line_counts_them(capsys: Any) -> None:
    refused = [_block_rule(f"(a+)+x{i}") for i in range(REFUSAL_LOG_MAX + 30)]
    fitting = [_block_rule(rf"^r{i}\.example$") for i in range(1100)]
    db, admitted = _dnsbl_compile_regex_rules([*refused, *fitting])
    assert admitted == 1100
    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == REFUSAL_LOG_MAX + 1, lines
    assert lines[-1].endswith("30 more refused block regex rules not logged"), lines


def test_build_loads_every_admitted_feed_block_and_allow_regex_rule() -> None:
    manifest = {
        "feeds": [{"feed": "F", "group": "G", "log_flag": "1", "raw": "F"}],
        "config": {},
    }
    lines = [f"/^b[0-9]+x{i}\\.example$/" for i in range(1500)] + [f"@@/^a[0-9]+x{i}\\.example$/" for i in range(1200)]
    result = pfb_unbound.build(manifest, {"regex_cap": False}, line_reader=lambda _ref: lines)
    assert len(result.regex_db) == 1500
    assert len(result.allow_regex_db) == 1200
    assert result.regex_count == 2700


def test_refused_feed_pattern_is_logged_as_a_short_excerpt_with_its_reason(capsys: Any) -> None:
    pattern = "(a+)+" + "a" * 285 + "TAILMARKER"  # refused by every gate generation: only its log form differs
    db, admitted = _dnsbl_compile_regex_rules([_block_rule(pattern), _block_rule(r"^ok\.example$")])
    assert admitted == 1
    err = capsys.readouterr().err
    assert _excerpt_of(pattern) in err
    assert "over 256 characters" in err
    assert "TAILMARKER" not in err


def test_feed_pattern_dropped_by_the_length_cap_is_logged_as_a_short_excerpt(capsys: Any) -> None:
    pattern = "^" + "a" * 228 + "TAILMARKER$"
    assert pfb_unbound.REGEX_STATIC_LEN_CAP < len(pattern) <= 256
    db, admitted = _dnsbl_compile_regex_rules([_block_rule(pattern)], static_cap=True)
    assert admitted == 0
    err = capsys.readouterr().err
    assert _excerpt_of(pattern) in err
    assert "TAILMARKER" not in err


@pytest.mark.parametrize("failure", [re.error, ValueError])
def test_feed_pattern_that_fails_to_compile_is_logged_as_a_short_excerpt(
    capsys: Any, monkeypatch: Any, failure: type[Exception]
) -> None:
    pattern = "^" + "a" * 150 + "TAILMARKER$"
    real_compile = re.compile

    def compile_or_fail(candidate: Any, flags: int = 0) -> Any:
        if candidate == pattern:
            raise failure("cannot compile " + pattern)  # a message that quotes the whole pattern
        return real_compile(candidate, flags)

    monkeypatch.setattr(pfb_unbound.re, "compile", compile_or_fail)
    db, admitted = _dnsbl_compile_regex_rules([_block_rule(pattern), _block_rule(r"^ok\.example$")])
    assert admitted == 1
    err = capsys.readouterr().err
    assert _excerpt_of(pattern) in err
    assert "TAILMARKER" not in err


def test_control_characters_in_a_refused_feed_pattern_never_reach_the_log_raw(capsys: Any) -> None:
    pattern = "(a+)+\x00b\x1bc\rd"
    db, admitted = _dnsbl_compile_regex_rules([_block_rule(pattern)])
    assert admitted == 0
    err = capsys.readouterr().err
    assert not any(character in err for character in ("\x00", "\x1b", "\r"))
    assert ascii(pattern) in err
    assert err.count("\n") == 1


# User regex lists load at two sites (init and the zero-downtime swap) into the user container;
# both take the per-pattern gate and the opt-in length cap, and no list has a rule limit.
class _UserLoads(NamedTuple):
    """What the two user-regex load sites produced for one ``MAIN.regex_list``."""

    initial: dict[str, dict[str, Any]]  # userRegexDB after init_standard
    swapped: dict[str, dict[str, Any]]  # user_regex_db of the swap snapshot ({} without a manifest)
    blacklist_at_stats_gate: bool | None  # python_blacklist where init opens stats DBs (None: not watched)
    feed_initial: dict[str, dict[str, Any]]  # regexDB after init_standard
    feed_swapped: dict[str, dict[str, Any]]  # regex_db of the swap snapshot
    user_allow_initial: dict[str, dict[str, Any]]  # userAllowRegexDB after init_standard
    user_allow_swapped: dict[str, dict[str, Any]]  # user_allow_regex_db of the swap snapshot
    count_initial: int | None  # what init emitted as pfb_py_regex_count
    count_swapped: int  # regex_count of the swap snapshot
    snapshot_count_initial: int  # regex_count of the snapshot init installed
    warned_after_init: set[str]  # the slow-match warning bookkeeping once init has run
    decision_initial: Any  # evaluate_domain over the snapshot init installed (None: no query given)
    decision_swapped: Any  # the same query over the swap snapshot (None: no query, or no manifest)
    important_initial: bool  # important_rules of the snapshot init installed
    important_swapped: bool | None  # important_rules of the swap snapshot (None: no manifest)


def _patterns(db: dict[str, dict[str, Any]]) -> dict[str, str]:
    return {name: entry["re"].pattern for name, entry in db.items()}


def _decide(snapshot: pfb_unbound.Snapshot, name: str) -> Any:
    """``evaluate_domain`` for ``name`` over ``snapshot``, through the per-query cfg and containers the
    resolver derives from it."""
    cfg = pfb_unbound._evaluate_cfg(snapshot)
    return evaluate_domain(name, name, name.rsplit(".", 1)[-1], False, cfg, snapshot.containers())


def _user_regex_loads(
    tmp_path: Path,
    monkeypatch: Any,
    rows: list[str],
    *,
    regex_cap: bool = False,
    manifest: bool = True,
    watch_stats_gate: bool = False,
    feeds: dict[str, list[str]] | None = None,
    user_feeds: tuple[str, ...] = (),
    feed_log_flags: dict[str, str] | None = None,
    query: str | None = None,
    stale_warnings: tuple[str, ...] = (),
) -> _UserLoads:
    """Run both load sites over one ``MAIN.regex_list``. ``manifest=False`` leaves out the DNSBL
    manifest: init then keeps what the user-regex load set (it would otherwise recompute the
    flags from the merged databases) and the swap has nothing to build on.
    ``watch_stats_gate`` records ``python_blacklist`` where init decides to open the DNSBL
    stats database (the databases are never opened: the validator and the gate answer False).
    ``query`` turns blocking on and decides that name over the snapshot of each load site.
    ``stale_warnings`` seeds the slow-match warning bookkeeping before init runs."""
    encoded = base64.b64encode("\n".join(rows).encode("utf-8")).decode("ascii")
    ini = tmp_path / "pfb_unbound.ini"
    manifest_path = tmp_path / "pfb_py_sources.json"
    if manifest:
        feed_rows = []
        for name, lines in (feeds or {}).items():
            (tmp_path / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
            provenance = "user" if name in user_feeds else "feed"
            flag = (feed_log_flags or {}).get(name, "1")
            feed_rows.append({"raw": name, "feed": name, "group": name, "log_flag": flag, "provenance": provenance})
        manifest_path.write_text(json.dumps({"version": 1, "config": {}, "feeds": feed_rows}) + "\n", encoding="utf-8")
    emitted: dict[str, int] = {}
    monkeypatch.setattr(pfb_unbound, "dnsbl_emit_count", lambda path, count: emitted.update({path: count}) or True)
    cap_line = "regex_cap = true\n" if regex_cap else ""
    blocking_line = "python_blocking = true\n" if query is not None else ""
    ini.write_text(f"[MAIN]\npython_enable = true\n{cap_line}{blocking_line}regex_list = {encoded}\n", encoding="utf-8")
    monkeypatch.setitem(pfb_unbound.pfb, "pfb_unbound.ini", str(ini))
    monkeypatch.setitem(pfb_unbound.pfb, "pfb_py_sources", str(manifest_path))
    monkeypatch.setitem(pfb_unbound.pfb, "regex_cap", False)  # init sets it; the test restores it
    monkeypatch.chdir(tmp_path)
    seen_at_gate: list[bool] = []
    if watch_stats_gate:

        def stats_gate_spy() -> bool:
            seen_at_gate.append(bool(pfb_unbound.pfb["python_blacklist"]))
            return False

        monkeypatch.setattr(pfb_unbound, "_validate_db_with_recovery", lambda _db: False)
        monkeypatch.setattr(pfb_unbound, "_dnsbl_stats_wanted", stats_gate_spy)
    pfb_unbound.pfb["mod_maxminddb_e"] = "stub"
    pfb_unbound.pfb["mod_threading_e"] = "stub"
    pfb_unbound.pfb["mod_sqlite3_e"] = "stub"
    pfb_unbound.pfb["mod_sqlite3"] = watch_stats_gate
    pfb_unbound.pfb["mod_threading"] = False
    pfb_unbound._regex_warned.update(stale_warnings)
    try:
        assert pfb_unbound.init_standard(0, unboundmodule.module_env()) is True
        initial = dict(pfb_unbound.userRegexDB)
        feed_initial = dict(pfb_unbound.regexDB)
        user_allow_initial = dict(pfb_unbound.userAllowRegexDB)
        count_initial = emitted.get(pfb_unbound.pfb["pfb_py_regex_count"])
        snapshot_count_initial = pfb_unbound._snapshot.regex_count
        warned_after_init = set(pfb_unbound._regex_warned)
        decision_initial = _decide(pfb_unbound._snapshot, query) if query is not None else None
        important_initial = pfb_unbound._snapshot.important_rules
        important_swapped: bool | None = None
        decision_swapped = None
        swapped: dict[str, dict[str, Any]] = {}
        feed_swapped: dict[str, dict[str, Any]] = {}
        user_allow_swapped: dict[str, dict[str, Any]] = {}
        count_swapped = 0
        if manifest:
            # Init's stderr bridge drops a line identical to the previous one; the swap load
            # must show its own log line, so clear that memory between the two loads.
            pfb_unbound.pfb["p_err"] = ""
            snapshot = pfb_unbound._build_swap_snapshot()
            assert snapshot is not None
            swapped = dict(snapshot.user_regex_db)
            feed_swapped = dict(snapshot.regex_db)
            user_allow_swapped = dict(snapshot.user_allow_regex_db)
            count_swapped = snapshot.regex_count
            important_swapped = snapshot.important_rules
            if query is not None:
                decision_swapped = _decide(snapshot, query)
        return _UserLoads(
            initial,
            swapped,
            seen_at_gate[0] if seen_at_gate else None,
            feed_initial,
            feed_swapped,
            user_allow_initial,
            user_allow_swapped,
            count_initial,
            count_swapped,
            snapshot_count_initial,
            warned_after_init,
            decision_initial,
            decision_swapped,
            important_initial,
            important_swapped,
        )
    finally:
        pfb_unbound.deinit(0)
        pfb_unbound._regex_warned.clear()


HOSTILE_ROW = "^[a-z]{1,255}[a-z]{1,255}[a-z]{1,255}x"
KEEP_ROW = r"^keep\.example$"


def test_user_regex_refused_by_the_gate_is_dropped_and_the_next_row_still_loads(
    tmp_path: Path, monkeypatch: Any
) -> None:
    loads = _user_regex_loads(tmp_path, monkeypatch, [f"{HOSTILE_ROW}#hostile", f"{KEEP_ROW}#keep"])
    assert _patterns(loads.initial) == {"keep": KEEP_ROW}
    assert _patterns(loads.swapped) == {"keep": KEEP_ROW}


WIDE_ROW = "^" + "[!-~]" * 6 + "x"


def test_user_regex_with_wide_classes_is_dropped_and_the_next_row_still_loads(tmp_path: Path, monkeypatch: Any) -> None:
    loads = _user_regex_loads(tmp_path, monkeypatch, [f"{WIDE_ROW}#wide", f"{KEEP_ROW}#keep"])
    assert _patterns(loads.initial) == {"keep": KEEP_ROW}
    assert _patterns(loads.swapped) == {"keep": KEEP_ROW}


def test_user_regex_entries_are_non_important_band_five_blocks_at_both_load_sites(
    tmp_path: Path, monkeypatch: Any
) -> None:
    loads = _user_regex_loads(tmp_path, monkeypatch, [f"{KEEP_ROW}#keep"])
    for db in (loads.initial, loads.swapped):
        assert set(db) == {"keep"}
        assert db["keep"]["important"] is False
        assert db["keep"]["band"] == PRIO_USER_BLOCK
        assert db["keep"]["re"].flags & re.IGNORECASE


@pytest.mark.parametrize(
    ("rows", "loaded"),
    [([f"{HOSTILE_ROW}#hostile"], False), ([f"{HOSTILE_ROW}#hostile", f"{KEEP_ROW}#keep"], True)],
    ids=["nothing-compiled", "one-compiled"],
)
def test_init_raises_python_blacklist_only_when_a_user_pattern_compiled(
    tmp_path: Path, monkeypatch: Any, rows: list[str], loaded: bool
) -> None:
    loads = _user_regex_loads(tmp_path, monkeypatch, rows, manifest=False, watch_stats_gate=True)
    assert bool(loads.initial) is loaded
    # The snapshot install at the end of init raises python_blacklist on its own, so the
    # user-regex load's own raise is only visible where init opens the stats databases.
    assert loads.blacklist_at_stats_gate is loaded


@pytest.mark.parametrize(
    ("rows", "loaded"),
    [([f"{HOSTILE_ROW}#hostile"], False), ([f"{HOSTILE_ROW}#hostile", f"{KEEP_ROW}#keep"], True)],
    ids=["nothing-compiled", "one-compiled"],
)
def test_the_swap_snapshot_carries_user_regex_only_when_one_compiled(
    tmp_path: Path, monkeypatch: Any, rows: list[str], loaded: bool
) -> None:
    loads = _user_regex_loads(tmp_path, monkeypatch, rows)
    assert bool(loads.swapped) is loaded


@pytest.mark.parametrize("regex_cap", [False, True])
def test_the_opt_in_length_cap_drops_an_over_length_user_pattern_at_both_load_sites(
    tmp_path: Path, monkeypatch: Any, regex_cap: bool
) -> None:
    long_row = "^" + "a" * 210 + "$"
    assert pfb_unbound.REGEX_STATIC_LEN_CAP < len(long_row) <= 256
    loads = _user_regex_loads(tmp_path, monkeypatch, [f"{long_row}#long", f"{KEEP_ROW}#keep"], regex_cap=regex_cap)
    expected = {"keep": KEEP_ROW} if regex_cap else {"long": long_row, "keep": KEEP_ROW}
    assert _patterns(loads.initial) == expected
    assert _patterns(loads.swapped) == expected


def test_user_regex_lists_have_no_rule_limit(
    tmp_path: Path, monkeypatch: Any, caplog: pytest.LogCaptureFixture
) -> None:
    rows = [rf"^u{i}\.example$#u{i}" for i in range(1501)]
    loads = _user_regex_loads(tmp_path, monkeypatch, rows)
    assert len(loads.initial) == 1501
    assert _patterns(loads.swapped) == _patterns(loads.initial)
    assert "dropping" not in caplog.text


def test_refused_user_regex_is_logged_as_a_short_excerpt_at_both_load_sites(
    tmp_path: Path, monkeypatch: Any, caplog: pytest.LogCaptureFixture
) -> None:
    pattern = "(a+)+" + "b" * 285 + "TAILMARKER"  # refused by every gate generation: only its log form differs
    loads = _user_regex_loads(tmp_path, monkeypatch, [f"{pattern}#long", f"{KEEP_ROW}#keep"])
    assert _patterns(loads.initial) == _patterns(loads.swapped) == {"keep": KEEP_ROW}
    assert caplog.text.count(_excerpt_of(pattern)) == 2, caplog.text
    assert "TAILMARKER" not in caplog.text


# The shared helper both sites call, driven directly: one behaviour per test.
def test_user_regex_log_lines_number_every_row_starting_at_one(capsys: Any) -> None:
    entries = [("first", "(a+)+"), ("second", KEEP_ROW), ("third", "(b+)+")]
    db = _dnsbl_compile_user_regex(entries, False)
    assert list(db) == ["second"]
    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == 2, lines
    assert "[ first ]" in lines[0] and "on line #1" in lines[0], lines
    assert "[ third ]" in lines[1] and "on line #3" in lines[1], lines


@pytest.mark.parametrize("failure", [OverflowError, RecursionError, ValueError])
def test_a_user_pattern_whose_compile_raises_anything_is_dropped_alone(
    monkeypatch: Any, failure: type[Exception]
) -> None:
    first, middle, last = r"^first\.example$", r"^middle\.example$", r"^last\.example$"
    real_compile = re.compile

    def compile_or_fail(pattern: Any, flags: int = 0) -> Any:
        if pattern == middle:
            raise failure("simulated compile failure")
        return real_compile(pattern, flags)

    monkeypatch.setattr(pfb_unbound.re, "compile", compile_or_fail)
    db = _dnsbl_compile_user_regex([("first", first), ("middle", middle), ("last", last)], False)
    assert _patterns(db) == {"first": first, "last": last}


def test_user_pattern_dropped_by_the_length_cap_is_logged_as_a_short_excerpt(capsys: Any) -> None:
    pattern = "^" + "a" * 228 + "TAILMARKER$"
    assert pfb_unbound.REGEX_STATIC_LEN_CAP < len(pattern) <= 256
    assert _dnsbl_compile_user_regex([("long", pattern)], True) == {}
    err = capsys.readouterr().err
    assert _excerpt_of(pattern) in err
    assert "TAILMARKER" not in err


def test_user_pattern_that_fails_to_compile_is_logged_as_a_short_excerpt(capsys: Any, monkeypatch: Any) -> None:
    pattern = "^" + "a" * 150 + "TAILMARKER$"
    real_compile = re.compile

    def compile_or_fail(candidate: Any, flags: int = 0) -> Any:
        if candidate == pattern:
            raise ValueError("cannot compile " + pattern)  # a message that quotes the whole pattern
        return real_compile(candidate, flags)

    monkeypatch.setattr(pfb_unbound.re, "compile", compile_or_fail)
    assert _dnsbl_compile_user_regex([("long", pattern)], False) == {}
    err = capsys.readouterr().err
    assert _excerpt_of(pattern) in err
    assert "TAILMARKER" not in err


# A pattern anchored only through a leading `.*` / `.+` is compiled behind a written `^`, so the engine
# itself skips every other start position. Every load site compiles that text, not the pattern as fed.
LEADING_DOT_ROW = r".*\.x\.com$"
LEADING_DOT_COMPILED = r"^(?:(?s:.*)\.x\.com$)"


def test_a_feed_block_rule_anchored_by_a_leading_dot_run_is_compiled_behind_a_caret() -> None:
    db, admitted = _dnsbl_compile_regex_rules([_block_rule(LEADING_DOT_ROW), _block_rule(KEEP_ROW)])
    assert admitted == 2
    assert _compiled_patterns(db) == [LEADING_DOT_COMPILED, KEEP_ROW]
    assert [entry["re"].search("www.x.com") is not None for entry in db.values()] == [True, False]


def test_a_feed_allow_rule_anchored_by_a_leading_dot_run_is_compiled_behind_a_caret() -> None:
    db, admitted = _dnsbl_compile_regex_rules([_allow_rule(LEADING_DOT_ROW)])
    assert admitted == 1
    assert _compiled_patterns(db) == [LEADING_DOT_COMPILED]


def test_a_user_row_anchored_by_a_leading_dot_run_is_compiled_behind_a_caret() -> None:
    db = _dnsbl_compile_user_regex([("lead", LEADING_DOT_ROW), ("keep", KEEP_ROW)], False)
    assert _patterns(db) == {"lead": LEADING_DOT_COMPILED, "keep": KEEP_ROW}
    assert db["lead"]["re"].search("www.x.com") is not None


def test_both_user_regex_load_sites_compile_a_leading_dot_run_behind_a_caret(tmp_path: Path, monkeypatch: Any) -> None:
    loads = _user_regex_loads(tmp_path, monkeypatch, [f"{LEADING_DOT_ROW}#lead", f"{KEEP_ROW}#keep"])
    expected = {"lead": LEADING_DOT_COMPILED, "keep": KEEP_ROW}
    assert _patterns(loads.initial) == expected
    assert _patterns(loads.swapped) == expected


# A user regex that comes from the Custom_List of the manifest and not from the Regex List alone still
# raises the master DNSBL gate at init, whichever list it is in.
@pytest.mark.parametrize("row", [r"/^c[0-9]+\.example$/", r"@@/^ca[0-9]+\.example$/"], ids=["block", "allow"])
def test_init_with_only_a_custom_list_user_regex_raises_python_blacklist(
    tmp_path: Path, monkeypatch: Any, row: str
) -> None:
    loads = _user_regex_loads(
        tmp_path, monkeypatch, [], feeds={"Custom": [row]}, user_feeds=("Custom",), watch_stats_gate=True
    )
    assert loads.blacklist_at_stats_gate is True
    assert len(loads.user_allow_initial) + len(loads.initial) == 1


class _ParseCounter:
    """Counts the parses the admission gate makes of a pattern: the gate's one parse function is
    replaced by a wrapper that records the text and calls it."""

    def __init__(self, monkeypatch: Any) -> None:
        self.texts: list[str] = []
        self._real = pfb_dnsbl_regex_rules._admit
        monkeypatch.setattr(pfb_dnsbl_regex_rules, "_admit", self)

    def __call__(self, text: str) -> Any:
        self.texts.append(text)
        return self._real(text)


def test_a_feed_rule_is_parsed_once_by_the_load(monkeypatch: Any) -> None:
    parses = _ParseCounter(monkeypatch)
    over_length = "^" + "a" * 210 + "$"
    patterns = [LEADING_DOT_ROW, KEEP_ROW, "(a+)+", over_length]
    db, admitted = _dnsbl_compile_regex_rules([_block_rule(pattern) for pattern in patterns], static_cap=True)
    assert (admitted, _compiled_patterns(db)) == (2, [LEADING_DOT_COMPILED, KEEP_ROW])
    assert parses.texts == patterns


def test_a_user_row_is_parsed_once_by_the_load(monkeypatch: Any) -> None:
    parses = _ParseCounter(monkeypatch)
    patterns = [LEADING_DOT_ROW, KEEP_ROW, "(a+)+"]
    db = _dnsbl_compile_user_regex([(f"row{index}", pattern) for index, pattern in enumerate(patterns)], False)
    assert _patterns(db) == {"row0": LEADING_DOT_COMPILED, "row1": KEEP_ROW}
    assert parses.texts == patterns


# The Regex List rows share the refusal-log budget the feed lists have: the first REFUSAL_LOG_MAX lines of one
# load are written and the rest are counted into one summary line.
def test_user_regex_refusal_log_lines_are_capped_and_the_rest_are_counted_once(capsys: Any) -> None:
    entries = [(f"row{i}", f"(a+)+x{i}") for i in range(REFUSAL_LOG_MAX + 5)]
    assert _dnsbl_compile_user_regex(entries, False) == {}
    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == REFUSAL_LOG_MAX + 1, lines
    assert all("dropping user regex" in line for line in lines[:REFUSAL_LOG_MAX]), lines
    assert lines[-1].endswith("5 more refused user regex rules not logged"), lines


@pytest.mark.parametrize(("count", "suppressed"), [(REFUSAL_LOG_MAX, 0), (REFUSAL_LOG_MAX + 1, 1)])
def test_the_user_regex_refusal_log_cap_is_exact_at_its_boundary(capsys: Any, count: int, suppressed: int) -> None:
    _dnsbl_compile_user_regex([(f"row{i}", f"(a+)+x{i}") for i in range(count)], False)
    lines = capsys.readouterr().err.splitlines()
    assert len(_per_rule_lines(lines)) == REFUSAL_LOG_MAX, lines
    if suppressed:
        assert len(lines) == REFUSAL_LOG_MAX + 1, lines
        assert f"{suppressed} more refused user regex rules not logged" in lines[-1], lines
    else:
        assert len(lines) == REFUSAL_LOG_MAX, lines


def test_user_gate_refusals_length_cap_drops_and_compile_errors_share_one_log_budget(
    capsys: Any, monkeypatch: Any
) -> None:
    real_compile = re.compile

    def compile_or_fail(candidate: Any, flags: int = 0) -> Any:
        if candidate.startswith("^boom"):
            raise ValueError("cannot compile")
        return real_compile(candidate, flags)

    monkeypatch.setattr(pfb_unbound.re, "compile", compile_or_fail)
    entries = (
        [(f"gate{i}", f"(a+)+x{i}") for i in range(10)]  # refused by the gate
        + [(f"long{i}", "^" + "a" * 210 + f"{i:02d}$") for i in range(10)]  # over the opt-in length cap
        + [(f"boom{i}", f"^boom{i}$") for i in range(5)]  # admitted, then the compile raises
    )
    assert _dnsbl_compile_user_regex(entries, True) == {}
    lines = capsys.readouterr().err.splitlines()
    assert len(_per_rule_lines(lines)) == REFUSAL_LOG_MAX, lines
    assert len(lines) == REFUSAL_LOG_MAX + 1, lines
    assert lines[-1].endswith("5 more refused user regex rules not logged"), lines


def test_user_refusals_past_the_log_budget_do_not_stop_the_rest_of_the_list_loading(capsys: Any) -> None:
    refused = [(f"bad{i}", f"(a+)+x{i}") for i in range(REFUSAL_LOG_MAX + 30)]
    fitting = [(f"ok{i}", rf"^r{i}\.example$") for i in range(100)]
    db = _dnsbl_compile_user_regex([*refused, *fitting], False)
    assert list(db) == [name for name, _pattern in fitting]
    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == REFUSAL_LOG_MAX + 1, lines
    assert lines[-1].endswith("30 more refused user regex rules not logged"), lines


# `re.ASCII` is not used at any compile site: a `\w` must keep matching the Latin-1 letters that a CNAME
# target decoded by ``convert_other()`` can carry.
LATIN1_ROW = r"^ads\w*\.example$"
LATIN1_NAME = "adsé.example"


def test_a_word_class_matches_a_latin_1_letter_through_the_feed_and_user_load_paths() -> None:
    feed_db, _admitted = _dnsbl_compile_regex_rules([_block_rule(LATIN1_ROW)])
    user_db = _dnsbl_compile_user_regex([("latin", LATIN1_ROW)], False)
    assert feed_db["F#0"]["re"].search(LATIN1_NAME)
    assert user_db["latin"]["re"].search(LATIN1_NAME)
    for db, cfg, containers in (
        (feed_db, _cfg(regexDB=True), _containers(regexDB=feed_db)),
        (user_db, _cfg(userRegexDB=True), _containers(userRegexDB=user_db)),
    ):
        decision = evaluate_domain(LATIN1_NAME, "alias.example", "example", True, cfg, containers)
        assert decision.is_found and decision.feed in db, decision


def test_init_starts_with_clean_slow_match_warning_bookkeeping(tmp_path: Path, monkeypatch: Any) -> None:
    stale = ("stale-rule", "list:DNSBL_Regex")
    seen: list[set[str]] = []
    compile_user = pfb_unbound._dnsbl_compile_user_regex

    def compile_after_reset(entries: Any, regex_cap: bool) -> Any:
        # Capture before the final snapshot swap: that swap independently clears the same bookkeeping.
        seen.append(set(pfb_unbound._regex_warned))
        return compile_user(entries, regex_cap)

    monkeypatch.setattr(pfb_unbound, "_dnsbl_compile_user_regex", compile_after_reset)
    loads = _user_regex_loads(tmp_path, monkeypatch, [f"{KEEP_ROW}#keep"], stale_warnings=stale)
    assert seen == [set(), set()], seen
    assert loads.warned_after_init == set()


def test_init_without_a_manifest_answers_a_user_regex_hit_as_null_blocking(tmp_path: Path, monkeypatch: Any) -> None:
    # issue #3539: with no DNSBL manifest, init keeps the fail-safe builtin_log_flag '0'
    # (Null Blocking, logged), so a built-in regex hit answers 0.0.0.0 instead of VIP.
    loads = _user_regex_loads(tmp_path, monkeypatch, [f"{KEEP_ROW}#keep"], manifest=False, query="keep.example")
    decision = loads.decision_initial
    assert decision.is_found is True, f"expected True, got {decision.is_found!r}"
    assert decision.feed == "keep", f"expected 'keep', got {decision.feed!r}"
    assert decision.log_type == "0", f"expected '0', got {decision.log_type!r}"
    assert decision.null_blocking is True, f"expected True, got {decision.null_blocking!r}"
