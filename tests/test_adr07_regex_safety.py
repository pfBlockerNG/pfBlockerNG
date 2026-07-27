"""ADR-07 Phase 7 -- regex safety: always-on catastrophic-shape gate + opt-in length
cap + always-on runtime warn/evict.

`re` does not release the GIL during a match and a Python thread cannot be killed
(ADR.md fact 2), so a query-time timeout CANNOT interrupt a catastrophic match. The
accepted design is a bounded residual: a pathological pattern's FIRST match may block
one query, but it is then EVICTED so it cannot hang again. The LOAD-time gate is split
into two DECOUPLED concerns, both stdlib + in-process, applied to FEED *and* user regex:

  (1a) always-on catastrophic-SHAPE gate -- a structurally pathological pattern (nested /
       adjacent / overlapping unbounded quantifier, stacked bounded repeat, or over the
       complexity budget) is dropped at LOAD UNCONDITIONALLY -- independent of any
       setting -- because such a shape drives catastrophic backtracking in `re`. Pure
       static string analysis, NO execution of the candidate;
  (1b) opt-in LENGTH ceiling -- a long-but-safe pattern is dropped at LOAD only when the
       "Limit long/complex regex" setting is enabled; length alone is a tunable
       convenience cap, NOT a safety gate, so it stays behind the flag;
  (2) always-on RUNTIME timing -- over a warn ceiling log, over a higher evict ceiling
      log + remove the pattern from the live regexDB/allowRegexDB (snapshot-iterate,
      evict-after-loop -- never mutate mid-iteration; dict.pop is atomic under the GIL).

These tests are pure (no live Unbound). The runtime tests drive a deterministic clock
by monkeypatching ``time.thread_time`` so a "slow" match is simulated without running a
genuinely catastrophic pattern (which could hang the suite -- exactly the residual the
design accepts but the tests must not pay).
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import pfb_unbound
from pfb_unbound import (
    DNSBL_KIND_BLOCK,
    PRIO_FEED_ALLOW,
    PRIO_FEED_BLOCK,
    RegexRule,
    _dnsbl_compile_regex_rules,
    _regex_is_catastrophic_shape,
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
        "tld_allow": False,
        "tld_allow_list": [],
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


def _long_benign_pattern() -> str:
    """A pattern over the length ceiling but STRUCTURALLY safe: a long concatenation of
    literal labels with a single optional group -- no nested/overlapping quantifier, no
    stacked repeat, and a complexity budget well under the threshold. Used to prove the
    LENGTH ceiling is decoupled from (and gated independently of) the shape gate."""
    pat = r"^(sub)?" + "verylongsubdomainlabel" * 10 + r"\.example\.com$"
    assert len(pat) > pfb_unbound.REGEX_STATIC_LEN_CAP
    return pat


def _install_clock(monkeypatch: Any, elapsed_ms_per_match: list[float]) -> None:
    """Make every match report a fixed elapsed time (ms). Forces the thread_time path
    so the warn/evict policy is deterministic (no perf-fallback 2-strike interplay)."""
    ticks: list[float] = []
    for ms in elapsed_ms_per_match:
        ticks.extend([0.0, ms / 1000.0])
    monkeypatch.setattr(pfb_unbound, "_REGEX_HAVE_THREAD_TIME", True)
    monkeypatch.setattr(pfb_unbound.time, "thread_time", _FakeClock(ticks))


# --------------------------------------------------------------------------- #
# (1a) CATASTROPHIC-SHAPE gate -- pure, ALWAYS-ON (length-independent)
# --------------------------------------------------------------------------- #
class TestCatastrophicShapeHeuristic:
    """``_regex_is_catastrophic_shape`` is the always-on SAFETY half: it flags the
    structurally dangerous shapes and is independent of pattern LENGTH."""

    def test_single_group_nested_quantifier_flagged(self) -> None:
        for pat in (r"(a+)+$", r"(a*)*", r"(\w+\.)+\w+$", r"([a-z]+)*\.example$", r"(.*a){20}$"):
            assert _regex_is_catastrophic_shape(pat) is True, pat

    def test_single_group_alternation_overlap_flagged(self) -> None:
        # A quantified group whose body contains `|` backtracks catastrophically yet
        # has no INNER quantifier, so the nested-quantifier heuristic alone misses it.
        for pat in (r"^(a|a)+$", r"(a|ab)*", r"(foo|foobar)+", r"(x|y|x){10}"):
            assert _regex_is_catastrophic_shape(pat) is True, pat

    def test_multi_group_adjacent_quantifier_flagged(self) -> None:
        # The dangerous shape the single-group heuristics MISS: two back-to-back groups
        # where the second is quantified -- the first group's unbounded body and the
        # quantified sibling share input, an exponential partition of the matched span.
        for pat in (r"(a+)(a+)+", r"(a+)(b+)*", r"(\w+)(\d+)+$", r"^(x+)(y+)*\.example$"):
            assert _regex_is_catastrophic_shape(pat) is True, pat

    def test_stacked_bounded_repeat_flagged(self) -> None:
        # Two consecutive {m}/{m,n} repeats multiply -> a tiny source string explodes.
        for pat in (r"a{500}{500}", r"(x){500}{500}", r"[a-z]{50}{50}", r"\w{20}{20}$"):
            assert _regex_is_catastrophic_shape(pat) is True, pat

    def test_complexity_budget_backstop_flagged(self) -> None:
        # A pattern with no single matching structural template but a large combined
        # count of unbounded quantifiers + alternations is caught by the budget backstop.
        over_budget = "".join(f"a{i}*|" for i in range(pfb_unbound._REGEX_BUDGET_MAX + 2))
        assert _regex_is_catastrophic_shape(over_budget) is True

    def test_complexity_budget_at_threshold_not_flagged(self) -> None:
        # The budget comparison is strictly `>` _REGEX_BUDGET_MAX, so a pattern whose budget
        # equals MAX exactly is the last admissible value (off-by-one guard: a `>=` regression
        # would flag this). Build a pattern whose budget is EXACTLY MAX -- `_REGEX_BUDGET_MAX`
        # unbounded `*` quantifiers, zero alternations, and no other catastrophic shape (no
        # nested/adjacent quantified group, no stacked bounded repeat).
        at_budget = "a*" * pfb_unbound._REGEX_BUDGET_MAX
        # Compute the budget the SAME way the code does and pin it to MAX before asserting.
        budget = len(pfb_unbound._REGEX_UNBOUNDED_QUANTIFIER.findall(at_budget)) + len(
            pfb_unbound._REGEX_ALTERNATION.findall(at_budget)
        )
        assert budget == pfb_unbound._REGEX_BUDGET_MAX
        assert _regex_is_catastrophic_shape(at_budget) is False

    # --- false-positive guard: realistic benign feed regex must NOT be flagged ----- #
    def test_benign_feed_patterns_not_flagged(self) -> None:
        for pat in (
            r"ads\.",
            r"ad[0-9]\.example\.com$",
            r"^x[0-9]+\.example\.com$",
            r"\.doubleclick\.net$",
            r"^(.+\.)?doubleclick\.net$",
            r"^(www\.)?ad-?serv(er|ice)\.example$",
            r"^(foo|bar)\.example$",
            r"^(.+\.)?ads?[0-9]*\.example\.(com|net|org)$",
        ):
            assert _regex_is_catastrophic_shape(pat) is False, pat

    def test_shape_gate_independent_of_length(self) -> None:
        # A long-but-structurally-safe pattern is NOT a catastrophic shape: the shape
        # gate must ignore length entirely (length is the separate opt-in ceiling).
        assert _regex_is_catastrophic_shape(_long_benign_pattern()) is False
        # And a SHORT catastrophic shape IS flagged regardless of being well under length.
        assert _regex_is_catastrophic_shape(r"(a+)+") is True


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
    def test_shape_gate_drops_catastrophic_even_with_cap_off(self) -> None:
        # DECOUPLING (the key change): a catastrophic SHAPE is dropped at load even when
        # the opt-in length cap is OFF -- the safety gate is unconditional. The benign
        # sibling is admitted, proving it is the SHAPE, not a blanket drop.
        rules = [_block_rule(r"(a+)+$"), _block_rule(r"^safe\.example$")]
        db, admitted = _dnsbl_compile_regex_rules(rules, static_cap=False)
        assert admitted == 1
        assert len(db) == 1
        compiled = next(iter(db.values()))["re"]
        assert compiled.search("safe.example")

    def test_shape_gate_drops_multi_group_and_stacked_repeat_cap_off(self) -> None:
        # The newly-broadened shapes (missed by the old single-group heuristics) are also
        # dropped with the cap OFF: multi-group adjacent quantifier + stacked repeat.
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
        # length cap (not the shape gate) is what the flag toggles, so use a long-but-
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


def test_save_time_probe_length_cap_matches_runtime_constant() -> None:
    """Issue #1688 parity: pfblockerng_extra.inc's embedded save-time probe rejects a
    pattern the SAME length that this module's REGEX_STATIC_LEN_CAP drops at load, so
    the save-time verdict cannot silently drift from the resolver's."""
    inc_path = Path(__file__).resolve().parent.parent / "src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc"
    source = inc_path.read_text()
    match = re.search(r"len\(pattern\)\s*>\s*(\d+):\s*#\s*REGEX_STATIC_LEN_CAP", source)
    assert match is not None, (
        "expected the PHP probe's length-cap comparison, tagged '# REGEX_STATIC_LEN_CAP', in pfblockerng_extra.inc"
    )
    php_cap = int(match.group(1))
    runtime_cap = pfb_unbound.REGEX_STATIC_LEN_CAP
    assert php_cap == runtime_cap, f"probe cap={php_cap} != pfb_unbound.REGEX_STATIC_LEN_CAP={runtime_cap}"


# --------------------------------------------------------------------------- #
# Issue #1711: extend #1688 parity pinning to EVERY rule the save-time probe
# duplicates from the resolver -- the four shape literals, the two budget
# literals, the budget threshold, the length-cap comparator strictness, and the
# runtime's exact-boundary admission behaviour.
# --------------------------------------------------------------------------- #
def _probe_source() -> str:
    """Extract pfblockerng_extra.inc's embedded save-time probe nowdoc verbatim (the
    text between <<<'PYTHON' and the closing PYTHON; delimiter) so probe/runtime parity
    is pinned against the actual nowdoc bytes. Anchored past the function name because a
    second, unrelated nowdoc probe exists later in the file."""
    inc_path = Path(__file__).resolve().parent.parent / "src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc"
    source = inc_path.read_text()
    anchor = source.index("function pfb_dnsbl_regex_validation_errors")
    match = re.search(r"<<<'PYTHON'\n(.*?)\nPYTHON;", source[anchor:], re.S)
    assert match is not None, "expected the probe's <<<'PYTHON' nowdoc after pfb_dnsbl_regex_validation_errors"
    return match.group(1)


_PROBE_SINGLE_TAG_RE = re.compile(r'r"((?:[^"\\]|\\.)*)"\s*\)?,?\s*#\s*(_REGEX_\w+) mirror \(pfb_unbound\.py\)')
_PROBE_COMBINED_TAG_RE = re.compile(r"#\s*(_REGEX_\w+)\s*\+\s*(_REGEX_\w+) mirror \(pfb_unbound\.py\)")


def _runtime_admission_regex_names() -> set[str]:
    """Issue #1711 completeness pin: the set of module-level `_REGEX_*` compiled
    patterns actually used as admission checks inside `_regex_is_catastrophic_shape`
    -- the shape patterns invoked via `.search(` plus the budget patterns invoked via
    `.findall(` in that same function's complexity-budget backstop.

    Extracted from the FUNCTION BODY TEXT (anchored on the `def` line, not a
    hardcoded name list and not a line-number offset) so this stays robust to
    unrelated edits elsewhere in the file: a NEW `_REGEX_*` pattern wired into the
    guard via `.search(`/`.findall(` is picked up automatically, and the parity
    test below then requires the probe to tag-mirror it too -- a 7th runtime shape
    added without a matching probe tag makes this set diverge from the probe's
    tagged literals and fails loudly instead of the previous hardcoded six staying
    silently in sync with nothing."""
    unbound_path = Path(__file__).resolve().parent.parent / "src/usr/local/pkg/pfblockerng/pfb_unbound.py"
    source = unbound_path.read_text()
    start = source.index("def _regex_is_catastrophic_shape")
    next_def = re.search(r"\ndef ", source[start + 1 :])
    body = source[start : start + 1 + next_def.start()] if next_def else source[start:]
    names = set(re.findall(r"(_REGEX_\w+)\.(?:search|findall)\(", body))
    assert names, "expected at least one _REGEX_*.search(/.findall( admission check in _regex_is_catastrophic_shape"
    return names


def test_probe_regex_literals_match_runtime_shape_and_budget_patterns() -> None:
    """Issue #1711: every regex LITERAL the save-time probe duplicates from the
    resolver's shape gate + complexity budget is tagged '<name> mirror (pfb_unbound.py)'
    in the probe source. Extract each tagged literal and assert it is byte-identical to
    the runtime pattern of the same name -- and that the tagged set is EXACTLY the set
    of `_REGEX_*` patterns `_regex_is_catastrophic_shape` actually consults (extracted
    from source, not hardcoded -- see `_runtime_admission_regex_names()`), so a
    renamed/added/removed runtime pattern that forgets to update the probe tag fails
    loudly instead of silently drifting."""
    probe = _probe_source()

    literals: dict[str, str] = {}
    for match in _PROBE_SINGLE_TAG_RE.finditer(probe):
        literals[match.group(2)] = match.group(1)

    combined = _PROBE_COMBINED_TAG_RE.search(probe)
    assert combined is not None, "expected the combined budget-literal tag comment in the probe"
    combined_line = next(line for line in probe.splitlines() if combined.group(0) in line)
    raw_literals = re.findall(r'r"((?:[^"\\]|\\.)*)"', combined_line)
    assert len(raw_literals) == 2, (
        f"expected exactly 2 raw-string literals on the combined-tag line, got {raw_literals}"
    )
    literals[combined.group(1)] = raw_literals[0]
    literals[combined.group(2)] = raw_literals[1]

    expected_names = _runtime_admission_regex_names()
    assert set(literals) == expected_names, (
        f"probe mirror tags drifted: extracted={sorted(literals)} expected={sorted(expected_names)}"
    )

    for name, raw in literals.items():
        pattern = ast.literal_eval(f'r"{raw}"')
        runtime_pattern = getattr(pfb_unbound, name).pattern
        assert pattern == runtime_pattern, f"{name}: probe={pattern!r} != runtime={runtime_pattern!r}"


def test_probe_budget_threshold_matches_runtime_budget_max() -> None:
    """Issue #1711: the probe's complexity-budget threshold (tagged '_REGEX_BUDGET_MAX
    mirror') must match pfb_unbound._REGEX_BUDGET_MAX, and the comparison on both sides
    must be a STRICT '>' -- a '>=' regression would silently shift the admissible budget
    down by one."""
    probe = _probe_source()
    match = re.search(r"if budget > (\d+):\s*#\s*_REGEX_BUDGET_MAX mirror \(pfb_unbound\.py\)", probe)
    assert match is not None, "expected the probe's tagged budget threshold comparison"
    probe_budget_max = int(match.group(1))
    assert probe_budget_max == pfb_unbound._REGEX_BUDGET_MAX, (
        f"probe budget max={probe_budget_max} != pfb_unbound._REGEX_BUDGET_MAX={pfb_unbound._REGEX_BUDGET_MAX}"
    )
    assert "budget >=" not in probe, "probe budget threshold regressed from strict '>' to '>='"


def test_runtime_length_cap_comparator_is_strict_at_every_site() -> None:
    """Issue #1711: pin the runtime's exact-200-character admission boundary. All three
    REGEX_STATIC_LEN_CAP comparisons in pfb_unbound.py (the build-time compile helper
    plus the two save-time www/ probes) use a STRICT '>' -- a '>=' regression at any site
    would silently drop a pattern exactly at the cap, which the resolver, this probe, and
    the PHP DnsblRegexEntryErrorTest suite all admit."""
    unbound_path = Path(__file__).resolve().parent.parent / "src/usr/local/pkg/pfblockerng/pfb_unbound.py"
    source = unbound_path.read_text()
    strict = re.findall(r"len\([^)\n]*\)\s*>\s*REGEX_STATIC_LEN_CAP", source)
    assert len(strict) == 3, f"expected exactly 3 strict '>' comparisons, found {len(strict)}: {strict}"
    non_strict = re.findall(r"len\([^)\n]*\)\s*>=\s*REGEX_STATIC_LEN_CAP", source)
    assert non_strict == [], f"found a non-strict '>=' REGEX_STATIC_LEN_CAP comparison: {non_strict}"


def _anchored_pattern(length: int) -> str:
    """Mirror of DnsblRegexEntryErrorTest::anchoredPattern (tests/php/DnsblRegexEntryErrorTest.php):
    an anchored, structurally benign pattern (no quantifier, no alternation, no stacked
    repeat) of EXACTLY the requested length, so only the length cap -- never the shape
    gate or the complexity budget -- can be the reason it is admitted or dropped."""
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
# Real catastrophic pattern dropped UNCONDITIONALLY (end-to-end, BOUNDED so it
# can't hang -- the pattern is never executed against any input)
# --------------------------------------------------------------------------- #
class TestRealCatastrophicCapped:
    def test_shape_gate_drops_real_redos_pattern_cap_off(self) -> None:
        # The shape gate catches the genuinely catastrophic shape WITHOUT executing it,
        # and does so with the length cap OFF (the always-on safety gate).
        rule = _block_rule(r"([a-z]+)*\.example$")
        db, admitted = _dnsbl_compile_regex_rules([rule], static_cap=False)
        assert admitted == 0
        assert db == {}

    def test_shape_gate_drops_alternation_overlap_cap_off(self) -> None:
        # ^(a|a)+$ PASSES a naive length cap but backtracks catastrophically; the shape
        # gate drops it at load WITHOUT executing it -- regardless of the length cap.
        rule = _block_rule(r"^(a|a)+$")
        for cap in (False, True):
            db, admitted = _dnsbl_compile_regex_rules([rule], static_cap=cap)
            assert admitted == 0, cap
            assert db == {}, cap
