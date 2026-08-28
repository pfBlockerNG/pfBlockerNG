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

import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import pfb_dnsbl_regex_rules
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

    def test_ungrouped_adjacent_quantifier_run_flagged(self) -> None:
        # issue #2035: a run of back-to-back atoms that each carry an unbounded quantifier
        # and whose character sets OVERLAP partitions the matched span the same way the
        # grouped shapes do -- every atom can cede characters to its neighbour. The four
        # group-keyed shapes above all miss it (no parentheses anywhere) and four
        # quantifiers sit well under the complexity budget. Measured at the maximum DNS
        # name length (253 characters, the longest input the matcher can ever be handed):
        # three adjacent `[a-z]+` cost 7 ms per query and four cost 462 ms.
        for pat in (
            r"^[a-z]+[a-z]+[a-z]+[a-z]+@example\.com$",  # the issue's console reproduction
            r"^[a-z]+[a-z]+[a-z]+\.example\.com$",
            r"\w+\w+\w+",
            r".*.*.*",
            r"[a-z]+[a-z0-9]+[0-9a-z]+",  # overlap does not require identical atoms
            r"^a{2,}a{2,}a{2,}$",  # `{m,}` is unbounded too
            r"^[a-z]+?[a-z]+?[a-z]+?$",  # lazy quantifiers backtrack just as hard
        ):
            assert _regex_is_catastrophic_shape(pat) is True, pat

    def test_adjacent_quantifier_run_overlap_is_case_insensitive(self) -> None:
        # The DNSBL matcher compiles every admitted regex with re.IGNORECASE, so
        # atom-overlap analysis must judge overlap under the same semantics: any
        # letter matches BOTH [A-Z] and [a-z] once case-folded, so this run is
        # exactly as catastrophic as the same-case run above.
        for pat in (
            r"^[A-Z]+[a-z]+[A-Z]+@example\.com$",
            r"^[a-z]+[A-Z]+[a-z]+@example\.com$",
        ):
            assert _regex_is_catastrophic_shape(pat) is True, pat

    def test_grouped_adjacent_quantifier_run_flagged(self) -> None:
        # The SAME shape wearing parentheses. Plain `(...)`/`(?:...)` groups do not change
        # what the engine backtracks over, so `([a-z]+)([a-z]+)([a-z]+)` is the ungrouped
        # run above -- and it is the more expensive form, measured at 1277 ms per query for
        # four groups against a 253-character name (vs 462 ms ungrouped). No group-keyed
        # shape above catches it: none of these carries a quantifier ON a group.
        for pat in (
            r"^([a-z]+)([a-z]+)([a-z]+)([a-z]+)@example\.com$",
            r"^([a-z]+)([a-z]+)([a-z]+)\.example\.com$",
            r"^(?:\w+)(?:\w+)(?:\w+)\.example$",
            r"^[a-z]+(\w+)[a-z]+\.example$",  # grouped and ungrouped atoms in one run
        ):
            assert _regex_is_catastrophic_shape(pat) is True, pat

    def test_zero_width_construct_does_not_split_a_run(self) -> None:
        # A comment or a lookaround consumes NOTHING, so dropping one into the middle of a
        # run leaves the engine backtracking over exactly the same span -- each row below
        # is the issue's own reproduction plus one inert construct, and each still costs
        # ~460 ms per query. Treating these as a run boundary would make the whole rule a
        # one-token bypass.
        for pat in (
            r"^[a-z]+[a-z]+(?#c)[a-z]+[a-z]+@example\.com$",
            r"^[a-z]+[a-z]+(?=a)[a-z]+[a-z]+@example\.com$",
            r"^[a-z]+[a-z]+(?!b)[a-z]+[a-z]+@example\.com$",
            r"^[a-z]+[a-z]+(?<=a)[a-z]+[a-z]+@example\.com$",
            r"^[a-z]+[a-z]+(?<!b)[a-z]+[a-z]+@example\.com$",
        ):
            assert _regex_is_catastrophic_shape(pat) is True, pat

    def test_quantified_single_atom_group_counts_as_its_atom(self) -> None:
        # `(?:[a-z])+` IS `[a-z]+` -- the group wraps one atom and the quantifier sits
        # outside it. Measured at 475 ms per query for the four-group row, so a run spelled
        # this way is the same defect, not a different one.
        for pat in (
            r"^(?:[a-z])+(?:[a-z])+(?:[a-z])+(?:[a-z])+@example\.com$",
            r"^([a-z])+([a-z])+([a-z])+@example\.com$",
            r"^(?P<a>\w)+(?P<b>\w)+(?P<c>\w)+@example\.com$",
            # A group body wider than one atom repeats the same way: measured 238 ms per
            # query for the four-group row against a matching 253-character name.
            r"^(ab)+(ab)+(ab)+@example\.com$",
            r"^(?:ab)+(?:ab)+(?:ab)+(?:ab)+@example\.com$",
        ):
            assert _regex_is_catastrophic_shape(pat) is True, pat

    def test_group_body_is_scanned_for_a_run_of_its_own(self) -> None:
        # Wrapping a run in a group hides it from nothing: the engine still backtracks over
        # the body (measured 24.8 ms at 81 characters for the first row, doubling every ten
        # further characters). Whatever a group does to its NEIGHBOURS, its body is scanned.
        for pat in (
            r"^([a-z]+[a-z]+[a-z]+[a-z]+)?@example\.com$",
            r"^([a-z]+(x)?[a-z]+[a-z]+[a-z]+)+@example\.com$",
            r"^(?:[a-z]+[a-z]+[a-z]+){0,3}@example\.com$",
            r"^[a-z]+([a-z]+)?[a-z]+[a-z]+@example\.com$",
        ):
            assert _regex_is_catastrophic_shape(pat) is True, pat
        # An optional group of literals is still just a literal prefix.
        assert _regex_is_catastrophic_shape(r"^(www\.)?ads?\.example\.com$") is False

    def test_lookaround_body_is_scanned_for_a_run_of_its_own(self) -> None:
        # A lookaround consumes nothing, so it bridges the run around it -- but the engine
        # still backtracks over what is INSIDE it (measured 18.5 ms at 110 characters), so
        # its body is scanned on its own terms rather than skipped with the construct.
        for pat in (
            r"^(?=([a-z]+[a-z]+[a-z]+[a-z]+x))\@example\.com$",
            r"^(?!(\w+\w+\w+y))[a-z]+\.example$",
            r"^(?<=([a-z]+[a-z]+[a-z]+))x$",
        ):
            assert _regex_is_catastrophic_shape(pat) is True, pat
        # A lookahead body is NOT adjacent to what follows it -- it matches no characters --
        # so its atoms never join the outer run.
        assert _regex_is_catastrophic_shape(r"^(?=.*ad)[a-z]+[a-z]+\.example$") is False
        assert _regex_is_catastrophic_shape(r"^(?=[a-z]+)[a-z]+[a-z]+\.example$") is False
        # A COMMENT is inert text rather than a pattern, so what looks like a run inside one
        # is not a run at all and must not be read as one.
        assert _regex_is_catastrophic_shape(r"^(?#[a-z]+[a-z]+[a-z]+)x$") is False

    def test_nested_lookaround_scan_stops_at_its_depth_bound(self) -> None:
        # The recursion into lookaround bodies is bounded so a hostile line cannot exhaust
        # the stack. Pin the ceiling from BOTH sides: a run at the deepest scanned nesting is
        # still found, and one nested a level deeper is deliberately not looked for -- which
        # is the documented cost of the bound, not an accident.
        run = "[a-z]+[a-z]+[a-z]+"
        at_bound = "(?=" * pfb_dnsbl_regex_rules._REGEX_NESTED_SCAN_MAX + run
        past_bound = "(?=" * (pfb_dnsbl_regex_rules._REGEX_NESTED_SCAN_MAX + 1) + run
        assert _regex_is_catastrophic_shape(at_bound + ")" * pfb_dnsbl_regex_rules._REGEX_NESTED_SCAN_MAX) is True
        assert (
            _regex_is_catastrophic_shape(past_bound + ")" * (pfb_dnsbl_regex_rules._REGEX_NESTED_SCAN_MAX + 1)) is False
        )
        # Nesting far past the bound is answered rather than crashing the load path.
        assert _regex_is_catastrophic_shape("(?=" * 5000 + "a" + ")" * 5000) is False

    def test_quantified_group_run_over_distinct_bodies_not_flagged(self) -> None:
        # Two quantified groups only partition the span when they can consume the same
        # input; `(ab)+(cd)+` has exactly one way to split, so it stays admitted.
        assert _regex_is_catastrophic_shape(r"^(ab)+(cd)+(ef)+@example\.com$") is False

    def test_optional_atom_does_not_split_a_run(self) -> None:
        # An atom that may match nothing cannot separate its neighbours: when it matches
        # empty the runs on either side are one run, and the engine explores that partition
        # too (measured 7.8 ms per query, over the warn ceiling and under the evict one).
        assert _regex_is_catastrophic_shape(r"^[a-z]+[a-z]+x?[a-z]+@example\.com$") is True
        assert _regex_is_catastrophic_shape(r"^[a-z]+[a-z]+(?P<g>x?)[a-z]+[a-z]+@example\.com$") is True
        # …but an optional atom only BRIDGES a run, it never starts or extends one: the
        # canonical `ads?` shape keeps its two quantifiers in runs of one.
        assert _regex_is_catastrophic_shape(r"^ads?[0-9]*\.example\.(com|net)$") is False

    def test_adjacent_quantifiers_over_disjoint_atoms_not_flagged(self) -> None:
        # Adjacency alone is NOT the danger: when neighbouring atoms cannot match the same
        # character there is exactly ONE way to split the input, so the engine never
        # backtracks (measured 0.00 ms at 253 characters for the four-atom row below).
        # Rejecting these would silently drop legitimate feed entries.
        for pat in (
            r"^cdn[a-z]+[0-9]*\.example\.com$",
            r"^[a-z]+[0-9]+[a-z]+[0-9]+@example\.com$",
            r"^\w+\.\w+$",
            r"^.+@.+$",  # '@' floats through '.' spans but leaves no adjacent pair
        ):
            assert _regex_is_catastrophic_shape(pat) is False, pat

    def test_two_adjacent_overlapping_quantifiers_not_flagged(self) -> None:
        # The rule flags runs LONGER than _REGEX_ADJACENT_ATOM_MAX (2), because a pair
        # splits the input linearly: measured 0.08 ms at the 253-character maximum, three
        # orders of magnitude under the 100 ms eviction ceiling and under the 10 ms warn
        # ceiling. A pair is the shape realistic host patterns actually use, so flagging it
        # would cost false positives to buy no measurable safety.
        for pat in (
            r"^[a-z]+[a-z0-9-]*\.doubleclick\.net$",
            r"^\w+\w+$",
        ):
            assert _regex_is_catastrophic_shape(pat) is False, pat

    def test_non_backtracking_adjacent_quantifiers_not_flagged(self) -> None:
        # A possessive quantifier (`a++`) never gives characters back, and a FIXED repeat
        # (`a{3}`) has nothing to give -- neither can partition the span, so neither starts
        # or continues a run.
        # The middle row is the discriminating one: its first two atoms already form a run,
        # so it stays admitted ONLY because the possessive third atom never joins it as a
        # third quantifier (it bridges the chain like any mandatory overlapping atom).
        for pat in (r"^[a-z]++[a-z]++[a-z]++$", r"^[a-z]+[a-z]+[a-z]++$", r"^[a-z]{3}[a-z]{3}[a-z]{3}$"):
            assert _regex_is_catastrophic_shape(pat) is False, pat

    def test_overlapping_mandatory_separator_does_not_split_a_run(self) -> None:
        # issue #2082: a mandatory atom whose character set overlaps its neighbours is no
        # boundary -- its position floats inside the span, so the quantifiers on both sides
        # keep multiplying through it. Measured with the runtime's IGNORECASE compile against
        # failing 253-character inputs (CI image; the rejected three-quantifier run costs
        # 24.9 ms in the same environment): 1533 ms for the issue's reproduction (first row),
        # 24 ms for the pair+separator+quantifier rows, 1465 ms for the fixed-repeat
        # separator, 490 ms for the multi-character literal, 75 s for the double-separator row.
        for pat in (
            r"^[a-z]+[a-z]+a[a-z]+[a-z]+@x\.com$",  # the issue's console reproduction
            r"^([a-z]+)([a-z]+)a([a-z]+)([a-z]+)@x\.com$",  # the same run wearing groups
            r"^[a-z]+[a-z]+a[a-z]+@x\.com$",
            r"^[a-z]+a[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+a{3}[a-z]+[a-z]+@x\.com$",  # a fixed repeat floats the same way
            r"^[a-z]+[a-z]+abc[a-z]+[a-z]+@x\.com$",  # multi-character literal separator
            r"^[a-z]+[a-z]+a[a-z]+a[a-z]+[a-z]+@x\.com$",
            r"^\w+\w+x\w+\w+$",
        ):
            assert _regex_is_catastrophic_shape(pat) is True, pat

    def test_separator_overlap_is_judged_case_insensitively(self) -> None:
        # The matcher compiles admitted patterns with re.IGNORECASE, so 'A' floats through
        # [a-z] spans exactly like 'a' does (measured 1520 ms per query at 253 characters).
        assert _regex_is_catastrophic_shape(r"^[A-Z]+[a-z]+A[a-z]+[A-Z]+@x\.com$") is True

    def test_single_quantifier_gaps_between_overlapping_separators_stay_admitted(self) -> None:
        # The issue's design constraint: with ONE quantifier per gap the floating separator
        # has no adjacent pair to multiply -- 5.8 ms worst case at 253 characters against an
        # adversarial separator-rich input, under the 10 ms warn ceiling. Run length through
        # bridged separators alone is NOT the discriminator; rejecting these would drop
        # benign feed shapes.
        for pat in (
            r"^[a-z]+x[a-z]+y[a-z]+@x\.com$",  # the issue's measured benign row
            r"^[a-z]+a[a-z]+$",
            r"^[a-z]+[a-z]+a$",  # trailing separator: no quantifier after the float
        ):
            assert _regex_is_catastrophic_shape(pat) is False, pat

    def test_conditional_group_separator_is_the_same_defect(self) -> None:
        # issue #2082's second spelling: `(?(1)a|b)` between the pairs is the bare `a`
        # separator wearing a conditional (measured 1492 ms per query at 253 characters,
        # CI image; the QUANTIFIED spelling below costs 79 s).
        for pat in (
            r"^([a-z])[a-z]+[a-z]+(?(1)a|b)[a-z]+[a-z]+@x\.com$",
            r"^([a-z])[a-z]+[a-z]+(?(1)a|b)+[a-z]+[a-z]+@x\.com$",
        ):
            assert _regex_is_catastrophic_shape(pat) is True, pat
        # A conditional whose EVERY alternative is disjoint from the run really does pin
        # the split, exactly like a bare disjoint literal.
        assert _regex_is_catastrophic_shape(r"^([0-9])[a-z]+[a-z]+(?(1)\.|,)[a-z]+[a-z]+@x\.com$") is False

    def test_scoped_flags_and_atomic_group_separator_spellings(self) -> None:
        # `(?i:a)` and `(?>a)` between the pairs are still the floating `a` separator:
        # scoped flags do not change what the engine backtracks over, and an atomic group's
        # POSITION floats with the run even though its body never gives characters back
        # (measured 1512 ms and 1558 ms per query at 253 characters, CI image).
        for pat in (
            r"^[a-z]+[a-z]+(?i:a)[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(?>a)[a-z]+[a-z]+@x\.com$",
        ):
            assert _regex_is_catastrophic_shape(pat) is True, pat

    def test_grouped_mandatory_separator_spellings(self) -> None:
        # The bare separator's grouped spellings float identically (issue #2082).
        # Measured per query at 253 characters (CI image): 1529 / 1539 / 721 / 786 ms.
        for pat in (
            r"^[a-z]+[a-z]+(a){3}[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(?:a){3}[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(ab){3}[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(a)++[a-z]+[a-z]+@x\.com$",
        ):
            assert _regex_is_catastrophic_shape(pat) is True, pat
        # A grouped DISJOINT separator still pins the split, exactly like the bare form.
        assert _regex_is_catastrophic_shape(r"^[a-z]+[a-z]+(\.){3}[a-z]+[a-z]+$") is False

    def test_alternation_group_separator_is_the_same_defect(self) -> None:
        # `(a|b)` between the pairs is the conditional separator without the condition --
        # its body compiles standalone, so the overlap probe judges it directly. Measured
        # 1719 / 1747 ms per query at 253 characters (CI image).
        for pat in (
            r"^[a-z]+[a-z]+(a|b)[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(?:a|b)[a-z]+[a-z]+@x\.com$",
        ):
            assert _regex_is_catastrophic_shape(pat) is True, pat
        # Disjoint alternatives really pin the split.
        assert _regex_is_catastrophic_shape(r"^([0-9])[a-z]+[a-z]+(\.|,)[a-z]+[a-z]+$") is False

    def test_alternation_separator_with_a_parenthesised_branch(self) -> None:
        # A parenthesised branch must stay on the alternation-separator path: entering the
        # group would read its bare `|` as a boundary and reset the chain.
        # Measured 1478 / 1463 / 1451 ms per query at 253 characters (CI image).
        for pat in (
            r"^[a-z]+[a-z]+(a|(b))[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(?:a|(b))[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+((a)|b){3}[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(a|(b))+[a-z]+[a-z]+@x\.com$",
        ):
            assert _regex_is_catastrophic_shape(pat) is True, pat
        # A quantifier-carrying body stays on the entered scan, so a run inside a branch
        # is still found -- the overlap-probe shortcut must never hide it.
        assert _regex_is_catastrophic_shape(r"^([a-z]+[a-z]+[a-z]+|x)@x\.com$") is True
        # A `|` that only sits inside a NESTED group does not make the outer body an
        # alternation: `(x(a|b)y)` must take the entered scan (where every atom bridges
        # the chain), not the overlap probe (whose single-character match would read the
        # multi-atom body as disjoint and reset the chain).
        assert _regex_is_catastrophic_shape(r"^[a-z]+[a-z]+(x(a|b)y)[a-z]+[a-z]+@x\.com$") is True
        # Disjoint parenthesised alternatives still pin the split.
        assert _regex_is_catastrophic_shape(r"^[a-z]+[a-z]+(\.|(,))[a-z]+[a-z]+$") is False

    def test_backreference_separator_bridges_the_chain(self) -> None:
        # A backreference's character set is unknowable statically, so the gate must not
        # read it as a boundary: measured 1564 ms (`\1`) and 2018 ms (`(?P=g)`) per query
        # at 253 characters (CI image). Conservative bridge: the chain survives it.
        for pat in (
            r"^([a-z])[a-z]+[a-z]+\1[a-z]+[a-z]+@x\.com$",
            r"^(?P<g>[a-z])[a-z]+[a-z]+(?P=g)[a-z]+[a-z]+@x\.com$",
        ):
            assert _regex_is_catastrophic_shape(pat) is True, pat

    def test_long_chain_without_a_pair_is_rejected(self) -> None:
        # Pair-adjacency alone under-covers. Four quantifiers connected
        # only by floating separators cost 1753 ms per query at 253 characters (CI image);
        # three cost 23 ms -- under the evict ceiling and the accepted warn-layer residual,
        # and rejecting three would drop the issue's admitted single-gap shapes.
        assert _regex_is_catastrophic_shape(r"^[a-z]+a[a-z]+a[a-z]+a[a-z]+@x\.com$") is True
        assert _regex_is_catastrophic_shape(r"^[a-z]+a[a-z]+a[a-z]+@x\.com$") is False

    def test_atomic_group_body_is_not_a_backtracking_run(self) -> None:
        # Atomicity forbids backtracking INSIDE the body -- `^(?>[a-z]+[a-z]+[a-z]+)@...`
        # costs 0.00 ms at 253 characters (CI image), so its body must never be read as a
        # joinable run (the no-false-positive constraint) -- while the atomic group AS a
        # floating separator stays the rejected 1558 ms shape.
        assert _regex_is_catastrophic_shape(r"^(?>[a-z]+[a-z]+[a-z]+)@x\.com$") is False
        assert _regex_is_catastrophic_shape(r"^[a-z]+[a-z]+(?>a)[a-z]+[a-z]+@x\.com$") is True

    def test_scoped_flags_group_body_is_scanned(self) -> None:
        # A `(?i:...)` group is entered like `(?:...)`: skipping it wholesale would hide a
        # run from the scan entirely (measured 1532 ms per query at 253 characters, CI
        # image, for the first row), and a quantified single-atom spelling IS that atom's
        # quantifier.
        assert _regex_is_catastrophic_shape(r"^(?i:[a-z]+[a-z]+[a-z]+[a-z]+)@x\.com$") is True
        assert _regex_is_catastrophic_shape(r"^(?i:[a-z])+(?i:[a-z])+(?i:[a-z])+@x\.com$") is True

    def test_conditional_branches_are_scanned_as_independent_bodies(self) -> None:
        for pat in (
            r"^([a-z])(?(1)[a-z]+[a-z]+[a-z]+[a-z]+|b)@x\.com$",
            r"^(a)?(?(1)b|[a-z]+[a-z]+[a-z]+[a-z]+)@x\.com$",
            r"^(?P<flag>a)?(?(flag)(?i:[a-z]+[a-z]+[a-z]+)|b)$",
            r"^(a)(?(1)(?P<body>[a-z]+[a-z]+[a-z]+)|b)$",
            r"^(a)(?(1)(?=[a-z])[a-z]+[a-z]+[a-z]+|b)$",
            r"^(a)(?(1)\([a-z]+[a-z]+[a-z]+\)|b)$",
            r"^(a)(?(1)[a-z]+[a-z]+(?>ab)[a-z]+[a-z]+|b)$",
        ):
            assert _regex_is_catastrophic_shape(pat) is True, pat
        # Branches are separate patterns: two runs on each side of `|` never join.
        for pat in (
            r"^(?P<flag>a)?(?(flag)b|c)$",
            r"^(a)?(?(1)[a-z]+[a-z]+|[a-z]+[a-z]+)$",
            r"^(a)(?(1)(?>[a-z]+[a-z]+[a-z]+)|b)$",
        ):
            assert _regex_is_catastrophic_shape(pat) is False, pat

    def test_multi_character_opaque_bodies_bridge_only_when_their_language_overlaps(self) -> None:
        for pat in (
            r"^[a-z]+[a-z]+(?>ab)[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(?>ab)+[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(foo|foobar)[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(?:foo|foobar)+[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(?i:foo|foobar)[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(?i:(?>ab))[a-z]+[a-z]+@x\.com$",
            r"^\w+\w+(?>éé)\w+\w+@x\.com$",
        ):
            assert _regex_is_catastrophic_shape(pat) is True, pat
        for pat in (
            r"^[a-z]+[a-z]+(?>12)[a-z]+[a-z]+$",
            r"^[a-z]+[a-z]+(?>a\.)[a-z]+[a-z]+$",
            r"^[a-z]+[a-z]+(\.|,)[a-z]+[a-z]+$",
            r"^[a-z]+[a-z]+(?i:12|34)[a-z]+[a-z]+$",
            r"^[a-z]+[a-z]+(?>\(\[)[a-z]+[a-z]+$",
            r"^[a-z]+[a-z]+(?>\N{BULLET})[a-z]+[a-z]+$",
            r"^(?>ab)[a-z]+$",
        ):
            assert _regex_is_catastrophic_shape(pat) is False, pat

    def test_alternation_shortcut_distinguishes_quantifiers_from_syntax_markers(self) -> None:
        for pat in (
            r"^[a-z]+[a-z]+(a|(?:b))[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(a|(?P<g1>b))[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(a|(?i:b))[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(a|(?>b))[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(a|(?=b)a)[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(a|(?!x)b)[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(a|\+)[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(a|\*)[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(a|\N{BULLET})[a-z]+[a-z]+@x\.com$",
            r"^[a-z]+[a-z]+(a|(?:b))+[a-z]+[a-z]+@x\.com$",
        ):
            assert _regex_is_catastrophic_shape(pat) is True, pat
        # Marker characters that are literals do not manufacture an overlapping atom.
        for pat in (
            r"^[a-z]+[a-z]+(\+|\*)[a-z]+[a-z]+$",
            r"^[a-z]+[a-z]+(?:\N{BULLET}|\*)[a-z]+[a-z]+$",
            r"^(a+|b)$",
        ):
            assert _regex_is_catastrophic_shape(pat) is False, pat
        # A genuine run in a branch is entered and scanned rather than hidden by the shortcut.
        assert _regex_is_catastrophic_shape(r"^([a-z]+[a-z]+[a-z]+|x)@x\.com$") is True

    def test_conditional_branch_scan_stops_at_the_shared_depth_bound(self) -> None:
        run = "[a-z]+[a-z]+[a-z]+"
        prefix = "(?P<flag>a)?"
        at_bound = "(?(flag)" * pfb_dnsbl_regex_rules._REGEX_NESTED_SCAN_MAX + run
        past_bound = "(?(flag)" * (pfb_dnsbl_regex_rules._REGEX_NESTED_SCAN_MAX + 1) + run
        assert (
            _regex_is_catastrophic_shape(prefix + at_bound + "|b)" * pfb_dnsbl_regex_rules._REGEX_NESTED_SCAN_MAX)
            is True
        )
        assert (
            _regex_is_catastrophic_shape(
                prefix + past_bound + "|b)" * (pfb_dnsbl_regex_rules._REGEX_NESTED_SCAN_MAX + 1)
            )
            is False
        )
        flood = prefix + "(?(flag)" * 2000 + "a" + "|b)" * 2000
        assert isinstance(_regex_is_catastrophic_shape(flood), bool)

    def test_issue2364_shapes_are_dropped_by_the_feed_loader_with_both_cap_modes(self) -> None:
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

    def test_newline_repeat_is_not_read_as_a_named_unicode_escape(self) -> None:
        # The two spellings are different regexes and each pins one half of the scanner.
        # Lowercase `\n{2,}` is a newline carrying an open-ended REPEAT; reading it as the
        # named-Unicode escape swallows the quantifier and blinds the gate to the run. This
        # is the spelling the gate meets in production; admission preserves raw pattern
        # syntax (issue #2079), while query normalization stays separate.
        assert _regex_is_catastrophic_shape(r"\n{2,}\n{2,}\n{2,}") is True
        # Capital-N `\N{BULLET}` IS the named escape and is ONE atom, so its quantified run
        # is a run of three too -- green here only if the braces are consumed as part of the
        # atom and `+` is read as its quantifier, the exact opposite parse from the row above.
        assert _regex_is_catastrophic_shape("\\N{BULLET}+\\N{BULLET}+\\N{BULLET}+") is True

    def test_stacked_bounded_repeat_flagged(self) -> None:
        # Two consecutive {m}/{m,n} repeats multiply -> a tiny source string explodes.
        for pat in (r"a{500}{500}", r"(x){500}{500}", r"[a-z]{50}{50}", r"\w{20}{20}$"):
            assert _regex_is_catastrophic_shape(pat) is True, pat

    def test_complexity_budget_backstop_flagged(self) -> None:
        # A pattern with no single matching structural template but a large combined
        # count of unbounded quantifiers + alternations is caught by the budget backstop.
        over_budget = "".join(f"a{i}*|" for i in range(pfb_dnsbl_regex_rules._REGEX_BUDGET_MAX + 2))
        assert _regex_is_catastrophic_shape(over_budget) is True

    def test_complexity_budget_at_threshold_not_flagged(self) -> None:
        # The budget comparison is strictly `>` _REGEX_BUDGET_MAX, so a pattern whose budget
        # equals MAX exactly is the last admissible value (off-by-one guard: a `>=` regression
        # would flag this). Build a pattern whose budget is EXACTLY MAX -- `_REGEX_BUDGET_MAX`
        # unbounded `*` quantifiers, zero alternations, and no other catastrophic shape (no
        # nested/adjacent quantified group, no stacked bounded repeat, and -- issue #2035 --
        # no run of adjacent quantified atoms either: the `b` separators are DISJOINT from
        # `a`, so they split every quantifier into a chain of its own (issue #2082)).
        at_budget = "a*b" * pfb_dnsbl_regex_rules._REGEX_BUDGET_MAX
        # Compute the budget the SAME way the code does and pin it to MAX before asserting.
        budget = len(pfb_dnsbl_regex_rules._REGEX_UNBOUNDED_QUANTIFIER.findall(at_budget)) + len(
            pfb_dnsbl_regex_rules._REGEX_ALTERNATION.findall(at_budget)
        )
        assert budget == pfb_dnsbl_regex_rules._REGEX_BUDGET_MAX
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
    for name in ("REGEX_STATIC_LEN_CAP", "_regex_is_catastrophic_shape", "pfb_split_regex_line"):
        assert getattr(pfb_unbound, name) is getattr(pfb_dnsbl_regex_rules, name), (
            f"pfb_unbound.{name} is not the same object as pfb_dnsbl_regex_rules.{name} -- single-source broken"
        )


def test_runtime_length_cap_comparator_is_strict_at_every_site() -> None:
    """Issue #1711/#1765: pin the runtime's exact-200-character admission boundary. All
    FOUR REGEX_STATIC_LEN_CAP comparisons -- the three call sites left in pfb_unbound.py
    (the build-time compile helper plus the two save-time-mirroring load paths) and the
    one inside pfb_dnsbl_regex_rules.py's save-time probe ``main()`` -- use a STRICT '>':
    a '>=' regression at any site would silently drop a pattern exactly at the cap, which
    the resolver, the probe, and the PHP DnsblRegexEntryErrorTest suite all admit."""
    unbound_path = Path(__file__).resolve().parent.parent / "src/usr/local/pkg/pfblockerng/pfb_unbound.py"
    rules_path = Path(__file__).resolve().parent.parent / "src/usr/local/pkg/pfblockerng/pfb_dnsbl_regex_rules.py"
    source = unbound_path.read_text() + "\n" + rules_path.read_text()
    strict = re.findall(r"len\([^)\n]*\)\s*>\s*REGEX_STATIC_LEN_CAP", source)
    assert len(strict) == 4, f"expected exactly 4 strict '>' comparisons, found {len(strict)}: {strict}"
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
