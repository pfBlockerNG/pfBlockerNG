"""pfb_dnsbl_regex_rules.py -- DNSBL regex admission rules (issue #1765 / #1711).

Single source of the pure static predicates that decide whether a DNSBL regex
pattern is admitted: the catastrophic-shape gate, the complexity-budget
backstop, the opt-in length cap, and the pattern/description line-splitter.
Two consumers share this ONE module instead of duplicating the literals:

  - pfb_unbound.py imports it at load (Unbound's pythonmod loader `chdir()`s
    into the script directory and appends '.' to sys.path before running
    pfb_unbound.py, so a plain module-scope import resolves).
  - pfblockerng_extra.inc's pfb_dnsbl_regex_validation_errors() runs it
    standalone as the save-time probe (this file's ``main()``).

Stdlib only, no ``unboundmodule`` reference at module scope or in any
function here -- import-safe standalone in a plain interpreter.

Probe usage: <pfb_python_interpreter()> pfb_dnsbl_regex_rules.py [1]
  argv[1] == "1" enables the opt-in length cap (absent argv -> cap off).
  Reads regex-list lines from stdin; each rejected line is reported on
  stderr as ``line <n>: <pattern!r>: <message>``. Exits 1 if any line
  failed, else 0.
"""

from __future__ import annotations

import re
import sys

# Length ceiling (heuristic): a pattern over this many characters is dropped
# at load ONLY when the opt-in "Limit long/complex regex" setting is enabled.
# Length alone is a tunable convenience cap, NOT a safety gate -- a long
# pattern is not inherently pathological -- so it stays behind the flag.
REGEX_STATIC_LEN_CAP = 200

# A quantified group that itself sits inside a quantifier: (a+)+, (a*)*, (\w+\.)+,
# ([a-z]+)*, (.*a){20}. Measured to catch 1/1 catastrophic patterns in
# the corpus with no false-negatives and no false-positives on the cap-passing set.
_REGEX_NESTED_QUANTIFIER = re.compile(r"\([^()]*[+*][^()]*\)\s*[+*{]")

# Alternation-overlap: a quantified group whose body contains an alternation `|`,
# e.g. (a|a)+, (a|ab)*, (foo|foobar)+. Overlapping/ambiguous alternatives under a
# quantifier backtrack catastrophically just like a nested quantifier, yet the
# nested-quantifier shape above does not catch them (no inner quantifier). Kept
# conservative: a single `(...)` (no inner parens) with a `|`, then a quantifier.
_REGEX_ALTERNATION_OVERLAP = re.compile(r"\([^()]*\|[^()]*\)\s*[+*{]")

# Multi-group adjacent quantified groups: (a+)(a+)+, (a+)(b+)*, (...)(...)+ -- two
# back-to-back groups where the SECOND carries a trailing quantifier. The first
# group's unbounded body and the quantified second group share input, so the engine
# explores an exponential partition of the matched span. The single-group
# _REGEX_NESTED_QUANTIFIER above misses this (the outer quantifier sits on a sibling
# group, not the enclosing one). Each group body is paren-free (kept conservative).
_REGEX_ADJACENT_GROUP_QUANTIFIER = re.compile(r"\([^()]*[+*][^()]*\)\([^()]*\)\s*[+*]")

# Stacked bounded repeats: a{1000}{1000}, (x){500}{500}, [a-z]{50}{50} -- a `{m}`/`{m,n}`
# repeat immediately followed by another `{...}`. Python's re multiplies the bounds, so a
# pair of large counts is a polynomial/exponential blow-up with a tiny source string. A
# group/atom (optionally already quantified) then two consecutive brace quantifiers.
_REGEX_STACKED_BOUNDED_REPEAT = re.compile(r"(?:\)|\]|\w)\{\d+(?:,\d*)?\}\{\d+(?:,\d*)?\}")

# Complexity-budget backstop: cap the combined count of unbounded quantifiers (`+`/`*`,
# unescaped) and alternations (`|`, unescaped) in one pattern. The structural regexes
# above catch KNOWN bad shapes; this catches novel compositions of many quantifiers /
# alternatives that together create a large backtracking surface even when no single
# pair matches a structural template. The threshold (12) is generous: realistic ABP/DNS
# feed regex carries a handful of anchors + one or two trailing quantifiers (a domain
# pattern like `^(.+\.)?ads?[0-9]*\.example\.(com|net|org)$` counts ~5), so 12 clears
# every benign pattern in the corpus while still bounding adversarial stacking.
_REGEX_BUDGET_MAX = 12
_REGEX_UNBOUNDED_QUANTIFIER = re.compile(r"(?<!\\)[+*]")
_REGEX_ALTERNATION = re.compile(r"(?<!\\)\|")

# The four structural shapes, tried in the order above.
_REGEX_SHAPE_PATTERNS: tuple[re.Pattern[str], ...] = (
    _REGEX_NESTED_QUANTIFIER,
    _REGEX_ALTERNATION_OVERLAP,
    _REGEX_ADJACENT_GROUP_QUANTIFIER,
    _REGEX_STACKED_BOUNDED_REPEAT,
)


def _regex_has_catastrophic_shape(pattern: str) -> bool:
    """True when ``pattern`` matches any of the four structural shapes above."""
    return any(shape.search(pattern) is not None for shape in _REGEX_SHAPE_PATTERNS)


def _regex_complexity_budget(pattern: str) -> int:
    """Combined count of unbounded quantifiers + alternations in ``pattern``
    (the complexity-budget backstop's input; compare against ``_REGEX_BUDGET_MAX``)."""
    return len(_REGEX_UNBOUNDED_QUANTIFIER.findall(pattern)) + len(_REGEX_ALTERNATION.findall(pattern))


def _regex_is_catastrophic_shape(pattern: str) -> bool:
    """Pure static analysis (NO execution): True when ``pattern`` carries a structurally
    catastrophic shape -- a nested / adjacent / overlapping unbounded quantifier, a
    stacked bounded repeat, or so many unbounded quantifiers + alternations combined that
    its backtracking surface is unsafe. This is the SAFETY gate: it is applied to FEED and
    user regex UNCONDITIONALLY at load (independent of the opt-in length cap) because these
    shapes drive catastrophic backtracking in the `re` engine. It only inspects the pattern
    STRING -- it never runs the candidate against any input -- so it is itself cheap and
    safe. Length is deliberately NOT part of this gate (a long pattern is not inherently
    catastrophic; the length ceiling is the separate opt-in convenience cap)."""
    return _regex_has_catastrophic_shape(pattern) or _regex_complexity_budget(pattern) > _REGEX_BUDGET_MAX


def pfb_split_regex_line(line: str) -> tuple[str, str | None]:
    """Split a regex-list line into (pattern, description) at the first UNESCAPED '#'.

    issue #1867: a '#' preceded by an ODD number of backslashes is escaped and
    belongs to the pattern; an EVEN run (including none) leaves it as the
    description marker. The escaped form is returned verbatim -- Python's ``re``
    already reads "\\#" as a literal '#', so no unescaping step is needed and the
    pattern half reaches ``re.compile`` unchanged.

    Returns ``(line, None)`` when the line carries no description marker at all;
    the caller distinguishes that from an empty description ("pattern#").

    The PHP twin is ``pfb_split_regex_line()`` in pfblockerng_extra.inc and the
    editor twin is the ``Pattern``/``Comment`` token pair in
    tools/webassets/lezer-pfb-regex-list/src/pfb-regex-list.grammar -- all three
    implement this one rule and their tests reference each other.
    """
    backslashes = 0
    for index, character in enumerate(line):
        if character == "\\":
            backslashes += 1
            continue
        if character == "#" and backslashes % 2 == 0:
            return line[:index], line[index + 1 :]
        backslashes = 0
    return line, None


def _report(line_number: int, pattern: str, message: str) -> None:
    print(f"line {line_number}: {pattern!r}: {message}", file=sys.stderr)


def main(argv: list[str]) -> int:
    """Save-time probe: read a regex-list body from stdin, report every entry the
    resolver's admission rules would reject. ``argv[1] == "1"`` enables the
    opt-in length cap (absent -> cap off), mirroring the resolver's ``regex_cap``
    setting. Returns 1 if any line failed, else 0."""
    regex_cap = len(argv) > 1 and argv[1] == "1"
    failed = False
    for line_number, raw_line in enumerate(sys.stdin, start=1):
        line = raw_line.rstrip("\r\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        pattern = pfb_split_regex_line(line)[0].strip().lower()
        if not pattern:
            continue
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in pattern):
            _report(line_number, pattern, "contains ASCII control character")
            failed = True
            continue
        if _regex_has_catastrophic_shape(pattern):
            _report(line_number, pattern, "catastrophic-backtracking shape")
            failed = True
            continue
        if _regex_complexity_budget(pattern) > _REGEX_BUDGET_MAX:
            _report(line_number, pattern, "too many quantifiers/alternations")
            failed = True
            continue
        if regex_cap and len(pattern) > REGEX_STATIC_LEN_CAP:
            _report(
                line_number,
                pattern,
                f'over the {REGEX_STATIC_LEN_CAP}-character length cap ("Limit long/complex regex")',
            )
            failed = True
            continue
        try:
            re.compile(pattern)
        except Exception as error:
            _report(line_number, pattern, f"Python regex compile error: {error}")
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
