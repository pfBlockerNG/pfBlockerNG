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

Probe usage:
  /usr/local/pkg/pfblockerng/pfb_python.sh \
    /usr/local/pkg/pfblockerng/pfb_dnsbl_regex_rules.py [1]
  argv[1] == "1" enables the opt-in length cap (absent argv -> cap off).
  Reads regex-list lines from stdin; each rejected line is reported on
  stderr as ``line <n>: <pattern!r>: <message>``. Exits 1 if any line
  failed, else 0.
"""

from __future__ import annotations

import re
import string
import sys
import warnings
from functools import lru_cache

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

# Adjacent unbounded quantifiers over OVERLAPPING atoms, grouped or not: [a-z]+[a-z]+[a-z]+,
# ([a-z]+)([a-z]+)([a-z]+), \w+\w+\w+, a{2,}a{2,}a{2,}. Each atom can cede characters to its
# neighbour, so a failing tail walks a partition of the matched span -- the mechanism the
# group-keyed shapes above already cover, minus the parentheses they all key on. Measured
# against a 253-character name (the longest the matcher can be handed): a run of 3 costs
# 7 ms and a run of 4 costs 462 ms, versus 0.08 ms for a run of 2 -- so a pair stays
# admitted (a pair is what real host patterns use). A mandatory atom whose character set
# overlaps the run is NOT a boundary (issue #2082): its position floats inside the span,
# so `[a-z]+[a-z]+a[a-z]+[a-z]+` multiplies through the `a` (1533 ms measured) -- such an
# atom bridges the chain while breaking pair-adjacency, and a chain is rejected once it
# carries more than this many quantifiers AND at least one back-to-back pair (single
# quantifiers between floating separators stay admitted: 5.8 ms worst-case measured).
_REGEX_ADJACENT_ATOM_MAX = 2

# Ceiling for chains connected ONLY by floating separators (no back-to-back pair): they
# blow up one quantifier later. Measured at 253 characters (CI image): 3 quantifiers cost
# 23 ms (the runtime warn layer's accepted residual; rejecting 3 would drop the admitted
# single-gap shapes above) while 4 cost 1753 ms, far over the 100 ms evict ceiling.
_REGEX_CHAIN_ATOM_MAX = 3

# Character sets are compared by probing both atoms with one character at a time: this
# alphabet only has to be big enough to separate the classes a domain pattern is written
# over (letters, digits, punctuation, whitespace, non-ASCII word characters).
_REGEX_OVERLAP_ALPHABET = string.printable + "é"

_REGEX_REPEAT = re.compile(r"\{(?P<min>\d+)(?P<comma>,?)(?P<max>\d*)\}")

# How deep the scan follows lookarounds nested inside lookarounds. Real patterns never nest
# more than one or two; the bound only stops a hostile line from exhausting the stack.
_REGEX_NESTED_SCAN_MAX = 8

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

# The four regex-matched structural shapes, tried in the order above (the adjacent-atom
# run below needs a scan rather than a pattern, so it is a predicate of its own).
_REGEX_SHAPE_PATTERNS: tuple[re.Pattern[str], ...] = (
    _REGEX_NESTED_QUANTIFIER,
    _REGEX_ALTERNATION_OVERLAP,
    _REGEX_ADJACENT_GROUP_QUANTIFIER,
    _REGEX_STACKED_BOUNDED_REPEAT,
)


def _regex_atom_end(pattern: str, index: int) -> int:
    """End offset of the single-character atom starting at ``index`` -- a character class,
    an escape, ``.``, or a literal. An unterminated class swallows the rest of the string."""
    character = pattern[index]
    if character == "\\":
        marker = pattern[index + 1 : index + 2]
        width = {"x": 2, "u": 4, "U": 8}.get(marker, 0)
        if width:
            end = index + 2 + width
            if end <= len(pattern) and all(digit in string.hexdigits for digit in pattern[index + 2 : end]):
                return end
        # `\N{NAME}` is one atom; lowercase `\n{2,}` is a newline carrying a REPEAT.
        elif marker == "N" and pattern[index + 2 : index + 3] == "{":
            closing = pattern.find("}", index + 3)
            if closing != -1:
                return closing + 1
        return min(index + 2, len(pattern))
    if character != "[":
        return index + 1
    end = index + 1
    if pattern[end : end + 1] == "^":
        end += 1
    if pattern[end : end + 1] == "]":
        end += 1
    while end < len(pattern):
        if pattern[end] == "\\":
            end += 2
            continue
        if pattern[end] == "]":
            return end + 1
        end += 1
    return len(pattern)


def _regex_quantifier(pattern: str, index: int) -> tuple[int, str]:
    """Classify the quantifier at ``index`` as ``(end offset, role in a run)``:

    "run"    -- backtracking and unbounded (`+`, `*`, `{m,}`, lazy forms): extends a run.
    "bridge" -- can match nothing (`?`, `{0,n}`): cannot separate its neighbours, so it
                neither extends nor ends a run.
    "break"  -- absent, fixed (`{m}`, `{m,n}`), or possessive: ends the run. A possessive
                quantifier never gives characters back, so it cannot partition a span.
    """
    end = index
    unbounded = True
    if pattern[index : index + 1] in ("+", "*"):
        end = index + 1
        optional = pattern[index] == "*"
    elif pattern[index : index + 1] == "{":
        repeat = _REGEX_REPEAT.match(pattern, index)
        if repeat is None:
            return index, "break"
        end = repeat.end()
        unbounded = repeat.group("max") == "" and repeat.group("comma") == ","
        optional = repeat.group("min") == "0"
    elif pattern[index : index + 1] == "?":
        end = index + 1
        unbounded = False
        optional = True
    else:
        return index, "break"
    modifier = pattern[end : end + 1]
    if modifier == "+":  # possessive
        return end + 1, "bridge" if optional else "break"
    if modifier == "?":  # lazy
        end += 1
    return end, "run" if unbounded else ("bridge" if optional else "break")


def _regex_group_end(pattern: str, index: int) -> int:
    """End offset past the ``)`` closing the group that opens at ``index`` (the end of the
    string when it is never closed). Parentheses inside a class or an escape do not count."""
    depth = 0
    while index < len(pattern):
        character = pattern[index]
        if character in ("\\", "["):
            index = _regex_atom_end(pattern, index)
            continue
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return len(pattern)


@lru_cache(maxsize=512)
def _regex_atoms_overlap(first: str, second: str) -> bool:
    """True when both atoms can match the same character, i.e. the pair is ambiguous.

    Compiled IGNORECASE (#2099): the DNSBL matcher compiles every admitted pattern
    case-insensitively (#2079/#2097), so this probe must judge overlap under the
    same semantics the runtime actually executes, not case-sensitive text overlap.
    """
    if first == second:
        return True
    try:
        # Warnings are suppressed for the same reason main() suppresses them: PHP turns
        # every stderr line into an admin-facing validation error.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            left = re.compile(first, re.IGNORECASE)
            right = re.compile(second, re.IGNORECASE)
    except re.error:
        return False
    return any(left.fullmatch(probe) and right.fullmatch(probe) for probe in _REGEX_OVERLAP_ALPHABET)


def _regex_body_alternates(body: str) -> bool:
    """True when ``body`` carries a top-level unescaped ``|`` -- an alternation whose
    branches the enclosing group's parentheses scope (one inside a nested group or a
    character class belongs to that construct instead)."""
    depth = 0
    index = 0
    while index < len(body):
        character = body[index]
        if character in ("\\", "["):
            index = _regex_atom_end(body, index)
            continue
        if character == "(":
            depth += 1
        elif character == ")":
            depth = max(depth - 1, 0)
        elif character == "|" and depth == 0:
            return True
        index += 1
    return False


def _regex_next_unit(pattern: str, index: int) -> tuple[str, str, int]:
    """Read one unit at ``index``, returning ``(atom, role, next index)`` with the roles of
    ``_regex_quantifier``. A group contributes by what it does to the engine, not by its
    punctuation: a comment or a lookaround consumes nothing and bridges; a plain
    ``(...)``/``(?:...)``/``(?P<n>...)`` -- and (issue #2082) a scoped-flags ``(?i:...)`` or
    atomic ``(?>...)`` group -- is scanned through as if the parentheses were not there; one
    wrapping a single atom IS that atom when the quantifier sits outside it; a conditional
    ``(?(...)...)``, an atomic ``(?>...)``, or a bare-alternation group returns its body for
    the caller's overlap probe; a named backreference is role ``float`` (mandatory,
    overlap unknowable)."""
    if pattern[index] == ")":
        # A group's closing punctuation separates nothing by itself -- the atoms inside
        # already decided whether the chain survives -- and a fixed repeat ON the group
        # floats with it (issue #2082), so `)` never ends a chain.
        quantifier_end, _ = _regex_quantifier(pattern, index + 1)
        return "", "bridge", max(quantifier_end, index + 1)
    if pattern[index] != "(":
        if pattern[index] in "|^$*+?{}":
            return "", "break", index + 1
        atom_end = _regex_atom_end(pattern, index)
        quantifier_end, role = _regex_quantifier(pattern, atom_end)
        return pattern[index:atom_end], role, max(quantifier_end, atom_end)

    group_end = _regex_group_end(pattern, index)
    closed = pattern[group_end - 1 : group_end] == ")"
    if pattern.startswith(("(?#", "(?=", "(?!", "(?<=", "(?<!"), index):
        # Skipping an UNCLOSED construct would blind the scan to everything after it.
        if not closed:
            return "", "break", index + 2
        if pattern.startswith("(?#", index):
            return "", "bridge", group_end  # a comment is inert text, not a pattern
        # A lookaround matches no characters, so it cannot join or separate the run around
        # it -- but the engine still backtracks over its body, which is scanned on its own.
        body_start = index + 4 if pattern[index + 2] == "<" else index + 3
        return pattern[body_start : group_end - 1], "nested", group_end
    if pattern.startswith("(?P<", index):
        name_end = pattern.find(">", index)
        if name_end == -1:
            return "", "break", group_end
        body_start = name_end + 1
    elif pattern.startswith("(?:", index):
        body_start = index + 3
    elif pattern.startswith("(?(", index):
        # issue #2082: a conditional is a mandatory construct whose POSITION floats, so its
        # post-condition body (an alternation the overlap probe can compile) is handed to
        # the caller to judge like a bare atom -- never read as a run boundary outright.
        condition_end = pattern.find(")", index + 3)
        if not closed or condition_end == -1 or condition_end >= group_end - 1:
            return "", "break", group_end
        body = pattern[condition_end + 1 : group_end - 1]
        quantifier_end, role = _regex_quantifier(pattern, group_end)
        if role == "bridge" or not body:
            return "", "bridge", max(quantifier_end, group_end)
        return body, role, max(quantifier_end, group_end)
    elif pattern.startswith("(?>", index):
        # Atomicity forbids backtracking INSIDE the body, so it is never entered as a run
        # source -- but the group's POSITION floats with the run around it (issue #2082),
        # so its body feeds the caller's overlap probe like a bare atom.
        if not closed:
            return "", "break", group_end
        body = pattern[index + 3 : group_end - 1]
        quantifier_end, role = _regex_quantifier(pattern, group_end)
        if role == "bridge" or not body:
            return "", "bridge", max(quantifier_end, group_end)
        return body, role, max(quantifier_end, group_end)
    elif pattern.startswith("(?P=", index):
        # A backreference's character set is unknowable statically, so it can never be
        # proven a boundary: mandatory, position floats, overlap assumed (issue #2082).
        return "", "float", group_end
    elif pattern.startswith("(?", index):
        flags_end = index + 2
        while flags_end < len(pattern) and pattern[flags_end] in "aiLmsux-":
            flags_end += 1
        if flags_end > index + 2 and pattern[flags_end : flags_end + 1] == ":":
            body_start = flags_end + 1  # scoped flags: `(?i:...)` backtracks like `(?:...)`
        else:
            return "", "break", group_end  # global flags and any unknown `(?` construct
    else:
        body_start = index + 1
    quantifier_end, role = _regex_quantifier(pattern, group_end)
    body = pattern[body_start : group_end - 1]
    # A quantified group repeats its body, so the body IS the run's atom -- one atom
    # (`(?:[a-z])+` is `[a-z]+`) or a plain sequence (`(ab)+(ab)+(ab)+` repeats too). A body
    # carrying its own group or alternation belongs to the shapes above instead.
    if role == "run" and body and not any(character in body for character in "()|"):
        return body, "run", quantifier_end
    # A mandatory group over a quantifier-free alternation (`(a|b)`, `(a|(b))`) is the
    # conditional separator without the condition (issue #2082): entering it would read `|`
    # as a boundary, so the body -- which compiles standalone -- is handed to the caller's
    # overlap probe instead. A body carrying any quantifier keeps the entered scan, so a
    # run inside a branch is still found rather than hidden behind the probe.
    if (
        role != "bridge"
        and body
        and _regex_body_alternates(body)
        and not any(character in body for character in "+*{?")
    ):
        return body, role, max(quantifier_end, group_end)
    # Every other group is entered rather than skipped: parentheses hide a run from the
    # reader, never from the engine, and its atoms -- not its punctuation -- decide what
    # happens to the chain (issue #2082: a fixed repeat ON the group floats with it).
    return "", "bridge", body_start


def _regex_is_backref(atom: str) -> bool:
    """``\\1``..``\\9`` as read by ``_regex_atom_end`` (two characters; ``\\0`` is the
    octal null escape, a literal atom, never a group reference)."""
    return len(atom) == 2 and atom[0] == "\\" and atom[1] in "123456789"


def _regex_has_adjacent_unbounded_atoms(pattern: str, depth: int = 0) -> bool:
    """True when ``pattern`` carries an overlap-connected CHAIN of more than
    ``_REGEX_ADJACENT_ATOM_MAX`` atoms that each take a backtracking unbounded quantifier,
    where the chain holds at least one back-to-back pair. A mandatory atom overlapping the
    chain is no boundary -- its position floats inside the span (issue #2082) -- so it
    bridges the chain while breaking pair-adjacency; a disjoint one really pins the split
    and ends the chain. A lookaround's body is scanned as a pattern of its own, bounded by
    ``_REGEX_NESTED_SCAN_MAX`` so nested lookarounds cannot exhaust the stack. Pure string
    analysis: nothing here runs the candidate against an input."""
    anchor = ""  # last quantified atom of the chain ("" = no chain)
    quantified = 0
    pairs = 0
    adjacent = False  # whether the chain unit before this one was a quantified atom
    index = 0
    while index < len(pattern):
        atom, role, index = _regex_next_unit(pattern, index)
        if role == "nested":
            if depth < _REGEX_NESTED_SCAN_MAX and _regex_has_adjacent_unbounded_atoms(atom, depth + 1):
                return True
            continue
        if role == "bridge":
            continue
        if role == "run":
            if anchor and _regex_atoms_overlap(anchor, atom):
                quantified += 1
                if adjacent:
                    pairs += 1
            else:
                quantified, pairs = 1, 0
            anchor, adjacent = atom, True
            if (pairs and quantified > _REGEX_ADJACENT_ATOM_MAX) or quantified > _REGEX_CHAIN_ATOM_MAX:
                return True
            continue
        # A mandatory unit whose set overlaps the chain -- or cannot be proven disjoint
        # (a backreference) -- floats, so it bridges the chain instead of ending it.
        if role == "float" or (atom and anchor and (_regex_atoms_overlap(anchor, atom) or _regex_is_backref(atom))):
            adjacent = False
            continue
        anchor, quantified, pairs, adjacent = "", 0, 0, False
    return False


def _regex_has_catastrophic_shape(pattern: str) -> bool:
    """True when ``pattern`` matches any of the four structural shapes above or carries a
    run of adjacent unbounded quantifiers over overlapping atoms."""
    return any(shape.search(pattern) is not None for shape in _REGEX_SHAPE_PATTERNS) or (
        _regex_has_adjacent_unbounded_atoms(pattern)
    )


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
        pattern = pfb_split_regex_line(line)[0].strip()
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
            # Only real "line N:" diagnostics may reach stderr: PHP turns EVERY
            # non-empty stderr line into an admin-facing validation error. A pattern
            # that compiles but warns (e.g. "[[a]]" -> FutureWarning "Possible nested
            # set") would otherwise leak this file's absolute path AND its source line
            # as two bogus errors -- warnings can resolve the source now that the probe
            # runs as a FILE rather than via ``python -c``. The resolver compiles the
            # same patterns at load without surfacing warnings either.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                re.compile(pattern, re.IGNORECASE)
        except Exception as error:
            _report(line_number, pattern, f"Python regex compile error: {error}")
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
