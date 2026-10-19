"""pfb_dnsbl_regex_rules.py -- DNSBL regex admission rules (issue #1765 / #1711).

Single source of the pure static predicates that decide whether a DNSBL regex
pattern is admitted: the bounded-grammar admission gate (an allowlist of
constructs plus a static cost bound), the text a pattern is compiled from, the
log excerpt, the opt-in length cap, and the pattern/description line-splitter.
Two consumers share this ONE module instead of duplicating the literals:

  - pfb_unbound.py imports it at load (Unbound's pythonmod loader `chdir()`s
    into the script directory and appends '.' to sys.path before running
    pfb_unbound.py, so a plain module-scope import resolves).
  - pfblockerng_extra.inc's pfb_dnsbl_regex_validation_errors() runs it
    standalone as the save-time probe (this file's ``main()``).

The admission gate reads the pattern text once, left to right, with an explicit
stack. It never compiles, matches or otherwise executes pattern text, so judging
a pattern costs time linear in its (capped) length however hostile it is.

Stdlib only, no ``unboundmodule`` reference at module scope or in any
function here -- import-safe standalone in a plain interpreter.

Probe usage:
  /usr/local/pkg/pfblockerng/pfb_python.sh \
    /usr/local/pkg/pfblockerng/pfb_dnsbl_regex_rules.py [1]
  argv[1] == "1" enables the opt-in length cap (absent argv -> cap off).
  Reads regex-list lines from stdin; each rejected line is reported on
  stderr as ``line <n>: <excerpt>: <message>``. Exits 1 if any line
  failed, else 0.
"""

from __future__ import annotations

import re
import sys
import warnings
from dataclasses import dataclass, field

# Length ceiling (heuristic): a pattern over this many characters is dropped
# at load ONLY when the opt-in "Limit long/complex regex" setting is enabled.
# Length alone is a tunable convenience cap, NOT a safety gate -- a long
# pattern is not inherently pathological -- so it stays behind the flag.
REGEX_STATIC_LEN_CAP = 200

# Admission bounds, always on. A pattern is matched against names of at most 253
# characters; the bounds below keep the matcher's work on one name within a fixed budget
# of backtracking steps.
REGEX_PATTERN_MAX_LEN = 256  # refused on length alone, before any scan
REGEX_REPEAT_MAX = 255  # largest m and n in {m}, {m,n}, {m,}
REGEX_GROUP_DEPTH_MAX = 8  # deepest nesting of ( ... )
REGEX_COST_MAX = 1 << 18  # largest admitted bound on backtracking steps (search-tree nodes)
# Largest sum, over the bracket classes of one pattern, of the ASCII characters each class
# lists, counted before any `^` negation and after case folding (`[a-z]` lists 52). It bounds
# compile time for wide classes (a pattern 4600 wide took about 5.5 ms). It does not bound the
# IGNORECASE case-fold cost of `s`/`i` in a class (about 0.16 ms per class): a 1000-rule list of
# `[sx]`-heavy rules compiled in about 10 s on a desktop CPU, against about 0.2 s for typical
# hostname rules. That is load time only; matching is unaffected. `re.ASCII` would remove it but
# changes verdicts on the Latin-1 CNAME targets `convert_other()` decodes, so it is not used.
REGEX_CLASS_WIDTH_MAX = 256
# Attempts of one unbounded quantifier (*, +, {m,}), and of an unanchored search (it
# starts a match at every position of the name).
REGEX_COST_UNBOUNDED = 256

# Cost saturates here so a refusal reason stays short.
_COST_SATURATION = 1 << 64
_EXCERPT_CHARS = 32
_QUANTIFIER_START = ("?", "*", "+", "{")
_SET_OPERATION_CHARS = "-&~|"
_OPTIONAL = (0, 1)

# (minimum, maximum) repeat count; maximum None = unbounded.
_Quantifier = tuple[int, int | None]

# Character sets of single-character atoms, as bit sets: bits 0-127 are the ASCII
# characters and bit 128 is one pseudo-member standing for every non-ASCII character (`re` reads `\d` and
# `\w` as Unicode, so they carry it like `.` and the negated escapes).
# Two atoms are disjoint when their sets share no bit. Sets are case-folded (a letter in
# a set adds its other case) because every pattern is compiled with IGNORECASE.
_ASCII = (1 << 128) - 1
_NONASCII = 1 << 128
_UPPER = ((1 << 26) - 1) << 65
_LOWER = ((1 << 26) - 1) << 97
_DIGITS = sum(1 << code for code in range(128) if chr(code).isdecimal())
_WORD = sum(1 << code for code in range(128) if chr(code).isalnum() or chr(code) == "_")
_SPACE = sum(1 << code for code in range(128) if chr(code).isspace())
_DOT = (_ASCII & ~(1 << ord("\n"))) | _NONASCII
_CLASS_ESCAPES = {
    "d": _DIGITS | _NONASCII,
    "D": (_ASCII & ~_DIGITS) | _NONASCII,
    "w": _WORD | _NONASCII,
    "W": (_ASCII & ~_WORD) | _NONASCII,
    "s": _SPACE | _NONASCII,
    "S": (_ASCII & ~_SPACE) | _NONASCII,
}

# Item kinds of a branch.
_ZERO = 0
_ATOM = 1
_GROUP = 2


def _fold(members: int) -> int:
    """``members`` with the other case of every letter in it added."""
    return members | ((members & _UPPER) << 32) | ((members & _LOWER) >> 32)


class _Refusal(Exception):
    """A pattern outside the grammar; the message is the short fixed reason."""


@dataclass(slots=True)
class _Item:
    """One element of a branch: an atom, a zero-width token or a group."""

    kind: int
    members: int = 0  # atom: the characters it matches
    quantified: bool = False
    low: int = 1  # repeat count, minimum
    high: int | None = 1  # repeat count, maximum; None = unbounded
    dollar: bool = False  # zero-width: a `$`
    nodes: int = 0  # group: search-tree nodes of its body
    out: int = 1  # group: ways its body can have been walked when it ends
    length: int = 0  # group: atoms in its body (a plain run when the group is repeated)


@dataclass(slots=True)
class _Frame:
    """One alternation level: the whole pattern (``top``) or the body of one open group."""

    top: bool
    items: list[_Item] = field(default_factory=list)  # the current branch
    nodes: int = 0  # search-tree nodes of the finished branches, summed
    out: int = 0  # ways the finished branches can end, summed
    atoms: int = 0  # atoms in the body (all branches)
    simple: bool = True  # body is only plain atoms: no quantifier, group, `|` or zero-width
    unanchored: int = 0  # finished branches that did not begin with `^` or a leading `.*` / `.+`
    branch_anchored: bool = False  # the current branch began with `^` (or a leading `.*` / `.+`)
    dot_runs: list[tuple[int, int]] = field(default_factory=list)  # top level: offsets of each leading dot run

    def end_branch(self) -> None:
        nodes, out = _branch_cost(self.items, self.top)
        self.nodes = min(self.nodes + nodes, _COST_SATURATION)
        self.out = min(self.out + out, _COST_SATURATION)
        self.unanchored += int(not self.branch_anchored)
        self.items = []
        self.branch_anchored = False


def _escape(pattern: str, index: int) -> tuple[str, int]:
    """Classify the escape at ``index`` as (``class`` | ``zero`` | ``literal``, next index)."""
    if index + 1 >= len(pattern):
        raise _Refusal(f"trailing backslash at {index}")
    escaped = pattern[index + 1]
    if escaped in "dDwWsS":
        return "class", index + 2
    if escaped in "bB":
        return "zero", index + 2
    if escaped.isalnum():  # backreferences, octal and every letter escape
        raise _Refusal(f"unsupported escape at {index}")
    return "literal", index + 2


def _check_set_operation(pattern: str, index: int) -> None:
    char = pattern[index]
    if char in _SET_OPERATION_CHARS and pattern[index + 1 : index + 2] == char:
        raise _Refusal(f"set operation in class at {index}")


def _class_item(pattern: str, index: int) -> tuple[int | None, int, int]:
    """One class item as ``(code point, its character set, next index)``; a class escape
    has no code point (it cannot end a range)."""
    char = pattern[index]
    if char == "\\":
        kind, end = _escape(pattern, index)
        if kind == "zero":
            raise _Refusal(f"unsupported escape in class at {index}")
        escaped = pattern[index + 1]
        if kind == "class":
            return None, _CLASS_ESCAPES[escaped], end
        return ord(escaped), 1 << ord(escaped), end
    if char == "[":
        raise _Refusal(f"nested class at {index}")
    return ord(char), 1 << ord(char), index + 1


def _class_end(pattern: str, index: int) -> tuple[int, int, int]:
    """``(index after the class, its character set, the ASCII characters it lists)`` for the
    class whose ``[`` precedes ``index``; a negated class lists the characters it excludes."""
    negated = pattern[index : index + 1] == "^"
    if negated:
        index += 1
    members = 0
    items = 0
    while index < len(pattern):
        if pattern[index] == "]":
            if not items:
                raise _Refusal(f"empty class at {index}")
            members = _fold(members)
            listed = (members & _ASCII).bit_count()
            return index + 1, ((_ASCII & ~members) | _NONASCII) if negated else members, listed
        _check_set_operation(pattern, index)
        low, found, index = _class_item(pattern, index)
        members |= found
        items += 1
        # A `-` that ends the class is a literal; any other `-` joins two literal ends.
        if pattern[index : index + 1] == "-" and pattern[index + 1 : index + 2] not in ("", "]"):
            _check_set_operation(pattern, index)
            high, found, index = _class_item(pattern, index + 1)
            if low is None or high is None:
                raise _Refusal(f"class escape in range at {index}")
            if low > high:
                raise _Refusal(f"reversed range at {index}")
            members |= ((1 << (high + 1)) - 1) ^ ((1 << low) - 1)
    raise _Refusal("unclosed class")


def _quantifier(pattern: str, index: int) -> tuple[int, _Quantifier | None]:
    """Read the quantifier starting at ``index`` -- ``?`` ``*`` ``+`` ``{m}`` ``{m,}``
    ``{m,n}`` with an optional lazy ``?`` -- as (next index, (min, max)); (index, None)
    when none starts there."""
    char = pattern[index : index + 1]
    if char not in _QUANTIFIER_START:
        return index, None
    if char == "{":
        close = pattern.find("}", index)
        if close < 0:
            raise _Refusal(f"invalid repeat at {index}")
        low_text, comma, high_text = pattern[index + 1 : close].partition(",")
        if not low_text.isdigit() or (high_text and not high_text.isdigit()):
            raise _Refusal(f"invalid repeat at {index}")
        low = int(low_text)
        high = (int(high_text) if high_text else None) if comma else low
        end = close + 1
    else:
        low, high = {"?": (0, 1), "*": (0, None), "+": (1, None)}[char]
        end = index + 1
    if low > REGEX_REPEAT_MAX or (high is not None and (high > REGEX_REPEAT_MAX or low > high)):
        raise _Refusal(f"repeat out of bounds at {index}")
    if pattern[end : end + 1] == "?":  # lazy
        end += 1
    return end, (low, high)


def _hands_nothing_on(items: list[_Item], index: int, top: bool, trailing: int) -> bool:
    """Whether the quantified atom ``items[index]`` leaves the work after it unmultiplied:
    nothing but ``$`` follows it in a top-level branch (the match ends or fails at once),
    or a mandatory atom that shares no character with it follows directly (the run cannot
    give a character to that atom, so each attempt of the run has one way on)."""
    if top and index + 1 >= trailing:
        return True
    if index + 1 >= len(items):
        return False
    following = items[index + 1]
    return following.kind == _ATOM and following.low >= 1 and not items[index].members & following.members


def _attempts(item: _Item) -> int:
    """Ways to end a quantified item's repeat after its ``low`` mandatory steps."""
    return REGEX_COST_UNBOUNDED if item.high is None else item.high - item.low + 1


def _branch_cost(items: list[_Item], top: bool) -> tuple[int, int]:
    """``(nodes, out)`` of one branch of an alternation: the matcher's search-tree nodes
    below this branch and the number of ways the branch can have been walked when it ends
    (what a following item multiplies by). ``top`` marks a branch of the whole pattern,
    not of a group."""
    nodes = 0 if items else 1  # an empty branch is still one step
    paths = 1
    trailing = len(items)  # index from which only `$` items remain
    while trailing and items[trailing - 1].dollar:
        trailing -= 1
    for index, item in enumerate(items):
        if item.kind == _ATOM and item.quantified:
            attempts = _attempts(item)
            nodes += paths * (item.low + attempts)
            if not _hands_nothing_on(items, index, top, trailing):
                paths *= attempts
        elif item.kind == _GROUP and item.quantified and (item.low, item.high) == _OPTIONAL:
            nodes += paths * (1 + item.nodes)  # the body, or skipping it
            paths *= 1 + item.out
        elif item.kind == _GROUP and item.quantified:
            # a plain run of `length` atoms repeated: every repeat walks the whole run
            attempts = _attempts(item)
            nodes += paths * item.length * (item.low + attempts)
            paths *= attempts
        elif item.kind == _GROUP:
            nodes += paths * item.nodes
            paths *= item.out
        else:  # an unquantified atom or a zero-width token
            nodes += paths
        nodes = min(nodes, _COST_SATURATION)
        paths = min(paths, _COST_SATURATION)
    return nodes, paths


# A leading dot run as written and as compiled: `(?s:.*)` crosses a newline (a CNAME target decoded from
# Latin-1 bytes may hold one), `[^\n]` is the character a `+` run needs besides.
_DOT_RUNS = {".*": "(?s:.*)", ".*?": "(?s:.*?)", ".+": r"(?s:.*)[^\n]", ".+?": r"(?s:.*?)[^\n]"}


def _compile_text(pattern: str, dot_runs: list[tuple[int, int]]) -> str:
    """``pattern`` behind a written ``^``, each leading dot run (as the ``(start, end)`` offsets) spelled
    so that it crosses a newline."""
    parts: list[str] = []
    last = 0
    for start, end in dot_runs:
        parts += (pattern[last:start], _DOT_RUNS[pattern[start:end]])
        last = end
    parts.append(pattern[last:])
    return "^(?:" + "".join(parts) + ")"


def _admit(pattern: str) -> tuple[int, str]:
    """``(cost, compile_text)`` of an admitted pattern: ``compile_text`` wraps a pattern that is
    anchored only through leading ``.*`` / ``.+`` runs behind a ``^``, so the compile text carries the anchor."""
    if len(pattern) == 0:
        raise _Refusal("empty pattern")
    if len(pattern) > REGEX_PATTERN_MAX_LEN:
        raise _Refusal(f"over {REGEX_PATTERN_MAX_LEN} characters")
    if any(not "!" <= char <= "~" for char in pattern):
        raise _Refusal("non-ASCII, space or control character")
    stack = [_Frame(top=True)]
    index = 0
    width = 0
    while index < len(pattern):
        char = pattern[index]
        frame = stack[-1]
        if char == "(":
            if pattern.startswith("(?", index):
                if not pattern.startswith("(?:", index):
                    raise _Refusal(f"unsupported group at {index}")
                index += 3
            else:
                index += 1
            if len(stack) > REGEX_GROUP_DEPTH_MAX:
                raise _Refusal(f"groups nested over {REGEX_GROUP_DEPTH_MAX} at {index}")
            frame.simple = False
            stack.append(_Frame(top=False))
        elif char == ")":
            if len(stack) == 1:
                raise _Refusal(f"unbalanced ) at {index}")
            body = stack.pop()
            body.end_branch()
            index, quantifier = _quantifier(pattern, index + 1)
            # A group repeated more than optionally must be a plain run of atoms, so its
            # repeat count stays one factor of the cost instead of nesting.
            if quantifier not in (None, _OPTIONAL) and not (body.simple and body.atoms):
                raise _Refusal("quantified group")
            group = _Item(_GROUP, nodes=body.nodes, out=body.out, length=body.atoms)
            if quantifier is not None:
                group.quantified = True
                group.low, group.high = quantifier
            stack[-1].items.append(group)
        elif char == "|":
            frame.simple = False
            frame.end_branch()
            index += 1
        elif char in "^$" or pattern.startswith(("\\b", "\\B"), index):
            if char == "^" and not frame.items:
                frame.branch_anchored = True
            frame.simple = False
            frame.items.append(_Item(_ZERO, dollar=char == "$"))
            index += 1 if char in "^$" else 2
        elif char in _QUANTIFIER_START:
            raise _Refusal(f"misplaced quantifier at {index}")
        else:
            if char == "[":
                index, members, listed = _class_end(pattern, index + 1)
                width += listed
            elif char == "\\":
                kind, end = _escape(pattern, index)  # refuses an unsupported or trailing escape
                escaped = pattern[index + 1]
                members = _CLASS_ESCAPES[escaped] if kind == "class" else _fold(1 << ord(escaped))
                index = end
            elif char in "]}":
                raise _Refusal(f"unescaped {char} at {index}")
            else:
                members = _DOT if char == "." else _fold(1 << ord(char))
                index += 1
            # A leading `.*` / `.+` (greedy or lazy) anchors its branch: the run can stand for everything
            # before the match, so a match from any start position can start at 0 instead. It costs what a
            # written `^` costs.
            leading_dot_run = char == "." and frame.top and not frame.items and pattern[index : index + 1] in ("*", "+")
            run_start = index - 1  # the `.` just read
            index, quantifier = _quantifier(pattern, index)
            if leading_dot_run:
                frame.dot_runs.append((run_start, index))
                frame.items.append(_Item(_ZERO))
                frame.branch_anchored = True
            atom = _Item(_ATOM, members=members)
            if quantifier is not None:
                atom.quantified = True
                atom.low, atom.high = quantifier
            frame.atoms += 1
            frame.simple = frame.simple and quantifier is None
            frame.items.append(atom)
    if len(stack) != 1:
        raise _Refusal("unbalanced (")
    top = stack[0]
    top.end_branch()
    anchored = top.unanchored == 0
    cost = min(top.nodes * (1 if anchored else REGEX_COST_UNBOUNDED), _COST_SATURATION)
    if cost > REGEX_COST_MAX:
        # Each unanchored branch needs one caret (one node and one character).
        # Suggest it only when the anchored text fits every admission bound.
        if (
            top.nodes + top.unanchored <= REGEX_COST_MAX
            and len(pattern) + top.unanchored <= REGEX_PATTERN_MAX_LEN
            and width <= REGEX_CLASS_WIDTH_MAX
        ):
            raise _Refusal(f"too costly to match unanchored (bound {cost} > {REGEX_COST_MAX}); anchor it with ^")
        raise _Refusal(f"too costly to match (bound {cost} > {REGEX_COST_MAX})")
    if width > REGEX_CLASS_WIDTH_MAX:
        raise _Refusal(f"character classes too wide (width {width} > {REGEX_CLASS_WIDTH_MAX})")
    return cost, (_compile_text(pattern, top.dot_runs) if anchored and top.dot_runs else pattern)


def pfb_regex_admission(pattern: str) -> tuple[int, str | None, str]:
    """``(cost, None, compile_text)`` when ``pattern`` is admitted, ``(0, reason, pattern)``
    when refused.

    ``compile_text`` is the text to hand ``re.compile``: ``pattern`` as written, except that when every
    top-level branch starts with ``^``, ``.*`` or ``.+`` and at least one relies on its leading dot run it
    is ``^(?:`` + the pattern with each such run spelled to cross a newline (``.*`` as ``(?s:.*)``,
    ``.+`` as ``(?s:.*)[^\\n]``) + ``)``. A dot run stands for everything before the match, so with or
    without it the pattern matches exactly the same names, newline or not, and ``re`` skips every later
    start position of a pattern that begins with ``^``; the cost counts that pattern as anchored, so it is
    compiled as one. A refused pattern is never compiled.

    The gate is applied to FEED and user regex UNCONDITIONALLY at load (independent
    of the opt-in length cap). It admits only the constructs a host-name pattern
    needs -- printable ASCII without spaces; literals, ``.``, ``\\d\\D\\w\\W\\s\\S`` and punctuation
    escapes, ``[...]`` classes, ``(...)`` / ``(?:...)`` groups, ``|``, ``^ $ \\b \\B`` and
    the quantifiers ``? * + {m} {m,} {m,n}`` -- and bounds the work of one failed match:
    ``cost`` counts the nodes of the matcher's backtracking search tree, from every start
    position unless every top-level branch starts with ``^``, ``.*`` or ``.+`` (a leading dot
    run costs what a written ``^`` costs). A quantified atom multiplies the work
    after it, unless a disjoint mandatory atom follows it directly or nothing but ``$``
    follows it in a top-level branch; a group repeated more than
    optionally must be a plain run of atoms. The bracket classes of one pattern list at
    most ``REGEX_CLASS_WIDTH_MAX`` ASCII characters in total, because compiling a class
    costs time in proportion to what it lists. Pure static analysis of the text, one
    left-to-right parse: nothing is compiled or matched, and the reason never quotes the
    pattern. A pattern over the bound only because of the unanchored search is refused with the
    remedy: a ``^`` in front of every branch."""
    try:
        cost, compile_text = _admit(pattern)
    except _Refusal as refusal:
        return 0, str(refusal), pattern
    return cost, None, compile_text


def pfb_regex_excerpt(pattern: str) -> str:
    """Log form of a pattern: ``ascii()`` of its first 32 characters, plus its length
    when longer. Keeps feed-supplied text short and free of raw control characters."""
    excerpt = ascii(pattern[:_EXCERPT_CHARS])
    if len(pattern) <= _EXCERPT_CHARS:
        return excerpt
    return f"{excerpt} ... ({len(pattern)} chars)"


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
    print(f"line {line_number}: {pfb_regex_excerpt(pattern)}: {message}", file=sys.stderr)


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
        _cost, refusal, compile_text = pfb_regex_admission(pattern)
        if refusal is not None:
            _report(line_number, pattern, refusal)
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
            # non-empty stderr line into an admin-facing validation error. A warning
            # raised while compiling would otherwise leak this file's absolute path AND
            # its source line as two bogus errors -- warnings can resolve the source now
            # that the probe runs as a FILE rather than via ``python -c``. The resolver
            # compiles the same patterns at load without surfacing warnings either.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                re.compile(compile_text, re.IGNORECASE)
        except Exception as error:
            _report(line_number, pattern, f"Python regex compile error: {error}")
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
