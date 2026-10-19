"""pfb_dnsbl_regex_rules.py (issue #1765): single-source DNSBL regex admission
rules, shared by pfb_unbound.py and the save-time probe.

Covers what the PHP suite (tests/php/DnsblRegexEntryErrorTest.php, which drives
the probe through pfb_dnsbl_regex_validation_errors()) cannot reach directly:
standalone import-safety (the #1711 pythonmod-globals regression guard), the
probe's argv-absent default, and stdin line-ending edge cases. The
diagnostic-message classes are already pinned in DnsblRegexEntryErrorTest --
not duplicated here.
"""

from __future__ import annotations

import itertools
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, NoReturn, SupportsIndex

import pytest

import pfb_dnsbl_regex_rules as rules

PKG_DIR = Path(__file__).resolve().parent.parent / "src/usr/local/pkg/pfblockerng"
SCRIPT = PKG_DIR / "pfb_dnsbl_regex_rules.py"


def _anchored_pattern(length: int) -> str:
    """An anchored, structurally benign pattern of EXACTLY the requested length
    (mirror of DnsblRegexEntryErrorTest::anchoredPattern / test_adr07's twin)."""
    return "^" + "a" * (length - 2) + "$"


def run_probe(stdin_bytes: bytes, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        input=stdin_bytes,
        capture_output=True,
        timeout=30,
        check=False,
    )


def test_import_is_standalone_with_no_pythonmod_globals() -> None:
    """issue #1711/#1765 regression guard: the module imports clean in a bare
    interpreter -- only the pkg dir on sys.path (cwd, mirroring Unbound's
    pythonmod chdir() + sys.path.append('.')), a stripped env, no unboundmodule
    stub. Fails the moment a pythonmod-injected name (log_info, RR_TYPE_*, ...)
    lands at module scope."""
    proc = subprocess.run(
        [sys.executable, "-c", "import pfb_dnsbl_regex_rules"],
        cwd=str(PKG_DIR),
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": os.environ.get("PATH", "")},
        check=False,
    )
    assert proc.returncode == 0, f"stderr: {proc.stderr!r}"
    assert proc.stderr == ""


def test_main_defaults_cap_off_when_argv_is_absent() -> None:
    """The nowdoc this module replaced used ``len(sys.argv) > 1 and sys.argv[1] ==
    "1"`` -- pin that the missing-argv case is cap OFF: a pattern over the opt-in
    length cap (and inside the always-on admission length) is accepted with no
    argv[1] at all."""
    from pfb_dnsbl_regex_rules import REGEX_PATTERN_MAX_LEN, REGEX_STATIC_LEN_CAP

    pattern = _anchored_pattern(REGEX_STATIC_LEN_CAP + 50)
    assert REGEX_STATIC_LEN_CAP < len(pattern) <= REGEX_PATTERN_MAX_LEN
    proc = run_probe((pattern + "\n").encode("utf-8"))
    assert proc.returncode == 0, f"stderr: {proc.stderr!r}"
    assert proc.stderr == b""


def test_main_reports_only_its_own_diagnostics_for_a_pattern_that_warns() -> None:
    """A pattern that would make ``re`` emit a warning (e.g. ``[[a]]`` -> FutureWarning
    "Possible nested set") must not add anything to stderr beyond real ``line N:``
    diagnostics.

    Every non-empty stderr line becomes an admin-facing validation error
    (pfb_dnsbl_regex_validation_errors() -> $input_errors on pfblockerng_dnsbl.php,
    and a line-1 lint diagnostic via pfb_lint_parse_regex_errors()). Running the
    rules module as a FILE rather than ``python -c`` lets ``warnings`` resolve the
    source, so an unsuppressed warning would leak BOTH this module's absolute path
    and a bare ``re.compile(pattern)`` source line to the admin as bogus errors.
    """
    # Line 1 would warn if compiled; line 2 is a second rejection, so the process exits
    # 1 and PHP reads stderr -- the case where a leak would surface.
    proc = run_probe(b"[[a]+[c]+x\n(a+)+\n", "0")
    assert proc.returncode == 1
    assert proc.stderr.decode("utf-8").splitlines() == [
        "line 1: '[[a]+[c]+x': nested class at 1",
        "line 2: '(a+)+': quantified group",
    ], proc.stderr


def test_main_ignores_a_warning_raised_while_compiling_an_admitted_pattern(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The grammar refuses every construct ``re`` warns about, but the compile step still
    runs with warnings silenced: a warning that did escape would become a bogus admin
    error. Run with warnings as errors, an unsilenced one fails the line."""
    import io
    import re
    import warnings

    real_compile = re.compile

    def compile_with_warning(pattern: Any, flags: int = 0) -> Any:
        warnings.warn("simulated compile warning", FutureWarning, stacklevel=2)
        return real_compile(pattern, flags)

    monkeypatch.setattr(rules.re, "compile", compile_with_warning)
    monkeypatch.setattr(sys, "stdin", io.StringIO("^ok\\.example$\n"))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert rules.main(["probe"]) == 0
    assert capsys.readouterr().err == ""


def test_probe_and_resolver_agree_on_every_admission_verdict() -> None:
    """The save-time probe and the resolver's load-time gate give one verdict per pattern.
    ``main()`` is a separate caller of ``pfb_regex_admission`` (it adds the control-character
    and opt-in length checks and the compile) while the resolver calls the gate directly.

    This pin is the admission axis only. Compile, length-cap and control-character rejects
    are covered by DnsblRegexEntryErrorTest (PHP probe) and are skipped here.
    """
    import io

    from pfb_dnsbl_regex_rules import main, pfb_regex_admission

    def main_rejects_admission(pattern: str) -> bool | None:
        """Return whether ``main()`` rejected on admission, or None if it rejected for
        compile/control/length cap (not this pin)."""
        old_in, old_err = sys.stdin, sys.stderr
        try:
            sys.stdin = io.StringIO(pattern + "\n")
            captured = io.StringIO()
            sys.stderr = captured
            rc = main(["probe"])
        finally:
            sys.stdin, sys.stderr = old_in, old_err
        err = captured.getvalue()
        if rc == 0:
            return False
        if any(text in err for text in ("control character", "compile error", "length cap")):
            return None
        return True

    # Single lines the probe reads whole: no comment marker, no padding, not empty.
    rows = [pattern for pattern, _cost in ADMITTED_COSTS] + list(REFUSED)
    corpus = [pattern for pattern in rows if pattern and pattern == pattern.strip() and "#" not in pattern]
    corpus = [pattern for pattern in corpus if len(pattern) < 1000]
    # The hand-written rows above only cover constructs known today, so they cannot
    # catch a FUTURE rule wired into one caller and not the other. Enumerate every
    # 4-way combination of the regex building blocks a rule can be written over,
    # so a new rule of ANY structural shape lands in this corpus. Combination, not
    # random fuzz: a rule keyed on a 3-character construct like "(?:" is astronomically
    # unlikely to be produced by random sampling, and would slip through unnoticed.
    blocks = ("(", ")", "(?:", "[a-z]", "a", ".", "+", "*", "{2}", "|", "\\", "$")
    corpus += ["".join(combination) for combination in itertools.product(blocks, repeat=4)]

    compared = {True: 0, False: 0}
    for pattern in corpus:
        probe_rejects = main_rejects_admission(pattern)
        if probe_rejects is None:
            continue
        compared[probe_rejects] += 1
        resolver_rejects = pfb_regex_admission(pattern)[1] is not None
        assert probe_rejects == resolver_rejects, (
            f"probe and resolver disagree on {pattern!r}: "
            f"probe rejects={probe_rejects}, resolver rejects={resolver_rejects}"
        )
    assert compared[True] and compared[False], f"corpus never exercised both verdicts: {compared}"


def test_probe_and_resolver_both_reject_an_adjacent_quantifier_run() -> None:
    """issue #2035: a run of ungrouped adjacent quantified atoms must be refused by BOTH
    consumers -- the save-time probe and the resolver's load-time gate.

    The rule lives in the one shared module, so this drives both surfaces the way they are
    really used: ``main()`` through a subprocess (what pfb_dnsbl_regex_validation_errors()
    runs) and the gate (what pfb_unbound.py imports).
    """
    from pfb_dnsbl_regex_rules import pfb_regex_admission

    pattern = r"^[a-z]+[a-z]+[a-z]+[a-z]+@example\.com$"
    reason = "too costly to match (bound 4546757122 > 262144)"
    assert pfb_regex_admission(pattern)[:2] == (0, reason)

    proc = run_probe((pattern + "\n").encode("utf-8"), "1")
    assert proc.returncode == 1, f"probe admitted {pattern!r}"
    assert proc.stderr.decode("utf-8").splitlines() == [
        f"line 1: {ascii(pattern[:32])} ... ({len(pattern)} chars): {reason}"
    ], proc.stderr


def test_admission_gate_stays_total_on_malformed_pattern_fragments() -> None:
    """The gate reads the pattern STRING before anything compiles it, so it is handed
    fragments ``re`` itself would reject -- an unterminated class, a dangling backslash, a
    half-written repeat. Each must return a verdict rather than raise, or a single bad feed
    line becomes an unhandled exception on the resolver's load path."""
    from pfb_dnsbl_regex_rules import pfb_regex_admission

    for fragment in (
        "",
        "[a-z",
        "[^",
        "[]",
        "\\",
        "\\x",
        "\\u00",
        "\\N{",
        "a{",
        "a{2,",
        "**",
        "((((",
        ")+",
        "(?",
        "(?(",
        "(?(1",
        "(?(1)",
        "(?(1)a",
        "(?(1)a|b",
        "(?(1))",
        "(?i",
        "(?i:",
        "(?>",
        "(?>a",
        "(?aiLmsux-imsx:x)",
        "(?-:x)",
        "(?P=",
        "(?P=g",
        "(?P=g)",
        "(a|b",
        "(a|(b",
        "(a|(b))",
        "(?>a)",
        "\\1",
        "([a-z])\\1",
        "[a-z]+" * 500,
        "a" * 5000 + "+",
    ):
        cost, reason, _text = pfb_regex_admission(fragment)
        assert (reason is None) == (cost > 0), fragment
    # A construct the grammar has no place for is refused whatever follows it: the gate
    # does not go blind from the first `(?#` onwards.
    for fragment in (r"(?#x\w+\w+\w+", r"(?=a\w+\w+\w+", r"(?i:\w+\w+\w+"):
        assert pfb_regex_admission(fragment)[1] is not None, fragment


def test_probe_and_resolver_agree_on_issue2364_admission_rows() -> None:
    """issue #2364's separator spellings. Under the bounded grammar the conditional and
    atomic spellings are refused as unsupported groups and the plain runs by their cost
    bound; the anchored host patterns whose runs are separated by dots stay admitted. The
    probe reports exactly the refusals the resolver's gate returns."""
    from pfb_dnsbl_regex_rules import pfb_regex_admission

    rows = (
        (r"^([a-z])(?(1)[a-z]+[a-z]+[a-z]+[a-z]+|b)@x\.com$", True),
        (r"^(a)?(?(1)b|[a-z]+[a-z]+[a-z]+[a-z]+)@x\.com$", True),
        (r"^[a-z]+[a-z]+(?>ab)[a-z]+[a-z]+@x\.com$", True),
        (r"^[a-z]+[a-z]+(foo|foobar)[a-z]+[a-z]+@x\.com$", True),
        (r"^[a-z]+[a-z]+(a|(?:b))+[a-z]+[a-z]+@x\.com$", True),
        (r"^(a)?(?(1)[a-z]+[a-z]+|[a-z]+[a-z]+)$", True),
        (r"^[a-z]+[a-z]+(?>12)[a-z]+[a-z]+$", True),
        (r"^[a-z]+[a-z]+(\+|\*)[a-z]+[a-z]+$", True),
        (r"^xn--bcher-kva\.[a-z]+$", False),
        (r"^[a-z]+\.[a-z]+\.[a-z]+$", False),
    )
    for pattern, expected in rows:
        assert (pfb_regex_admission(pattern)[1] is not None) is expected, pattern

    proc = run_probe(("".join(pattern + "\n" for pattern, _ in rows)).encode("utf-8"), "0")
    assert proc.returncode == 1
    diagnostics = proc.stderr.decode("utf-8").splitlines()
    refused = [(number, pattern) for number, (pattern, rejected) in enumerate(rows, 1) if rejected]
    assert len(diagnostics) == len(refused)
    for diagnostic, (number, pattern) in zip(diagnostics, refused, strict=True):
        assert diagnostic.startswith(f"line {number}: {ascii(pattern[:32])}"), diagnostic
        assert diagnostic.endswith(f": {pfb_regex_admission(pattern)[1]}"), diagnostic


def test_probe_and_resolver_both_reject_an_overlapping_separator_run() -> None:
    """issue #2082: a mandatory atom overlapping its neighbours must not split a run of
    unbounded quantifiers into harmless halves. Same two surfaces as the #2035 twin above:
    the gate the resolver imports, and ``main()`` the way pfb_dnsbl_regex_validation_errors()
    runs it."""
    from pfb_dnsbl_regex_rules import pfb_regex_admission

    pattern = r"^[a-z]+[a-z]+a[a-z]+[a-z]+@x\.com$"
    reason = "too costly to match (bound 4446159362 > 262144)"
    assert pfb_regex_admission(pattern)[:2] == (0, reason)

    proc = run_probe((pattern + "\n").encode("utf-8"), "0")
    assert proc.returncode == 1, f"probe admitted {pattern!r}"
    assert proc.stderr.decode("utf-8").splitlines() == [
        f"line 1: {ascii(pattern[:32])} ... ({len(pattern)} chars): {reason}"
    ], proc.stderr


def test_main_treats_crlf_terminated_lines_like_lf() -> None:
    """A regex-list body with CRLF line endings splits into the same lines (and
    reports the same line numbers) as an LF-only body; a control character in a
    pattern is refused by the admission grammar like any other character outside it."""
    body = b"^ads\x01$\r\n(a+)+\r\n^ok$\r\n"
    proc = run_probe(body)
    assert proc.returncode == 1
    assert proc.stderr.decode("utf-8").splitlines() == [
        "line 1: '^ads\\x01$': non-ASCII, space or control character",
        "line 2: '(a+)+': quantified group",
    ], proc.stderr


def test_main_does_not_hang_on_a_lone_cr_with_no_newline() -> None:
    """A regex-list body using bare CR (old-Mac style) line endings with no '\\n'
    anywhere is NOT split by ``sys.stdin`` (unlike CRLF, which still carries a
    real '\\n' for the line-terminator search) -- Python's text stdin only treats
    '\\n' as a line boundary here, so the whole blob is read as ONE line. Pin
    the safe outcome: no hang, and the embedded control bytes (CR itself is
    0x0D, an ASCII control character) make the admission grammar refuse that one
    line -- never a crash, never a silent pass."""
    body = b"^ads\x01$\r(a+)+\r^ok$\r"
    proc = run_probe(body)
    assert proc.returncode == 1
    stderr = proc.stderr.decode("utf-8")
    assert stderr.startswith("line 1:")
    assert stderr.count("line ") == 1, f"expected the whole blob read as one line, got: {stderr!r}"
    assert stderr.endswith(": non-ASCII, space or control character\n"), stderr


# --------------------------------------------------------------------------- #
# Admission grammar: a bounded allowlist, judged without running the pattern text
# --------------------------------------------------------------------------- #

# Generous outer watchdog for the child-process rows: it only salvages a run that never
# returns (the child is killed and reaped and the row fails as STUCK). Duration is never
# an assertion -- completion and the verdicts are.
WATCHDOG_SECONDS = 10

MAX_LEN = 256
COST_MAX = 1 << 18
CLASS_WIDTH_MAX = 256


def _brief(pattern: str) -> str:
    return ascii(pattern[:40]) + (f" ... ({len(pattern)} chars)" if len(pattern) > 40 else "")


# Every row the grammar must refuse, whatever the reason (the reason has its own rows).
REFUSED = [
    "",
    "a" * (MAX_LEN + 1),
    "a" * 1_000_000,
    "é",
    "a b",
    "a\tb",
    "a\x00",
    "(",
    ")",
    "[",
    "[]",
    "[^]",
    "[z-a]",
    "[[a]]",
    "[a--b]",
    "[\\b]",
    "(?=a)",
    "(?!a)",
    "(?<=a)",
    "(?<!a)",
    "(?P<n>a)",
    "(?P=n)",
    "(?i)a",
    "(?#c)",
    "(?(1)a|b)",
    "(?>a)",
    "\\1",
    "\\g<1>",
    "\\x41",
    "\\u0041",
    "\\U00000041",
    "\\N{DIGIT ONE}",
    "\\0",
    "\\t",
    "\\A",
    "\\Z",
    "a\\",
    "[\\x00-\\U0010ffff]",
    "a{256}",
    "a{4294967296}",
    "a{5,3}",
    "a{,3}",
    "a{",
    "a{x}",
    "a**",
    "a*+",
    "a{2}{3}",
    "+a",
    "^*",
    "\\b+",
    "(|a)+",
    "(" * 9 + "a" + ")" * 9,
    "[\\d-a]",
    "[a-\\d]",
    "[+--]",
    "a}",
    "a]",
    "(a+)+",
    "(a|b)+",
    "(a?){5}",
    "((a))+",
    "(.*a){20}",
    "a{1,256}",
    "[a-z]+[a-z]+x",
    "^a?a?a?a?a?.*.*x",
    "^[a-z]{1,255}[a-z]{1,255}[a-z]{1,255}x",
    "()+",
    "(?:)*",
    "(){2}",
    "(^a)+",
    r"(\ba)+",
    "(a$){3}",
    "(a(b+))+",
    "(a(b))+",
    r"\B+",
    r"(\Ba)+",
    "[a&&b]",
    "[a~~b]",
    "[a||b]",
    "^a?a?a?a?.*.*x",
    "^[a-z]+[a-z]+[a-z]+x",
    "^" + "(a|a)" * 20 + "x",
    "^" + "a?" * 16 + "a" * 216 + "b",
    "^" + "a?" * 20 + "a" * 208 + "b",
    "^" + ".?" * 20 + "." * 208 + "b",
    "^" + "a?" * 12 + "a" * 224 + "b",
    "^" + "[!-~]" * 6 + "x",
]

# Rows the grammar must admit, with the exact cost bound it computes for each.
ADMITTED_COSTS = [
    (r"^(.+\.)?ads?[0-9]*\.example\.(com|net|org)$", 143921),
    (r"^[a-z0-9-]+\.[a-z0-9-]+\.[a-z]{2,}$", 776),
    (r"\d+\.\d+", 131840),
    (r"[a-z]+[0-9]+\.example\.com", 134656),
    (r"^[^.]+\.[^.]+\.[^.]+\.example$", 783),
    (r"^[a-z]+\.[a-z]+\.[a-z]+$", 775),
    (r"metrics?-[0-9a-f]{6,}\.example$", 71680),
    ("cdn[0-9]+", 66560),
    ("analytics", 2304),
    (r"^cdn[a-z]{1,3}\.ads\.example$", 21),
    ("^[a-z]+[a-z]+x", 131586),
    ("^" + "(a|a)" * 16 + "x", 196607),
    ("a{255}" * 4, COST_MAX),  # exactly at the bound
    ("(ab)+", 131584),
    ("^(ab)+c", 771),  # a repeated plain run multiplies what follows it
    (r"^\w+_", 514),  # `_` is a word character: the run and the next atom overlap
    ("^a+A", 514),  # letters fold: `a` also matches `A`
    ("^[a-c]+c", 514),  # the upper end of a class range is a member
    (r"^(\.[a-z]){2}x", 8),
    (r"^xn--[a-z0-9-]+\.example$", 271),
    ("a|", 512),  # an empty branch is still a step
    ("|", 512),
    ("()", 256),
    ("a||b", 768),
    ("(|a)b", 1024),
    ("^a|^b", 4),
    ("a|^b", 768),  # one branch is not anchored: the whole pattern is searched from every position
    ("a^", 512),  # a `^` that does not lead its branch does not anchor it
    (r"\B", 256),
    (r"\/ads\/", 1280),
    ("ad#1", 1024),
    ("[-a]", 256),
    ("[a-]", 256),
    ("[^.]", 256),
    ("[!-~]", 256),
    ("a*?", 65536),
    ("a{0,1}", 512),
    ("(" * 8 + "a" + ")" * 8, 256),
    ("a" * MAX_LEN, 65536),
    ("a{255}", 65536),
    ("^a{1,255}", 257),
    ("[a-z-9]", 256),
    ("[a-a]", 256),
    (r"[\d-]", 256),
    (r"^(a\))x", 4),  # an escaped `)` inside a group is a literal, not the group's end
    # A branch that starts with `.*` or `.+` is anchored (see LEADING_DOT_PAIRS): `.*ads.*` costs what `^.*ads.*` does.
    (".*ads.*", 66561),
    (".*", 257),
    # The anchored forms of the patterns the unanchored search refuses (ANCHOR_REMEDY_REFUSALS).
    (r"^\S+\.EXAMPLE\.COM", 3330),
    (r"^\D+\.EXAMPLE\.COM", 3330),
    (r"^\W+\.EXAMPLE\.COM", 3330),
    (r"^ad.*\.example\.com", 3331),
    ("^a+b{1,255}a?a*a", COST_MAX),  # the caret costs one node: exactly at the bound
]

# Refused only because the bound on its backtracking work is exceeded, with that bound.
COST_REFUSALS = [
    ("a?" * 128, 1 << 64),  # the bound saturates, so the reason stays short
    ("^" + "a?" * 12 + "a" * 224 + "b", 929791),  # a long mandatory tail behind a dozen optional atoms
    ("^[a-z]{1,60}[a-z]{1,60}[a-z]{1,60}x", 439322),
    ("^" + "(a|a)" * 17 + "x", 393215),
    ("^a?a?a?a?.*.*x", 2101279),
    ("^a?a?a?a?a?.*.*x", 4202559),
    ("^[a-z]+[a-z]+[a-z]+x", 33686018),
    ("^[a-z]+a[a-z]+a[a-z]+1$", 17105666),
    ("^" + "(a|a)" * 20 + "x", 3145727),
    ("^" + "a?" * 16 + "a" * 216 + "b", 14352383),
    ("^" + "a?" * 20 + "a" * 208 + "b", 221249535),
    ("^" + ".?" * 20 + "." * 208 + "b", 221249535),
    ("^[a-z]{1,255}[a-z]{1,255}[a-z]{1,255}x", 33293312),
]

# Unanchored and over the bound even with a `^` in front of every branch, so the reason offers no
# remedy that would not work.
UNANCHORED_PLAIN_REFUSALS = [
    ("[a-z]+[a-z]+[a-z]+x", 8623620352),
    ("a*a+b{1,255}a?", 67108864),  # 262144 nodes: the caret itself costs one more
    ("a*b{1,255}a?a*a|x", 67108608),  # two branches need two carets
]

# Over the bound only because an unanchored search starts a match at every position of the name
# (x256): with a `^` in front of every branch the pattern fits.
ANCHOR_REMEDY_REFUSALS = [
    ("a{255}" * 4 + "a", 262400),  # one node over the bound
    ("[a-z]+[a-z]+x", 33685760),
    (r"\S+\.EXAMPLE\.COM", 852224),
    (r"\D+\.EXAMPLE\.COM", 852224),
    (r"\W+\.EXAMPLE\.COM", 852224),
    (r"ad.*\.example\.com", 852480),
    ("a+b{1,255}a?a*a", 67108608),  # with the caret it is exactly at the bound
]


# The bound on the ASCII members that the bracket classes of one pattern list, summed. A class
# lists its members before any `^` negation; letters fold, so `[a-z]` lists 52; `\d \w \s \D \W \S`
# inside a bracket list their ASCII members; `.` and the bare escapes list none.
WIDTH_REFUSALS = [
    ("^" + "[!-~]" * 3 + "x", 282),  # printable ASCII listed three times
    ("^" + "[!-~]" * 6 + "x", 564),
    ("^" + "[!-~]" * 49 + "x0001", 4606),  # cheap to match, milliseconds to compile
    ("^" + "[a-z]" * 5 + "x", 260),  # folded: 52 each, not 26
    ("^" + "[^!-~]" * 3 + "x", 282),  # counted before the negation, not after
    ("^" + r"[\w]" * 5 + "x", 315),  # 63 ASCII members, no non-ASCII stand-in
    ("^" + r"[\W]" * 4 + "x", 260),
    ("^" + r"[\D]" * 3 + "x", 354),
    ("^" + r"[\S]" * 3 + "x", 354),
    ("^" + r"[\d]" * 26 + "x", 260),
    ("^" + r"[\s]" * 26 + "x", 260),
    ("^(?:" + "|".join(["[!-~]"] * 3) + ")x", 282),  # summed across the branches of a group
    ("^" + r"[\w.-]" * 9 + "x", 585),
    ("^[!-~][!-~][abcdefghijklmnopqrstuvwxyz0123456789!#%&][!][#][%]x", 257),  # a 40-item class counts in full
]

# Admitted rows: the exact cost bound, and in the comment the class width that stays under the bound.
WIDTH_ADMITTED = [
    (r"^[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+\.example$", 1041),  # 252
    ("^" + "[!-~]" * 2 + "x", 4),  # 188
    ("^" + "[a-z]" * 4 + "x", 6),  # 208, folded
    ("^" + "[^a]" * 60 + "x", 62),  # 120 listed, although each class matches 126 ASCII characters
    ("^" + r"[\w]" * 4 + "[!]" * 4 + "x", 10),  # 256: [\w] lists 63
    ("^" + "[!-@]" * 8 + "." * 50 + "x", 60),  # `.` lists nothing: still exactly at the bound
    ("^" + r"[\d]" * 25 + "x", 27),  # 250
    ("^" + r"[\s]" * 25 + "x", 27),  # 250
    ("^" + r"[\D]" * 2 + "x", 4),  # 236
    ("^" + r"[\W]" * 3 + "x", 5),  # 195
    ("^(?:[!-~]|[!-~])x", 5),  # 188
    ("^" + r"\w" * 60 + "x", 62),  # bare escapes list nothing
    ("^" + r"\D\W\S\d\w\s" * 20 + ".x", 123),
]


# A pattern whose every branch starts with `^`, `.*` or `.+` (greedy or lazy) is anchored: a leading dot
# run can stand for everything before the match, so it matches from position 0 exactly when it matches
# from some start position, and the leading run costs what the same run behind a written `^` costs.
# (unanchored form, the same pattern with `^` written in, its cost bound)
LEADING_DOT_PAIRS = [
    (r".*\.microsoft\.com$", r"^.*\.microsoft\.com$", 4097),
    (r".+\.x\.com$", r"^.+\.x\.com$", 2050),
    (".*ads.*", "^.*ads.*", 66561),
    (".+ads.+", "^.+ads.+", 66818),
    (".*?a", "^.*?a", 513),
    (".+?a", "^.+?a", 514),
    (".*a|.+b", "^.*a|^.+b", 1027),
    (".*a|^b", "^.*a|^b", 515),
    (".*", "^.*", 257),
    (".+", "^.+", 258),
]

# A leading `.*` or `.+` anchors only as the very first item of a top-level branch: another quantifier
# (`.?` is optional, not a run), a group around it or a class standing in for the dot keep the unanchored
# search (every start position).
UNANCHORED_DOT_ROWS = [
    ("(.*)x", 131072),
    ("[^.]*x", 131072),
    (".{2,}x", 131584),
    ("a|.*b", 131584),  # one branch is not anchored, so the whole pattern is searched from every position
    (".*a|b", 131584),
    ("(?:.*a)|b", 131328),
    (".?x", 1024),
    (".??x", 1024),
]

# The compile text (third item of the admission result): the text a pattern is compiled from. A pattern
# that is anchored only through a leading `.*` / `.+` is compiled behind a written `^` so the engine
# itself skips every other start position, and each such leading run is spelled so that it crosses a
# newline exactly as an unanchored search does: `.*` as `(?s:.*)`, `.+` as `(?s:.*)[^\n]` (lazy forms
# likewise). Every other pattern is compiled as written.
COMPILE_TEXT = [
    (".*a|.+b", r"^(?:(?s:.*)a|(?s:.*)[^\n]b)"),
    (r".*\.microsoft\.com$", r"^(?:(?s:.*)\.microsoft\.com$)"),
    (".+?a", r"^(?:(?s:.*?)[^\n]a)"),
    (".*?a", r"^(?:(?s:.*?)a)"),
    (".+a", r"^(?:(?s:.*)[^\n]a)"),
    ("^a|.*b", r"^(?:^a|(?s:.*)b)"),
    (".*a|^b", r"^(?:(?s:.*)a|^b)"),
    (".*ads.*", r"^(?:(?s:.*)ads.*)"),  # only the leading run is rewritten
    (".*", r"^(?:(?s:.*))"),
    (".+", r"^(?:(?s:.*)[^\n])"),
    # compiled as written: not anchored, anchored by `^` alone, or refused
    ("a|.*b", "a|.*b"),
    ("(.*)x", "(.*)x"),
    ("[^.]*x", "[^.]*x"),
    (".{2,}x", ".{2,}x"),
    (".?x", ".?x"),
    (".??x", ".??x"),
    ("^.*x", "^.*x"),
    ("^.+x", "^.+x"),
    ("^.*?x", "^.*?x"),
    ("^a|^b", "^a|^b"),
    ("abc", "abc"),
    ("(.*a)+", "(.*a)+"),
]


class _NoRe:
    """Stands in for the ``re`` module: any attribute access fails the test."""

    def __getattr__(self, name: str) -> NoReturn:
        raise AssertionError(f"the gate reached for re.{name} while judging feed-supplied pattern text")


class _LengthOnly(str):
    """A pattern that claims one million characters and answers no other question: the
    length check must settle it before anything reads, iterates or searches the text."""

    def __len__(self) -> int:
        return 1_000_000

    def __iter__(self) -> NoReturn:
        raise AssertionError("the gate iterated an oversized pattern")

    def __getitem__(self, key: SupportsIndex | slice) -> NoReturn:
        raise AssertionError("the gate indexed an oversized pattern")

    def __contains__(self, key: object) -> NoReturn:
        raise AssertionError("the gate searched an oversized pattern")

    def isascii(self) -> NoReturn:
        raise AssertionError("the gate scanned an oversized pattern")

    def startswith(self, *args: Any) -> NoReturn:
        raise AssertionError("the gate scanned an oversized pattern")

    def find(self, *args: Any) -> NoReturn:
        raise AssertionError("the gate scanned an oversized pattern")

    def encode(self, *args: Any, **kwargs: Any) -> NoReturn:
        raise AssertionError("the gate encoded an oversized pattern")


def test_gate_never_compiles_or_matches_feed_pattern_text(monkeypatch: pytest.MonkeyPatch) -> None:
    """The verdict is reached by reading the text once, never by handing any piece of
    it to the regex engine: with ``re`` unreachable the gate still answers every row."""
    monkeypatch.setattr(rules, "re", _NoRe())
    benign = [pattern for pattern, _cost in [*ADMITTED_COSTS, *WIDTH_ADMITTED, *UNANCHORED_DOT_ROWS]]
    benign += [pattern for pattern, _anchored, _cost in LEADING_DOT_PAIRS]
    benign += [pattern for pattern, _text in COMPILE_TEXT]
    wide = [pattern for pattern, _width in WIDTH_REFUSALS]
    for pattern in [*benign, *REFUSED, *wide, "[a-z]+[a-z]+[a-z]+[a-z]+", r"^([a-z]+)\1$", "(a+)(a+)+"]:
        cost, reason, compile_text = rules.pfb_regex_admission(pattern)
        assert isinstance(cost, int) and (reason is None or isinstance(reason, str)), _brief(pattern)
        assert isinstance(compile_text, str), _brief(pattern)


def test_gate_module_keeps_no_compiled_patterns_of_its_own() -> None:
    """A regex applied to the pattern text would itself be exposed to hostile input, so
    the module holds none: no compiled pattern at module scope."""
    import re

    held = sorted(name for name, value in vars(rules).items() if isinstance(value, re.Pattern))
    assert held == [], f"module-level compiled patterns: {held}"


def test_oversized_pattern_is_refused_from_its_length_alone() -> None:
    """The length ceiling is checked before any scan, so a megabyte pattern costs one
    ``len()`` call: the stand-in below fails on any attempt to read its text."""
    cost, reason, _text = rules.pfb_regex_admission(_LengthOnly("a"))
    assert (cost, reason) == (0, f"over {MAX_LEN} characters")


_HOSTILE_CHILD = """
SIZES = (2_000, 32_000, 1_000_000)
BIG = {
    "unclosed-group-plus-run": lambda size: "(a" + "+" * (size - 2),
    "open-groups": lambda size: "(" * size,
    "nested-alternation": lambda size: "(?:a|" * (size // 7) + "b" + ")" * (size // 7),
    "class-plus-run": lambda size: "[a-z]+" * (size // 6),
}
SMALL = {
    "groups-to-the-depth-limit": "(" * 8 + "a" + ")" * 8,
    "groups-past-the-depth-limit": "(" * 9 + "a" + ")" * 9,
    "open-groups-to-the-length-limit": "(" * 256,
    "unclosed-group-plus-run": "(a" + "+" * 250,
    "alternation-nested-to-the-depth-limit": "(?:a|" * 8 + "b" + ")" * 8,
    "alternation-chain": "|".join(["ab"] * 60),
    "optional-chain": "a?" * 128,
    "class-plus-run": "[a-z]+" * 42,
    "class-of-many-items": "[" + "a" * 254 + "]",
    "wide-classes": "^" + "[!-~]" * 49 + "x0001",
}
big = []
for family, build in BIG.items():
    for size in SIZES:
        pattern = build(size)
        cost, reason, _text = gate(pattern)
        big.append([family, len(pattern), reason])
small = {name: [*gate(pattern)[:2], len(pattern)] for name, pattern in SMALL.items()}
print(json.dumps({"big": big, "small": small}))
"""

_GENERATED_CHILD = """
import random, re, warnings

SEED = 0x5EED
ATOMS = ["a", "b", "1", "-", r"\\.", ".", "[a-z]", "[a-z0-9-]", r"\\w", r"\\d", "[^.]", "a", "[ab]"]
QUANTS = ["", "", "", "?", "*", "+", "{1,3}", "{2,}", "{1,60}", "{1,255}", "{2}", "+", "*"]
GROUPS = ["(ab)", "(?:a|b)", r"(\\.[a-z])", "(a?b)", "(?:a|)", "(.*a)", "(a+)", r"([a-z]+\\.)"]
TAILS = ["", "#", "x", "$", "#", "x"]  # '#' and 'x' never occur in the names: forces full backtracking
NAMES = ["a" * 253, ("a." * 127)[:253], ("ab-1." * 60)[:253]]


def generate(rng):
    parts = ["^"] if rng.random() < 0.5 else []
    for _ in range(rng.randint(2, 7)):
        unit = rng.choice(GROUPS) if rng.random() < 0.2 else rng.choice(ATOMS)
        parts.append(unit + rng.choice(QUANTS))
    parts.append(rng.choice(TAILS))
    return "".join(parts)


rng = random.Random(SEED)
admitted = refused = 0
unclean = []
for _ in range(400):
    pattern = generate(rng)
    cost, reason, _text = gate(pattern)
    if reason is not None:
        refused += 1
        continue
    admitted += 1
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            compiled = re.compile(rules.pfb_regex_admission(pattern)[2], re.IGNORECASE)
    except Exception as error:
        unclean.append([pattern, repr(error)])
        continue
    for name in NAMES:
        compiled.search(name)
print(json.dumps({"admitted": admitted, "refused": refused, "unclean": unclean}))
"""

_CHILD_PRELUDE = """
import json, sys
sys.path.insert(0, sys.argv[1])
import pfb_dnsbl_regex_rules as rules
gate = rules.pfb_regex_admission
"""


def _run_in_child(body: str) -> Any:
    """Run ``body`` (with ``gate`` and ``json`` in scope) in a killable child interpreter
    and return its JSON output; a child that does not return fails the row as STUCK."""
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _CHILD_PRELUDE + body, str(PKG_DIR)],
            capture_output=True,
            text=True,
            timeout=WATCHDOG_SECONDS,
            check=True,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"STUCK: child did not return within {WATCHDOG_SECONDS}s")
    except subprocess.CalledProcessError as error:
        pytest.fail(f"child failed (exit {error.returncode}): {error.stderr[-600:]}")
    return json.loads(proc.stdout)


def test_gate_settles_hostile_patterns_of_any_size_without_stalling() -> None:
    """Unclosed-group runs, open-group floods, deep alternation and class runs of 2,000 up
    to a million characters are each refused on length and the gate returns for all of
    them. Hostile shapes that fit the length ceiling reach the scan and the cost walk:
    they are settled with their own verdicts, within the same watchdog."""
    verdicts = _run_in_child(_HOSTILE_CHILD)
    assert len(verdicts["big"]) == 12
    wrong = [row for row in verdicts["big"] if row[2] != f"over {MAX_LEN} characters"]
    assert wrong == [], f"expected refusal on length for every row, got: {wrong}"

    small = verdicts["small"]
    assert max(length for _cost, _reason, length in small.values()) <= MAX_LEN
    admitted = {name: cost for name, (cost, reason, _length) in small.items() if reason is None}
    assert admitted == {
        "groups-to-the-depth-limit": 256,
        "alternation-nested-to-the-depth-limit": 2304,
        "alternation-chain": 30720,
        "class-of-many-items": 256,
    }
    refused = {name: reason for name, (_cost, reason, _length) in small.items() if reason is not None}
    assert refused.keys() == {
        "groups-past-the-depth-limit",
        "open-groups-to-the-length-limit",
        "unclosed-group-plus-run",
        "optional-chain",
        "class-plus-run",
        "wide-classes",
    }
    for name, fragment in (
        ("groups-past-the-depth-limit", "nested"),
        ("open-groups-to-the-length-limit", "nested"),
        ("unclosed-group-plus-run", "quantifier"),
        ("optional-chain", "too costly to match"),
        ("class-plus-run", "too costly to match"),
        ("wide-classes", "character classes too wide"),
    ):
        assert fragment in refused[name], (name, refused[name])


def test_every_admitted_generated_pattern_compiles_clean_and_searches_hostile_names_to_completion() -> None:
    """Whatever the grammar admits compiles without warnings, and the child returns after
    searching every admitted pattern of a fixed-seed corpus against 253-character names
    built to force backtracking. Duration is never asserted: the watchdog only salvages a
    child that never returns, failing the row as STUCK."""
    result = _run_in_child(_GENERATED_CHILD)
    assert result["unclean"] == [], f"admitted but did not compile cleanly: {result['unclean']}"
    # Non-vacuity: the corpus exercises both verdicts in volume.
    assert result["admitted"] >= 50, result
    assert result["refused"] >= 50, result


@pytest.mark.parametrize("pattern", REFUSED, ids=_brief)
def test_pattern_outside_the_grammar_is_refused(pattern: str) -> None:
    cost, reason, _text = rules.pfb_regex_admission(pattern)
    assert (cost, reason is not None) == (0, True), f"expected a refusal of {_brief(pattern)}, got cost={cost}"


@pytest.mark.parametrize(("pattern", "expected_cost"), ADMITTED_COSTS, ids=[_brief(p) for p, _ in ADMITTED_COSTS])
def test_admitted_pattern_reports_its_backtracking_bound(pattern: str, expected_cost: int) -> None:
    cost, reason, _text = rules.pfb_regex_admission(pattern)
    assert (cost, reason) == (expected_cost, None), (
        f"{_brief(pattern)}: expected cost {expected_cost}, got {(cost, reason)}"
    )


@pytest.mark.parametrize(("pattern", "bound"), COST_REFUSALS, ids=[_brief(p) for p, _ in COST_REFUSALS])
def test_pattern_over_the_cost_bound_is_refused_and_names_the_bound(pattern: str, bound: int) -> None:
    cost, reason, _text = rules.pfb_regex_admission(pattern)
    assert cost == 0, _brief(pattern)
    assert reason == f"too costly to match (bound {bound} > {COST_MAX})", reason


@pytest.mark.parametrize(
    ("pattern", "bound"), ANCHOR_REMEDY_REFUSALS, ids=[_brief(p) for p, _ in ANCHOR_REMEDY_REFUSALS]
)
def test_a_pattern_refused_only_for_its_unanchored_search_says_so_and_names_the_remedy(
    pattern: str, bound: int
) -> None:
    cost, reason, _text = rules.pfb_regex_admission(pattern)
    assert cost == 0, _brief(pattern)
    assert reason == f"too costly to match unanchored (bound {bound} > {COST_MAX}); anchor it with ^", reason
    # The remedy it names works: a `^` in front of every branch admits the pattern.
    anchored = "|".join("^" + branch for branch in pattern.split("|"))
    assert rules.pfb_regex_admission(anchored)[1] is None, _brief(anchored)


@pytest.mark.parametrize(
    ("pattern", "bound"), UNANCHORED_PLAIN_REFUSALS, ids=[_brief(p) for p, _ in UNANCHORED_PLAIN_REFUSALS]
)
def test_a_pattern_a_caret_would_not_save_keeps_the_plain_reason(pattern: str, bound: int) -> None:
    cost, reason, _text = rules.pfb_regex_admission(pattern)
    assert cost == 0, _brief(pattern)
    assert reason == f"too costly to match (bound {bound} > {COST_MAX})", reason
    # Anchoring it would still be over the bound.
    anchored = "|".join("^" + branch for branch in pattern.split("|"))
    assert rules.pfb_regex_admission(anchored)[1] is not None, _brief(anchored)


@pytest.mark.parametrize(("pattern", "width"), WIDTH_REFUSALS, ids=[_brief(p) for p, _ in WIDTH_REFUSALS])
def test_pattern_over_the_class_width_bound_is_refused_and_names_the_width(pattern: str, width: int) -> None:
    cost, reason, _text = rules.pfb_regex_admission(pattern)
    assert cost == 0, _brief(pattern)
    assert reason == f"character classes too wide (width {width} > {CLASS_WIDTH_MAX})", reason


@pytest.mark.parametrize(("pattern", "expected_cost"), WIDTH_ADMITTED, ids=[_brief(p) for p, _ in WIDTH_ADMITTED])
def test_pattern_within_the_class_width_bound_is_admitted(pattern: str, expected_cost: int) -> None:
    assert rules.pfb_regex_admission(pattern)[:2] == (expected_cost, None), _brief(pattern)


def _classes_of_width(width: int) -> str:
    """An anchored pattern whose bracket classes list exactly ``width`` ASCII members, none a letter."""
    blocks, rest = divmod(width, 32)
    return "^" + "[!-@]" * blocks + "[!]" * rest + "x"


@pytest.mark.parametrize("width", [CLASS_WIDTH_MAX - 31, CLASS_WIDTH_MAX - 1, CLASS_WIDTH_MAX])
def test_the_class_width_bound_admits_every_width_up_to_its_limit(width: int) -> None:
    cost, reason, _text = rules.pfb_regex_admission(_classes_of_width(width))
    assert reason is None, reason
    assert cost > 0


@pytest.mark.parametrize("width", [CLASS_WIDTH_MAX + 1, CLASS_WIDTH_MAX + 32])
def test_the_class_width_bound_refuses_every_width_past_its_limit(width: int) -> None:
    cost, reason, _text = rules.pfb_regex_admission(_classes_of_width(width))
    assert (cost, reason) == (0, f"character classes too wide (width {width} > {CLASS_WIDTH_MAX})")


# Cost of patterns built from quantified single atoms. Two atoms are disjoint when no ASCII
# character (letters folded to both cases) and no non-ASCII character can match both; the
# non-ASCII side is one shared pseudo-member of ``.``, ``\w \W \D \S \s`` and every negated
# class. A quantified atom multiplies the work after it, unless a disjoint mandatory atom
# follows it directly (it cannot hand characters over) or nothing but ``$`` follows it in a
# top-level branch (nothing is left to fail).
DISJOINTNESS_COSTS = [
    # disjoint: the run cannot give characters to the atom after it
    (r"^\w+-", 259),
    (r"^\w+\.", 259),
    (r"^[^.]+\.", 259),
    ("^[a-z]+1", 259),
    (r"^\d+\.", 259),  # a digit class and a literal that is not a digit
    (r"^\d+x", 259),
    # overlap: the run and the next atom can share a character
    (r"^.+\.", 514),
    (r"^\W+\.", 514),
    ("^[a-z]+A", 514),  # letters fold: [a-z] also matches A
    ("^[a-z]+[A-Z]", 514),
    (r"^\S+\w", 514),
    (r"^\w+\W", 514),  # no ASCII overlap: only the non-ASCII pseudo-member is shared
    # the next item must be a MANDATORY single atom
    (r"^[a-z]*\.", 258),
    (r"^[a-z]+\.?", 770),
    (r"^[a-z]+(\.)", 514),
    (r"^[a-z]+\b\.", 770),
    (r"^[a-z]+a?\.", 1026),
    # a run that ends a top-level branch, or is followed only by `$`, multiplies nothing
    ("^[a-z]+", 258),
    ("^[a-z]+$", 259),
    ("^[a-z]+$$", 260),
    (r"^[a-z]+\b", 514),
    ("[a-z]+$", 66048),
    # inside a group the run still multiplies what follows the group
    (r"^(x|[a-z]+)\.", 516),
    # the non-ASCII pseudo-member: shared by `\d \s \S \D` and every negated class (`\d` matches every
    # Unicode decimal digit, so it stands for non-ASCII characters too), not by an ASCII literal
    (r"^\s+\S", 514),
    (r"^\S+\s", 514),
    (r"^\D+[^\D]", 514),
    (r"^[^\W]+\W", 514),
    (r"^\D+\d", 514),
    (r"^\d+\D", 514),
    (r"^\d+\W", 514),
    (r"^\d+\s", 514),
    (r"^[^0-9]+\d", 514),
]


@pytest.mark.parametrize(("pattern", "expected_cost"), DISJOINTNESS_COSTS, ids=[p for p, _ in DISJOINTNESS_COSTS])
def test_a_quantified_atom_multiplies_the_work_after_it_only_when_they_can_share_characters(
    pattern: str, expected_cost: int
) -> None:
    assert rules.pfb_regex_admission(pattern)[:2] == (expected_cost, None)


@pytest.mark.parametrize(
    ("pattern", "anchored", "expected_cost"),
    LEADING_DOT_PAIRS,
    ids=[_brief(pattern) for pattern, _anchored, _cost in LEADING_DOT_PAIRS],
)
def test_a_leading_dot_run_costs_what_the_same_run_behind_a_written_caret_costs(
    pattern: str, anchored: str, expected_cost: int
) -> None:
    assert rules.pfb_regex_admission(anchored)[:2] == (expected_cost, None), _brief(anchored)
    assert rules.pfb_regex_admission(pattern)[:2] == (expected_cost, None), _brief(pattern)


@pytest.mark.parametrize(
    ("pattern", "expected_cost"), UNANCHORED_DOT_ROWS, ids=[_brief(pattern) for pattern, _cost in UNANCHORED_DOT_ROWS]
)
def test_a_dot_run_that_is_not_the_first_item_of_every_branch_keeps_the_unanchored_search(
    pattern: str, expected_cost: int
) -> None:
    assert rules.pfb_regex_admission(pattern)[:2] == (expected_cost, None), _brief(pattern)


@pytest.mark.parametrize(
    ("pattern", "expected"), COMPILE_TEXT, ids=[_brief(pattern) for pattern, _expected in COMPILE_TEXT]
)
def test_the_compile_text_is_wrapped_behind_a_caret_only_when_a_leading_dot_run_anchors_the_pattern(
    pattern: str, expected: str
) -> None:
    assert rules.pfb_regex_admission(pattern)[2] == expected


# The admission result is one parse of the text: ``(cost, reason, compile_text)``. A refused pattern costs
# 0 and carries its own text as the compile text (nothing compiles it).
ADMISSION_RESULTS = [
    (".*a|.+b", (1027, None, r"^(?:(?s:.*)a|(?s:.*)[^\n]b)")),
    (r"^keep\.example$", (None, None, r"^keep\.example$")),
    ("a|.*b", (131584, None, "a|.*b")),
    ("(a+)+", (0, "quantified group", "(a+)+")),
    ("a" * (MAX_LEN + 1), (0, f"over {MAX_LEN} characters", "a" * (MAX_LEN + 1))),
]


@pytest.mark.parametrize(
    ("pattern", "expected"), ADMISSION_RESULTS, ids=[_brief(pattern) for pattern, _expected in ADMISSION_RESULTS]
)
def test_admission_returns_the_cost_the_reason_and_the_compile_text_together(
    pattern: str, expected: tuple[int | None, str | None, str]
) -> None:
    result = rules.pfb_regex_admission(pattern)
    assert len(result) == 3, result
    cost, reason, compile_text = result
    assert (reason, compile_text) == expected[1:], result
    if expected[0] is not None:
        assert cost == expected[0], result
    else:
        assert cost > 0, result


@pytest.mark.parametrize("pattern", [".*a|.+b", r"^keep\.example$", "(a+)+", "a" * (MAX_LEN + 1)], ids=_brief)
def test_admission_parses_a_pattern_once(monkeypatch: pytest.MonkeyPatch, pattern: str) -> None:
    parses: list[str] = []
    real_admit = rules._admit

    def counting_admit(text: str) -> Any:
        parses.append(text)
        return real_admit(text)

    monkeypatch.setattr(rules, "_admit", counting_admit)
    rules.pfb_regex_admission(pattern)
    assert parses == [pattern]


def test_the_probe_parses_each_pattern_line_once(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The save-time probe takes the verdict and the compile text from one call per line."""
    import io

    parses: list[str] = []
    real_admit = rules._admit

    def counting_admit(text: str) -> Any:
        parses.append(text)
        return real_admit(text)

    monkeypatch.setattr(rules, "_admit", counting_admit)
    lines = [".*a|.+b", r"^keep\.example$", "(a+)+"]
    monkeypatch.setattr(sys, "stdin", io.StringIO("\n".join(lines) + "\n"))
    assert rules.main(["probe"]) == 1
    assert parses == lines
    assert capsys.readouterr().err.splitlines() == ["line 3: '(a+)+': quantified group"]


# Names that separate every wrapped row from its wrongly anchored cousin: each row matches some of
# them and fails others, and the matches sit at the start, in the middle and at the end of a name.
EQUIVALENCE_NAMES = [
    "",
    "a",
    "b",
    "xa",
    "xb",
    "ba",
    "ab",
    "a.example",
    "ads.example",
    "foo.ads.example",
    "sub.x.com",
    "x.com",
    "microsoft.com",
    "foo.microsoft.com",
    "foo.microsoft.com.evil.example",
    "www.example.com",
]


# Names that carry a newline (a CNAME target is decoded from Latin-1 bytes and may hold one): the compile
# text must match exactly the names the pattern as written matches, newline or not.
NEWLINE_NAMES = [
    "x\n.ads.example",
    "b\nads",
    "\n",
    "a\nb\nc.x.com",
    "x\n.microsoft.com",
    "a\n",
    "\na",
    "foo\n.ads.example\n",
]

# Every pattern that a leading dot run anchors, as written (the unanchored forms).
LEADING_DOT_ROWS = sorted(
    {pattern for pattern, text in COMPILE_TEXT if text != pattern}
    | {pattern for pattern, _anchored, _cost in LEADING_DOT_PAIRS}
)

# Matches every name, so no name tells it from a wrongly anchored cousin.
MATCHES_EVERY_NAME = {".*"}


@pytest.mark.parametrize("pattern", LEADING_DOT_ROWS, ids=_brief)
def test_the_compile_text_and_the_pattern_as_written_agree_on_every_name_newline_or_not(pattern: str) -> None:
    import re

    original = re.compile(pattern, re.IGNORECASE)
    compiled = re.compile(rules.pfb_regex_admission(pattern)[2], re.IGNORECASE)
    verdicts = {
        name: (original.search(name) is not None, compiled.search(name) is not None)
        for name in [*EQUIVALENCE_NAMES, *NEWLINE_NAMES]
    }
    assert all(before == after for before, after in verdicts.values()), verdicts
    if pattern not in MATCHES_EVERY_NAME:
        # Non-vacuity: the name set is told apart by this pattern, in both directions.
        assert {before for before, _after in verdicts.values()} == {True, False}, (pattern, verdicts)


def test_a_caret_written_before_a_plain_dot_run_would_not_match_what_the_unanchored_pattern_does() -> None:
    """The leading run is rewritten, not just prefixed: on a name with a newline the unanchored pattern
    matches from after the newline, which a `^` before a plain `.*` cannot."""
    import re

    name = "x\n.microsoft.com"
    assert re.search(r".*\.microsoft\.com$", name, re.IGNORECASE)
    assert not re.search(r"^.*\.microsoft\.com$", name, re.IGNORECASE)
    assert re.search(rules.pfb_regex_admission(r".*\.microsoft\.com$")[2], name, re.IGNORECASE)


@pytest.mark.parametrize(
    ("pattern", "fragment"),
    [
        ("", "empty pattern"),
        ("a" * (MAX_LEN + 1), f"over {MAX_LEN} characters"),
        ("a b", "non-ASCII, space or control character"),
        ("é", "non-ASCII, space or control character"),
        (r"\1", "unsupported escape"),
        (r"\x41", "unsupported escape"),
        ("(?=a)", "unsupported group"),
        ("(?P<n>a)", "unsupported group"),
        ("(a+)+", "quantified group"),
        ("(|a)+", "quantified group"),
        ("(" * 9 + "a" + ")" * 9, "nested"),
        ("(", "unbalanced"),
        (")", "unbalanced"),
        ("[a", "unclosed"),
        ("[]", "empty"),
        ("[z-a]", "range"),
        ("a{256}", "repeat"),
        ("a**", "quantifier"),
        (r"\b+", "quantifier"),
        ("()+", "quantified group"),
        ("(?:)*", "quantified group"),
        ("(){2}", "quantified group"),
        ("(^a)+", "quantified group"),
        (r"(\ba)+", "quantified group"),
        ("(a$){3}", "quantified group"),
        ("(a(b+))+", "quantified group"),
        ("(a(b))+", "quantified group"),
        ("[a&&b]", "set operation"),
        ("[a~~b]", "set operation"),
        ("[a||b]", "set operation"),
        ("[a--b]", "set operation"),
        ("^" + "a?" * 20 + "a" * 208 + "b", "too costly to match"),
    ],
)
def test_refusal_names_its_reason(pattern: str, fragment: str) -> None:
    cost, reason, _text = rules.pfb_regex_admission(pattern)
    assert cost == 0 and reason is not None and fragment in reason, f"{_brief(pattern)}: {(cost, reason)}"


def test_refusal_reason_never_embeds_the_pattern_text() -> None:
    """Reasons end up in logs and admin-facing errors; they stay short and fixed."""
    for pattern in ("(?P<TAILMARKER>a)", "[TAILMARKER-A]", "TAILMARKER\\x41", "TAILMARKER{999}"):
        _cost, reason, _text = rules.pfb_regex_admission(pattern)
        assert reason is not None, _brief(pattern)
        assert "TAILMARKER" not in reason, reason
        assert len(reason) < 100, reason


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        ("abc", "'abc'"),
        ("a" * 32, "'" + "a" * 32 + "'"),
        ("a" * 33, "'" + "a" * 32 + "' ... (33 chars)"),
        ("a" * 300, "'" + "a" * 32 + "' ... (300 chars)"),
        ("a\nb\x00c\x1b", "'a\\nb\\x00c\\x1b'"),
        ("é" * 40, "'" + "\\xe9" * 32 + "' ... (40 chars)"),
    ],
)
def test_excerpt_is_a_short_escaped_prefix_with_the_full_length(pattern: str, expected: str) -> None:
    assert rules.pfb_regex_excerpt(pattern) == expected


def test_probe_compiles_the_text_the_resolver_compiles(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The save-time probe compiles what the resolver compiles, so a pattern the resolver would
    wrap behind a caret is judged in that form."""
    import io
    import re

    real_compile = re.compile
    seen: list[str] = []

    def record_compile(pattern: Any, flags: int = 0) -> Any:
        seen.append(pattern)
        return real_compile(pattern, flags)

    monkeypatch.setattr(rules.re, "compile", record_compile)
    monkeypatch.setattr(sys, "stdin", io.StringIO(".*\\.microsoft\\.com$\n^ok\\.example$\n"))
    assert rules.main(["probe"]) == 0
    assert capsys.readouterr().err == ""
    assert seen == [r"^(?:(?s:.*)\.microsoft\.com$)", r"^ok\.example$"]


def test_probe_refuses_an_over_costly_pattern_and_quotes_it_in_full_when_short() -> None:
    proc = run_probe(b"[a-z]+[a-z]+x\n")
    assert proc.returncode == 1
    assert proc.stderr.decode("utf-8").splitlines() == [
        f"line 1: '[a-z]+[a-z]+x': too costly to match unanchored (bound 33685760 > {COST_MAX}); anchor it with ^"
    ], proc.stderr


def test_probe_refuses_wide_classes_and_names_the_width() -> None:
    proc = run_probe(("^" + "[!-~]" * 5 + "x\n").encode("utf-8"))
    assert proc.returncode == 1
    assert proc.stderr.decode("utf-8").splitlines() == [
        f"line 1: '^[!-~][!-~][!-~][!-~][!-~]x': character classes too wide (width 470 > {CLASS_WIDTH_MAX})"
    ], proc.stderr


def test_probe_reports_a_long_refused_pattern_by_excerpt_and_length_only() -> None:
    pattern = "^" + "a" * 290 + "TAILMARKER$"
    proc = run_probe((pattern + "\n").encode("utf-8"))
    assert proc.returncode == 1
    assert proc.stderr.decode("utf-8").splitlines() == [
        f"line 1: {ascii(pattern[:32])} ... ({len(pattern)} chars): over {MAX_LEN} characters"
    ], proc.stderr
    assert b"TAILMARKER" not in proc.stderr


def test_probe_reports_each_entry_with_its_own_line_number_and_admits_the_rest() -> None:
    proc = run_probe(b"^ok\\.example$\n(a+)+\n# note\n^fine\\.example$\n(?=a)b\n")
    assert proc.returncode == 1
    lines = proc.stderr.decode("utf-8").splitlines()
    assert [line.split(":")[0] for line in lines] == ["line 2", "line 5"], lines
    assert "quantified group" in lines[0] and "unsupported group" in lines[1], lines


def test_the_probe_keeps_unicode_word_matching_for_latin_1_cname_targets(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import io
    import re

    compiled: list[re.Pattern[str]] = []
    real_compile = re.compile

    def compile_and_record(pattern: Any, flags: int = 0) -> Any:
        result = real_compile(pattern, flags)
        compiled.append(result)
        return result

    monkeypatch.setattr(rules.re, "compile", compile_and_record)
    monkeypatch.setattr(sys, "stdin", io.StringIO(r"^ads\w*\.example$" + "\n"))
    assert rules.main(["probe"]) == 0
    assert capsys.readouterr().err == ""
    assert len(compiled) == 1
    assert compiled[0].search("adsé.example")


def test_anchoring_is_not_offered_when_the_character_class_width_would_still_refuse_the_pattern() -> None:
    pattern = "[!-~]" * 3 + "a?" * 10 + "x"
    cost, reason, _text = rules.pfb_regex_admission(pattern)
    assert cost == 0 and reason is not None
    assert "anchor it" not in reason, reason
    assert rules.pfb_regex_admission("^" + pattern)[1] is not None


def test_anchoring_is_not_offered_when_the_caret_would_exceed_the_pattern_length_limit() -> None:
    pattern = "a?" * 8 + "a" * 240
    assert len(pattern) == MAX_LEN
    cost, reason, _text = rules.pfb_regex_admission(pattern)
    assert cost == 0 and reason is not None
    assert "anchor it" not in reason, reason
    assert rules.pfb_regex_admission("^" + pattern)[1] == "over 256 characters"
