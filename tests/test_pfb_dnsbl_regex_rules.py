"""pfb_dnsbl_regex_rules.py (issue #1765): single-source DNSBL regex admission
rules, shared by pfb_unbound.py and the save-time probe.

Covers what the PHP suite (tests/php/DnsblRegexEntryErrorTest.php, which drives
the probe through pfb_dnsbl_regex_validation_errors()) cannot reach directly:
standalone import-safety (the #1711 pythonmod-globals regression guard), the
probe's argv-absent default, and stdin line-ending edge cases. The five
diagnostic-message classes and the shape-vs-budget distinction are already
pinned in DnsblRegexEntryErrorTest -- not duplicated here.
"""

from __future__ import annotations

import itertools
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, SupportsIndex

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
    "1"`` -- pin that the missing-argv case is cap OFF: a long-but-benign pattern
    is accepted with no argv[1] at all."""
    from pfb_dnsbl_regex_rules import REGEX_STATIC_LEN_CAP

    pattern = _anchored_pattern(REGEX_STATIC_LEN_CAP + 100)
    proc = run_probe((pattern + "\n").encode("utf-8"))
    assert proc.returncode == 0, f"stderr: {proc.stderr!r}"
    assert proc.stderr == b""


def test_main_reports_only_its_own_diagnostics_for_a_pattern_that_warns() -> None:
    """A pattern that COMPILES but makes ``re`` emit a warning (e.g. ``[[a]]`` ->
    FutureWarning "Possible nested set") must not add anything to stderr.

    Every non-empty stderr line becomes an admin-facing validation error
    (pfb_dnsbl_regex_validation_errors() -> $input_errors on pfblockerng_dnsbl.php,
    and a line-1 lint diagnostic via pfb_lint_parse_regex_errors()). Running the
    rules module as a FILE rather than ``python -c`` lets ``warnings`` resolve the
    source, so an unsuppressed warning would leak BOTH this module's absolute path
    and a bare ``re.compile(pattern)`` source line to the admin as bogus errors.
    Only real ``line N:`` diagnostics may reach stderr.
    """
    # Line 1 warns but compiles (accepted); line 2 is a genuine rejection, so the
    # process exits 1 and PHP reads stderr -- the case where a leak would surface.
    # Line 1 also carries two DIFFERENT quantified atoms, which is what drives the shape
    # gate's atom-overlap probe to compile a fragment of its own: the leak has two possible
    # sources now, and neither may reach the admin.
    proc = run_probe(b"[[a]+[c]+x\n(a+)+\n", "0")
    assert proc.returncode == 1
    assert proc.stderr.decode("utf-8").splitlines() == ["line 2: '(a+)+': catastrophic-backtracking shape"], proc.stderr


def test_probe_and_resolver_agree_on_every_admission_verdict() -> None:
    """The save-time probe and the resolver's load-time gate are two INDEPENDENT
    compositions over the shared literals: ``main()`` tests the shape and the budget
    as two separate branches (it needs the two distinct diagnostics), while the
    resolver calls the single composed ``_regex_is_catastrophic_shape``.

    Sharing the literals only closes the literal-drift row. This pin is the
    shape/budget axis only. Compile and control-character rejects are covered
    by DnsblRegexEntryErrorTest (PHP probe) and are skipped here.
    """
    import io

    from pfb_dnsbl_regex_rules import _REGEX_BUDGET_MAX, _regex_is_catastrophic_shape, main

    def main_rejects_shape(pattern: str) -> bool | None:
        """Return whether ``main()`` rejected for shape/budget, or None if it
        skipped the line or rejected for compile/control (not this pin)."""
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
        if "catastrophic-backtracking shape" in err or "too many quantifiers" in err:
            return True
        return None

    corpus = [
        "^ads\\.example\\.com$",
        "^(.+\\.)?ads?[0-9]*\\.example\\.(com|net|org)$",
        "(a+)+",
        "(a*)*",
        "(\\w+\\.)+",
        "(.*a){20}",
        "(a|a)+",
        "(foo|foobar)*",
        "(a+)(a+)+",
        "(a+)(b+)*",
        "a{1000}{1000}",
        "(x){500}{500}",
        "[a-z]{50}{50}",
        "|" * _REGEX_BUDGET_MAX,
        "|" * (_REGEX_BUDGET_MAX + 1),
        "+" * _REGEX_BUDGET_MAX,
        "\\|" * (_REGEX_BUDGET_MAX + 2),
        "^" + "a" * 300 + "$",
        "",
        "^$",
        "^([a-z])(?(1)[a-z]+[a-z]+[a-z]+[a-z]+|b)@x\\.com$",
        "^[a-z]+[a-z]+(?>ab)[a-z]+[a-z]+@x\\.com$",
        "^[a-z]+[a-z]+(foo|foobar)[a-z]+[a-z]+@x\\.com$",
        "^[a-z]+[a-z]+(a|(?:b))+[a-z]+[a-z]+@x\\.com$",
        "^[a-z]+[a-z]+(?>12)[a-z]+[a-z]+$",
    ]
    # The hand-written rows above only cover rules that exist TODAY, so they cannot
    # catch a FUTURE rule wired into one composition and not the other. Enumerate every
    # 4-way combination of the regex building blocks a shape rule can be written over,
    # so a new rule of ANY structural shape lands in this corpus. Combination, not
    # random fuzz: a rule keyed on a 3-character construct like "(?:" is astronomically
    # unlikely to be produced by random sampling, and would slip through unnoticed.
    blocks = ("(", ")", "(?:", "[a-z]", "a", ".", "+", "*", "{2}", "|", "\\", "$")
    corpus += ["".join(combination) for combination in itertools.product(blocks, repeat=4)]

    compared = {True: 0, False: 0}
    for pattern in corpus:
        probe_rejects = main_rejects_shape(pattern)
        if probe_rejects is None:
            continue
        compared[probe_rejects] += 1
        assert probe_rejects == _regex_is_catastrophic_shape(pattern), (
            f"probe and resolver disagree on {pattern!r}: "
            f"probe rejects={probe_rejects}, resolver rejects={_regex_is_catastrophic_shape(pattern)}"
        )
    assert compared[True] and compared[False], f"corpus never exercised both verdicts: {compared}"


def test_probe_and_resolver_both_reject_an_adjacent_quantifier_run() -> None:
    """issue #2035: the shape gate's structural rules all keyed on a parenthesised group,
    so a run of ungrouped adjacent quantified atoms reached BOTH consumers unflagged --
    the save-time probe returned 0 and the resolver's load-time gate returned False.

    The rule lives in the one shared module, so this drives both surfaces the way they are
    really used: ``main()`` through a subprocess (what pfb_dnsbl_regex_validation_errors()
    runs) and the composed predicate (what pfb_unbound.py imports).
    """
    from pfb_dnsbl_regex_rules import _regex_is_catastrophic_shape

    pattern = r"^[a-z]+[a-z]+[a-z]+[a-z]+@example\.com$"
    assert _regex_is_catastrophic_shape(pattern) is True

    proc = run_probe((pattern + "\n").encode("utf-8"), "1")
    assert proc.returncode == 1, f"probe admitted {pattern!r}"
    assert proc.stderr.decode("utf-8").splitlines() == [f"line 1: {pattern!r}: catastrophic-backtracking shape"], (
        proc.stderr
    )


def test_shape_gate_stays_total_on_malformed_pattern_fragments() -> None:
    """The gate reads the pattern STRING before anything compiles it, so it is handed
    fragments ``re`` itself would reject -- an unterminated class, a dangling backslash, a
    half-written repeat. Each must return a verdict rather than raise, or a single bad feed
    line becomes an unhandled exception on the resolver's load path."""
    from pfb_dnsbl_regex_rules import _regex_is_catastrophic_shape

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
        assert isinstance(_regex_is_catastrophic_shape(fragment), bool), fragment
    # A construct that is never closed must not swallow the rest of the scan: such a pattern
    # cannot compile, so it never reaches the resolver, but the gate still reads what is
    # there rather than going blind from the first `(?#` onwards.
    assert _regex_is_catastrophic_shape(r"(?#x\w+\w+\w+") is True
    assert _regex_is_catastrophic_shape(r"(?=a\w+\w+\w+") is True
    assert _regex_is_catastrophic_shape(r"(?i:\w+\w+\w+") is True


def test_group_end_scan_is_linear_and_preserves_regex_escaping(monkeypatch: Any) -> None:
    import pfb_dnsbl_regex_rules
    from pfb_dnsbl_regex_rules import (
        _regex_group_end,
        _regex_has_adjacent_unbounded_atoms,
        _regex_is_catastrophic_shape,
    )

    cases = (
        ("(a(b)c)d", 7),
        (r"(\))x", 4),
        ("([)])x", 5),
        ("(a", 2),
    )
    for pattern, expected in cases:
        assert _regex_group_end(pattern, 0) == expected, pattern

    class CountingPattern(str):
        indexed = 0
        copied = 0

        def __getitem__(self, key: SupportsIndex | slice) -> str:
            if isinstance(key, slice):
                type(self).copied += len(range(*key.indices(len(self))))
            else:
                type(self).indexed += 1
            return super().__getitem__(key)

    def scan_work(pattern: str) -> int:
        CountingPattern.indexed = CountingPattern.copied = 0
        assert _regex_has_adjacent_unbounded_atoms(CountingPattern(pattern)) is False
        return CountingPattern.indexed + CountingPattern.copied

    for build in (lambda size: "(" * size, lambda size: "(" * size + ")" * size):
        small = scan_work(build(400))
        large = scan_work(build(800))
        assert small > 0 and large > 0
        assert large <= small * 3, f"2x input caused {large / small:.2f}x string work ({small} -> {large})"

    body_scans = 0
    original_body_scan = pfb_dnsbl_regex_rules._regex_body_has_run

    def counted_body_scan(body: str, depth: int = 0) -> bool:
        nonlocal body_scans
        body_scans += 1
        return original_body_scan(body, depth)

    monkeypatch.setattr("pfb_dnsbl_regex_rules._regex_body_has_run", counted_body_scan)
    nested_alternation = "(a|" * 800 + "b" + ")" * 800
    assert isinstance(_regex_has_adjacent_unbounded_atoms(nested_alternation), bool)
    assert body_scans <= pfb_dnsbl_regex_rules._REGEX_NESTED_SCAN_MAX
    anchored_alternation = "[a-z]+[a-z]+" + nested_alternation + "[a-z]+[a-z]+"
    assert isinstance(_regex_is_catastrophic_shape(anchored_alternation), bool)


def test_probe_and_resolver_agree_on_issue2364_admission_rows() -> None:
    from pfb_dnsbl_regex_rules import _regex_is_catastrophic_shape

    rows = (
        (r"^([a-z])(?(1)[a-z]+[a-z]+[a-z]+[a-z]+|b)@x\.com$", True),
        (r"^(a)?(?(1)b|[a-z]+[a-z]+[a-z]+[a-z]+)@x\.com$", True),
        (r"^[a-z]+[a-z]+(?>ab)[a-z]+[a-z]+@x\.com$", True),
        (r"^[a-z]+[a-z]+(foo|foobar)[a-z]+[a-z]+@x\.com$", True),
        (r"^[a-z]+[a-z]+(a|(?:b))+[a-z]+[a-z]+@x\.com$", True),
        (r"^(a)?(?(1)[a-z]+[a-z]+|[a-z]+[a-z]+)$", False),
        (r"^[a-z]+[a-z]+(?>12)[a-z]+[a-z]+$", False),
        (r"^[a-z]+[a-z]+(\+|\*)[a-z]+[a-z]+$", False),
        (r"^xn--bcher-kva\.[a-z]+$", False),
    )
    for pattern, expected in rows:
        assert _regex_is_catastrophic_shape(pattern) is expected, pattern

    proc = run_probe(("".join(pattern + "\n" for pattern, _ in rows)).encode("utf-8"), "0")
    assert proc.returncode == 1
    diagnostics = proc.stderr.decode("utf-8").splitlines()
    expected_lines = [
        f"line {line_number}: {pattern!r}: catastrophic-backtracking shape"
        for line_number, (pattern, rejected) in enumerate(rows, 1)
        if rejected
    ]
    assert diagnostics == expected_lines


def test_probe_and_resolver_both_reject_an_overlapping_separator_run() -> None:
    """issue #2082: a mandatory atom overlapping its neighbours was read as a run BOUNDARY,
    so the issue's reproduction reached both consumers unflagged. Same two surfaces as the
    #2035 twin above: the composed predicate the resolver imports, and ``main()`` the way
    pfb_dnsbl_regex_validation_errors() runs it."""
    from pfb_dnsbl_regex_rules import _regex_is_catastrophic_shape

    pattern = r"^[a-z]+[a-z]+a[a-z]+[a-z]+@x\.com$"
    assert _regex_is_catastrophic_shape(pattern) is True

    proc = run_probe((pattern + "\n").encode("utf-8"), "0")
    assert proc.returncode == 1, f"probe admitted {pattern!r}"
    assert proc.stderr.decode("utf-8").splitlines() == [f"line 1: {pattern!r}: catastrophic-backtracking shape"], (
        proc.stderr
    )


def test_main_treats_crlf_terminated_lines_like_lf() -> None:
    """A regex-list body with CRLF line endings splits into the same lines (and
    reports the same line numbers) as an LF-only body."""
    body = b"^ads\x01$\r\n(a+)+\r\n^ok$\r\n"
    proc = run_probe(body)
    assert proc.returncode == 1
    stderr = proc.stderr.decode("utf-8")
    assert "line 1:" in stderr and "control character" in stderr
    assert "line 2:" in stderr and "catastrophic-backtracking shape" in stderr
    assert "line 3:" not in stderr


def test_main_does_not_hang_on_a_lone_cr_with_no_newline() -> None:
    """A regex-list body using bare CR (old-Mac style) line endings with no '\\n'
    anywhere is NOT split by ``sys.stdin`` (unlike CRLF, which still carries a
    real '\\n' for the line-terminator search) -- Python's text stdin only treats
    '\\n' as a line boundary here, so the whole blob is read as ONE line. Pin
    the safe outcome: no hang, and the embedded control byte (CR itself is
    0x0D, an ASCII control character) still trips the control-character
    diagnostic on that one line -- never a crash, never a silent pass."""
    body = b"^ads\x01$\r(a+)+\r^ok$\r"
    proc = run_probe(body)
    assert proc.returncode == 1
    stderr = proc.stderr.decode("utf-8")
    assert stderr.startswith("line 1:")
    assert stderr.count("line ") == 1, f"expected the whole blob read as one line, got: {stderr!r}"
    assert "control character" in stderr
