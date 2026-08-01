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
    proc = run_probe(b"[[a]]\n(a+)+\n", "0")
    assert proc.returncode == 1
    assert proc.stderr.decode("utf-8").splitlines() == ["line 2: '(a+)+': catastrophic-backtracking shape"], proc.stderr


def test_probe_and_resolver_agree_on_every_admission_verdict() -> None:
    """The save-time probe and the resolver's load-time gate are two INDEPENDENT
    compositions over the shared literals: ``main()`` tests the shape and the budget
    as two separate branches (it needs the two distinct diagnostics), while the
    resolver calls the single composed ``_regex_is_catastrophic_shape``.

    Sharing the literals only closes the literal-drift row. This closes the row the
    #1711 parity tests actually existed for: a rule wired into one composition and
    not the other silently reopens "the save page accepts it, the resolver drops it".
    """
    from pfb_dnsbl_regex_rules import (
        _REGEX_BUDGET_MAX,
        _regex_complexity_budget,
        _regex_has_catastrophic_shape,
        _regex_is_catastrophic_shape,
    )

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
    ]
    # The hand-written rows above only cover rules that exist TODAY, so they cannot
    # catch a FUTURE rule wired into one composition and not the other. Enumerate every
    # 4-way combination of the regex building blocks a shape rule can be written over,
    # so a new rule of ANY structural shape lands in this corpus. Combination, not
    # random fuzz: a rule keyed on a 3-character construct like "(?:" is astronomically
    # unlikely to be produced by random sampling, and would slip through unnoticed.
    blocks = ("(", ")", "(?:", "[a-z]", "a", ".", "+", "*", "{2}", "|", "\\", "$")
    corpus += ["".join(combination) for combination in itertools.product(blocks, repeat=4)]

    for pattern in corpus:
        probe_rejects = _regex_has_catastrophic_shape(pattern) or _regex_complexity_budget(pattern) > _REGEX_BUDGET_MAX
        assert probe_rejects == _regex_is_catastrophic_shape(pattern), (
            f"probe and resolver disagree on {pattern!r}: "
            f"probe rejects={probe_rejects}, resolver rejects={_regex_is_catastrophic_shape(pattern)}"
        )
    # Guard against a vacuously one-sided corpus.
    assert any(_regex_is_catastrophic_shape(pattern) for pattern in corpus)
    assert any(not _regex_is_catastrophic_shape(pattern) for pattern in corpus)


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
