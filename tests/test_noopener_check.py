"""Tests for scripts/check_noopener.py.

Covers BOTH branches per dimension per CLAUDE.md's test-coverage rules: every
case that flags a violation is paired with the corresponding correct form that
must stay clean. `test_www_tree_clean` is the issue #1217 fix's red->green
proof: RED against the unfixed tree (179 unfixed `target=_blank` sites),
GREEN once every site carries its adjacent `rel="noopener noreferrer"`.

The checker is a hyphen-free, underscore-named script under scripts/, so it is
importable directly by path via importlib.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.gitenv import scrubbed_git_env

# --------------------------------------------------------------------------- #
# Load the script as a module.
# --------------------------------------------------------------------------- #

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TOOL = _REPO_ROOT / "scripts" / "check_noopener.py"
_spec = importlib.util.spec_from_file_location("check_noopener", _TOOL)
assert _spec is not None and _spec.loader is not None
cno = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cno
_spec.loader.exec_module(cno)


def _find(text: str, source: str = "t.php") -> list[Any]:
    return cno.find_violations(text, source)


# --------------------------------------------------------------------------- #
# Hostile-input rows 1-12 (brief issue #1217) -- bad (flagged) vs good (clean)
# --------------------------------------------------------------------------- #


def test_row1_double_quoted_no_rel_is_flagged() -> None:
    v = _find('<a target="_blank" href="x">')
    assert len(v) == 1
    assert v[0].line == 1
    assert v[0].source == "t.php"


def test_row2_single_quoted_no_rel_is_flagged() -> None:
    v = _find("<a target='_blank' href='x'>")
    assert len(v) == 1


def test_row3_no_quote_no_rel_is_flagged() -> None:
    v = _find('<a target=_blank href="x">')
    assert len(v) == 1


def test_row4_double_quoted_with_rel_is_clean() -> None:
    assert _find('<a target="_blank" rel="noopener noreferrer" href="x">') == []


def test_row5_single_quoted_with_rel_is_clean() -> None:
    assert _find("<a target='_blank' rel='noopener noreferrer' href='x'>") == []


def test_row6_no_quote_target_with_double_quoted_rel_is_clean() -> None:
    assert _find('<a target=_blank rel="noopener noreferrer" href="x">') == []


def test_row7_checker_is_idempotent_on_already_fixed_input() -> None:
    fixed = '<a target="_blank" rel="noopener noreferrer" href="x">'
    assert _find(fixed) == []
    assert _find(fixed) == []  # calling twice must not accumulate state


def test_row8_rel_before_target_is_flagged_with_convention_hint(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # rel BEFORE target does not satisfy the strict-adjacency convention.
    v = _find('<a rel="noopener noreferrer" target="_blank">')
    assert len(v) == 1

    f = tmp_path / "page.php"
    f.write_text('<a rel="noopener noreferrer" target="_blank">\n')
    rc = cno.main([str(f)])
    assert rc == 1
    # main()'s printed message states the rel-after-target convention explicitly.
    assert "rel must sit directly after target" in capsys.readouterr().err


def test_row9_data_target_attribute_is_clean() -> None:
    # word/hyphen boundary excludes a `data-target="_blank"` tail.
    assert _find('<div data-target="_blank">') == []


def test_row10_two_anchors_one_line_flags_only_the_bad_one() -> None:
    line = '<a target="_blank" href="a"> <a target="_blank" rel="noopener noreferrer" href="b">'
    v = _find(line)
    assert len(v) == 1  # per-occurrence, not per-line


def test_row11_noopener_ok_marker_escape_hatch_is_clean() -> None:
    assert _find('<a target="_blank" href="x"> <!-- noopener-ok: exempt sample -->') == []


def test_row12_wrong_rel_value_is_flagged() -> None:
    # rel present but not "noopener" -- must still flag.
    v = _find('<a target="_blank" rel="opener" href="x">')
    assert len(v) == 1


def test_row13_noopener_with_hyphen_suffix_is_flagged() -> None:
    # `noopener-evil` is a DIFFERENT rel token, not `noopener` -- a browser grants it
    # none of noopener's protection, so the tripwire must flag it (fail-safe). Guards
    # against a `\b` boundary that would treat the hyphen as a token end and pass it.
    v = _find('<a target="_blank" rel="noopener-evil" href="x">')
    assert len(v) == 1


def test_row14_noopener_with_wordchar_suffix_is_flagged() -> None:
    # Pins the `\w` half of the `(?![\w-])` guard independently of the hyphen half
    # (test_row13): `noopener_evil` is a distinct, unprotected token and must flag.
    # Without this, a guard narrowed to hyphen-only would pass the suite yet accept it.
    v = _find('<a target="_blank" rel="noopener_evil" href="x">')
    assert len(v) == 1


# --------------------------------------------------------------------------- #
# Issue #1294: HTML ASCII target spelling and whitespace variants
# --------------------------------------------------------------------------- #

_IN_SCOPE_SUFFIXES = ("php", "inc", "xml")


@pytest.mark.parametrize("suffix", _IN_SCOPE_SUFFIXES)
@pytest.mark.parametrize(
    ("case_name", "target_attribute"),
    (
        ("double_quoted", 'target="_blank"'),
        ("single_quoted", "target='_blank'"),
        ("unquoted", "target=_blank"),
        ("uppercase_attribute", 'TARGET="_blank"'),
        ("mixed_case_keyword", 'target="_Blank"'),
        ("mixed_case_unquoted_keyword", "target=_Blank"),
    ),
    ids=lambda value: value if isinstance(value, str) and "=" not in value else None,
)
def test_target_case_variants_require_adjacent_rel(suffix: str, case_name: str, target_attribute: str) -> None:
    source = f"page.{suffix}"
    violations = _find(f'<a {target_attribute} href="x">', source)
    assert len(violations) == 1, f"{case_name} in {source}: expected one violation, got {violations!r}"
    assert violations[0].source == source

    clean = f'<a {target_attribute} rel="noopener noreferrer" href="x">'
    assert _find(clean, source) == [], f"{case_name} in {source}: adjacent noopener rel was not clean"


@pytest.mark.parametrize("suffix", _IN_SCOPE_SUFFIXES)
@pytest.mark.parametrize(
    ("case_name", "target_attribute"),
    (
        ("space_before_equals", 'target ="_blank"'),
        ("space_after_equals", 'target= "_blank"'),
        ("space_both_sides", 'target = "_blank"'),
        ("tabs_around_equals", 'target\t=\t"_blank"'),
        ("consecutive_spaces", 'target  =  "_blank"'),
        ("quoted_trailing_space", 'target="_blank "'),
        ("quoted_trailing_tab", 'target="_blank\t"'),
        ("unquoted_spaced_equals", "target = _blank"),
    ),
    ids=lambda value: value if isinstance(value, str) and "=" not in value else None,
)
def test_target_whitespace_variants_require_adjacent_rel(suffix: str, case_name: str, target_attribute: str) -> None:
    source = f"page.{suffix}"
    violations = _find(f'<a {target_attribute} href="x">', source)
    assert len(violations) == 1, f"{case_name} in {source}: expected one violation, got {violations!r}"

    clean = f'<a {target_attribute} rel="noopener noreferrer" href="x">'
    assert _find(clean, source) == [], f"{case_name} in {source}: adjacent noopener rel was not clean"


_HOSTILE_CLEAN_ROWS = (
    ("data_target", '<div data-target="_blank">'),
    ("data_target_ascii_case", '<div data-TARGET="_Blank">'),
    ("identifier_prefix", '<div mytarget="_blank">'),
    ("unicode_identifier_prefix", '<div étarget="_blank">'),
    ("unicode_casefold_keyword", '<a target="_blanK">'),
    ("nbsp_around_equals", '<a target\u00a0=\u00a0"_blank">'),
    ("zero_width_around_equals", '<a target\u200b=\u200b"_blank">'),
    ("empty_target", '<a target="">'),
    ("missing_target_value", "<a target=>"),
    ("mismatched_quotes", "<a target=\"_blank'>"),
    ("shell_shaped_value", '<a target="$(_blank)">'),
    ("bracketed_value", '<a target="[_blank]">'),
    ("unquoted_word_suffix", "<a target=_blank_evil>"),
    ("unquoted_hyphen_suffix", "<a target=_blank-evil>"),
    ("target_equals_split", '<a target\n="_blank" rel="noopener noreferrer">'),
    ("adjacent_noopener", '<a target="_blank" rel="noopener noreferrer">'),
    ("escape_marker", '<a target="_blank" href="x"> <!-- noopener-ok: sample -->'),
)


@pytest.mark.parametrize("suffix", _IN_SCOPE_SUFFIXES)
@pytest.mark.parametrize(("case_name", "text"), _HOSTILE_CLEAN_ROWS, ids=[row[0] for row in _HOSTILE_CLEAN_ROWS])
def test_target_matcher_hostile_clean_inputs_stay_clean(suffix: str, case_name: str, text: str) -> None:
    source = f"page.{suffix}"
    assert _find(text, source) == [], f"{case_name} in {source}: non-target input was flagged"


_HOSTILE_VIOLATION_ROWS = (
    ("rel_before_target", '<a rel="noopener noreferrer" target="_blank">'),
    ("intervening_attribute", '<a target="_blank" href="x" rel="noopener noreferrer">'),
    ("rel_next_line", '<a target="_blank"\nrel="noopener noreferrer">'),
    ("wrong_rel", '<a target="_blank" rel="opener">'),
    ("hyphen_rel_suffix", '<a target="_blank" rel="noopener-evil">'),
    ("word_rel_suffix", '<a target="_blank" rel="noopener_evil">'),
    ("unquoted_slash", "<a target=_blank/>"),
    ("unquoted_slash_with_rel", '<a target=_blank/ rel="noopener noreferrer">'),
    ("quoted_slash", '<a target="_blank"/>'),
)


@pytest.mark.parametrize("suffix", _IN_SCOPE_SUFFIXES)
@pytest.mark.parametrize(
    ("case_name", "text"), _HOSTILE_VIOLATION_ROWS, ids=[row[0] for row in _HOSTILE_VIOLATION_ROWS]
)
def test_target_matcher_hostile_violations_remain_flagged(suffix: str, case_name: str, text: str) -> None:
    source = f"page.{suffix}"
    violations = _find(text, source)
    assert len(violations) == 1, f"{case_name} in {source}: expected one violation, got {violations!r}"


@pytest.mark.parametrize("suffix", _IN_SCOPE_SUFFIXES)
def test_target_matcher_hostile_oversized_non_target_stays_clean(suffix: str) -> None:
    long_value = "x" * 8192
    text = f'<div data-prefix="{long_value}" data-target="_blank" data-suffix="{long_value}">'
    assert _find(text, f"page.{suffix}") == []


# --------------------------------------------------------------------------- #
# Additional branch coverage: line numbers, multiple violations, quote forms
# --------------------------------------------------------------------------- #


def test_line_number_reported_correctly_on_later_line() -> None:
    v = _find('<div>\n<a target="_blank" href="x">\n</div>')
    assert len(v) == 1
    assert v[0].line == 2


def test_multiple_violations_across_lines_all_reported() -> None:
    text = '<a target="_blank" href="a">\n<a target=\'_blank\' href="b">\n'
    v = _find(text)
    assert len(v) == 2
    assert [x.line for x in v] == [1, 2]


def test_rel_noopener_only_no_referrer_still_clean() -> None:
    # "noopener" alone (no "noreferrer") already satisfies the adjacency check --
    # the checker enforces the noopener value, not the exact full string.
    assert _find('<a target="_blank" rel="noopener" href="x">') == []


# --------------------------------------------------------------------------- #
# CLI (main) over real temp files -- exit codes both ways
# --------------------------------------------------------------------------- #


def test_main_returns_1_on_violation_and_prints_message(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "page.php"
    f.write_text('<a target="_blank" href="x">\n')
    rc = cno.main([str(f)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "noopener" in err
    assert f"{f}:1:" in err


def test_main_returns_0_on_clean_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "page.php"
    f.write_text('<a target="_blank" rel="noopener noreferrer" href="x">\n')
    rc = cno.main([str(f)])
    assert rc == 0
    assert capsys.readouterr().err == ""


def test_default_scan_set_covers_both_ui_trees(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # issue #3075: pkg help text renders on the www pages and carries the same
    # external links, so the ARGLESS default set -- the one the pre-commit hook and
    # CI both run -- must cover both trees. A violation is planted in each and both
    # paths are asserted, because the exit code alone cannot distinguish "both
    # scanned" from "one scanned".
    env = scrubbed_git_env(drop_git_vars=True)
    for name in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", env["GIT_CONFIG_GLOBAL"])
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", env["GIT_CONFIG_SYSTEM"])
    monkeypatch.chdir(tmp_path)

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    www = tmp_path / "src/usr/local/www/pfblockerng"
    pkg = tmp_path / "src/usr/local/pkg/pfblockerng"
    www.mkdir(parents=True)
    pkg.mkdir(parents=True)
    (www / "dirty.php").write_text('<a target="_blank" href="https://example.invalid">\n')
    (pkg / "help.inc").write_text('<a target="_blank" href="https://example.invalid">\n')
    # docs/ is outside the default scan set: the set must be LIMITED to www + pkg,
    # not merely include them.
    outside = tmp_path / "docs"
    outside.mkdir()
    (outside / "stray.php").write_text('<a target="_blank" href="https://example.invalid">\n')
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)

    assert cno.main([]) == 1
    err = capsys.readouterr().err
    assert "src/usr/local/www/pfblockerng/dirty.php:1:" in err
    assert "src/usr/local/pkg/pfblockerng/help.inc:1:" in err
    assert "docs/stray.php" not in err


def test_main_fails_closed_when_default_scan_set_unenumerable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A policy gate must FAIL CLOSED: when `git ls-files` cannot enumerate the default
    # scan set (git absent / not a checkout), main() must error instead of exiting 0
    # and silently passing. Reproduce by running argless main() from a non-git dir.
    monkeypatch.chdir(tmp_path)
    rc = cno.main([])
    assert rc == 2
    assert "failing closed" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# Tree scan -- issue #1217 fix's red->green proof. RED: 179 unfixed sites
# across the 16 files enumerated in the brief's coverage matrix. GREEN: 0.
# --------------------------------------------------------------------------- #


def test_ui_trees_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every tracked www + pkg .php/.inc/.xml file is noopener-clean.

    Enumerated by the production helper rather than a copy of its pathspec
    (issue #3075).
    """
    monkeypatch.chdir(_REPO_ROOT)
    files = cno._git_tracked_ui()
    assert len(files) >= 26  # sanity: 16 www coverage-matrix files + the pkg tree

    all_violations: list[Any] = []
    for rel_path in files:
        text = (_REPO_ROOT / rel_path).read_text(encoding="utf-8", errors="replace")
        all_violations.extend(cno.find_violations(text, rel_path))

    assert all_violations == [], (
        f'{len(all_violations)} target=_blank site(s) missing rel="noopener noreferrer": '
        + ", ".join(f"{v.source}:{v.line}" for v in all_violations[:20])
    )
