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
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

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


def test_www_tree_clean() -> None:
    """Every tracked src/usr/local/www .php/.inc/.xml file is noopener-clean."""
    out = subprocess.run(
        ["git", "ls-files", "-z", "src/usr/local/www"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    files = sorted(p for p in out.split("\0") if p and p.endswith((".php", ".inc", ".xml")))
    assert len(files) >= 16  # sanity: the coverage-matrix file set must be present

    all_violations: list[Any] = []
    for rel_path in files:
        text = (_REPO_ROOT / rel_path).read_text(encoding="utf-8", errors="replace")
        all_violations.extend(cno.find_violations(text, rel_path))

    assert all_violations == [], (
        f'{len(all_violations)} target=_blank site(s) missing rel="noopener noreferrer": '
        + ", ".join(f"{v.source}:{v.line}" for v in all_violations[:20])
    )
