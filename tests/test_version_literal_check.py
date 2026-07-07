"""Tests for scripts/check_version_literals.py.

Per CLAUDE.md's test-coverage rule, every flagged case is paired with the
correct/embedded/prose form that must stay clean, so a green run proves the
check discriminates on VALUE POSITION (a version token that stands alone as a
whole value) rather than firing on any occurrence of a version-shaped
substring.

The bad tokens are assembled at runtime (string concatenation) so this
tracked test file does not match its own checker's patterns, mirroring
tests/test_appliance_python_check.py's convention -- defensive even though
``tests/`` is not one of the checker's scan roots today.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "check_version_literals.py"
_spec = importlib.util.spec_from_file_location("check_version_literals", _TOOL)
assert _spec is not None and _spec.loader is not None
cvl = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cvl
_spec.loader.exec_module(cvl)

# Version tokens, assembled so no literal token appears as source text here.
_FREEBSD15 = "FreeBSD" + ":15:amd64"
_FREEBSD14 = "FreeBSD" + ":14"
_FREEBSD17 = "FreeBSD" + ":17"
_PY311 = "py3" + "11"
_PY311_PKG = _PY311 + "-sqlite3"
_PY3110_LOOKALIKE = _PY311 + "0"
_CE28 = "2" + ".8"
_PLUS2603 = "26" + ".03"
_CE_VARVER = "ce-" + _CE28
_PLUS_VARVER = "plus-" + _PLUS2603


def _find(tmp_path: Path, content: str) -> list[Any]:
    f = tmp_path / "sample.sh"
    f.write_text(content, encoding="utf-8")
    return cvl.find_violations([f])


# --- Row 1: FreeBSD ABI as exact quoted value -> FLAGGED ------------------


def test_flags_freebsd_abi_exact_quoted_value(tmp_path: Path) -> None:
    line = f'_ABI="{_FREEBSD15}"\n'
    violations = _find(tmp_path, line)
    assert len(violations) == 1, f"exact quoted FreeBSD ABI must be flagged; got {violations}"
    assert violations[0][1] == 1


# --- Row 2: FreeBSD ABI embedded in a help/sentence string -> NOT flagged -


def test_freebsd_abi_embedded_in_sentence_not_flagged(tmp_path: Path) -> None:
    line = f'help="target ABI, e.g. {_FREEBSD15} (CE {_CE28}) -- see docs"\n'
    assert _find(tmp_path, line) == [], "a token embedded in a prose sentence must stay clean"


# --- Row 3: ABI in a `#` comment / doc arrow -> NOT flagged ----------------


def test_freebsd_abi_in_comment_not_flagged(tmp_path: Path) -> None:
    line = f"# {_FREEBSD15} -> freebsd-15-amd64\n"
    assert _find(tmp_path, line) == [], "a comment restating the value must stay clean"


# --- Row 4: py flavor exact quoted value -> FLAGGED (two syntaxes) --------


def test_flags_py_flavor_exact_quoted_value(tmp_path: Path) -> None:
    yaml_line = f'default: "{_PY311}"\n'
    shell_line = f"PYFLAVOR='{_PY311}'\n"
    assert len(_find(tmp_path, yaml_line)) == 1, "YAML quoted py flavor must be flagged"
    assert len(_find(tmp_path, shell_line)) == 1, "shell single-quoted py flavor must be flagged"


# --- Row 5: py flavor embedded in a package name -> NOT flagged (ceiling) -


def test_py_flavor_embedded_in_package_name_not_flagged(tmp_path: Path) -> None:
    # Documents the checker's known ceiling: a flavor token glued to a longer
    # package name is not a value on its own, so it is not caught here.
    line = f'pkg install -y "{_PY311_PKG}"\n'
    assert _find(tmp_path, line) == [], "a flavor embedded in a package name must stay clean"


# --- Row 6: CE "2.8" and Plus "26.03" quoted -> both FLAGGED ---------------


def test_flags_ce_and_plus_quoted_values(tmp_path: Path) -> None:
    assert len(_find(tmp_path, f'version: "{_CE28}"\n')) == 1, "quoted CE version must be flagged"
    assert len(_find(tmp_path, f'version: "{_PLUS2603}"\n')) == 1, "quoted Plus version must be flagged"


# --- Row 7: varver "ce-2.8" / "plus-26.03" quoted -> both FLAGGED ----------


def test_flags_varver_quoted_values(tmp_path: Path) -> None:
    assert len(_find(tmp_path, f'varver: "{_CE_VARVER}"\n')) == 1, "quoted ce-X.Y varver must be flagged"
    assert len(_find(tmp_path, f'varver: "{_PLUS_VARVER}"\n')) == 1, "quoted plus-NN.NN varver must be flagged"


# --- Row 8: unquoted standalone RHS -> FLAGGED (shell and YAML) -----------


def test_flags_unquoted_standalone_rhs(tmp_path: Path) -> None:
    shell_line = f"ABI={_FREEBSD15}\n"
    yaml_line = f"default: {_PY311}\n"
    assert len(_find(tmp_path, shell_line)) == 1, "unquoted shell assignment must be flagged"
    assert len(_find(tmp_path, yaml_line)) == 1, "unquoted YAML assignment must be flagged"


# --- Row 9: `version-literal-ok` escape suppresses an otherwise-exact hit -


def test_escape_comment_suppresses_flag(tmp_path: Path) -> None:
    line = f'_ABI="{_FREEBSD15}"  # version-literal-ok: pinned intentionally\n'
    assert _find(tmp_path, line) == [], "the version-literal-ok escape must suppress the flag"


# --- Row 10: path exclusion, Markdown -> NOT flagged (via main()) ---------


def test_path_exclusion_markdown_not_flagged(tmp_path: Path) -> None:
    md = tmp_path / "notes.md"
    md.write_text(f'version: "{_CE28}"\n', encoding="utf-8")
    assert cvl.main([str(md)]) == 0, "a .md path must be excluded even with an exact quoted token"


# --- Row 11: path exclusion, install_deps_* -> NOT flagged (via main()) --


def test_path_exclusion_install_deps_not_flagged(tmp_path: Path) -> None:
    dep_file = tmp_path / "install_deps_CE_2.8.sh"
    dep_file.write_text(f'PYFLAVOR="{_PY311}"\n', encoding="utf-8")
    assert cvl.main([str(dep_file)]) == 0, "install_deps_* must be excluded even with an exact token"


# --- Row 12: main() exit codes ---------------------------------------------


def test_main_exit_codes(tmp_path: Path) -> None:
    bad = tmp_path / "bad.sh"
    bad.write_text(f'_ABI="{_FREEBSD15}"\n', encoding="utf-8")
    good = tmp_path / "good.sh"
    good.write_text('_ABI="$ABI_FROM_MATRIX"\n', encoding="utf-8")
    assert cvl.main([str(good)]) == 0
    assert cvl.main([str(bad)]) == 1


# --- Row 13: VACUITY GUARD -- version-shaped non-tokens stay clean --------


def test_vacuity_guard_non_token_decimals_stay_clean(tmp_path: Path) -> None:
    # python/php DOTTED forms ("3.11", "8.3") are not in the token list -- only
    # php8x/py31x/2.8/2.9 are. FreeBSD:14/:17 are outside the supported 15/16
    # window. If the checker discriminated on nothing but decimal shape, every
    # one of these would (wrongly) flag.
    assert _find(tmp_path, 'python_version: "3.11"\n') == [], '"3.11" is not a token'
    assert _find(tmp_path, 'php_version: "8.3"\n') == [], '"8.3" is not a token'
    assert _find(tmp_path, f'target: "{_FREEBSD14}"\n') == [], "FreeBSD:14 is outside the supported window"
    assert _find(tmp_path, f'target: "{_FREEBSD17}"\n') == [], "FreeBSD:17 is outside the supported window"


# --- Hostile inputs ---------------------------------------------------------


def test_empty_file_stays_clean(tmp_path: Path) -> None:
    assert _find(tmp_path, "") == []


def test_blank_lines_stay_clean(tmp_path: Path) -> None:
    assert _find(tmp_path, "\n\n\n") == []


def test_undecodable_file_skipped_gracefully(tmp_path: Path) -> None:
    f = tmp_path / "binary.sh"
    f.write_bytes(b"\xff\xfe\x00\x01garbage")
    # Must not raise; the mold's read_text(errors="replace") degrades gracefully.
    violations = cvl.find_violations([f])
    assert violations == []


def test_extra_whitespace_around_quoted_value_still_flagged(tmp_path: Path) -> None:
    line = f'default:   "{_PY311}"   \n'
    assert len(_find(tmp_path, line)) == 1, "surrounding whitespace must not hide an exact quoted value"


def test_two_quoted_literals_only_exact_one_flags(tmp_path: Path) -> None:
    # The line carries one EXACT value and one token embedded in prose -- it
    # must still flag (because of the exact one), proving the exact match is
    # what triggers detection, not mere token presence anywhere on the line.
    line = f'_ABI="{_FREEBSD15}"  # see also: "{_FREEBSD15} is the CE {_CE28} ABI"\n'
    violations = _find(tmp_path, line)
    assert len(violations) == 1, f"expected exactly one flag from the exact-value literal; got {violations}"


def test_docstring_example_line_not_flagged(tmp_path: Path) -> None:
    # A doc example illustrating a transformation inside a Python docstring is
    # prose, not a value assignment, even though the quoted span alone would
    # otherwise fullmatch a token exactly (real case from build-repo-portable.py).
    content = (
        "def f(v: str) -> str:\n"
        '    """Derive the catalog name.\n'
        "\n"
        f'      "2.8.1"  + "CE"   -> "{_CE_VARVER}"\n'
        f'      "{_PLUS2603}"  + "Plus" -> "{_PLUS_VARVER}"\n'
        '    """\n'
    )
    f = tmp_path / "sample.py"
    f.write_text(content, encoding="utf-8")
    assert cvl.find_violations([f]) == [], "docstring example lines must stay clean"


def test_comment_prefixed_quoted_example_not_flagged(tmp_path: Path) -> None:
    # A `#`-comment line with an EXACT quoted token (not just an embedded/prose
    # token like row 3) must also stay clean -- it's documentation, not a value.
    line = f'# pfsense_version is now the floating tag (e.g. "{_CE28}"), so...\n'
    assert _find(tmp_path, line) == [], "a quoted example inside a comment must stay clean"


def test_inline_trailing_comment_example_not_flagged(tmp_path: Path) -> None:
    # A trailing `# e.g. "ce-2.8"` on an otherwise-real code line is a comment
    # illustrating the value, not the value itself (real case from
    # build-repo-portable.py / check-pfsense-versions.py).
    line = f'varver = catalog_name_from_version(version, variant)  # e.g. "{_CE_VARVER}"\n'
    assert _find(tmp_path, line) == [], "a trailing inline comment example must stay clean"


def test_lookalike_tokens_not_flagged(tmp_path: Path) -> None:
    # Longer lookalikes that merely start with a real token must not fullmatch.
    assert _find(tmp_path, f'flavor: "{_PY3110_LOOKALIKE}"\n') == [], "py3110 is not py31[0-9]"
    assert _find(tmp_path, f'target: "{_FREEBSD14}"\n') == [], "FreeBSD:14 is outside 15/16"


# --- PR #937 review follow-ups ---------------------------------------------


def test_shell_triple_quoted_value_flagged(tmp_path: Path) -> None:
    # F1 (blocking, PR #937): the triple-quote docstring heuristic is Python-only.
    # In shell, `X="""tok"""` is adjacent-quote concatenation that evaluates to
    # `tok`; treating a `"""` line as prose in a .sh/.yml file let a hardcoded
    # token bypass the whole gate. These MUST flag (they scan as .sh via _find).
    assert len(_find(tmp_path, f'ABI="""{_FREEBSD15}"""\n')) == 1, "shell triple-double-quoted value must flag"
    assert len(_find(tmp_path, f"PYF='''{_PY311}'''\n")) == 1, "shell triple-single-quoted value must flag"


def test_python_docstring_body_still_exempt(tmp_path: Path) -> None:
    # The boundary complement of the above: inside a real .py docstring the same
    # triple-quoted token stays prose-exempt, so F1's fix did not over-correct.
    content = '"""\n' + f'    "{_PY311}"\n' + '"""\n'
    f = tmp_path / "d.py"
    f.write_text(content, encoding="utf-8")
    assert cvl.find_violations([f]) == [], "a .py docstring body must remain prose-exempt"


def test_export_readonly_prefixed_unquoted_assignment_flagged(tmp_path: Path) -> None:
    # Copilot (PR #937): `export`/`readonly` prefixes slipped UNQUOTED assignments
    # past _ASSIGNMENT_RE (the quoted form was always caught by the literal path).
    assert len(_find(tmp_path, f"export ABI={_FREEBSD15}\n")) == 1, "export-prefixed unquoted assignment must flag"
    assert len(_find(tmp_path, f"readonly PYF={_PY311}\n")) == 1, "readonly-prefixed unquoted assignment must flag"


def test_flags_php_flavor_quoted_value(tmp_path: Path) -> None:
    # F4 (PR #937): the php8[0-9] token shape had no explicit coverage-matrix row.
    php83 = "php8" + "3"
    php85 = "php8" + "5"
    assert len(_find(tmp_path, f'PHPFLAVOR="{php83}"\n')) == 1, "quoted php83 flavor must flag"
    assert len(_find(tmp_path, f'flavor: "{php85}"\n')) == 1, "quoted php85 flavor must flag"


# --- Issue #941: comment syntax follows the file type (PHP/JS) --------------
# The axis is enumerated from the scan roots' actual extensions (git ls-files):
# sh/yml/conf use `#` (already covered above); php/inc/js use `//` and
# `/* ... */`, with `#` valid in the PHP family only.


def _find_named(tmp_path: Path, name: str, content: str) -> list[Any]:
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return cvl.find_violations([f])


def test_php_line_comment_not_flagged(tmp_path: Path) -> None:
    content = f'// example: "{_CE28}" is the CE version\n$x = 1;\n'
    assert _find_named(tmp_path, "s.php", content) == [], "a // comment line must stay clean in PHP"


def test_php_docblock_not_flagged(tmp_path: Path) -> None:
    content = f'/**\n * @example "{_CE28}"\n */\n$x = 1;\n'
    assert _find_named(tmp_path, "s.inc", content) == [], "a docblock body must stay clean in PHP"


def test_php_trailing_line_comment_not_flagged(tmp_path: Path) -> None:
    content = f'$v = pfb_build_varver($ver);  // e.g. "{_CE_VARVER}"\n'
    assert _find_named(tmp_path, "s.php", content) == [], "a trailing // example must stay clean in PHP"


def test_php_real_value_still_flagged(tmp_path: Path) -> None:
    # Vacuity complement of the three exemptions above: a REAL PHP value must
    # still flag, proving the comment stripping does not swallow code.
    violations = _find_named(tmp_path, "s.php", f'$v = "{_CE28}";\n')
    assert len(violations) == 1, f"a real PHP value assignment must flag; got {violations}"


def test_php_same_line_block_comment_keeps_code(tmp_path: Path) -> None:
    # A /*...*/ pair closed on the same line drops only the comment span; the
    # code after it is still scanned.
    violations = _find_named(tmp_path, "s.php", f'/* note */ $v = "{_CE28}";\n')
    assert len(violations) == 1, f"code after a same-line block comment must be scanned; got {violations}"


def test_php_comment_marker_inside_string_not_comment(tmp_path: Path) -> None:
    # Quote-awareness: // inside a quoted string is content, so the real value
    # after it must still flag.
    violations = _find_named(tmp_path, "s.php", f'$s = "a // b"; $v = "{_CE28}";\n')
    assert len(violations) == 1, f"// inside a string must not truncate the scan; got {violations}"


def test_js_line_and_block_comments_not_flagged(tmp_path: Path) -> None:
    line = f'// default "{_PY311}"\n'
    block = f'/*\n * fallback "{_PY311}"\n */\nvar x = 1;\n'
    assert _find_named(tmp_path, "s.js", line) == [], "a // comment must stay clean in JS"
    assert _find_named(tmp_path, "s.js", block) == [], "a block-comment body must stay clean in JS"


def test_js_hash_is_not_a_comment(tmp_path: Path) -> None:
    # `#` is a private-field sigil in JS, not a comment -- a real value after a
    # `#` must still flag (in PHP the same line would be comment-stripped).
    content = f'this.#flavor = "{_PY311}";\n'
    violations = _find_named(tmp_path, "s.js", content)
    assert len(violations) == 1, f"# must not comment-strip JS; got {violations}"


# --- Issue #941: Python triple-quote fixes (parity + one-line value) --------


def test_py_one_line_triple_quoted_value_flagged(tmp_path: Path) -> None:
    # The .py mirror of PR #937's blocking F1: X = """tok""" is a real string
    # assignment, not a docstring -- sweeping any triple-quote line as prose
    # let it bypass the gate.
    content = 'FLAVOR = """' + _PY311 + '"""\n'
    violations = _find_named(tmp_path, "s.py", content)
    assert len(violations) == 1, f"a one-line triple-quoted value must flag; got {violations}"


def test_py_docstring_close_reopen_stays_prose(tmp_path: Path) -> None:
    # Parity bug (PR #937 audit): a line that closes AND reopens a docstring
    # (even token count) must leave the docstring state OPEN, so the next line
    # is still prose. The old `if open_token in line` check cleared the state
    # and spuriously scanned line 3.
    content = '"""doc\nx """ + """ y\n"' + _PY311 + '"\n"""\n'
    assert _find_named(tmp_path, "s.py", content) == [], "a close-and-reopen line must keep the docstring open"


# --- Issue #941: shell assignment-prefix builtins (the full class) ----------


def test_prefixed_unquoted_assignments_flagged(tmp_path: Path) -> None:
    # The class enumerated, not example-driven: POSIX export/readonly (covered
    # above), plus local and bash/ksh declare/typeset (with option words).
    for line in (
        f"local ABI={_FREEBSD15}\n",
        f"declare -r PYF={_PY311}\n",
        f"typeset ABI={_FREEBSD15}\n",
    ):
        violations = _find(tmp_path, line)
        assert len(violations) == 1, f"prefixed unquoted assignment must flag: {line!r}; got {violations}"
