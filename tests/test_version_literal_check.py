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
import json
import subprocess
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
    # python/php DOTTED forms ("3.11", "8.3") are not in the token list. If the
    # checker discriminated on nothing but decimal shape, both would (wrongly)
    # flag. (FreeBSD:14/:17 moved to the FLAGGED rows in issue #940 -- the ABI
    # shape is version-agnostic now.)
    assert _find(tmp_path, 'python_version: "3.11"\n') == [], '"3.11" is not a token'
    assert _find(tmp_path, 'php_version: "8.3"\n') == [], '"8.3" is not a token'


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
    # Lookalikes that merely start with a real token shape must not fullmatch.
    freebsd_1x = "FreeBSD" + ":1x"
    assert _find(tmp_path, f'flavor: "{_PY3110_LOOKALIKE}"\n') == [], "py3110 is one digit too long"
    assert _find(tmp_path, f'target: "{freebsd_1x}"\n') == [], "FreeBSD:1x is not a numeric ABI"


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


def test_escaped_quote_does_not_misclose_string(tmp_path: Path) -> None:
    # Copilot (PR #947): a backslash-escaped quote inside a string mis-closed
    # the quote tracker, so a // (PHP/JS) or # (shell) INSIDE the string read
    # as a comment opener and truncated the scan -- hiding a real value after
    # it. Same class in both trackers (_split_c_comment and
    # _strip_inline_comment), so all three rows must flag.
    php_dquote = '$s = "a \\" // not a comment"; $v = "' + _CE28 + '";\n'
    php_squote = "$s = 'it\\'s // x'; $v = \"" + _CE28 + '";\n'
    sh_dquote = 'MSG="a \\" # note"; V="' + _CE28 + '"\n'
    assert len(_find_named(tmp_path, "s.php", php_dquote)) == 1, "escaped dquote must not hide a PHP value"
    assert len(_find_named(tmp_path, "s2.php", php_squote)) == 1, "escaped squote must not hide a PHP value"
    assert len(_find(tmp_path, sh_dquote)) == 1, "escaped dquote must not hide a shell value"


def test_js_hash_is_not_a_comment(tmp_path: Path) -> None:
    # `#` is a private-field sigil in JS, not a comment -- a real value after a
    # `#` must still flag (in PHP the same line would be comment-stripped).
    content = f'this.#flavor = "{_PY311}";\n'
    violations = _find_named(tmp_path, "s.js", content)
    assert len(violations) == 1, f"# must not comment-strip JS; got {violations}"


def test_js_template_literal_slashes_not_a_comment(tmp_path: Path) -> None:
    # review-fanout C5 (PR #947): a // inside a backtick template literal is
    # content, not a comment opener -- the real value after it must still flag.
    content = 'const u = `https://example/x`; const f = "' + _PY311 + '";\n'
    violations = _find_named(tmp_path, "s.js", content)
    assert len(violations) == 1, f"// inside a template literal must not truncate the scan; got {violations}"


def test_php_escaped_squote_before_squoted_token_flagged(tmp_path: Path) -> None:
    # review-fanout C9 (PR #947): PHP/JS support \' inside single quotes; the
    # naive single-quote span pairing swallowed a later single-quoted token on
    # the same line. The C-style extractor is escape-aware on both quote types.
    # The .inc row pins that the whole PHP family shares the branch (re-review
    # F3, PR #947).
    content = "$s = 'it\\'s fine'; $f = '" + _PY311 + "';\n"
    for name in ("s.php", "s.inc"):
        violations = _find_named(tmp_path, name, content)
        assert len(violations) == 1, f"\\' must not swallow a later single-quoted token ({name}); got {violations}"


def test_backtick_spans_do_not_mispair_quotes(tmp_path: Path) -> None:
    # re-review F1 (PR #947): two backtick segments each holding an odd count
    # of the same quote char let the extractor pair a quote from inside the
    # first with one from inside the second, swallowing the real value between
    # them. Backtick spans are consumed as boundaries in BOTH extractor
    # variants, so the bracketed value must flag in JS, PHP, and shell alike.
    js = "const a = `it's`; const b = \"" + _CE28 + "\"; const c = `he's fine`;\n"
    php = "$a = `it's`; $b = \"" + _CE28 + "\"; $c = `he's fine`;\n"
    sh = "A=`echo it's`; B=\"" + _CE28 + "\"; C=`echo he's`\n"
    assert len(_find_named(tmp_path, "s.js", js)) == 1, "JS backtick spans must not swallow the value between them"
    assert len(_find_named(tmp_path, "s.php", php)) == 1, "PHP backtick spans must not swallow the value between them"
    assert len(_find(tmp_path, sh)) == 1, "shell backtick spans must not swallow the value between them"


def test_backtick_template_literal_is_a_value_in_js_only(tmp_path: Path) -> None:
    # A backtick-delimited exact token is a template-literal VALUE in JS/PHP
    # (C-style extractor captures the span); in shell a backtick span is
    # command substitution, so the same shape stays clean there.
    js = "const f = `" + _PY311 + "`;\n"
    sh = "F=`" + _PY311 + "`\n"
    assert len(_find_named(tmp_path, "s.js", js)) == 1, "a backtick-exact token is a value in JS"
    assert _find(tmp_path, sh) == [], "a backtick span in shell is command substitution, not a value"


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


# --- Issue #940: unambiguous shapes are version-agnostic ---------------------


def test_stale_and_future_version_shapes_flagged(tmp_path: Path) -> None:
    # A stale (FreeBSD:14) or future (FreeBSD:17) ABI, or an out-of-window
    # php/py flavor, is a hardcode with the same drift hazard as a current one
    # (issue #940) -- the unambiguous shapes no longer carry a version window.
    for value in (_FREEBSD14, _FREEBSD17, "php7" + "4", "py3" + "12"):
        violations = _find(tmp_path, f'target: "{value}"\n')
        assert len(violations) == 1, f"version-agnostic shape must flag: {value}; got {violations}"


def test_widened_varvers_flagged(tmp_path: Path) -> None:
    # Discriminating rows for the varver widening (review-fanout C4/C8, PR
    # #947): multi-digit components the old single-digit ce- pattern and the
    # old exactly-2-digit plus- pattern could not match.
    for value in ("ce-" + "2.10", "ce-" + "10.0", "plus-" + "27.1", "plus-" + "100.03"):
        violations = _find(tmp_path, f'varver: "{value}"\n')
        assert len(violations) == 1, f"generalized varver must flag: {value}; got {violations}"


# --- Issue #940: the matrix tripwire (--verify-matrix) -----------------------
# The windowed CE/Plus numerics restate the matrix window; the tripwire fails
# CI the moment supported-versions.json carries a version they no longer cover.


def _matrix(entries: list[dict[str, str]]) -> dict[str, Any]:
    return {"versions": entries}


def _current_shape_matrix() -> dict[str, Any]:
    return _matrix(
        [
            {
                "pfsense_version": _CE28,
                "channel": "CE",
                "freebsd_major": "15",
                "php_version": "8.3",
                "py_flavor": _PY311,
            },
            {
                "pfsense_version": _PLUS2603,
                "channel": "Plus",
                "freebsd_major": "16",
                "php_version": "8.5",
                "py_flavor": _PY311,
            },
        ]
    )


def test_matrix_tokens_current_shape_covered() -> None:
    uncovered = cvl.uncovered_matrix_tokens(_current_shape_matrix())
    assert uncovered == [], f"the live-shape matrix must be fully covered; got {uncovered}"


def test_matrix_tokens_dot_x_suffix_stripped() -> None:
    m = _matrix(
        [
            {
                "pfsense_version": _CE28 + ".x",
                "channel": "CE",
                "freebsd_major": "15",
                "php_version": "8.3",
                "py_flavor": _PY311,
            }
        ]
    )
    uncovered = cvl.uncovered_matrix_tokens(m)
    assert uncovered == [], f"a trailing .x on pfsense_version must be stripped; got {uncovered}"


def test_matrix_tokens_future_versions_uncovered() -> None:
    # The tripwire's red case: CE 3.0 and Plus 27.01 fall outside the windowed
    # numerics (their varvers, ABI, and flavors are already version-agnostic).
    ce30 = "3" + ".0"
    plus2701 = "27" + ".01"
    m = _matrix(
        [
            {
                "pfsense_version": ce30,
                "channel": "CE",
                "freebsd_major": "17",
                "php_version": "9.1",
                "py_flavor": "py3" + "13",
            },
            {
                "pfsense_version": plus2701,
                "channel": "Plus",
                "freebsd_major": "17",
                "php_version": "9.1",
                "py_flavor": "py3" + "13",
            },
        ]
    )
    uncovered = cvl.uncovered_matrix_tokens(m)
    assert uncovered == [plus2701, ce30], f"future windowed numerics must be reported uncovered; got {uncovered}"


def test_verify_matrix_cli_exit_codes(tmp_path: Path) -> None:
    good = tmp_path / "good.json"
    good.write_text(json.dumps(_current_shape_matrix()), encoding="utf-8")
    bad = tmp_path / "bad.json"
    bad_entry = {
        "pfsense_version": "27" + ".01",
        "channel": "Plus",
        "freebsd_major": "17",
        "php_version": "9.1",
        "py_flavor": "py3" + "13",
    }
    bad.write_text(json.dumps(_matrix([bad_entry])), encoding="utf-8")
    assert cvl.main(["--verify-matrix", "--matrix-file", str(good)]) == 0
    assert cvl.main(["--verify-matrix", "--matrix-file", str(bad)]) == 1


def test_verify_matrix_config_errors_exit_2(tmp_path: Path) -> None:
    # review-fanout C7 (PR #947): a misconfigured invocation (missing file,
    # malformed JSON, bad ref) gets a one-line stderr message + exit 2 -- never
    # a traceback, and never conflated with exit 1 (uncovered tokens).
    missing = tmp_path / "nope.json"
    garbled = tmp_path / "garbled.json"
    garbled.write_text("{not json", encoding="utf-8")
    assert cvl.main(["--verify-matrix", "--matrix-file", str(missing)]) == 2
    assert cvl.main(["--verify-matrix", "--matrix-file", str(garbled)]) == 2
    assert cvl.main(["--verify-matrix", "--ref", "origin/does-not-exist-" + "xyz"]) == 2


def test_matrix_tokens_route_only_entries_excluded() -> None:
    # review-fanout C1 (PR #947): a role=route-only entry (ADR-27 -- EOL'd but
    # still served, frozen catalog) is excluded from the tripwire derivation,
    # mirroring read-version-matrix.sh. Its wildly-out-of-window version must
    # NOT be reported uncovered; the same entry without the role must be.
    entry = {
        "pfsense_version": "99" + ".99",
        "channel": "Plus",
        "freebsd_major": "15",
        "php_version": "8.3",
        "py_flavor": _PY311,
        "role": "route-only",
    }
    assert cvl.uncovered_matrix_tokens(_matrix([entry])) == [], "route-only entries must be excluded"
    active = {k: v for k, v in entry.items() if k != "role"}
    uncovered = cvl.uncovered_matrix_tokens(_matrix([active]))
    assert uncovered == ["99" + ".99"], f"the same entry without role must be reported; got {uncovered}"


# --------------------------------------------------------------------------- #
# Issue #1000: --staged / --diff <base> diff-scoped CLI modes
#
# The full scan (no args) stays the pre-commit/CI gate; these modes are the
# ad-hoc / CI-PR entry points. Full-file content is re-read per changed file
# (scan_text needs whole-file comment/docstring state) and filtered to added
# lines, mirroring test_comment_narration_check.py's subprocess CLI harness.
# --------------------------------------------------------------------------- #


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def _run(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(_TOOL), *args], cwd=repo, capture_output=True, text=True)


def _rev(repo: Path) -> str:
    out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True)
    return out.stdout.strip()


def test_cli_staged_mode_flags_then_clears(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/tool.sh").write_text("_CLEAN=1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")

    (tmp_path / "scripts/tool.sh").write_text(f'_CLEAN=1\n_ABI="{_FREEBSD15}"\n')
    _git(tmp_path, "add", ".")
    res = _run(tmp_path, "--staged")
    assert res.returncode == 1, res.stderr
    assert "scripts/tool.sh:2" in res.stderr

    # Committing (nothing staged afterwards) -> empty diff -> exit 0.
    _git(tmp_path, "commit", "-qm", "add literal")
    assert _run(tmp_path, "--staged").returncode == 0


def test_cli_diff_red_canary_flags_added_but_not_preexisting_literal(tmp_path: Path) -> None:
    # RED CANARY (issue #1000's explicit ask): (a) a diff ADDING a version
    # literal fails naming file:line; (b) the SAME literal sitting unchanged
    # while only an unrelated clean line is added passes -- proving the scan
    # is filtered to the diff, not the whole file.
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/tool.sh").write_text(f'_OLD="{_FREEBSD15}"\n_CLEAN=1\n')
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _rev(tmp_path)

    # (a) added literal -> exit 1 naming file:line
    (tmp_path / "scripts/tool.sh").write_text(f'_OLD="{_FREEBSD15}"\n_CLEAN=1\n_NEW="{_PY311}"\n')
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "add a literal")
    res = _run(tmp_path, "--diff", base)
    assert res.returncode == 1, res.stderr
    assert "scripts/tool.sh:3" in res.stderr
    added_rev = _rev(tmp_path)

    # (b) both literals now pre-existing/unchanged; only an unrelated clean
    # line is added -> exit 0 (must NOT re-flag the pre-existing literals)
    (tmp_path / "scripts/tool.sh").write_text(f'_OLD="{_FREEBSD15}"\n_CLEAN=1\n_NEW="{_PY311}"\n_UNRELATED=1\n')
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "unrelated clean add")
    res = _run(tmp_path, "--diff", added_rev)
    assert res.returncode == 0, res.stderr


def test_cli_diff_added_line_inside_preexisting_comment_block_not_flagged(tmp_path: Path) -> None:
    # Full-file-context axis: proves scan_text sees the WHOLE file, not
    # isolated added-line text -- an added line inside an already-open
    # /* ... */ block must not flag, even though the raw diff hunk alone
    # gives no clue the line sits inside a comment.
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "src").mkdir()
    (tmp_path / "src/a.inc").write_text("/*\n * base note\n */\n$x = 1;\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _rev(tmp_path)

    (tmp_path / "src/a.inc").write_text(f'/*\n * base note\n * "{_CE28}" version note\n */\n$x = 1;\n')
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "extend comment")
    res = _run(tmp_path, "--diff", base)
    assert res.returncode == 0, res.stderr


def test_cli_diff_excluded_paths_not_flagged(tmp_path: Path) -> None:
    # Exclusion axis: .md, install_deps_*, and the checker's own file stay
    # clean even when the added line is an exact quoted token.
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "docs").mkdir()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "docs/notes.md").write_text("clean\n")
    (tmp_path / "scripts/install_deps_CE_2.8.sh").write_text(f'PYFLAVOR="{_PY311}"\n')
    (tmp_path / "scripts/check_version_literals.py").write_text("x = 1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _rev(tmp_path)

    (tmp_path / "docs/notes.md").write_text(f'clean\nversion: "{_CE28}"\n')
    (tmp_path / "scripts/install_deps_CE_2.8.sh").write_text(f'PYFLAVOR="{_PY311}"\nEXTRA="{_FREEBSD15}"\n')
    (tmp_path / "scripts/check_version_literals.py").write_text(f'x = 1\ny = "{_CE28}"\n')
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "add excluded-path literals")
    res = _run(tmp_path, "--diff", base)
    assert res.returncode == 0, res.stderr


def test_cli_diff_out_of_scan_root_path_not_flagged(tmp_path: Path) -> None:
    # Scan-root parity: the full scan only visits src/scripts/.github-workflows,
    # so the diff modes must too. A version literal added to a changed file
    # OUTSIDE those roots (here tests/, where fixtures legitimately carry
    # version tokens) must NOT be flagged -- else --diff origin/devel on a PR
    # would false-positive on a file the authoritative full gate never sees.
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/fixture.py").write_text("x = 1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _rev(tmp_path)

    (tmp_path / "tests/fixture.py").write_text(f'x = 1\n_ABI = "{_FREEBSD15}"\n')
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "add literal outside scan roots")
    res = _run(tmp_path, "--diff", base)
    assert res.returncode == 0, res.stderr


def test_cli_diff_escape_comment_suppresses_added_literal(tmp_path: Path) -> None:
    # Escape axis: an added line carrying `version-literal-ok` stays clean.
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/tool.sh").write_text("_CLEAN=1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _rev(tmp_path)

    (tmp_path / "scripts/tool.sh").write_text(
        f'_CLEAN=1\n_ABI="{_FREEBSD15}"  # version-literal-ok: pinned intentionally\n'
    )
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "escaped literal")
    res = _run(tmp_path, "--diff", base)
    assert res.returncode == 0, res.stderr


def test_cli_diff_bad_base_ref_exits_2(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-qb", "devel")
    (tmp_path / "f").write_text("x\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    res = _run(tmp_path, "--diff", "no-such-ref-" + "xyz")
    assert res.returncode == 2, res.stderr
    assert "git diff failed" in res.stderr


def test_cli_diff_missing_base_arg_is_usage_error(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-qb", "devel")
    (tmp_path / "f").write_text("x\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    res = _run(tmp_path, "--diff")
    assert res.returncode == 2, res.stderr
    assert "usage" in res.stderr.lower()


def test_cli_diff_empty_diff_exits_0(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-qb", "devel")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/tool.sh").write_text("_CLEAN=1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _rev(tmp_path)
    _git(tmp_path, "commit", "--allow-empty", "-qm", "empty")
    res = _run(tmp_path, "--diff", base)
    assert res.returncode == 0, res.stderr


# --- Hostile inputs: the diff parser itself ---------------------------------


def test_cli_diff_new_and_renamed_and_multiple_files(tmp_path: Path) -> None:
    # Brand-new file (all lines added, whole file via git show), renamed file
    # (the b/ NEW path is used), and multiple changed files in one diff.
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/old.sh").write_text("_CLEAN=1\n_STABLE=1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _rev(tmp_path)

    (tmp_path / "scripts/new.sh").write_text(f'_ABI="{_FREEBSD15}"\n')
    (tmp_path / "scripts/old.sh").unlink()
    (tmp_path / "scripts/renamed.sh").write_text(f'_CLEAN=1\n_STABLE=1\n_NEW="{_PY311}"\n')
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "new + rename + literal")
    res = _run(tmp_path, "--diff", base)
    assert res.returncode == 1, res.stderr
    assert "scripts/new.sh:1" in res.stderr
    assert "scripts/renamed.sh:3" in res.stderr


def test_cli_diff_deleted_file_is_skipped_without_crash(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/tool.sh").write_text(f'_ABI="{_FREEBSD15}"\n')
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _rev(tmp_path)

    (tmp_path / "scripts/tool.sh").unlink()
    (tmp_path / "scripts/clean.sh").write_text("_OK=1\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "delete + add clean file")
    res = _run(tmp_path, "--diff", base)
    assert res.returncode == 0, res.stderr


def test_cli_diff_binary_file_is_skipped_without_crash(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/tool.sh").write_text("_CLEAN=1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _rev(tmp_path)

    (tmp_path / "scripts/blob.bin").write_bytes(b"\x00\x01\xff\xfe\x02binarydata")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "add binary")
    res = _run(tmp_path, "--diff", base)
    assert res.returncode == 0, res.stderr


def test_cli_diff_space_bearing_path_tab_is_stripped(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/my tool.sh").write_text("_CLEAN=1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _rev(tmp_path)

    (tmp_path / "scripts/my tool.sh").write_text(f'_CLEAN=1\n_ABI="{_FREEBSD15}"\n')
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "add literal")
    res = _run(tmp_path, "--diff", base)
    assert res.returncode == 1, res.stderr
    assert "scripts/my tool.sh:2" in res.stderr


def test_cli_diff_added_line_at_eof_no_trailing_newline(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/tool.sh").write_text("_CLEAN=1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _rev(tmp_path)

    (tmp_path / "scripts/tool.sh").write_bytes(f'_CLEAN=1\n_ABI="{_FREEBSD15}"'.encode())
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "add literal no eol")
    res = _run(tmp_path, "--diff", base)
    assert res.returncode == 1, res.stderr
    assert "scripts/tool.sh:2" in res.stderr


def test_cli_diff_replacing_no_eol_last_line_is_flagged(tmp_path: Path) -> None:
    # Hostile input (issue #1051): when the OLD file's last line lacks a
    # trailing newline, git emits "\ No newline at end of file" BETWEEN the
    # "-" and "+" lines. Counting that marker as a content line shifts every
    # following added line by one, silently filtering out the real violation.
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/tool.sh").write_bytes(b"_CLEAN=1\n_TAIL=0")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base no eol")
    base = _rev(tmp_path)

    (tmp_path / "scripts/tool.sh").write_text(f'_CLEAN=1\n_ABI="{_FREEBSD15}"\n')
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "replace no-eol tail with literal")
    res = _run(tmp_path, "--diff", base)
    assert res.returncode == 1, res.stderr
    assert "scripts/tool.sh:2" in res.stderr


def test_cli_diff_plus_plus_prefixed_added_line_not_misparsed_as_header(tmp_path: Path) -> None:
    # Hostile input: an added content line starting with "++" renders in the
    # unified diff as "+++ ..." (marker '+' + content "++ ..."). It must NOT be
    # taken for a "+++ b/<path>" file header -- doing so drops it AND every
    # following added line, silently missing a real literal (the exact #1000
    # no-op class). The literal sits AFTER such a line, so a miss => exit 0.
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/tool.sh").write_text("#!/bin/sh\necho hello\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _rev(tmp_path)

    (tmp_path / "scripts/tool.sh").write_text(f'#!/bin/sh\n++ banner\n_ABI="{_FREEBSD15}"\n')
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "add ++ line then a literal")
    res = _run(tmp_path, "--diff", base)
    assert res.returncode == 1, res.stderr
    assert "scripts/tool.sh:3" in res.stderr


def test_cli_diff_non_utf8_byte_does_not_crash_the_run(tmp_path: Path) -> None:
    # Hostile input: a non-UTF-8 byte anywhere in the diff must not crash the
    # whole run with an UnicodeDecodeError traceback (was exit 1 + traceback).
    # The bad file is decoded lossily like the full scan; a literal added to a
    # SEPARATE file in the same run is still caught -- proving the run survived
    # the bad bytes rather than aborting before reaching it.
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/a.sh").write_text("_CLEAN=1\n")
    (tmp_path / "scripts/b.sh").write_text("_CLEAN=1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _rev(tmp_path)

    (tmp_path / "scripts/a.sh").write_bytes(b"_CLEAN=1\n_NOTE=caf\xe9\n")
    (tmp_path / "scripts/b.sh").write_text(f'_CLEAN=1\n_ABI="{_FREEBSD15}"\n')
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "non-utf8 byte + a literal elsewhere")
    res = _run(tmp_path, "--diff", base)
    assert res.returncode == 1, res.stderr
    assert "Traceback" not in res.stderr, res.stderr
    assert "scripts/b.sh:2" in res.stderr


# --- issue #1082: triple-quote inside a normal string/comment must not open a
# --- spurious docstring that swallows a real version literal on later lines ----


def _find_py(tmp_path: Path, content: str) -> list[Any]:
    f = tmp_path / "sample.py"
    f.write_text(content, encoding="utf-8")
    return cvl.find_violations([f])


def test_py_triple_quote_inside_string_does_not_swallow_next_line(tmp_path: Path) -> None:
    # `SEP = "'''"` holds one `'''` INSIDE a normal string; before the fix its odd
    # count opened a phantom docstring, masking the ABI literal on the next line.
    sep_line = 'SEP = "' + "'''" + '"\n'  # SEP = "'''"
    abi_line = '_ABI = "' + _FREEBSD15 + '"\n'
    violations = _find_py(tmp_path, sep_line + abi_line)
    assert len(violations) == 1, f"literal after a string-embedded triple-quote must be flagged; got {violations}"
    assert violations[0][1] == 2


def test_py_triple_quote_in_trailing_comment_does_not_swallow_next_line(tmp_path: Path) -> None:
    violations = _find_py(tmp_path, "x = 1  # " + "'''" + "\n" + f'_ABI = "{_FREEBSD15}"\n')
    assert len(violations) == 1, f"literal after a comment-embedded triple-quote must be flagged; got {violations}"
    assert violations[0][1] == 2


def test_py_real_docstring_block_still_masks_prose(tmp_path: Path) -> None:
    # Behaviour-preserving oracle: a genuine triple-quoted docstring block still
    # masks its prose, so a version token inside it stays clean (green before AND after).
    content = '"""' + "\n" + _FREEBSD15 + "\n" + '"""' + "\n"
    assert _find_py(tmp_path, content) == [], "a version token inside a real docstring must stay clean"


def test_py_triple_quote_after_escaped_single_quote_does_not_swallow_next_line(tmp_path: Path) -> None:
    # issue #1082: a single-quoted Python string may contain an escaped
    # quote (\') before a triple-quote token, e.g. x = 'it\'s """'. The probe
    # must honour the backslash escape (single quotes escape in Python, unlike POSIX
    # sh) so the string does not close early and the """ inside it is not miscounted.
    tricky = "x = 'it\\'s " + '"""' + "'\n"  # -> x = 'it\'s """'
    abi_line = '_ABI = "' + _FREEBSD15 + '"\n'
    violations = _find_py(tmp_path, tricky + abi_line)
    assert len(violations) == 1, f"literal after an escaped-quote + triple-quote line must be flagged; got {violations}"
    assert violations[0][1] == 2
