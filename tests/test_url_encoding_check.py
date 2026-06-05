"""Tests for scripts/check_url_encoding.py.

Covers BOTH branches per dimension per CLAUDE.md's test-coverage rules: every
case that flags a violation is paired with the corresponding correct form that
must stay clean, so a green proves the heuristic discriminates rather than always
firing (or never firing).

The checker is a hyphen-free, underscore-named script under scripts/, so it is
importable directly by path via importlib.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

# --------------------------------------------------------------------------- #
# Load the script as a module.
# --------------------------------------------------------------------------- #

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "check_url_encoding.py"
_spec = importlib.util.spec_from_file_location("check_url_encoding", _TOOL)
assert _spec is not None and _spec.loader is not None
cue = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cue
_spec.loader.exec_module(cue)


def _find(text: str, source: str = "t.sh") -> list[Any]:
    return cue.find_violations(text, source)


def _find_md(text: str, source: str = "t.md") -> list[Any]:
    return cue.find_violations_in_markdown(text, source)


# --------------------------------------------------------------------------- #
# Shell — bad (flagged) vs good (clean)
# --------------------------------------------------------------------------- #


def test_shell_curl_naked_query_var_is_flagged() -> None:
    v = _find('curl "http://h/x?ip=$VAR"')
    assert len(v) == 1
    assert v[0].line == 1
    assert v[0].source == "t.sh"
    assert "--data-urlencode" in v[0].message


def test_shell_wget_naked_query_var_with_ampersand_is_flagged() -> None:
    v = _find('wget "http://h?a=1&k=$V"')
    assert len(v) == 1
    assert v[0].line == 1
    assert "--data-urlencode" in v[0].message


def test_shell_fetch_naked_query_var_is_flagged() -> None:
    v = _find('fetch "https://h/cb?ip=$IP"')
    assert len(v) == 1
    assert "--data-urlencode" in v[0].message


def test_shell_braced_var_is_flagged() -> None:
    v = _find('curl "http://h/x?ip=${PFB_CHANGED_IP_ALIASES}"')
    assert len(v) == 1


def test_shell_data_urlencode_correct_form_is_clean() -> None:
    # The GOOD form: value rides its own flag token, not the URL token.
    assert _find('curl --data-urlencode "ip=$VAR" http://h/x') == []


def test_shell_data_urlencode_unquoted_is_clean() -> None:
    assert _find("curl --data-urlencode ip=$VAR http://h/x") == []


def test_shell_data_urlencode_alongside_static_query_is_clean() -> None:
    # A static query on the URL plus the variable carried by --data-urlencode.
    assert _find('curl "http://h/x?fixed=1" --data-urlencode "ip=$VAR"') == []


def test_shell_static_query_param_is_clean() -> None:
    assert _find('curl "http://h/x?fixed=1"') == []


def test_shell_base_var_no_query_is_clean() -> None:
    assert _find('curl "$BASE/path"') == []


def test_shell_path_segment_var_is_clean() -> None:
    # Path-segment interpolation is intentionally out of scope.
    assert _find('curl "http://h/$ID"') == []


def test_non_http_client_line_with_query_var_is_clean() -> None:
    # Same `?k=$V` shape, but not a curl/wget/fetch invocation.
    assert _find('echo "http://h/x?ip=$VAR"') == []


def test_curl_substring_word_is_not_an_http_client() -> None:
    # `curling` / `mycurl` must not match (word-boundary).
    assert _find('curling "http://h/x?ip=$VAR"') == []


# --------------------------------------------------------------------------- #
# Continuation handling — bad vs good
# --------------------------------------------------------------------------- #


def test_shell_continuation_url_is_flagged_at_start_line() -> None:
    text = 'curl \\\n  "http://h/cb?ip=$VAR"'
    v = _find(text)
    assert len(v) == 1
    # Reported at the curl line (logical line start), not the continuation.
    assert v[0].line == 1


def test_shell_continuation_data_urlencode_is_clean() -> None:
    text = 'curl \\\n  --data-urlencode "ip=$VAR" \\\n  http://h/cb'
    assert _find(text) == []


def test_shell_before_state_static_then_var_transition() -> None:
    # Before-state: the static-query line alone is clean.
    static_only = 'curl "http://h/cb?fixed=1"'
    assert _find(static_only) == []
    # After swapping the static value for a naked variable, it is flagged —
    # proving the variable interpolation (not merely the query) is the cause.
    naked = 'curl "http://h/cb?fixed=$VAR"'
    assert len(_find(naked)) == 1


# --------------------------------------------------------------------------- #
# Markdown fenced blocks — bad vs good vs non-shell
# --------------------------------------------------------------------------- #


def test_markdown_shell_fence_naked_var_is_flagged_with_right_line() -> None:
    md = '# Title\n\nText.\n\n```sh\ncurl "http://h/cb?ip=$VAR"\n```\n'
    v = _find_md(md)
    assert len(v) == 1
    # The curl line is line 6 (1-based) in the file.
    assert v[0].line == 6
    assert "--data-urlencode" in v[0].message


def test_markdown_bash_fence_naked_var_is_flagged() -> None:
    md = '```bash\nwget "http://h?k=$V"\n```\n'
    v = _find_md(md)
    assert len(v) == 1
    assert v[0].line == 2


def test_markdown_shell_fence_data_urlencode_is_clean() -> None:
    md = '```sh\ncurl --data-urlencode "ip=$VAR" http://h/cb\n```\n'
    assert _find_md(md) == []


def test_markdown_non_shell_fence_is_not_scanned() -> None:
    # A ```python block with the naked pattern must NOT be scanned.
    md = '```python\nrequests.get("http://h/x?ip=$VAR")\n```\n'
    assert _find_md(md) == []


def test_markdown_prose_outside_fence_is_not_scanned() -> None:
    # The pattern in prose (no fence) is ignored.
    md = 'Run curl "http://h/x?ip=$VAR" to break things.\n'
    assert _find_md(md) == []


def test_markdown_before_state_good_then_bad_fence() -> None:
    good = '```sh\ncurl --data-urlencode "ip=$VAR" http://h/cb\n```\n'
    assert _find_md(good) == []
    bad = '```sh\ncurl "http://h/cb?ip=$VAR"\n```\n'
    assert len(_find_md(bad)) == 1


# --------------------------------------------------------------------------- #
# CLI (main) over real temp files — exit codes both ways
# --------------------------------------------------------------------------- #


def test_main_returns_1_on_violation_and_prints_fix(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "hook.sh"
    f.write_text('#!/bin/sh\ncurl "http://h/cb?ip=$VAR"\n')
    rc = cue.main([str(f)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "--data-urlencode" in err
    assert f"{f}:2:" in err


def test_main_returns_0_on_clean_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "hook.sh"
    f.write_text('#!/bin/sh\ncurl --data-urlencode "ip=$VAR" http://h/cb\n')
    rc = cue.main([str(f)])
    assert rc == 0
    assert capsys.readouterr().err == ""


def test_main_scans_markdown_by_extension(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "recipe.md"
    f.write_text('```sh\ncurl "http://h/cb?ip=$VAR"\n```\n')
    rc = cue.main([str(f)])
    assert rc == 1
    assert "--data-urlencode" in capsys.readouterr().err
