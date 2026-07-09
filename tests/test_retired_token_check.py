"""Tests for scripts/check_retired_tokens.py.

Every candidate/threshold rule is paired with the nearest form that must
stay clean, so a green run proves the checker discriminates a genuine
tree-wide retirement (issue #1047's ``' [ NOW ]'`` shape: >=3 removed sites,
0 re-adds) from a rename/move, a partial edit, or noise -- rather than firing
on any repeated quoted string.

Fixture tokens are assembled at runtime (string concatenation) so this
tracked test file does not itself contain a flaggable literal, mirroring
tests/test_version_literal_check.py's convention.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "check_retired_tokens.py"
_spec = importlib.util.spec_from_file_location("check_retired_tokens", _TOOL)
assert _spec is not None and _spec.loader is not None
crt = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = crt
_spec.loader.exec_module(crt)


# --------------------------------------------------------------------------- #
# Synthetic-diff helpers (pure parsing/candidate rows -- no real git needed)
# --------------------------------------------------------------------------- #


def _diff_hunk(path: str, removed: list[str], added: list[str], old_path: str | None = None) -> str:
    """One file's unified-diff section (mirrors ``git diff --unified=0`` shape)."""
    a = old_path or path
    lines = [f"diff --git a/{a} b/{path}", f"--- a/{a}", f"+++ b/{path}", "@@ -1,0 +1,0 @@"]
    lines += [f"-{ln}" for ln in removed]
    lines += [f"+{ln}" for ln in added]
    return "\n".join(lines) + "\n"


def _deleted_diff_hunk(path: str, removed: list[str]) -> str:
    lines = [
        f"diff --git a/{path} b/{path}",
        "deleted file mode 100644",
        f"--- a/{path}",
        "+++ /dev/null",
        "@@ -1,0 +0,0 @@",
    ]
    lines += [f"-{ln}" for ln in removed]
    return "\n".join(lines) + "\n"


def _diff_hunk_with_marker(path: str, removed: list[str]) -> str:
    """A removed-only hunk followed by the ``\\ No newline`` marker (issue #1051 shape)."""
    lines = [f"diff --git a/{path} b/{path}", f"--- a/{path}", f"+++ b/{path}", "@@ -1,0 +1,0 @@"]
    lines += [f"-{ln}" for ln in removed]
    lines.append("\\ No newline at end of file")
    return "\n".join(lines) + "\n"


def _retired(diff_text: str) -> list[str]:
    removed, added = crt._parse_diff(diff_text)
    return crt.find_retired_tokens(removed, added)


# --------------------------------------------------------------------------- #
# Real-git helpers (CLI-mode / grep-target rows -- mirrors
# tests/test_version_literal_check.py's subprocess harness)
# --------------------------------------------------------------------------- #


def _init_repo(repo: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True, capture_output=True)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def _run(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(_TOOL), *args], cwd=repo, capture_output=True, text=True)


def _run_hook(repo: Path, stdin_text: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_TOOL), "--claude-hook"], cwd=repo, input=stdin_text, capture_output=True, text=True
    )


def _rev(repo: Path) -> str:
    out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True)
    return out.stdout.strip()


def _seed_retirement_with_survivor(repo: Path, tok: str) -> None:
    """Commit src/a.php (3 quoted ``tok`` sites) + src/b.php (1 untouched site), then STAGE a.php's retirement."""
    _init_repo(repo)
    (repo / "src").mkdir()
    (repo / "src/a.php").write_text("\n".join(f"logger('{tok}');" for _ in range(3)) + "\n")
    (repo / "src/b.php").write_text(f"echo '{tok} survivor';\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    (repo / "src/a.php").write_text("logger();\n" * 3)
    _git(repo, "add", ".")


# --------------------------------------------------------------------------- #
# R1 -- threshold-hit: 3 removed, 0 added, 1 surviving site -> flagged
# --------------------------------------------------------------------------- #


def test_r1_threshold_hit_staged(tmp_path: Path) -> None:
    tok = "TOK" + "_R1S_MARK"
    _seed_retirement_with_survivor(tmp_path, tok)
    res = _run(tmp_path, "--staged")
    assert res.returncode == 1, f"expected exit 1 (findings); got {res.returncode}, stderr={res.stderr}"
    assert f"{tok!r}: 1 site(s) remain:" in res.stdout, f"expected exactly 1 site reported; got stdout={res.stdout!r}"
    assert "src/b.php:1" in res.stdout, f"report must name the surviving site; got stdout={res.stdout!r}"


def test_r1_threshold_hit_diff_mode_strips_head_prefix(tmp_path: Path) -> None:
    tok = "TOK" + "_R1D_MARK"
    _init_repo(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src/a.php").write_text("\n".join(f"logger('{tok}');" for _ in range(3)) + "\n")
    (tmp_path / "src/b.php").write_text(f"echo '{tok} survivor';\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _rev(tmp_path)

    (tmp_path / "src/a.php").write_text("logger();\n" * 3)
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "retire token")
    res = _run(tmp_path, "--diff", base)
    assert res.returncode == 1, f"expected exit 1; got {res.returncode}, stderr={res.stderr}"
    assert "HEAD:" not in res.stdout, f"the HEAD: revision prefix must be stripped; got stdout={res.stdout!r}"
    assert "src/b.php:1" in res.stdout, f"report must name the surviving site; got stdout={res.stdout!r}"


# --------------------------------------------------------------------------- #
# R2 -- threshold-under: 2 removed lines only -> NOT flagged
# --------------------------------------------------------------------------- #


def test_r2_threshold_under_two_removed_lines_not_flagged() -> None:
    tok = "TOK" + "_R2_MARK"
    diff = _diff_hunk("src/a.php", removed=[f"logger('{tok}');" for _ in range(2)], added=[])
    retired = _retired(diff)
    assert tok not in retired, f"2 removed lines must be below the >=3 threshold; got retired={retired}"


# --------------------------------------------------------------------------- #
# R3 -- moved token: 3 removed + 1 added -> NOT flagged (a move, not a retirement)
# --------------------------------------------------------------------------- #


def test_r3_moved_token_not_flagged() -> None:
    tok = "TOK" + "_R3_MARK"
    diff = _diff_hunk("src/a.php", removed=[f"logger('{tok}');" for _ in range(3)], added=[f"logger('{tok}');"])
    retired = _retired(diff)
    assert tok not in retired, f"a token re-added elsewhere must not be treated as retired; got retired={retired}"


# --------------------------------------------------------------------------- #
# R4 -- added-outside-scan-roots: 3 removed (scan-root) + 1 added under tests/
# -> STILL flagged (the 958e679f shape -- its only additions were test-only)
# --------------------------------------------------------------------------- #


def test_r4_added_outside_scan_roots_still_flagged() -> None:
    tok = "TOK" + "_R4_MARK"
    diff = _diff_hunk("src/a.php", removed=[f"logger('{tok}');" for _ in range(3)], added=[]) + _diff_hunk(
        "tests/fixture.py", removed=[], added=[f"assert '{tok}' not in log"]
    )
    retired = _retired(diff)
    assert tok in retired, f"an addition OUTSIDE scan roots must not block retirement; got retired={retired}"


# --------------------------------------------------------------------------- #
# R5 -- removed-outside-scan-roots only -> no candidate
# --------------------------------------------------------------------------- #


def test_r5_removed_outside_scan_roots_no_candidate() -> None:
    tok = "TOK" + "_R5_MARK"
    diff = _diff_hunk("tests/fixture.py", removed=[f"assert '{tok}' not in log" for _ in range(3)], added=[])
    retired = _retired(diff)
    assert tok not in retired, f"removed lines outside scan roots must never seed a candidate; got retired={retired}"


# --------------------------------------------------------------------------- #
# R6 -- zero remaining sites: retired, but nothing survives -> exit 0, NO output
# --------------------------------------------------------------------------- #


def test_r6_zero_remaining_sites_no_output(tmp_path: Path) -> None:
    tok = "TOK" + "_R6_MARK"
    _init_repo(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src/a.php").write_text("\n".join(f"logger('{tok}');" for _ in range(3)) + "\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")

    (tmp_path / "src/a.php").write_text("logger();\n" * 3)
    _git(tmp_path, "add", ".")
    res = _run(tmp_path, "--staged")
    assert res.returncode == 0, f"a fully retired token with no stragglers must exit 0; got {res.returncode}"
    assert res.stdout == "", f"a clean result must print nothing; got stdout={res.stdout!r}"


# --------------------------------------------------------------------------- #
# R7 -- escape comment: 2 surviving sites, 1 carries retired-token-ok -> only
# the OTHER site is reported (vacuity guard: proves the exemption discriminates)
# --------------------------------------------------------------------------- #


def test_r7_escape_comment_exempts_only_that_site(tmp_path: Path) -> None:
    tok = "TOK" + "_R7_MARK"
    _init_repo(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src/a.php").write_text("\n".join(f"logger('{tok}');" for _ in range(3)) + "\n")
    (tmp_path / "src/b.php").write_text(f"echo '{tok} survivor';\n")
    (tmp_path / "src/c.php").write_text(f"echo '{tok} kept';  # retired-token-ok: legacy fixture\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")

    (tmp_path / "src/a.php").write_text("logger();\n" * 3)
    _git(tmp_path, "add", ".")
    res = _run(tmp_path, "--staged")
    assert res.returncode == 1, f"one non-exempt straggler must still flag; got {res.returncode}, stderr={res.stderr}"
    assert "src/b.php:1" in res.stdout, f"the non-exempt site must be reported; got stdout={res.stdout!r}"
    assert "src/c.php" not in res.stdout, f"the escaped site must be exempt; got stdout={res.stdout!r}"
    assert f"{tok!r}: 1 site(s) remain:" in res.stdout, f"expected exactly 1 surviving site; got stdout={res.stdout!r}"


# --------------------------------------------------------------------------- #
# R8 -- allowlist: retirement + straggler present, but token allowlisted
# -> exit 0
# --------------------------------------------------------------------------- #


def test_r8_allowlist_skips_token(tmp_path: Path) -> None:
    tok = "TOK" + "_R8_MARK"
    _seed_retirement_with_survivor(tmp_path, tok)
    res = _run(tmp_path, "--staged", "--token-allowlist", tok)
    assert res.returncode == 0, (
        f"an allowlisted retired token must not flag; got {res.returncode}, stdout={res.stdout!r}"
    )
    assert res.stdout == "", f"an allowlisted-clean result must print nothing; got stdout={res.stdout!r}"


# --------------------------------------------------------------------------- #
# R9 -- min-length gate: trimmed length 3 skipped, length 4 is a candidate
# --------------------------------------------------------------------------- #


def test_r9_min_length_gate_both_sides() -> None:
    short = "AB1"  # trimmed length 3 -- below the gate
    long_ = "AB12"  # trimmed length 4 -- at the gate
    diff = _diff_hunk("src/a.php", removed=[f"x('{short}');" for _ in range(3)], added=[]) + _diff_hunk(
        "src/b.php", removed=[f"y('{long_}');" for _ in range(3)], added=[]
    )
    retired = _retired(diff)
    assert short not in retired, f"a length-3 token must be skipped; got retired={retired}"
    assert long_ in retired, f"a length-4 token must be a candidate; got retired={retired}"


# --------------------------------------------------------------------------- #
# R10 -- pure-punctuation token (length >= 4, no alnum) -> skipped
# --------------------------------------------------------------------------- #


def test_r10_pure_punctuation_token_skipped() -> None:
    punct = "-" * 4
    diff = _diff_hunk("src/a.php", removed=[f"x('{punct}');" for _ in range(3)], added=[])
    retired = _retired(diff)
    assert punct not in retired, f"a no-alnum token must be skipped even at length >=4; got retired={retired}"


# --------------------------------------------------------------------------- #
# R11 -- '\ No newline at end of file' marker: not counted as content;
# candidate math identical with vs without it present (issue #1051 lesson)
# --------------------------------------------------------------------------- #


def test_r11_no_newline_marker_not_counted_as_content() -> None:
    tok = "TOK" + "_R11_MARK"
    removed_lines = [f"x('{tok}');" for _ in range(3)]
    with_marker = _retired(_diff_hunk_with_marker("src/a.php", removed_lines))
    without_marker = _retired(_diff_hunk("src/a.php", removed=removed_lines, added=[]))
    assert with_marker == without_marker, (
        f"the no-newline marker must not change retirement math; "
        f"with_marker={with_marker} without_marker={without_marker}"
    )
    assert tok in with_marker, f"expected {tok!r} retired even with the marker present; got {with_marker}"


# --------------------------------------------------------------------------- #
# R12 -- deleted-file diff: '+++ /dev/null', path taken from '--- a/'
# --------------------------------------------------------------------------- #


def test_r12_deleted_file_removed_lines_contribute_from_a_path() -> None:
    tok = "TOK" + "_R12_MARK"
    diff = _deleted_diff_hunk("src/gone.php", removed=[f"x('{tok}');" for _ in range(3)])
    retired = _retired(diff)
    assert tok in retired, f"a deleted file's removed lines must still seed candidates; got retired={retired}"


# --------------------------------------------------------------------------- #
# R13 -- header lines ('--- a/...' / '+++ b/...') never enter content lists
# --------------------------------------------------------------------------- #


def test_r13_header_lines_never_enter_content() -> None:
    tok = "TOK" + "_R13_MARK"
    # A path-like header line embedding a token-shaped quoted span, repeated
    # across 3 files -- if header text were mistakenly scanned as content,
    # this alone would satisfy the >=3-removed-lines threshold.
    diff = (
        "\n".join(
            f'diff --git a/src/f{i}.sh b/src/f{i}.sh\n--- a/src/f{i}.sh "{tok}"\n'
            f'+++ b/src/f{i}.sh "{tok}"\n@@ -1,0 +1,0 @@'
            for i in range(3)
        )
        + "\n"
    )
    removed, added = crt._parse_diff(diff)
    assert removed == {} and added == {}, (
        f"header lines must never enter content lists; got removed={removed} added={added}"
    )
    assert tok not in crt.find_retired_tokens(removed, added), "header-only text must never be flagged as retired"


# --------------------------------------------------------------------------- #
# R14 -- hostile-input tokens
# --------------------------------------------------------------------------- #


def test_r14a_regex_metachar_token_matched_fixed_string(tmp_path: Path) -> None:
    tok = ".*[$]()" + "A"  # regex metachars + one ASCII alnum char to pass the gate
    _seed_retirement_with_survivor(tmp_path, tok)
    res = _run(tmp_path, "--staged")
    assert res.returncode == 1, (
        f"a regex-metachar token must still be found via fixed-string grep; got {res.returncode}, stderr={res.stderr}"
    )
    assert "src/b.php:1" in res.stdout, f"expected the survivor site reported; got stdout={res.stdout!r}"


def test_r14b_tab_and_consecutive_spaces_preserved(tmp_path: Path) -> None:
    tok = "A" + "\t" + "B" + "   " + "C1"
    _seed_retirement_with_survivor(tmp_path, tok)
    res = _run(tmp_path, "--staged")
    assert res.returncode == 1, f"expected findings; got {res.returncode}, stderr={res.stderr}"
    assert repr(tok) in res.stdout, f"the report must preserve tab/space bytes exactly; got stdout={res.stdout!r}"


def test_r14c_oversized_token_works(tmp_path: Path) -> None:
    tok = "X" * 500
    _seed_retirement_with_survivor(tmp_path, tok)
    res = _run(tmp_path, "--staged")
    assert res.returncode == 1, f"expected findings; got {res.returncode}, stderr={res.stderr}"
    assert "src/b.php:1" in res.stdout, f"expected the survivor site reported; got stdout={res.stdout!r}"


# --------------------------------------------------------------------------- #
# R15 -- --claude-hook mode
# --------------------------------------------------------------------------- #


def test_r15a_hook_reports_findings_as_single_json_line(tmp_path: Path) -> None:
    tok = "TOK" + "_R15A_MARK"
    _seed_retirement_with_survivor(tmp_path, tok)
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "git commit -m 'retire token'"}})
    res = _run_hook(tmp_path, payload)
    assert res.returncode == 0, f"hook mode must never exit nonzero; got {res.returncode}, stderr={res.stderr}"
    out_lines = res.stdout.splitlines()
    assert len(out_lines) == 1, f"expected exactly one stdout line; got {out_lines!r}"
    parsed = json.loads(out_lines[0])
    assert parsed["hookSpecificOutput"]["hookEventName"] == "PreToolUse", f"got {parsed!r}"
    ctx = parsed["hookSpecificOutput"]["additionalContext"]
    assert repr(tok) in ctx, f"additionalContext must show the token repr; got {ctx!r}"
    assert "src/b.php:1" in ctx, f"additionalContext must name the surviving site; got {ctx!r}"


def test_r15b_hook_skips_analysis_without_git_commit(tmp_path: Path) -> None:
    tok = "TOK" + "_R15B_MARK"
    _seed_retirement_with_survivor(tmp_path, tok)
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "git status"}})
    res = _run_hook(tmp_path, payload)
    assert res.returncode == 0, f"hook mode must exit 0; got {res.returncode}"
    assert res.stdout == "", (
        f"no 'git commit' substring must print nothing even with a real retirement; got {res.stdout!r}"
    )


def test_r15c_hook_garbled_stdin_fails_open(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    res = _run_hook(tmp_path, "totally not json at all {{{ ]]] ***")
    assert res.returncode == 0, f"garbled stdin must fail open; got {res.returncode}, stderr={res.stderr}"
    assert res.stdout == "", f"garbled stdin (no 'git commit') must print nothing; got {res.stdout!r}"


def test_r15_hook_not_a_git_repo_fails_open(tmp_path: Path) -> None:
    # No `git init` -- tmp_path is NOT a repository, so the internal `git
    # diff --cached` call must fail; the hook must swallow that, not crash.
    payload = json.dumps({"tool_input": {"command": "git commit -m 'x'"}})
    res = _run_hook(tmp_path, payload)
    assert res.returncode == 0, (
        f"a git failure inside the hook must fail open; got {res.returncode}, stderr={res.stderr}"
    )
    assert res.stdout == "", f"a git failure inside the hook must print nothing; got {res.stdout!r}"


def test_r15d_hook_normalizes_double_space_before_git_commit(tmp_path: Path) -> None:
    tok = "TOK" + "_R15D1_MARK"
    _seed_retirement_with_survivor(tmp_path, tok)
    payload = json.dumps({"tool_input": {"command": "git  commit -m 'x'"}})  # double space
    res = _run_hook(tmp_path, payload)
    assert res.returncode == 0, f"hook mode must exit 0; got {res.returncode}"
    assert res.stdout != "", f"a double-spaced 'git  commit' must still trigger analysis; got stdout={res.stdout!r}"


def test_r15d_hook_normalizes_escaped_quotes_before_git_commit(tmp_path: Path) -> None:
    tok = "TOK" + "_R15D2_MARK"
    _seed_retirement_with_survivor(tmp_path, tok)
    # Raw payload with JSON-escaped quotes around "commit" (as if the shell
    # command itself quoted the subcommand): git \"commit\" -m x
    payload = '{"tool_input": {"command": "git \\"commit\\" -m x"}}'
    res = _run_hook(tmp_path, payload)
    assert res.returncode == 0, f"hook mode must exit 0; got {res.returncode}"
    assert res.stdout != "", f"escaped quotes around 'commit' must still normalize+trigger; got stdout={res.stdout!r}"


# --------------------------------------------------------------------------- #
# R16 -- exit codes (findings=>1 is R1; clean=>0 is R6; usage errors here)
# --------------------------------------------------------------------------- #


def test_r16_unknown_flag_exits_2(tmp_path: Path) -> None:
    res = _run(tmp_path, "--totally-bogus-flag")
    assert res.returncode == 2, f"an unknown flag must exit 2; got {res.returncode}, stdout={res.stdout!r}"


def test_r16_missing_diff_base_exits_2(tmp_path: Path) -> None:
    res = _run(tmp_path, "--diff")
    assert res.returncode == 2, f"a missing --diff base must exit 2; got {res.returncode}, stdout={res.stdout!r}"


# --------------------------------------------------------------------------- #
# R17 -- two distinct retired tokens -> both reported, deterministic order
# --------------------------------------------------------------------------- #


def test_r17_format_report_sorts_tokens_and_hits() -> None:
    tok_late = "Z" + "_TOKEN_LATE"
    tok_early = "A" + "_TOKEN_EARLY"
    findings = {
        tok_late: ["src/z.php:9: zzz", "src/a.php:1: aaa"],
        tok_early: ["src/b.php:2: bbb"],
    }
    report = crt.format_report(findings)
    early_idx = report.index(repr(tok_early))
    late_idx = report.index(repr(tok_late))
    assert early_idx < late_idx, f"tokens must be sorted; got report={report!r}"
    aaa_idx = report.index("src/a.php:1")
    zzz_idx = report.index("src/z.php:9")
    assert aaa_idx < zzz_idx, f"hits within a token must be sorted; got report={report!r}"


def test_r17_two_distinct_retired_tokens_both_reported(tmp_path: Path) -> None:
    tok_a = "AAA" + "_R17_MARK"
    tok_b = "ZZZ" + "_R17_MARK"
    _init_repo(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src/a.php").write_text(
        "\n".join(f"logger('{tok_a}');" for _ in range(3))
        + "\n"
        + "\n".join(f"logger('{tok_b}');" for _ in range(3))
        + "\n"
    )
    (tmp_path / "src/b.php").write_text(f"echo '{tok_a} survivor';\necho '{tok_b} survivor';\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")

    (tmp_path / "src/a.php").write_text("logger();\n" * 6)
    _git(tmp_path, "add", ".")
    res = _run(tmp_path, "--staged")
    assert res.returncode == 1, f"expected findings; got {res.returncode}, stderr={res.stderr}"
    assert repr(tok_a) in res.stdout and repr(tok_b) in res.stdout, (
        f"both tokens must be reported; got stdout={res.stdout!r}"
    )
    a_pos = res.stdout.index(repr(tok_a))
    b_pos = res.stdout.index(repr(tok_b))
    assert a_pos < b_pos, f"tokens must print in sorted order; got stdout={res.stdout!r}"


# --------------------------------------------------------------------------- #
# R18 -- unquoted-only text on removed lines -> no candidate
# --------------------------------------------------------------------------- #


def test_r18_unquoted_token_never_becomes_a_candidate() -> None:
    tok = "TOK" + "_R18_MARK"
    diff = _diff_hunk("src/a.php", removed=[f"x = {tok};" for _ in range(3)], added=[])
    retired = _retired(diff)
    assert tok not in retired, f"an unquoted-only token must never seed a candidate; got retired={retired}"
