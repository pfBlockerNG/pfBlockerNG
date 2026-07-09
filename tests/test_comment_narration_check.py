"""Tests for scripts/check_comment_narration.py.

Covers both branches per dimension (CLAUDE.md test-coverage rules): every
pattern that flags a violation is paired with the nearest correct form that
must stay clean, so a green proves the checker discriminates rather than
always firing (or never firing).

The checker is diff-scoped: only ADDED lines are judged, so the tests build
unified-diff text (the exact format `git diff --unified=0` emits) rather than
whole files.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "check_comment_narration.py"
_spec = importlib.util.spec_from_file_location("check_comment_narration", _TOOL)
assert _spec is not None and _spec.loader is not None
ccn = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ccn
_spec.loader.exec_module(ccn)


def _diff(path: str, added: list[str], start: int = 1) -> str:
    """Unified diff adding ``added`` lines to ``path`` at ``start``."""
    hunk = "\n".join("+" + line for line in added)
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -0,0 +{start},{len(added)} @@\n{hunk}\n"


def _find(path: str, added: list[str], start: int = 1) -> list:
    return ccn.find_violations(_diff(path, added, start))


# --------------------------------------------------------------------------- #
# Patterns — flagged vs the nearest clean sibling
# --------------------------------------------------------------------------- #


def test_results_ref_is_flagged() -> None:
    v = _find("src/usr/local/pkg/pfblockerng/pfblockerng.inc", ["// see RESULTS/01 SS2"])
    assert len(v) == 1
    assert v[0].line == 1
    assert "RESULTS/" in v[0].reason


def test_results_word_without_slash_is_clean() -> None:
    assert _find("src/a.inc", ["// the RESULTS are cached"]) == []


def test_slashless_results_handoff_ref_is_flagged() -> None:
    assert len(_find("src/a.py", ["# the 6-band scale (RESULTS-P2 SS2)"])) == 1


def test_capital_phase_number_is_flagged() -> None:
    v = _find("src/a.py", ["# wired into init() in Phase 4"])
    assert len(v) == 1
    assert "phase" in v[0].reason.lower()


def test_lowercase_phase_number_is_clean() -> None:
    # Only the ADR-narration capitalised form is banned; ordinary prose about a
    # protocol's "phase 2" stays legal.
    assert _find("src/a.py", ["# TLS handshake phase 2 resumes here"]) == []


def test_hyphenated_and_abbreviated_phase_idioms_are_flagged() -> None:
    # The repo's other narration spellings: "Phase-3" and "ADR-NN PN".
    assert len(_find("src/a.inc", ["// falls back to the Phase-3 hard rule"])) == 1
    assert len(_find("src/a.py", ["# ADR-53 P6: token-shape guard"])) == 1
    assert _find("src/a.py", ["# two-phase-commit protocol, phase-2 resumes"]) == []
    assert _find("src/a.py", ["# the P6 bus register"]) == []


def test_number_needs_trailing_boundary() -> None:
    # "Phase 9x"/"PR #9foo" are not phase/PR references; multi-digit ones are.
    assert _find("src/a.py", ["# gets a Phase 9x speedup"]) == []
    assert _find("src/a.inc", ["// tracked as PR #9foo"]) == []
    assert len(_find("src/a.py", ["# wired in Phase 10"])) == 1
    assert len(_find("src/a.inc", ["// per PR #1024"])) == 1


def test_review_fanout_is_flagged() -> None:
    v = _find("scripts/build-leg.sh", ["# review-fanout C9 pinned this"])
    assert len(v) == 1


def test_pr_number_is_flagged_but_issue_breadcrumb_is_clean() -> None:
    assert len(_find("src/a.inc", ["// escape-aware (Copilot, PR #947)"])) == 1
    assert len(_find("src/a.inc", ["// see PR#947 for context"])) == 1
    assert _find("src/a.inc", ["// issue #946: decode UTF-16 BOM first"]) == []
    assert _find("src/a.inc", ["// case-fold TOP1M match (#920)"]) == []


def test_review_fanout_is_case_insensitive() -> None:
    assert len(_find("src/a.inc", ["// Review-Fanout C9 pinned this"])) == 1


# --------------------------------------------------------------------------- #
# Scope — roots, extensions, self-exclusions, escape hatch
# --------------------------------------------------------------------------- #


def test_markdown_and_out_of_root_paths_are_clean() -> None:
    bad = ["see RESULTS/01 and Phase 3"]
    assert _find("docs/misc/architecture-notes.md", bad) == []
    assert _find("src/notes.md", bad) == []
    assert _find("tests/test_x.py", bad) == []
    assert _find(".ADRs/ADR_60_X/prompt.txt", bad) == []


def test_self_and_phase_prompt_checker_are_excluded() -> None:
    bad = ["# RESULTS/ Phase 1"]
    assert _find("scripts/check_comment_narration.py", bad) == []
    assert _find("tests/test_comment_narration_check.py", bad) == []
    assert _find("scripts/check_phase_prompts.py", bad) == []


def test_self_exclusion_is_full_path_not_basename() -> None:
    assert len(_find("src/nested/check_comment_narration.py", ["# RESULTS/ Phase 1"])) == 1


def test_narration_ok_escape_exempts_the_line() -> None:
    assert _find("src/a.inc", ["// Phase 2 of BGP convergence  // narration-ok: protocol term"]) == []
    assert _find("src/a.inc", ["// Phase 2 of BGP convergence  // Narration-OK: protocol term"]) == []


# --------------------------------------------------------------------------- #
# Diff mechanics — only added lines judged, line numbers from hunk headers
# --------------------------------------------------------------------------- #


def test_space_bearing_path_tab_is_stripped() -> None:
    # git appends a disambiguation tab to +++ headers of space-bearing paths;
    # unstripped it defeats the .md suffix exclusion.
    tabbed = (
        "diff --git a/src/my notes.md b/src/my notes.md\n"
        "--- a/src/my notes.md\t\n"
        "+++ b/src/my notes.md\t\n"
        "@@ -0,0 +1,1 @@\n"
        "+see RESULTS/01 and Phase 4\n"
    )
    assert ccn.find_violations(tabbed) == []


def test_removed_and_context_lines_are_ignored() -> None:
    diff = (
        "diff --git a/src/a.inc b/src/a.inc\n"
        "--- a/src/a.inc\n"
        "+++ b/src/a.inc\n"
        "@@ -5,2 +5,1 @@\n"
        "-// old RESULTS/01 note\n"
        " // context Phase 9 line\n"
        "+// clean replacement\n"
    )
    assert ccn.find_violations(diff) == []


def test_line_numbers_track_hunk_headers_across_files() -> None:
    diff = _diff("src/a.inc", ["// ok", "// see RESULTS/02"], start=40) + _diff(
        "src/b.py", ["# ADR-48 Phase 4 tally"], start=7
    )
    v = ccn.find_violations(diff)
    assert [(x.path, x.line) for x in v] == [("src/a.inc", 41), ("src/b.py", 7)]


def test_clean_diff_yields_nothing() -> None:
    assert _find("src/a.inc", ["// pfb_foo(): guard empty input"]) == []


def test_added_line_starting_with_plus_plus_is_not_misread_as_a_header() -> None:
    # Hostile input (issue #1029): an added line whose own content starts
    # with "++" renders in the diff as "+++ ..." -- must not be mistaken for
    # a file header, which would drop it and every following added line.
    diff = (
        "diff --git a/scripts/tool.sh b/scripts/tool.sh\n"
        "--- a/scripts/tool.sh\n"
        "+++ b/scripts/tool.sh\n"
        "@@ -0,0 +1,2 @@\n"
        "+++ banner\n"
        "+// per RESULTS/03 SS1\n"
    )
    v = ccn.find_violations(diff)
    assert len(v) == 1
    assert v[0].path == "scripts/tool.sh"
    assert v[0].line == 2


# --------------------------------------------------------------------------- #
# CLI — the two production modes, end-to-end in a scratch repo
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


def test_cli_staged_and_diff_modes(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "src").mkdir()
    (tmp_path / "src/a.inc").write_text("// clean\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")

    # --staged: violating staged line fails with file:line on stderr...
    (tmp_path / "src/a.inc").write_text("// clean\n// per RESULTS/03 SS1\n")
    _git(tmp_path, "add", ".")
    res = _run(tmp_path, "--staged")
    assert res.returncode == 1, res.stderr
    assert "src/a.inc:2" in res.stderr

    # --diff BASE: committed violation vs the base branch fails the same way,
    # and a clean staged tree passes --staged.
    _git(tmp_path, "commit", "-qm", "bad")
    assert _run(tmp_path, "--staged").returncode == 0
    res = _run(tmp_path, "--diff", "devel~1")
    assert res.returncode == 1, res.stderr
    assert "src/a.inc:2" in res.stderr

    # Reverting to clean content passes --diff again.
    (tmp_path / "src/a.inc").write_text("// clean\n")
    _git(tmp_path, "commit", "-qam", "clean")
    assert _run(tmp_path, "--diff", "devel~2").returncode == 0


def test_cli_diff_replacing_no_eol_last_line_reports_correct_lineno(tmp_path: Path) -> None:
    # Hostile input (issue #1051): when the OLD file's last line lacks a
    # trailing newline, git emits "\ No newline at end of file" BETWEEN the
    # "-" and "+" lines. Counting that marker as a content line shifts every
    # following added line by one — the violation must be reported at its
    # REAL line number, not real+1.
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "src").mkdir()
    (tmp_path / "src/a.inc").write_bytes(b"// clean\n// tail")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base no eol")

    (tmp_path / "src/a.inc").write_text("// clean\n// per RESULTS/03 SS1\n")
    _git(tmp_path, "add", ".")
    res = _run(tmp_path, "--staged")
    assert res.returncode == 1, res.stderr
    assert "src/a.inc:2" in res.stderr, f"expected src/a.inc:2, got: {res.stderr}"


def test_cli_hostile_git_configs_cannot_bypass_the_gate(tmp_path: Path) -> None:
    # core.quotePath defaults true (octal-quotes non-ASCII paths) and
    # diff.mnemonicPrefix rewrites the +++ prefix — either must not blind the scan.
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "src").mkdir()
    (tmp_path / "src/café.inc").write_text("// clean\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    (tmp_path / "src/café.inc").write_text("// clean\n// see RESULTS/01\n")
    _git(tmp_path, "add", ".")
    res = _run(tmp_path, "--staged")
    assert res.returncode == 1, res.stderr
    assert "src/café.inc:2" in res.stderr

    _git(tmp_path, "config", "diff.mnemonicPrefix", "true")
    _git(tmp_path, "config", "diff.noprefix", "true")
    assert _run(tmp_path, "--staged").returncode == 1

    # An external diff driver replaces the unified output entirely — the gate
    # must still see the real diff (config form and env form).
    _git(tmp_path, "config", "diff.external", "/bin/echo")
    assert _run(tmp_path, "--staged").returncode == 1
    env = {**os.environ, "GIT_EXTERNAL_DIFF": "/bin/echo"}
    res = subprocess.run(
        [sys.executable, str(_TOOL), "--staged"], cwd=tmp_path, capture_output=True, text=True, env=env
    )
    assert res.returncode == 1, res.stderr


def test_cli_space_bearing_md_path_stays_clean(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "src").mkdir()
    (tmp_path / "src/my notes.md").write_text("// clean\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    (tmp_path / "src/my notes.md").write_text("// clean\n// RESULTS/01 and Phase 4\n")
    _git(tmp_path, "add", ".")
    res = _run(tmp_path, "--staged")
    assert res.returncode == 0, res.stderr


def test_cli_usage_error(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    assert _run(tmp_path).returncode == 2
    assert _run(tmp_path, "--bogus").returncode == 2


def test_cli_bad_ref_is_a_usage_error_not_a_traceback(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-qb", "devel")
    (tmp_path / "f").write_text("x\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    res = _run(tmp_path, "--diff", "no-such-ref")
    assert res.returncode == 2, res.stderr
    assert "git diff failed" in res.stderr


def test_cli_staged_non_utf8_byte_does_not_crash_the_run(tmp_path: Path) -> None:
    # Hostile input (issue #1029): a non-UTF-8 byte anywhere in the staged
    # diff must not crash the run with a raw UnicodeDecodeError traceback --
    # decode lossily and still report the real violation on its own line.
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "src").mkdir()
    (tmp_path / "src/a.inc").write_text("// clean\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")

    (tmp_path / "src/a.inc").write_bytes(b"// clean\n// note caf\xff\xfe\n// per RESULTS/03 SS1\n")
    _git(tmp_path, "add", ".")
    res = _run(tmp_path, "--staged")
    assert res.returncode == 1, res.stderr
    assert "Traceback" not in res.stderr, res.stderr
    assert "src/a.inc:3" in res.stderr
