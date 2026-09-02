"""Tests for scripts/check_guard_erosion.py.

Every "is flagged" case is paired with the nearest form that must stay clean, so
a green run proves the checker discriminates rather than always firing (or never
firing): a retirement with a marker, a retirement with a tombstone row, a body
edit that keeps its declaration, and a declaration re-added under the same name.

The checker is diff-scoped, so the unit tests build unified-diff text (the shape
`git diff --unified=0` emits) instead of whole files; the CLI tests drive real
scratch repositories.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "check_guard_erosion.py"
_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("check_guard_erosion", _TOOL)
assert _spec is not None and _spec.loader is not None
cge = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cge
_spec.loader.exec_module(cge)

_PY = "tests/test_reaper.py"
_UNEXCUSED = "no successor"
_MALFORMED = "malformed"


def _section(
    *,
    old_path: str | None,
    new_path: str | None,
    removed: tuple[str, ...] = (),
    added: tuple[str, ...] = (),
    old_start: int = 1,
    new_start: int = 1,
) -> str:
    """One unified-diff file section. ``None`` renders the ``/dev/null`` side."""
    header = old_path or new_path
    lines = [
        f"diff --git a/{header} b/{header}",
        "--- /dev/null" if old_path is None else f"--- a/{old_path}",
        "+++ /dev/null" if new_path is None else f"+++ b/{new_path}",
        f"@@ -{old_start},{len(removed)} +{new_start},{len(added)} @@",
    ]
    lines += [f"-{line}" for line in removed]
    lines += [f"+{line}" for line in added]
    return "\n".join(lines) + "\n"


def _edit(path: str, removed: tuple[str, ...] = (), added: tuple[str, ...] = (), old_start: int = 1) -> str:
    return _section(old_path=path, new_path=path, removed=removed, added=added, old_start=old_start)


def _find(*sections: str) -> list:
    return cge.find_violations("".join(sections))


def _tombstone_row(name: str, date: str = "2026-09-02", reason: str = "folded into the fleet reaper") -> str:
    return f"| {date} | `{name}` | {reason} |"


# --------------------------------------------------------------------------- #
# Python — the retirement and each way of excusing it
# --------------------------------------------------------------------------- #


def test_removed_python_test_without_successor_or_tombstone_is_flagged() -> None:
    v = _find(_edit(_PY, removed=("def test_reaps_the_orphan(tmp_path):",), old_start=12))
    assert len(v) == 1, v
    assert v[0].path == _PY
    assert v[0].name == "test_reaps_the_orphan"
    assert v[0].line == 12, "the report must cite the OLD-side line the declaration stood on"
    assert _UNEXCUSED in v[0].reason


def test_removed_python_test_with_successor_marker_is_clean() -> None:
    assert (
        _find(
            _edit(_PY, removed=("def test_reaps_the_orphan(tmp_path):",)),
            _edit(
                "tests/test_fleet.py",
                added=(
                    "def test_fleet_reaps_the_orphan(tmp_path):",
                    "    # successor: test_reaps_the_orphan",
                ),
            ),
        )
        == []
    )


def test_removed_python_test_with_tombstone_row_is_clean() -> None:
    assert (
        _find(
            _edit(_PY, removed=("def test_reaps_the_orphan(tmp_path):",)),
            _edit(cge.TOMBSTONE, added=(_tombstone_row("test_reaps_the_orphan"),)),
        )
        == []
    )


def test_async_python_test_retirement_is_flagged() -> None:
    v = _find(_edit(_PY, removed=("    async def test_reaps_the_orphan(self):",)))
    assert len(v) == 1, v
    assert v[0].name == "test_reaps_the_orphan"


def test_edited_python_test_body_is_neutral() -> None:
    """A body change never touches the declaration line, so nothing retires."""
    assert _find(_edit(_PY, removed=("    assert old_shape",), added=("    assert new_shape",))) == []


def test_redeclared_python_test_is_neutral() -> None:
    """A signature change removes and re-adds the same name — not a retirement."""
    assert (
        _find(
            _edit(
                _PY,
                removed=("def test_reaps_the_orphan(tmp_path):",),
                added=("def test_reaps_the_orphan(tmp_path, monkeypatch):",),
            )
        )
        == []
    )


def test_moved_python_test_is_neutral_across_files() -> None:
    """Same name re-declared in another test file is a move, not a retirement."""
    assert (
        _find(
            _edit(_PY, removed=("def test_reaps_the_orphan(tmp_path):",)),
            _edit("tests/test_fleet.py", added=("def test_reaps_the_orphan(tmp_path):",)),
        )
        == []
    )


def test_renamed_python_test_without_marker_is_flagged_by_its_old_name() -> None:
    v = _find(
        _edit(
            _PY,
            removed=("def test_reaps_the_orphan(tmp_path):",),
            added=("def test_reaps_every_orphan(tmp_path):",),
        )
    )
    assert len(v) == 1, v
    assert v[0].name == "test_reaps_the_orphan"


def test_successor_marker_must_name_the_exact_retired_test() -> None:
    """A marker for a longer name must not excuse the shorter one."""
    v = _find(
        _edit(_PY, removed=("def test_reaps_the_orphan(tmp_path):",)),
        _edit("tests/test_fleet.py", added=("# successor: test_reaps_the_orphan_twice",)),
    )
    assert len(v) == 1, v
    assert v[0].name == "test_reaps_the_orphan"


def test_successor_marker_may_quote_the_retired_name() -> None:
    assert (
        _find(
            _edit(_PY, removed=("def test_reaps_the_orphan(tmp_path):",)),
            _edit("tests/test_fleet.py", added=("# successor: `test_reaps_the_orphan`",)),
        )
        == []
    )


def test_successor_marker_needs_a_name() -> None:
    v = _find(
        _edit(_PY, removed=("def test_reaps_the_orphan(tmp_path):",)),
        _edit("tests/test_fleet.py", added=("# successor:",)),
    )
    assert len(v) == 1, v


def test_successor_marker_outside_the_test_tree_does_not_count() -> None:
    """The marker rides the successor test, so a PR-body-style doc line is not it."""
    v = _find(
        _edit(_PY, removed=("def test_reaps_the_orphan(tmp_path):",)),
        _edit("docs/misc/architecture-notes.md", added=("# successor: test_reaps_the_orphan",)),
    )
    assert len(v) == 1, v


def test_removed_helper_function_is_neutral() -> None:
    assert _find(_edit(_PY, removed=("def _scratch_repo(tmp_path):",))) == []


def test_removed_test_outside_the_test_tree_is_neutral() -> None:
    assert _find(_edit("src/usr/local/pkg/pfblockerng/tooling.py", removed=("def test_reaps(x):",))) == []


def test_the_checkers_own_test_file_is_excluded() -> None:
    """This file plants declaration-shaped fixtures; it cannot police itself."""
    assert _find(_edit("tests/test_guard_erosion_check.py", removed=("def test_reaps_the_orphan(x):",))) == []


def test_deleting_a_whole_test_file_flags_every_test_it_carried() -> None:
    v = _find(
        _section(
            old_path=_PY,
            new_path=None,
            removed=(
                "def test_reaps_the_orphan(tmp_path):",
                "    assert True",
                "def test_reaps_the_sibling(tmp_path):",
            ),
        )
    )
    assert sorted(item.name for item in v) == ["test_reaps_the_orphan", "test_reaps_the_sibling"]


# --------------------------------------------------------------------------- #
# PHPUnit and shellspec — the other two named declaration forms
# --------------------------------------------------------------------------- #


def test_removed_phpunit_method_is_flagged() -> None:
    v = _find(_edit("tests/php/ReaperTest.php", removed=("    public function testReapsTheOrphan(): void",)))
    assert len(v) == 1, v
    assert v[0].name == "testReapsTheOrphan"


def test_removed_phpunit_method_with_successor_marker_is_clean() -> None:
    assert (
        _find(
            _edit("tests/php/ReaperTest.php", removed=("    public function testReapsTheOrphan(): void",)),
            _edit(
                "tests/php/FleetTest.php",
                added=(
                    "    public function testFleetReapsTheOrphan(): void",
                    "        // successor: testReapsTheOrphan",
                ),
            ),
        )
        == []
    )


def test_removed_phpunit_helper_is_neutral() -> None:
    assert _find(_edit("tests/php/ReaperTest.php", removed=("    private function makeReaper(): Reaper",))) == []


def test_removed_shellspec_example_is_flagged() -> None:
    v = _find(_edit("tests/shell/reaper_spec.sh", removed=("    It 'reaps the orphan'",)))
    assert len(v) == 1, v
    assert v[0].name == "reaps the orphan"


def test_removed_shellspec_example_with_tombstone_row_is_clean() -> None:
    assert (
        _find(
            _edit("tests/shell/reaper_spec.sh", removed=("    It 'reaps the orphan'",)),
            _edit(cge.TOMBSTONE, added=(_tombstone_row("reaps the orphan"),)),
        )
        == []
    )


def test_removed_shellspec_describe_block_is_neutral() -> None:
    """`Describe` groups examples; only the examples themselves are assertions."""
    assert _find(_edit("tests/shell/reaper_spec.sh", removed=("Describe 'the reaper'",))) == []


# --------------------------------------------------------------------------- #
# Tombstone rows — the entry must be dated, named, and reasoned
# --------------------------------------------------------------------------- #


def test_tombstone_row_without_a_reason_is_flagged() -> None:
    v = _find(
        _edit(_PY, removed=("def test_reaps_the_orphan(tmp_path):",)),
        _edit(cge.TOMBSTONE, added=("| 2026-09-02 | `test_reaps_the_orphan` |  |",)),
    )
    assert [item.reason for item in v if _MALFORMED in item.reason], v
    assert any(item.name == "test_reaps_the_orphan" and _UNEXCUSED in item.reason for item in v), v


def test_tombstone_row_without_a_date_is_flagged() -> None:
    v = _find(
        _edit(_PY, removed=("def test_reaps_the_orphan(tmp_path):",)),
        _edit(cge.TOMBSTONE, added=("| soon | `test_reaps_the_orphan` | folded into the fleet reaper |",)),
    )
    assert [item.reason for item in v if _MALFORMED in item.reason], v
    assert any(item.name == "test_reaps_the_orphan" and _UNEXCUSED in item.reason for item in v), v


def test_tombstone_header_and_delimiter_rows_are_not_malformed_entries() -> None:
    assert (
        _find(
            _edit(
                cge.TOMBSTONE,
                added=(
                    "| Date | Retired test | Reason |",
                    "| --- | --- | --- |",
                    "Prose about the format.",
                    "",
                ),
            )
        )
        == []
    )


def test_a_removed_tombstone_row_does_not_excuse_anything() -> None:
    """Deleting history is not a retirement record; only ADDED rows count."""
    v = _find(
        _edit(_PY, removed=("def test_reaps_the_orphan(tmp_path):",)),
        _edit(cge.TOMBSTONE, removed=(_tombstone_row("test_reaps_the_orphan"),)),
    )
    assert len(v) == 1, v
    assert v[0].name == "test_reaps_the_orphan"


def test_tombstone_row_excuses_only_the_test_it_names() -> None:
    v = _find(
        _edit(
            _PY,
            removed=(
                "def test_reaps_the_orphan(tmp_path):",
                "def test_reaps_the_sibling(tmp_path):",
            ),
        ),
        _edit(cge.TOMBSTONE, added=(_tombstone_row("test_reaps_the_orphan"),)),
    )
    assert [item.name for item in v] == ["test_reaps_the_sibling"]


# --------------------------------------------------------------------------- #
# The committed tombstone file
# --------------------------------------------------------------------------- #


def test_the_committed_tombstone_file_parses() -> None:
    """Every row of the shipped ledger must satisfy the format the gate enforces."""
    path = _ROOT / cge.TOMBSTONE
    body = path.read_text(encoding="utf-8")
    rows = [line for line in body.splitlines() if cge.tombstone_entry(line) is not None]
    assert rows, f"{cge.TOMBSTONE} carries no parseable retirement entry"
    added = tuple(line for line in body.splitlines())
    assert [v for v in _find(_edit(cge.TOMBSTONE, added=added)) if _MALFORMED in v.reason] == []


# --------------------------------------------------------------------------- #
# CLI
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


def _repo_with_a_test(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q", "-b", "devel")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test_reaper.py").write_text("def test_reaps_the_orphan():\n    assert True\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    return tmp_path


def test_cli_staged_and_diff_modes(tmp_path: Path) -> None:
    repo = _repo_with_a_test(tmp_path)
    (repo / "tests/test_reaper.py").unlink()
    _git(repo, "add", "-A")
    staged = _run(repo, "--staged")
    assert staged.returncode == 1, staged.stderr
    assert "test_reaps_the_orphan" in staged.stderr

    _git(repo, "commit", "-qm", "retire")
    assert _run(repo, "--staged").returncode == 0
    diffed = _run(repo, "--diff", "devel~1")
    assert diffed.returncode == 1, diffed.stderr
    assert "test_reaps_the_orphan" in diffed.stderr


def test_cli_accepts_a_tombstone_entry(tmp_path: Path) -> None:
    repo = _repo_with_a_test(tmp_path)
    (repo / "tests/test_reaper.py").unlink()
    tombstone = repo / cge.TOMBSTONE
    tombstone.parent.mkdir(parents=True)
    header = "| Date | Retired test | Reason |\n| --- | --- | --- |\n"
    tombstone.write_text(f"{header}{_tombstone_row('test_reaps_the_orphan')}\n")
    _git(repo, "add", "-A")
    result = _run(repo, "--staged")
    assert result.returncode == 0, result.stderr


def test_cli_hostile_git_configs_cannot_bypass_the_gate(tmp_path: Path) -> None:
    repo = _repo_with_a_test(tmp_path)
    (repo / "tests/test_reaper.py").unlink()
    _git(repo, "add", "-A")
    _git(repo, "config", "diff.mnemonicPrefix", "true")
    _git(repo, "config", "diff.noprefix", "true")
    _git(repo, "config", "diff.external", "/bin/echo")
    result = _run(repo, "--staged")
    assert result.returncode == 1, result.stderr
    assert "test_reaps_the_orphan" in result.stderr


def test_cli_non_utf8_diff_byte_does_not_crash_the_run(tmp_path: Path) -> None:
    repo = _repo_with_a_test(tmp_path)
    (repo / "tests/test_reaper.py").write_bytes(b"# caf\xff\xfe\ndef test_reaps_it_now():\n    assert True\n")
    _git(repo, "add", "-A")
    result = _run(repo, "--staged")
    assert result.returncode == 1, result.stderr
    assert "Traceback" not in result.stderr, result.stderr
    assert "test_reaps_the_orphan" in result.stderr


def test_cli_usage_error(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    assert _run(tmp_path).returncode == 2
    assert _run(tmp_path, "--bogus").returncode == 2


def test_cli_bad_ref_is_a_usage_error_not_a_traceback(tmp_path: Path) -> None:
    repo = _repo_with_a_test(tmp_path)
    result = _run(repo, "--diff", "no-such-ref")
    assert result.returncode == 2, result.stderr
    assert "git diff failed" in result.stderr


# --------------------------------------------------------------------------- #
# Wiring — the gate blocks in both places the owner ruling names
# --------------------------------------------------------------------------- #


def test_pre_commit_hook_runs_the_gate_on_the_staged_diff() -> None:
    hook = (_ROOT / ".githooks/pre-commit").read_text(encoding="utf-8")
    assert "scripts/check_guard_erosion.py --staged || failed" in hook


def test_pre_commit_sandboxes_list_the_new_checker() -> None:
    """Both `.githooks-exempt` sandboxes enumerate every checker the hook wants."""
    for spec in ("tests/shell/precommit_githooks_exempt_spec.sh", "tests/shell/precommit_identity_spec.sh"):
        body = (_ROOT / spec).read_text(encoding="utf-8")
        assert body.count("scripts/check_guard_erosion.py") == body.count("ALL_CHECKERS="), spec


def test_ci_wires_the_gate_as_a_blocking_job() -> None:
    workflow = (_ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")
    assert re.search(r"^  guard-erosion:$", workflow, re.MULTILINE), "no guard-erosion job"
    assert "scripts/check_guard_erosion.py --diff" in workflow
    needs = re.search(r"^    needs: \[(.+)\]$", workflow, re.MULTILINE)
    assert needs is not None and "guard-erosion" in needs.group(1), "job not folded into all-tests-passed"
    assert "needs.guard-erosion.result" in workflow, "no result check in all-tests-passed"
