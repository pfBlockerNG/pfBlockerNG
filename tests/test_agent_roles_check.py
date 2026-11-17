"""Tests for scripts/check_agent_roles.py.

Every violation class is paired with the nearest clean sibling (the valid
fixture tree), so a green run proves the checker discriminates rather than
always firing (or never firing). The checker validates SEMANTIC fields —
mutation boundaries, binding targets, contract fields — so the
fixtures vary exactly one semantic aspect per test while wording stays free.

The conditional trigger (--staged / --diff run the full validation iff a role
surface changed) is exercised through the CLI against real scratch git repos.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import sys
from pathlib import Path

from tests._workflow_steps import extract_after, extract_before, extract_between
from tests.gitenv import scrubbed_git_env

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "check_agent_roles.py"
_spec = importlib.util.spec_from_file_location("check_agent_roles", _TOOL)
assert _spec is not None and _spec.loader is not None
car = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = car
_spec.loader.exec_module(car)

_REPO_ROOT = Path(__file__).resolve().parent.parent

_HEADER_ROWS = (
    "| Role | Mutation | Independent | Claude bindings | Codex bindings | Copilot bindings |",
    "| ---- | -------- | ----------- | --------------- | -------------- | ---------------- |",
)

_ROWS = (
    "| builder | workspace-write | no | session | agent:builder | agent:builder |",
    "| checker | read-only | yes | agent:checker | agent:checker | agent:checker |",
    "| lander | workspace-write | no | skill:land | skill:land | skill:land |",
    "| steward | read-only | no | session | session | session |",
    "| keeper | workspace-write | no | policy:flow.md | policy:flow.md | policy:flow.md |",
)
_ROLE_NAMES = ("builder", "checker", "lander", "steward", "keeper")


def _section(name: str) -> str:
    fields = "\n".join(f"- **{field}:** x" for field in car._SECTION_FIELDS)
    return f"### {name}\n\n{fields}\n"


def _doc(rows: tuple[str, ...] = _ROWS, sections: tuple[str, ...] = _ROLE_NAMES) -> str:
    table = "\n".join((*_HEADER_ROWS, *rows))
    body = "\n".join(_section(name) for name in sections)
    return f"# roles\n\n<!-- role-registry:begin -->\n{table}\n<!-- role-registry:end -->\n\n{body}"


def _toml(sandbox: str) -> str:
    return f'name = "x"\nsandbox_mode = "{sandbox}"\n'


def _agent_md(mutation: str, description: str = "fixture") -> str:
    return f"---\nname: x\ndescription: {description}\n---\n\n<!-- mutation: {mutation} -->\n\nbody\n"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_tree(
    root: Path,
    *,
    doc: str | None = None,
    builder_toml: str | None = None,
    checker_toml: str | None = None,
    checker_claude_md: str | None = None,
    builder_agent_md: str | None = None,
    checker_agent_md: str | None = None,
) -> Path:
    _write(root / ".agents/policy/agent-roles.md", doc if doc is not None else _doc())
    _write(root / ".agents/skills/land/SKILL.md", "# land\n")
    _write(root / ".agents/policy/flow.md", "# flow\n")
    _write(root / ".claude/agents/checker.md", checker_claude_md or _agent_md("read-only"))
    _write(root / ".codex/agents/builder.toml", builder_toml or _toml("workspace-write"))
    _write(root / ".codex/agents/checker.toml", checker_toml or _toml("read-only"))
    _write(root / ".github/agents/builder.agent.md", builder_agent_md or _agent_md("workspace-write"))
    _write(root / ".github/agents/checker.agent.md", checker_agent_md or _agent_md("read-only"))
    return root


def _problems(root: Path) -> list[str]:
    return car.validate(root)[1]


def _assert_flags(problems: list[str], needle: str) -> None:
    assert any(needle in problem for problem in problems), f"expected {needle!r} in {problems}"


# --------------------------------------------------------------------------- #
# Clean baselines (the paired positives for every violation test below)
# --------------------------------------------------------------------------- #


def test_valid_fixture_is_clean(tmp_path: Path) -> None:
    count, problems = car.validate(make_tree(tmp_path))
    assert problems == []
    assert count == len(_ROWS)


def test_copilot_agent_unterminated_front_matter_rejected(tmp_path: Path) -> None:
    # An unclosed `---` block is malformed, not "flat fields to EOF": parsing it
    # leniently would let a truncated agent file satisfy the description/mutation
    # checks with values that Copilot itself never reads.
    make_tree(tmp_path, builder_agent_md="---\nname: x\ndescription: d\n\nbody\n")
    _assert_flags(_problems(tmp_path), "missing YAML front matter")


def test_live_repository_registry_is_consistent() -> None:
    count, problems = car.validate(_REPO_ROOT)
    assert problems == []
    assert count >= 6  # explorer/planner/implementer/reviewer/publisher/coordinator


# One workflow gates both agent-config checkers (issue #2473). The parity guard is
# POSIX sh with no importable trigger table, so the surfaces it needs beyond the role
# checker's stay literal here.
_PARITY_GUARD = "scripts/agent/check-agent-config-parity.sh"
_WORKFLOW = ".github/workflows/agent-config.yml"
# The workflow gates its own definition too: editing a trigger or a step re-runs both.
_PARITY_EXTRA_TRIGGERS = {".claude/skills/**", ".claude/workflows/**", _PARITY_GUARD, _WORKFLOW}


def _workflow_text() -> str:
    return (_REPO_ROOT / _WORKFLOW).read_text(encoding="utf-8")


def test_ci_workflow_paths_match_checker_triggers() -> None:
    # The CI trigger must mirror both checkers' surfaces: test.yml's global
    # `paths-ignore: '**/*.md'` skips that whole workflow for md-only changes,
    # so the agent-config gates ride their own path-filtered workflow instead.
    text = _workflow_text()
    expected = set(car._TRIGGER_FILES) | {f"{d}**" for d in car._TRIGGER_DIRS} | _PARITY_EXTRA_TRIGGERS
    # Compare each trigger block INDEPENDENTLY: the two hand-duplicated paths
    # lists drift exactly one-block-at-a-time, and a whole-file set comparison
    # cannot see an entry dropped from only one of them.
    push_block = extract_before(text, "pull_request:")
    pr_block = extract_between(text, "pull_request:", "permissions:")
    for name, block in (("push", push_block), ("pull_request", pr_block)):
        listed = re.findall(r"^\s+- '([^']+)'\s*$", block, re.MULTILINE)
        assert len(listed) == len(expected), f"{name} paths list has duplicates or gaps: {sorted(listed)}"
        assert set(listed) == expected, f"{name} paths {sorted(listed)} != checker triggers {sorted(expected)}"


def test_ci_workflow_runs_on_push() -> None:
    # Dev-only classes (skills, agent config, policy docs) land as direct pushes
    # to devel, so a pull_request-only gate never sees the dominant landing path.
    text = _workflow_text()
    push_block = extract_before(text, "pull_request:")
    assert "push:" in push_block, "dev-only surfaces land as direct pushes to devel"
    assert re.search(r"^\s+branches: \[main, devel\]$", push_block, re.MULTILINE), push_block


def test_ci_workflow_runs_the_parity_gate() -> None:
    # Match the RUN step, not the guard's name anywhere: the name is also a trigger
    # path, so a bare substring assertion stays green with the step deleted.
    steps = extract_after(_workflow_text(), "\njobs:")
    assert re.search(rf"^\s+run: sh {re.escape(_PARITY_GUARD)}$", steps, re.MULTILINE), steps


# --------------------------------------------------------------------------- #
# Registry document and table parsing
# --------------------------------------------------------------------------- #


def test_missing_doc_reported(tmp_path: Path) -> None:
    make_tree(tmp_path)
    (tmp_path / ".agents/policy/agent-roles.md").unlink()
    _assert_flags(_problems(tmp_path), "missing role contract")


def test_registry_markers_missing(tmp_path: Path) -> None:
    make_tree(tmp_path, doc="# roles, but no table markers\n")
    _assert_flags(_problems(tmp_path), "registry markers missing")


def test_registry_empty_table(tmp_path: Path) -> None:
    make_tree(tmp_path, doc="<!-- role-registry:begin -->\n<!-- role-registry:end -->\n")
    _assert_flags(_problems(tmp_path), "registry table is empty")


def test_registry_header_drift(tmp_path: Path) -> None:
    doc = _doc().replace("| Role |", "| Family |")
    make_tree(tmp_path, doc=doc)
    _assert_flags(_problems(tmp_path), "registry header must be")


def test_registry_retired_tiers_column_rejected(tmp_path: Path) -> None:
    doc = _doc().replace("| Role | Mutation |", "| Role | Tiers | Mutation |")
    make_tree(tmp_path, doc=doc)
    _assert_flags(_problems(tmp_path), "registry header must be")


def test_registry_row_column_count(tmp_path: Path) -> None:
    rows = (*_ROWS, "| stub | read-only | no |")
    make_tree(tmp_path, doc=_doc(rows=rows))
    _assert_flags(_problems(tmp_path), "columns")


def test_duplicate_role(tmp_path: Path) -> None:
    rows = (*_ROWS, _ROWS[0])
    make_tree(tmp_path, doc=_doc(rows=rows))
    _assert_flags(_problems(tmp_path), "duplicate role")


def test_invalid_role_id(tmp_path: Path) -> None:
    rows = (*_ROWS, "| Builder2! | read-only | no | session | session | session |")
    make_tree(tmp_path, doc=_doc(rows=rows))
    _assert_flags(_problems(tmp_path), "invalid role id")


def test_bad_mutation_value(tmp_path: Path) -> None:
    rows = (*_ROWS, "| muta | writable | no | session | session | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "muta")))
    _assert_flags(_problems(tmp_path), "Mutation must be one of")


def test_bad_independent_value(tmp_path: Path) -> None:
    rows = (*_ROWS, "| indy | read-only | maybe | session | session | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "indy")))
    _assert_flags(_problems(tmp_path), "Independent must be yes/no")


def test_claude_disallowed_kind_rejected(tmp_path: Path) -> None:
    rows = (*_ROWS, "| xrole | read-only | no | container:builder | session | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "xrole")))
    _assert_flags(_problems(tmp_path), "Claude binding 'container:builder'")


def test_claude_workflow_kind_rejected(tmp_path: Path) -> None:
    rows = (*_ROWS, "| xrole | read-only | no | workflow:build | session | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "xrole")))
    _assert_flags(_problems(tmp_path), "Claude binding 'workflow:build'")


def test_codex_workflow_kind_rejected(tmp_path: Path) -> None:
    rows = (*_ROWS, "| yrole | read-only | no | session | workflow:build | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "yrole")))
    _assert_flags(_problems(tmp_path), "Codex binding 'workflow:build'")


def test_empty_binding_cell(tmp_path: Path) -> None:
    rows = (*_ROWS, "| zrole | read-only | no |  | session | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "zrole")))
    _assert_flags(_problems(tmp_path), "empty Claude binding")


def test_session_binding_with_target_rejected(tmp_path: Path) -> None:
    rows = _ROWS[:3] + ("| steward | read-only | no | session:evil | session | session |",) + _ROWS[4:]
    make_tree(tmp_path, doc=_doc(rows=rows))
    _assert_flags(_problems(tmp_path), "Claude binding 'session:evil'")


def test_registry_blank_row_rejected(tmp_path: Path) -> None:
    make_tree(tmp_path, doc=_doc(rows=(*_ROWS, "|  |  |  |  |  |  |")))
    _assert_flags(_problems(tmp_path), "invalid role id")


def test_doc_not_utf8_clean_error(tmp_path: Path) -> None:
    make_tree(tmp_path)
    (tmp_path / ".agents/policy/agent-roles.md").write_text(_doc(), encoding="utf-16")
    result = _cli(tmp_path, "--all")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "Traceback" not in result.stderr
    assert "registry markers missing" in result.stderr


# --------------------------------------------------------------------------- #
# Contract sections (the seven semantic fields per role)
# --------------------------------------------------------------------------- #


def test_missing_role_section(tmp_path: Path) -> None:
    make_tree(tmp_path, doc=_doc(sections=("builder", "checker", "lander")))
    _assert_flags(_problems(tmp_path), "missing contract section '### steward'")


def test_section_missing_field(tmp_path: Path) -> None:
    doc = _doc().replace("- **Independence:** x\n\n### checker", "\n### checker", 1)
    make_tree(tmp_path, doc=doc)
    _assert_flags(_problems(tmp_path), "section '### builder' missing field '**Independence:**'")


# --------------------------------------------------------------------------- #
# Claude and Copilot agent bindings (front matter + mutation marker)
# --------------------------------------------------------------------------- #


def test_claude_agent_file_missing(tmp_path: Path) -> None:
    make_tree(tmp_path)
    (tmp_path / ".claude/agents/checker.md").unlink()
    _assert_flags(_problems(tmp_path), "missing Claude agent .claude/agents/checker.md")


def test_claude_agent_missing_front_matter(tmp_path: Path) -> None:
    make_tree(tmp_path, checker_claude_md="# No front matter\n")
    _assert_flags(_problems(tmp_path), ".claude/agents/checker.md: missing YAML front matter")


def test_claude_agent_missing_description(tmp_path: Path) -> None:
    make_tree(tmp_path, checker_claude_md="---\nname: x\n---\n\n<!-- mutation: read-only -->\n")
    _assert_flags(_problems(tmp_path), ".claude/agents/checker.md: front matter has no description")


def test_claude_agent_mutation_mismatch(tmp_path: Path) -> None:
    make_tree(tmp_path, checker_claude_md=_agent_md("workspace-write"))
    _assert_flags(
        _problems(tmp_path), ".claude/agents/checker.md mutation marker 'workspace-write' != role Mutation 'read-only'"
    )


def test_claude_agent_quoted_front_matter_values_parsed(tmp_path: Path) -> None:
    content = "---\nname: \"x\"\ndescription: 'test agent'\n---\n\n<!-- mutation: read-only -->\n"
    make_tree(tmp_path, checker_claude_md=content)
    assert _problems(tmp_path) == []


def test_claude_agent_quoted_empty_description_rejected(tmp_path: Path) -> None:
    make_tree(tmp_path, checker_claude_md="---\nname: x\ndescription: ''\n---\n\n<!-- mutation: read-only -->\n")
    _assert_flags(_problems(tmp_path), ".claude/agents/checker.md: front matter has no description")


def test_orphan_claude_agent(tmp_path: Path) -> None:
    make_tree(tmp_path)
    _write(tmp_path / ".claude/agents/stray.md", _agent_md("read-only"))
    _assert_flags(_problems(tmp_path), "stray.md: Claude agent not claimed by any registry row")


def test_copilot_agent_file_missing(tmp_path: Path) -> None:
    make_tree(tmp_path)
    (tmp_path / ".github/agents/builder.agent.md").unlink()
    _assert_flags(_problems(tmp_path), "missing Copilot agent .github/agents/builder.agent.md")


def test_copilot_agent_mutation_mismatch(tmp_path: Path) -> None:
    make_tree(tmp_path, builder_agent_md=_agent_md("read-only"))
    _assert_flags(
        _problems(tmp_path),
        ".github/agents/builder.agent.md mutation marker 'read-only' != role Mutation 'workspace-write'",
    )


def test_orphan_copilot_agent(tmp_path: Path) -> None:
    make_tree(tmp_path)
    _write(tmp_path / ".github/agents/stray.agent.md", _agent_md("read-only"))
    _assert_flags(_problems(tmp_path), "stray.agent.md: Copilot role not claimed by any registry row")


# --------------------------------------------------------------------------- #
# Codex agent bindings (sandbox/mutation)
# --------------------------------------------------------------------------- #


def test_codex_agent_file_missing(tmp_path: Path) -> None:
    make_tree(tmp_path)
    (tmp_path / ".codex/agents/builder.toml").unlink()
    _assert_flags(_problems(tmp_path), "missing Codex agent .codex/agents/builder.toml")


def test_codex_sandbox_mismatch(tmp_path: Path) -> None:
    make_tree(tmp_path, builder_toml=_toml("read-only"))
    _assert_flags(_problems(tmp_path), "sandbox_mode 'read-only' != role Mutation 'workspace-write'")


def test_codex_sandbox_missing(tmp_path: Path) -> None:
    make_tree(tmp_path, builder_toml='name = "x"\n')
    _assert_flags(_problems(tmp_path), "sandbox_mode None != role Mutation 'workspace-write'")


def test_codex_toml_unparsable(tmp_path: Path) -> None:
    make_tree(tmp_path, builder_toml="sandbox_mode = read-only oops\n")
    _assert_flags(_problems(tmp_path), "unparsable TOML")


def test_codex_conflicting_mutation_roles(tmp_path: Path) -> None:
    rows = (*_ROWS, "| auditor | read-only | yes | session | agent:builder | agent:builder |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "auditor")))
    problems = _problems(tmp_path)
    _assert_flags(problems, ".codex/agents/builder.toml is bound by roles with conflicting Mutation")
    _assert_flags(problems, ".github/agents/builder.agent.md is bound by roles with conflicting Mutation")


# --------------------------------------------------------------------------- #
# Skill / policy bindings and orphaned vendor definitions
# --------------------------------------------------------------------------- #


def test_skill_binding_missing(tmp_path: Path) -> None:
    make_tree(tmp_path)
    (tmp_path / ".agents/skills/land/SKILL.md").unlink()
    _assert_flags(_problems(tmp_path), "skill binding 'land' has no")


def test_policy_binding_missing(tmp_path: Path) -> None:
    rows = (*_ROWS, "| scribe | read-only | no | policy:missing.md | session | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "scribe")))
    _assert_flags(_problems(tmp_path), "policy binding 'missing.md' has no")


def test_orphan_codex_agent(tmp_path: Path) -> None:
    make_tree(tmp_path)
    _write(tmp_path / ".codex/agents/stray.toml", _toml("read-only"))
    _assert_flags(_problems(tmp_path), "stray.toml: Codex role not claimed by any registry row")


def test_missing_vendor_dir_ok_when_side_unclaimed(tmp_path: Path) -> None:
    rows = tuple(
        row.replace("| agent:checker | agent:checker | agent:checker |", "| session | agent:checker | agent:checker |")
        for row in _ROWS
    )
    make_tree(tmp_path, doc=_doc(rows=rows))
    shutil.rmtree(tmp_path / ".claude/agents")
    assert _problems(tmp_path) == []


def test_missing_vendor_dir_flagged_when_side_claimed(tmp_path: Path) -> None:
    make_tree(tmp_path)
    shutil.rmtree(tmp_path / ".claude/agents")
    _assert_flags(_problems(tmp_path), "missing directory: .claude/agents")


# --------------------------------------------------------------------------- #
# Conditional trigger + CLI (--staged / --diff / --all, exit codes)
# --------------------------------------------------------------------------- #


def test_touches_role_surface_unit() -> None:
    assert car.touches_role_surface([".codex/agents/planner.toml"])
    assert car.touches_role_surface([".claude/agents/adversarial-reviewer.md"])
    assert car.touches_role_surface([".github/agents/planner.agent.md"])
    assert car.touches_role_surface([".agents/skills/release/SKILL.md"])
    assert car.touches_role_surface([".agents/policy/agent-roles.md"])
    assert car.touches_role_surface([".agents/policy/flow.md"])
    assert car.touches_role_surface(["scripts/check_agent_roles.py"])
    assert not car.touches_role_surface(["src/usr/local/pkg/pfblockerng/pfblockerng.inc", "README.md"])
    assert not car.touches_role_surface([])
    # Exact-file trigger, not a lookalike sibling file.
    assert not car.touches_role_surface(["scripts/check_agent_roles.py.bak"])


def _git(root: Path, *args: str) -> None:
    env = scrubbed_git_env()
    subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        check=True,
        capture_output=True,
        env=env,
    )


def _cli(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_TOOL), *args, "--root", str(root)],
        capture_output=True,
        encoding="utf-8",
    )


def _git_tree(root: Path) -> Path:
    make_tree(root)
    _write(root / "README.md", "unrelated\n")
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base", "--no-verify")
    return root


def test_cli_staged_skips_unrelated_change(tmp_path: Path) -> None:
    root = _git_tree(tmp_path)
    _write(root / "README.md", "changed\n")
    _git(root, "add", "README.md")
    result = _cli(root, "--staged")
    assert result.returncode == 0, result.stderr
    assert "skipped" in result.stdout


def test_cli_staged_validates_clean_role_surface_change(tmp_path: Path) -> None:
    root = _git_tree(tmp_path)
    _write(root / ".agents/policy/agent-roles.md", _doc() + "\nextra prose\n")
    _git(root, "add", ".agents/policy/agent-roles.md")
    result = _cli(root, "--staged")
    assert result.returncode == 0, result.stderr
    assert "consistent" in result.stdout


def test_cli_staged_red_on_drift(tmp_path: Path) -> None:
    root = _git_tree(tmp_path)
    _write(root / ".codex/agents/builder.toml", _toml("read-only"))
    _git(root, "add", ".codex/agents/builder.toml")
    result = _cli(root, "--staged")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "Agent role-family drift detected" in result.stderr
    assert "builder.toml sandbox_mode 'read-only'" in result.stderr


def test_cli_staged_red_on_deleted_policy_binding(tmp_path: Path) -> None:
    root = _git_tree(tmp_path)
    _git(root, "rm", "-q", ".agents/policy/flow.md")
    result = _cli(root, "--staged")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "policy binding 'flow.md' has no .agents/policy/flow.md" in result.stderr


def test_cli_diff_skips_unrelated_change(tmp_path: Path) -> None:
    root = _git_tree(tmp_path)
    _write(root / "README.md", "changed\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "unrelated", "--no-verify")
    result = _cli(root, "--diff", "HEAD~1")
    assert result.returncode == 0, result.stderr
    assert "skipped" in result.stdout


def test_cli_diff_red_on_drift(tmp_path: Path) -> None:
    root = _git_tree(tmp_path)
    _write(root / ".claude/agents/checker.md", _agent_md("workspace-write"))
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "drift", "--no-verify")
    result = _cli(root, "--diff", "HEAD~1")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "checker.md mutation marker 'workspace-write'" in result.stderr


def test_cli_all_green_and_exit_codes(tmp_path: Path) -> None:
    result = _cli(make_tree(tmp_path), "--all")
    assert result.returncode == 0, result.stderr
    assert "consistent (5 roles)" in result.stdout


def test_cli_usage_error_exit_2(tmp_path: Path) -> None:
    result = _cli(tmp_path)  # no mode flag
    assert result.returncode == 2
