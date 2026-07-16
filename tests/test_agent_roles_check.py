"""Tests for scripts/check_agent_roles.py.

Every violation class is paired with the nearest clean sibling (the valid
fixture tree), so a green run proves the checker discriminates rather than
always firing (or never firing). The checker validates SEMANTIC fields —
tier vocabulary, mutation boundaries, binding targets, model pins — so the
fixtures vary exactly one semantic aspect per test while wording stays free.

The conditional trigger (--staged / --diff run the full validation iff a role
surface changed) is exercised through the CLI against real scratch git repos.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "check_agent_roles.py"
_spec = importlib.util.spec_from_file_location("check_agent_roles", _TOOL)
assert _spec is not None and _spec.loader is not None
car = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = car
_spec.loader.exec_module(car)

_REPO_ROOT = Path(__file__).resolve().parent.parent

_TIERS_TEXT = (
    "TOP_CLAUDE=claude-top-x\n"
    "TOP_CODEX=codex-top\n"
    "MID_CLAUDE=claude-mid-x\n"
    "MID_CODEX=codex-mid\n"
    "SMALL_CLAUDE=claude-small-x\n"
    "SMALL_CODEX=codex-small\n"
)

_HEADER_ROWS = (
    "| Role | Tiers | Mutation | Independent | Claude bindings | Codex bindings |",
    "| ---- | ----- | -------- | ----------- | --------------- | -------------- |",
)

_ROWS = (
    "| builder | small | workspace-write | no | workflow:build | agent:builder |",
    "| checker | small+top | read-only | yes | workflow:check | agent:checker, agent:checker-top |",
    "| lander | small | workspace-write | no | skill:land | skill:land |",
    "| steward | top | read-only | no | session | session |",
)
_ROLE_NAMES = ("builder", "checker", "lander", "steward")


def _section(name: str) -> str:
    fields = "\n".join(f"- **{field}:** x" for field in car._SECTION_FIELDS)
    return f"### {name}\n\n{fields}\n"


def _doc(rows: tuple[str, ...] = _ROWS, sections: tuple[str, ...] = _ROLE_NAMES) -> str:
    table = "\n".join((*_HEADER_ROWS, *rows))
    body = "\n".join(_section(name) for name in sections)
    return f"# roles\n\n<!-- role-registry:begin -->\n{table}\n<!-- role-registry:end -->\n\n{body}"


def _toml(model: str, sandbox: str) -> str:
    return f'name = "x"\nmodel = "{model}"\nsandbox_mode = "{sandbox}"\n'


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_tree(
    root: Path,
    *,
    doc: str | None = None,
    tiers: str = _TIERS_TEXT,
    build_js: str = "agent(p, { model: 'claude-small-x' })\n",
    check_js: str = "a 'claude-small-x' b \"claude-top-x\"\n",
    builder_toml: str | None = None,
    checker_toml: str | None = None,
    checker_top_toml: str | None = None,
) -> Path:
    _write(root / ".agents/model-tiers.conf", tiers)
    _write(root / ".agents/policy/agent-roles.md", doc if doc is not None else _doc())
    _write(root / ".agents/skills/land/SKILL.md", "# land\n")
    _write(root / ".claude/workflows/build.js", build_js)
    _write(root / ".claude/workflows/check.js", check_js)
    _write(root / ".codex/agents/builder.toml", builder_toml or _toml("codex-small", "workspace-write"))
    _write(root / ".codex/agents/checker.toml", checker_toml or _toml("codex-small", "read-only"))
    _write(root / ".codex/agents/checker-top.toml", checker_top_toml or _toml("codex-top", "read-only"))
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


def test_live_repository_registry_is_consistent() -> None:
    count, problems = car.validate(_REPO_ROOT)
    assert problems == []
    assert count >= 7  # explorer/planner/implementer/verifier/reviewer/publisher/coordinator


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


def test_registry_row_column_count(tmp_path: Path) -> None:
    rows = (*_ROWS, "| stub | small | read-only |")
    make_tree(tmp_path, doc=_doc(rows=rows))
    _assert_flags(_problems(tmp_path), "columns")


def test_unknown_tier_token(tmp_path: Path) -> None:
    rows = (*_ROWS, "| giant | huge | read-only | no | session | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "giant")))
    _assert_flags(_problems(tmp_path), "Tiers must be distinct")


def test_duplicate_tier_token(tmp_path: Path) -> None:
    rows = (*_ROWS, "| twice | small+small | read-only | no | session | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "twice")))
    _assert_flags(_problems(tmp_path), "Tiers must be distinct")


def test_duplicate_role(tmp_path: Path) -> None:
    rows = (*_ROWS, _ROWS[0])
    make_tree(tmp_path, doc=_doc(rows=rows))
    _assert_flags(_problems(tmp_path), "duplicate role")


def test_invalid_role_id(tmp_path: Path) -> None:
    rows = (*_ROWS, "| Builder2! | small | read-only | no | session | session |")
    make_tree(tmp_path, doc=_doc(rows=rows))
    _assert_flags(_problems(tmp_path), "invalid role id")


def test_bad_mutation_value(tmp_path: Path) -> None:
    rows = (*_ROWS, "| muta | small | writable | no | session | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "muta")))
    _assert_flags(_problems(tmp_path), "Mutation must be one of")


def test_bad_independent_value(tmp_path: Path) -> None:
    rows = (*_ROWS, "| indy | small | read-only | maybe | session | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "indy")))
    _assert_flags(_problems(tmp_path), "Independent must be yes/no")


def test_claude_agent_kind_rejected(tmp_path: Path) -> None:
    rows = (*_ROWS, "| xrole | small | read-only | no | agent:builder | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "xrole")))
    _assert_flags(_problems(tmp_path), "Claude binding 'agent:builder'")


def test_codex_workflow_kind_rejected(tmp_path: Path) -> None:
    rows = (*_ROWS, "| yrole | small | read-only | no | session | workflow:build |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "yrole")))
    _assert_flags(_problems(tmp_path), "Codex binding 'workflow:build'")


def test_empty_binding_cell(tmp_path: Path) -> None:
    rows = (*_ROWS, "| zrole | small | read-only | no |  | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "zrole")))
    _assert_flags(_problems(tmp_path), "empty Claude binding")


# --------------------------------------------------------------------------- #
# Tier vocabulary (.agents/model-tiers.conf)
# --------------------------------------------------------------------------- #


def test_tiers_missing_key(tmp_path: Path) -> None:
    make_tree(tmp_path, tiers=_TIERS_TEXT.replace("MID_CODEX=codex-mid\n", ""))
    _assert_flags(_problems(tmp_path), "missing tier key: MID_CODEX")


def test_tiers_missing_file(tmp_path: Path) -> None:
    make_tree(tmp_path)
    (tmp_path / ".agents/model-tiers.conf").unlink()
    _assert_flags(_problems(tmp_path), "missing tier vocabulary")


def test_tiers_duplicate_key(tmp_path: Path) -> None:
    make_tree(tmp_path, tiers=_TIERS_TEXT + "TOP_CLAUDE=claude-other\n")
    _assert_flags(_problems(tmp_path), "duplicate tier key: TOP_CLAUDE")


def test_tiers_unknown_key(tmp_path: Path) -> None:
    make_tree(tmp_path, tiers=_TIERS_TEXT + "HUGE_CLAUDE=claude-huge\n")
    _assert_flags(_problems(tmp_path), "unknown tier key: HUGE_CLAUDE")


def test_tiers_invalid_line(tmp_path: Path) -> None:
    make_tree(tmp_path, tiers=_TIERS_TEXT + "SMALL_CODEX\n")
    _assert_flags(_problems(tmp_path), "invalid tier assignment")


# --------------------------------------------------------------------------- #
# Contract sections (the eight semantic fields per role)
# --------------------------------------------------------------------------- #


def test_missing_role_section(tmp_path: Path) -> None:
    make_tree(tmp_path, doc=_doc(sections=("builder", "checker", "lander")))
    _assert_flags(_problems(tmp_path), "missing contract section '### steward'")


def test_section_missing_field(tmp_path: Path) -> None:
    doc = _doc().replace("- **Tier intent:** x\n\n### checker", "\n### checker", 1)
    make_tree(tmp_path, doc=doc)
    _assert_flags(_problems(tmp_path), "section '### builder' missing field '**Tier intent:**'")


# --------------------------------------------------------------------------- #
# Claude workflow bindings (model pins vs declared tiers)
# --------------------------------------------------------------------------- #


def test_workflow_file_missing(tmp_path: Path) -> None:
    make_tree(tmp_path)
    (tmp_path / ".claude/workflows/build.js").unlink()
    _assert_flags(_problems(tmp_path), "missing Claude workflow .claude/workflows/build.js")


def test_workflow_pin_outside_role_tiers(tmp_path: Path) -> None:
    make_tree(tmp_path, build_js="m 'claude-small-x'\nx 'claude-top-x'\n")
    _assert_flags(_problems(tmp_path), "pins 'claude-top-x' (top tier), outside tier(s) small")


def test_workflow_pin_unknown_model(tmp_path: Path) -> None:
    make_tree(tmp_path, build_js="m 'claude-small-x'\nx 'claude-weird-9'\n")
    _assert_flags(_problems(tmp_path), "pins 'claude-weird-9', which is not in")


def test_workflow_missing_primary_pin(tmp_path: Path) -> None:
    make_tree(tmp_path, build_js="no pins here\n")
    _assert_flags(_problems(tmp_path), "never pins role 'builder' primary tier 'small'")


def test_workflow_escape_line_exempt(tmp_path: Path) -> None:
    make_tree(tmp_path, build_js="m 'claude-small-x'\n// roles-ok: fallback note 'claude-top-x'\n")
    assert _problems(tmp_path) == []


def test_workflow_mid_string_mention_not_a_pin(tmp_path: Path) -> None:
    make_tree(tmp_path, build_js="m 'claude-small-x'\nconst t = 'pass claude-top-x when told'\n")
    assert _problems(tmp_path) == []


# --------------------------------------------------------------------------- #
# Codex agent bindings (model tier + sandbox/mutation)
# --------------------------------------------------------------------------- #


def test_codex_agent_file_missing(tmp_path: Path) -> None:
    make_tree(tmp_path)
    (tmp_path / ".codex/agents/builder.toml").unlink()
    _assert_flags(_problems(tmp_path), "missing Codex agent .codex/agents/builder.toml")


def test_codex_model_wrong_tier(tmp_path: Path) -> None:
    make_tree(tmp_path, builder_toml=_toml("codex-top", "workspace-write"))
    _assert_flags(_problems(tmp_path), "builder.toml model 'codex-top' is not a Codex model")


def test_codex_model_missing_key(tmp_path: Path) -> None:
    make_tree(tmp_path, builder_toml='name = "x"\nsandbox_mode = "workspace-write"\n')
    _assert_flags(_problems(tmp_path), "builder.toml model None is not a Codex model")


def test_codex_sandbox_mismatch(tmp_path: Path) -> None:
    make_tree(tmp_path, builder_toml=_toml("codex-small", "read-only"))
    _assert_flags(_problems(tmp_path), "sandbox_mode 'read-only' != role Mutation 'workspace-write'")


def test_codex_toml_unparsable(tmp_path: Path) -> None:
    make_tree(tmp_path, builder_toml="model = codex-small oops\n")
    _assert_flags(_problems(tmp_path), "unparsable TOML")


def test_codex_primary_tier_uncovered(tmp_path: Path) -> None:
    # Both checker agents on the top model: legal tiers, but nobody runs the
    # small primary — the drift the coverage rule exists to catch.
    make_tree(tmp_path, checker_toml=_toml("codex-top", "read-only"))
    _assert_flags(_problems(tmp_path), "role 'checker': no Codex agent binding runs its primary tier 'small'")


def test_codex_conflicting_mutation_roles(tmp_path: Path) -> None:
    rows = (*_ROWS, "| auditor | small | read-only | yes | workflow:check | agent:builder |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "auditor")))
    _assert_flags(_problems(tmp_path), "bound by roles with conflicting Mutation")


# --------------------------------------------------------------------------- #
# Skill / policy bindings and orphaned vendor definitions
# --------------------------------------------------------------------------- #


def test_skill_binding_missing(tmp_path: Path) -> None:
    make_tree(tmp_path)
    (tmp_path / ".agents/skills/land/SKILL.md").unlink()
    _assert_flags(_problems(tmp_path), "skill binding 'land' has no")


def test_policy_binding_missing(tmp_path: Path) -> None:
    rows = (*_ROWS, "| scribe | small | read-only | no | policy:missing.md | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "scribe")))
    _assert_flags(_problems(tmp_path), "policy binding 'missing.md' has no")


def test_orphan_codex_agent(tmp_path: Path) -> None:
    make_tree(tmp_path)
    _write(tmp_path / ".codex/agents/stray.toml", _toml("codex-small", "read-only"))
    _assert_flags(_problems(tmp_path), "stray.toml: Codex role not claimed by any registry row")


def test_unclaimed_claude_workflow(tmp_path: Path) -> None:
    make_tree(tmp_path)
    _write(tmp_path / ".claude/workflows/stray.js", "x\n")
    _assert_flags(_problems(tmp_path), "stray.js: Claude workflow not claimed by any registry row")


# --------------------------------------------------------------------------- #
# Conditional trigger + CLI (--staged / --diff / --all, exit codes)
# --------------------------------------------------------------------------- #


def test_touches_role_surface_unit() -> None:
    assert car.touches_role_surface([".codex/agents/planner.toml"])
    assert car.touches_role_surface([".claude/workflows/phase-step.js"])
    assert car.touches_role_surface([".agents/model-tiers.conf"])
    assert car.touches_role_surface([".agents/policy/agent-roles.md"])
    assert car.touches_role_surface(["scripts/check_agent_roles.py"])
    assert not car.touches_role_surface(["src/usr/local/pkg/pfblockerng/pfblockerng.inc", "README.md"])
    assert not car.touches_role_surface([])
    # Exact-file trigger, not a lookalike sibling file.
    assert not car.touches_role_surface([".agents/model-tiers.conf.bak"])


def _git(root: Path, *args: str) -> None:
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
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
    _write(root / ".agents/model-tiers.conf", _TIERS_TEXT + "# comment\n")
    _git(root, "add", ".agents/model-tiers.conf")
    result = _cli(root, "--staged")
    assert result.returncode == 0, result.stderr
    assert "consistent" in result.stdout


def test_cli_staged_red_on_drift(tmp_path: Path) -> None:
    # The wired gate's red path: a retiered Codex implementer must FAIL --staged.
    root = _git_tree(tmp_path)
    _write(root / ".codex/agents/builder.toml", _toml("codex-top", "workspace-write"))
    _git(root, "add", ".codex/agents/builder.toml")
    result = _cli(root, "--staged")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "Agent role-family drift detected" in result.stderr
    assert "builder.toml model 'codex-top'" in result.stderr


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
    _write(root / ".codex/agents/checker.toml", _toml("codex-mid", "read-only"))
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "retier", "--no-verify")
    result = _cli(root, "--diff", "HEAD~1")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "checker.toml model 'codex-mid'" in result.stderr


def test_cli_all_green_and_exit_codes(tmp_path: Path) -> None:
    result = _cli(make_tree(tmp_path), "--all")
    assert result.returncode == 0, result.stderr
    assert "consistent (4 roles)" in result.stdout


def test_cli_usage_error_exit_2(tmp_path: Path) -> None:
    result = _cli(tmp_path)  # no mode flag
    assert result.returncode == 2
