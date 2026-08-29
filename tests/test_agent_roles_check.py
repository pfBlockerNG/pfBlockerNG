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

_TIERS_TEXT = (
    "TOP_CLAUDE=claude-top-x\n"
    "TOP_CODEX=codex-top\n"
    "TOP_COPILOT=copilot-top\n"
    "MID_CLAUDE=claude-mid-x\n"
    "MID_CODEX=codex-mid\n"
    "MID_COPILOT=copilot-mid\n"
    "SMALL_CLAUDE=claude-small-x\n"
    "SMALL_CODEX=codex-small\n"
    "SMALL_COPILOT=copilot-small\n"
)

_HEADER_ROWS = (
    "| Role | Tiers | Mutation | Independent | Claude bindings | Codex bindings | Copilot bindings |",
    "| ---- | ----- | -------- | ----------- | --------------- | -------------- | ---------------- |",
)

_ROWS = (
    "| builder | small | workspace-write | no | workflow:build | agent:builder | agent:builder |",
    "| checker | small+top | read-only | yes | workflow:check | agent:checker, agent:checker-top "
    "| agent:checker, agent:checker-top |",
    "| lander | small | workspace-write | no | skill:land | skill:land | skill:land |",
    "| steward | top | read-only | no | session | session | session |",
    "| keeper | small | workspace-write | no | policy:flow.md | policy:flow.md | policy:flow.md |",
)
_ROLE_NAMES = ("builder", "checker", "lander", "steward", "keeper")


def _section(name: str) -> str:
    fields = "\n".join(f"- **{field}:** x" for field in car._SECTION_FIELDS)
    return f"### {name}\n\n{fields}\n"


def _doc(rows: tuple[str, ...] = _ROWS, sections: tuple[str, ...] = _ROLE_NAMES) -> str:
    table = "\n".join((*_HEADER_ROWS, *rows))
    body = "\n".join(_section(name) for name in sections)
    return f"# roles\n\n<!-- role-registry:begin -->\n{table}\n<!-- role-registry:end -->\n\n{body}"


def _toml(model: str, sandbox: str) -> str:
    return f'name = "x"\nmodel = "{model}"\nsandbox_mode = "{sandbox}"\n'


def _agent_md(model: str, mutation: str) -> str:
    return f"---\nname: x\ndescription: fixture\nmodel: {model}\n---\n\n<!-- mutation: {mutation} -->\n\nbody\n"


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
    builder_agent_md: str | None = None,
    checker_agent_md: str | None = None,
    checker_top_agent_md: str | None = None,
) -> Path:
    _write(root / ".agents/model-tiers.conf", tiers)
    _write(root / ".agents/policy/agent-roles.md", doc if doc is not None else _doc())
    _write(root / ".agents/skills/land/SKILL.md", "# land\n")
    _write(root / ".agents/policy/flow.md", "# flow\n")
    _write(root / ".claude/workflows/build.js", build_js)
    _write(root / ".claude/workflows/check.js", check_js)
    _write(root / ".codex/agents/builder.toml", builder_toml or _toml("codex-small", "workspace-write"))
    _write(root / ".codex/agents/checker.toml", checker_toml or _toml("codex-small", "read-only"))
    _write(root / ".codex/agents/checker-top.toml", checker_top_toml or _toml("codex-top", "read-only"))
    _write(
        root / ".github/agents/builder.agent.md",
        builder_agent_md or _agent_md("copilot-small", "workspace-write"),
    )
    _write(
        root / ".github/agents/checker.agent.md",
        checker_agent_md or _agent_md("copilot-small", "read-only"),
    )
    _write(
        root / ".github/agents/checker-top.agent.md",
        checker_top_agent_md or _agent_md("copilot-top", "read-only"),
    )
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
    # leniently would let a truncated agent file satisfy the model/mutation
    # checks with values that Copilot itself never reads.
    make_tree(tmp_path, builder_agent_md="---\nname: x\nmodel: copilot-small\n\nbody\n")
    _assert_flags(_problems(tmp_path), "missing YAML front matter")


def test_live_repository_registry_is_consistent() -> None:
    count, problems = car.validate(_REPO_ROOT)
    assert problems == []
    assert count >= 7  # explorer/planner/implementer/verifier/reviewer/publisher/coordinator


# One workflow gates both agent-config checkers (issue #2473). The parity guard is
# POSIX sh with no importable trigger table, so the surfaces it needs beyond the role
# checker's stay literal here.
_PARITY_GUARD = "scripts/agent/check-agent-config-parity.sh"
_WORKFLOW = ".github/workflows/agent-config.yml"
# The workflow gates its own definition too: editing a trigger or a step re-runs both.
_PARITY_EXTRA_TRIGGERS = {".claude/skills/**", _PARITY_GUARD, _WORKFLOW}


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


def test_registry_row_column_count(tmp_path: Path) -> None:
    rows = (*_ROWS, "| stub | small | read-only |")
    make_tree(tmp_path, doc=_doc(rows=rows))
    _assert_flags(_problems(tmp_path), "columns")


def test_unknown_tier_token(tmp_path: Path) -> None:
    rows = (*_ROWS, "| giant | huge | read-only | no | session | session | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "giant")))
    _assert_flags(_problems(tmp_path), "Tiers must be distinct")


def test_duplicate_tier_token(tmp_path: Path) -> None:
    rows = (*_ROWS, "| twice | small+small | read-only | no | session | session | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "twice")))
    _assert_flags(_problems(tmp_path), "Tiers must be distinct")


def test_duplicate_role(tmp_path: Path) -> None:
    rows = (*_ROWS, _ROWS[0])
    make_tree(tmp_path, doc=_doc(rows=rows))
    _assert_flags(_problems(tmp_path), "duplicate role")


def test_invalid_role_id(tmp_path: Path) -> None:
    rows = (*_ROWS, "| Builder2! | small | read-only | no | session | session | session |")
    make_tree(tmp_path, doc=_doc(rows=rows))
    _assert_flags(_problems(tmp_path), "invalid role id")


def test_bad_mutation_value(tmp_path: Path) -> None:
    rows = (*_ROWS, "| muta | small | writable | no | session | session | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "muta")))
    _assert_flags(_problems(tmp_path), "Mutation must be one of")


def test_bad_independent_value(tmp_path: Path) -> None:
    rows = (*_ROWS, "| indy | small | read-only | maybe | session | session | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "indy")))
    _assert_flags(_problems(tmp_path), "Independent must be yes/no")


def test_claude_agent_kind_rejected(tmp_path: Path) -> None:
    rows = (*_ROWS, "| xrole | small | read-only | no | agent:builder | session | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "xrole")))
    _assert_flags(_problems(tmp_path), "Claude binding 'agent:builder'")


def test_codex_workflow_kind_rejected(tmp_path: Path) -> None:
    rows = (*_ROWS, "| yrole | small | read-only | no | session | workflow:build | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "yrole")))
    _assert_flags(_problems(tmp_path), "Codex binding 'workflow:build'")


def test_empty_binding_cell(tmp_path: Path) -> None:
    rows = (*_ROWS, "| zrole | small | read-only | no |  | session | session |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "zrole")))
    _assert_flags(_problems(tmp_path), "empty Claude binding")


# --------------------------------------------------------------------------- #
# Tier vocabulary (.agents/model-tiers.conf)
# --------------------------------------------------------------------------- #


def test_session_binding_with_target_rejected(tmp_path: Path) -> None:
    rows = _ROWS[:3] + ("| steward | top | read-only | no | session:evil | session | session |",) + _ROWS[4:]
    make_tree(tmp_path, doc=_doc(rows=rows))
    _assert_flags(_problems(tmp_path), "Claude binding 'session:evil'")


def test_registry_blank_row_rejected(tmp_path: Path) -> None:
    make_tree(tmp_path, doc=_doc(rows=(*_ROWS, "|  |  |  |  |  |  |  |")))
    _assert_flags(_problems(tmp_path), "invalid role id")


def test_doc_not_utf8_clean_error(tmp_path: Path) -> None:
    make_tree(tmp_path)
    (tmp_path / ".agents/policy/agent-roles.md").write_text(_doc(), encoding="utf-16")
    result = _cli(tmp_path, "--all")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "Traceback" not in result.stderr
    assert "registry markers missing" in result.stderr


def test_tiers_not_utf8_clean_error(tmp_path: Path) -> None:
    make_tree(tmp_path)
    (tmp_path / ".agents/model-tiers.conf").write_text(_TIERS_TEXT, encoding="utf-16")
    result = _cli(tmp_path, "--all")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "Traceback" not in result.stderr
    assert "tier key" in result.stderr


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
    rows = (*_ROWS, "| auditor | small | read-only | yes | workflow:check | agent:builder | agent:builder |")
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "auditor")))
    _assert_flags(_problems(tmp_path), "bound by roles with conflicting Mutation")


def test_codex_luna_reviewer_rejects_xhigh(tmp_path: Path) -> None:
    rows = tuple(row.replace("| checker |", "| reviewer |") for row in _ROWS)
    sections = tuple("reviewer" if name == "checker" else name for name in _ROLE_NAMES)
    make_tree(
        tmp_path,
        doc=_doc(rows=rows, sections=sections),
        checker_toml=(
            'name = "x"\nmodel = "codex-small"\nmodel_reasoning_effort = "xhigh"\nsandbox_mode = "read-only"\n'
        ),
        checker_top_toml=(
            'name = "x"\nmodel = "codex-top"\nmodel_reasoning_effort = "medium"\nsandbox_mode = "read-only"\n'
        ),
    )
    _assert_flags(
        _problems(tmp_path),
        "checker.toml model_reasoning_effort 'xhigh' != required 'high' for Codex reviewer/verifier role(s) reviewer",
    )


def test_shared_bindings_use_each_roles_tier_intersection(tmp_path: Path) -> None:
    rows = (
        *_ROWS,
        "| auditor | small | read-only | yes | workflow:check "
        "| agent:checker, agent:checker-top | agent:checker, agent:checker-top |",
    )
    make_tree(tmp_path, doc=_doc(rows=rows, sections=(*_ROLE_NAMES, "auditor")))
    problems = _problems(tmp_path)
    _assert_flags(problems, ".claude/workflows/check.js pins 'claude-top-x' (top tier), outside tier(s) small")
    _assert_flags(problems, ".codex/agents/checker-top.toml model 'codex-top' is not a Codex model")
    _assert_flags(problems, ".github/agents/checker-top.agent.md model 'copilot-top' is not a Copilot model")
    assert len(problems) == 3, problems


# --------------------------------------------------------------------------- #
# Skill / policy bindings and orphaned vendor definitions
# --------------------------------------------------------------------------- #


def test_skill_binding_missing(tmp_path: Path) -> None:
    make_tree(tmp_path)
    (tmp_path / ".agents/skills/land/SKILL.md").unlink()
    _assert_flags(_problems(tmp_path), "skill binding 'land' has no")


def test_policy_binding_missing(tmp_path: Path) -> None:
    rows = (*_ROWS, "| scribe | small | read-only | no | policy:missing.md | session | session |")
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


def test_missing_vendor_dir_ok_when_side_unclaimed(tmp_path: Path) -> None:
    """A registry with no workflow bindings tolerates an absent .claude/workflows (issue #1431)."""
    rows = tuple(row.replace("workflow:build", "session").replace("workflow:check", "session") for row in _ROWS)
    make_tree(tmp_path, doc=_doc(rows=rows))
    shutil.rmtree(tmp_path / ".claude/workflows")
    assert _problems(tmp_path) == []


def test_missing_vendor_dir_flagged_when_side_claimed(tmp_path: Path) -> None:
    make_tree(tmp_path)
    shutil.rmtree(tmp_path / ".claude/workflows")
    _assert_flags(_problems(tmp_path), "missing directory: .claude/workflows")


# --------------------------------------------------------------------------- #
# Conditional trigger + CLI (--staged / --diff / --all, exit codes)
# --------------------------------------------------------------------------- #


def test_touches_role_surface_unit() -> None:
    assert car.touches_role_surface([".codex/agents/planner.toml"])
    assert car.touches_role_surface([".claude/workflows/phase-step.js"])
    assert car.touches_role_surface([".agents/model-tiers.conf"])
    assert car.touches_role_surface([".agents/policy/agent-roles.md"])
    assert car.touches_role_surface([".agents/policy/flow.md"])
    assert car.touches_role_surface(["scripts/check_agent_roles.py"])
    assert not car.touches_role_surface(["src/usr/local/pkg/pfblockerng/pfblockerng.inc", "README.md"])
    assert not car.touches_role_surface([])
    # Exact-file trigger, not a lookalike sibling file.
    assert not car.touches_role_surface([".agents/model-tiers.conf.bak"])


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
    _write(root / ".agents/model-tiers.conf", _TIERS_TEXT + "# comment\n")
    _git(root, "add", ".agents/model-tiers.conf")
    result = _cli(root, "--staged")
    assert result.returncode == 0, result.stderr
    assert "consistent" in result.stdout


def test_cli_staged_red_on_drift(tmp_path: Path) -> None:
    root = _git_tree(tmp_path)
    _write(root / ".codex/agents/builder.toml", _toml("codex-top", "workspace-write"))
    _git(root, "add", ".codex/agents/builder.toml")
    result = _cli(root, "--staged")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "Agent role-family drift detected" in result.stderr
    assert "builder.toml model 'codex-top'" in result.stderr


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
    _write(root / ".codex/agents/checker.toml", _toml("codex-mid", "read-only"))
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "retier", "--no-verify")
    result = _cli(root, "--diff", "HEAD~1")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "checker.toml model 'codex-mid'" in result.stderr


def test_cli_all_green_and_exit_codes(tmp_path: Path) -> None:
    result = _cli(make_tree(tmp_path), "--all")
    assert result.returncode == 0, result.stderr
    assert "consistent (5 roles)" in result.stdout


def test_cli_escape_requires_colon_and_reason(tmp_path: Path) -> None:
    valid = (
        "roles-ok: reason",
        "roles-ok:\t  reason",
        "roles-ok: []{}()$.*+?",
        f"roles-ok: {'x' * 4096}",
        "roles-ok: \ufffd",
    )
    malformed = (
        "roles-ok",
        "roles-ok:",
        "roles-ok:   ",
        "roles-ok reason",
        "roles-ok - reason",
        "xroles-ok: reason",
        "roles-ok-extra: reason",
        "Roles-OK: reason",
        "roles-ok:\n// reason",
    )
    for marker in valid:
        make_tree(tmp_path, build_js=f"m 'claude-small-x'\nm 'claude-top-x' // {marker}\n")
        result = _cli(tmp_path, "--all")
        assert result.returncode == 0, f"valid marker {marker!r}: {result.stdout}{result.stderr}"
    for marker in malformed:
        make_tree(tmp_path, build_js=f"m 'claude-small-x'\nm 'claude-top-x' // {marker}\n")
        result = _cli(tmp_path, "--all")
        assert result.returncode == 1, f"malformed marker {marker!r}: {result.stdout}{result.stderr}"


def test_cli_usage_error_exit_2(tmp_path: Path) -> None:
    result = _cli(tmp_path)  # no mode flag
    assert result.returncode == 2
