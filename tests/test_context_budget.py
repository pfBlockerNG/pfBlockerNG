"""Tests for scripts/check_context_budget.py.

Every violation class is paired with its nearest clean sibling (the checker
must fire on the violating shape and stay quiet on the compliant one):
budgets per surface class, boundary at the exact budget,
routing-table extraction/resolution, both header shapes, capsule extraction,
and the conditional --staged/--diff trigger through the CLI against scratch
git repos. One test pins the live repository tree itself within budget.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "check_context_budget.py"
_spec = importlib.util.spec_from_file_location("check_context_budget", _TOOL)
assert _spec is not None and _spec.loader is not None
ccb = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ccb
_spec.loader.exec_module(ccb)

_REPO_ROOT = Path(__file__).resolve().parent.parent

_HEADER = "Scope: test file. Load when: testing.\n"

_BOOTSTRAP = """# Bootstrap

## Routing table — read on trigger, not up front

| Task touches | Read first |
| ------------ | ---------- |
| policy work | `.agents/policy/alpha.md` |
| context work | `beta.md` |
| languages | `lang-<php\\|python\\|shell>.md` per touched language |

## After

Prose mentioning `outside.md` that is not a routing row.
"""

_HOSTILE_BOOTSTRAP = """# Bootstrap

## Routing table — read on trigger, not up front

| Task touches | Read first |
| ------------ | ---------- |
| policy work | `.agents/policy/alpha.md` |
| empty group | `<>.md` |
| empty alts both | `<|>.md` |
| empty alt middle | `<a||b>.md` |
| unclosed group | `lang-<php|python.md` |
| two groups | `a<b|c>d<e|f>g.md` |
"""

_PARITY_AGENTS = """# Doc

Never assume — read the source of truth, investigate the live state, and confirm a
genuine fork before building.

Delegation shape: substantial coding work is planned by the **top tier**, implemented
by small-tier agents.
"""


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _scratch_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    _write(root, "AGENTS.md", _BOOTSTRAP)
    _write(root, ".agents/policy/alpha.md", f"# Alpha\n\n{_HEADER}")
    _write(root, ".agents/context/beta.md", f"# Beta\n\n{_HEADER}")
    # _BOOTSTRAP's `lang-<php\|python\|shell>.md` row now expands (map #1439) —
    # all three alternatives must resolve for this fixture to stay header-clean.
    _write(root, ".agents/context/lang-php.md", f"# PHP\n\n{_HEADER}")
    _write(root, ".agents/context/lang-python.md", f"# Python\n\n{_HEADER}")
    _write(root, ".agents/context/lang-shell.md", f"# Shell\n\n{_HEADER}")
    subprocess.run(["git", "init", "-q", root], check=True)
    subprocess.run(["git", "-C", root, "add", "-A"], check=True)
    return root


def _tracked(root: Path) -> list[str]:
    out = subprocess.run(["git", "-C", root, "ls-files"], capture_output=True, text=True, check=True).stdout
    return [line for line in out.split("\n") if line]


# --- budget_for: one assertion per surface class -------------------------------


@pytest.mark.parametrize(
    ("rel", "budget"),
    [
        ("AGENTS.md", 10_240),
        ("CLAUDE.md", 8_192),
        (".agents/policy/new-policy.md", 12_288),
        (".agents/context/new-context.md", 12_288),
        (".agents/policy/landing.md", 26_000),
        (".agents/policy/agent-roles.md", 19_000),
        (".agents/policy/delegation.md", 18_000),
        ("tests/smoke/CLAUDE.md", 400),
        ("src/usr/local/AGENTS.md", 400),
        # Nested stubs under .agents/ are dir stubs, not routed policy files —
        # the stub branch must win over the policy/context prefix.
        (".agents/context/sub/AGENTS.md", 400),
        (".agents/policy/sub/CLAUDE.md", 400),
        ("plugins/ponytail/AGENTS.md", None),
        ("src/usr/local/pkg/pfblockerng/pfblockerng.inc", None),
        ("docs/misc/architecture-notes.md", None),
        (".claude/rules/smoke.md", 400),
        (".claude/rules/sub/deep.md", 400),
        # A `plugins/` segment ANYWHERE (not just root-anchored) is vendored.
        (".claude/plugins/foo/CLAUDE.md", None),
    ],
)
def test_budget_for_surface_classes(rel: str, budget: int | None) -> None:
    assert ccb.budget_for(rel) == budget


def test_size_over_budget_fires_and_at_budget_passes(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, ".agents/policy/fat.md", "x" * 12_289)
    _write(root, ".agents/policy/exact.md", "x" * 12_288)
    violations = ccb.check_sizes(root, [".agents/policy/fat.md", ".agents/policy/exact.md"])
    assert violations == [".agents/policy/fat.md: 12289 bytes > budget 12288"]


def test_nested_stub_over_budget_fires_root_files_use_own_budget(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, "www/CLAUDE.md", "x" * 401)
    _write(root, "AGENTS.md", "x" * 401)  # root bootstrap: 401 B is far under 10,240
    violations = ccb.check_sizes(root, ["www/CLAUDE.md", "AGENTS.md"])
    assert violations == ["www/CLAUDE.md: 401 bytes > budget 400"]


def test_size_of_missing_tracked_file_fails_closed(tmp_path: Path) -> None:
    # Tracked-but-deleted (deletion unstaged) must yield a violation, not a traceback.
    violations = ccb.check_sizes(tmp_path, [".agents/policy/gone.md"])
    assert len(violations) == 1 and violations[0].startswith(".agents/policy/gone.md: unreadable")


def test_rules_budget_over_fires_and_at_budget_passes(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, ".claude/rules/x.md", "x" * 401)
    _write(root, ".claude/rules/y.md", "x" * 400)
    violations = ccb.check_sizes(root, [".claude/rules/x.md", ".claude/rules/y.md"])
    assert violations == [".claude/rules/x.md: 401 bytes > budget 400"]


def test_nested_plugins_segment_oversized_stub_has_no_budget(tmp_path: Path) -> None:
    # A `plugins/` segment anywhere in the path is vendored content, not our dir
    # stub — no budget applies, so an oversized file here is not a violation.
    root = tmp_path
    _write(root, ".claude/plugins/foo/CLAUDE.md", "x" * 500)
    assert ccb.check_sizes(root, [".claude/plugins/foo/CLAUDE.md"]) == []


# --- routing-table extraction and resolution -----------------------------------


def test_routing_targets_extracts_table_rows_only() -> None:
    # The `lang-<php\|python\|shell>.md` template row expands into three concrete
    # tokens now (markdown-escaped pipes stripped) — it is no longer skipped.
    tokens, skipped = ccb.routing_targets(_BOOTSTRAP)
    assert tokens == [".agents/policy/alpha.md", "beta.md", "lang-php.md", "lang-python.md", "lang-shell.md"]
    assert skipped == []


def test_routing_targets_hostile_templates_skip_without_crash() -> None:
    tokens, skipped = ccb.routing_targets(_HOSTILE_BOOTSTRAP)
    assert tokens == [".agents/policy/alpha.md"]
    assert skipped == ["<>.md", "<|>.md", "<a||b>.md", "lang-<php|python.md", "a<b|c>d<e|f>g.md"]


def test_resolve_target_bare_token_searches_policy_context_docs(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    assert ccb.resolve_target(root, "beta.md") == ".agents/context/beta.md"
    assert ccb.resolve_target(root, ".agents/policy/alpha.md") == ".agents/policy/alpha.md"
    assert ccb.resolve_target(root, "missing.md") is None


def test_check_headers_clean_tree_passes(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    assert ccb.check_headers(root) == []


def test_check_headers_flags_unresolvable_target(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    (root / ".agents/context/beta.md").unlink()
    assert ccb.check_headers(root) == ["AGENTS.md: routing target `beta.md` does not resolve to a file"]


def test_check_headers_flags_missing_header(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    _write(root, ".agents/context/beta.md", "# Beta\n\nNo routing header here.\n")
    violations = ccb.check_headers(root)
    assert violations == [".agents/context/beta.md: routed file lacks a Scope: + Load-when: header (first 12 lines)"]


def test_check_headers_flags_renamed_routing_table_heading(tmp_path: Path) -> None:
    # Zero extracted targets must be a violation, not a vacuous pass — otherwise
    # renaming the "## Routing table" heading disarms the whole header gate.
    root = _scratch_repo(tmp_path)
    _write(root, "AGENTS.md", _BOOTSTRAP.replace("## Routing table", "## Where to read"))
    _write(root, ".agents/context/beta.md", "# Beta\n\nNo routing header here.\n")
    violations = ccb.check_headers(root)
    assert violations == ["AGENTS.md: no routing-table targets extracted — heading renamed or table removed?"]


def test_check_headers_expanded_template_flags_missing_alternative(tmp_path: Path) -> None:
    # _scratch_repo ships all three lang-*.md alternatives already (fixture must
    # stay header-clean by default) — remove one to prove the expansion resolves
    # and header-checks each alternative independently.
    root = _scratch_repo(tmp_path)
    (root / ".agents/context/lang-shell.md").unlink()
    violations = ccb.check_headers(root)
    assert violations == ["AGENTS.md: routing target `lang-shell.md` does not resolve to a file"]


def test_check_headers_expanded_template_all_alternatives_present_clean(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    assert ccb.check_headers(root) == []


def test_check_headers_hostile_templates_skip_silently_no_crash(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, "AGENTS.md", _HOSTILE_BOOTSTRAP)
    _write(root, ".agents/policy/alpha.md", f"# Alpha\n\n{_HEADER}")
    assert ccb.check_headers(root) == []


# --- both header shapes accepted; window enforced ------------------------------


@pytest.mark.parametrize(
    "header",
    [
        "Scope: things. Load when: touching things.",
        "- **Scope:** things over multiple words.\n- **Load-when:** touching things.",
    ],
)
def test_has_context_header_accepts_both_house_shapes(header: str) -> None:
    assert ccb.has_context_header(f"# Title\n\n{header}\n")


@pytest.mark.parametrize(
    "text",
    [
        "# Title\n\nLoad when: no scope line.\n",
        "# Title\n\nScope: no load-when line.\n",
        "# Title\n" + "\n" * 12 + "Scope: too late. Load when: beyond the window.\n",
    ],
)
def test_has_context_header_rejects_missing_or_late_fields(text: str) -> None:
    assert not ccb.has_context_header(text)


# --- capsule extraction and budget ---------------------------------------------


def _settings(capsule: str) -> str:
    payload = json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": capsule}})
    return json.dumps(
        {
            "hooks": {
                "SessionStart": [{"hooks": [{"type": "command", "command": f"echo '{payload}'"}]}],
                "PreToolUse": [{"hooks": [{"type": "command", "command": "true"}]}],
            }
        }
    )


def _settings_ups(capsule: str) -> str:
    payload = json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": capsule}})
    return json.dumps(
        {"hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": f"echo '{payload}'"}]}]}}
    )


def test_extract_capsules_measures_payload_bytes() -> None:
    # extract_capsules now returns the capsule TEXT per event, not a precomputed
    # byte length — byte-length is derived by the caller where it matters.
    capsules, errors = ccb.extract_capsules(_settings("abc"))
    assert capsules == [("SessionStart", "abc")] and errors == []
    assert len(capsules[0][1].encode("utf-8")) == 3


def test_check_capsules_flags_over_budget_only(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, ".claude/settings.json", _settings("x" * 1_801))
    assert ccb.check_capsules(root) == [".claude/settings.json: SessionStart capsule 1801 bytes > budget 1800"]
    _write(root, ".claude/settings.json", _settings("x" * 1_800))
    assert ccb.check_capsules(root) == []


def test_extract_capsules_reports_unextractable_payload() -> None:
    settings = json.dumps(
        {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "emit-additionalContext.sh 'oops"}]}]}}
    )
    capsules, errors = ccb.extract_capsules(settings)
    assert capsules == []
    assert errors == [".claude/settings.json: SessionStart capsule payload is not extractable JSON"]


@pytest.mark.parametrize(
    "settings_text",
    [
        "{not json",  # parse error
        '{"hooks": ["not", "a", "dict"]}',  # valid JSON, hooks is a list
        '["top-level list"]',  # valid JSON, wrong top-level shape
        '{"hooks": {"SessionStart": "not-entries"}}',  # entries not a list of dicts
    ],
)
def test_extract_capsules_malformed_settings_fails_closed(settings_text: str) -> None:
    capsules, errors = ccb.extract_capsules(settings_text)
    assert capsules == []
    assert errors == [".claude/settings.json: not a parseable hooks structure — capsule budgets unverifiable"]


def test_run_checks_reports_size_violations_despite_malformed_settings(tmp_path: Path) -> None:
    # A capsule-check failure must not swallow violations the other checks found.
    root = _scratch_repo(tmp_path)
    _write(root, ".agents/policy/alpha.md", "# Alpha\n\n" + _HEADER + "x" * 20_000)
    _write(root, ".claude/settings.json", '{"hooks": ["not", "a", "dict"]}')
    violations = ccb.run_checks(root, [".agents/policy/alpha.md", ".claude/settings.json"])
    assert any("> budget 12288" in v for v in violations)
    assert any("not a parseable hooks structure" in v for v in violations)


# --- UserPromptSubmit capsule <-> AGENTS.md parity ------------------------------


def test_check_parity_all_verbatim_segments_clean(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, "AGENTS.md", _PARITY_AGENTS)
    capsule = (
        "DISCIPLINE: read the source of truth, investigate the live state, and confirm a "
        "genuine fork before building. · planned by the top tier, implemented by small-tier agents."
    )
    _write(root, ".claude/settings.json", _settings_ups(capsule))
    assert ccb.check_parity(root) == []


def test_check_parity_alien_segment_flags_violation(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, "AGENTS.md", _PARITY_AGENTS)
    _write(root, ".claude/settings.json", _settings_ups("DISCIPLINE: totally alien text absent from agents md"))
    violations = ccb.check_parity(root)
    assert len(violations) == 1
    assert "totally alien text absent from agents md" in violations[0]


def test_check_parity_no_user_prompt_submit_capsule_clean(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, "AGENTS.md", _PARITY_AGENTS)
    _write(root, ".claude/settings.json", _settings("abc"))  # SessionStart capsule only
    assert ccb.check_parity(root) == []


def test_check_parity_capsule_without_colon_shape_flags_violation(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, "AGENTS.md", _PARITY_AGENTS)
    _write(root, ".claude/settings.json", _settings_ups("no colon separator here at all"))
    violations = ccb.check_parity(root)
    assert len(violations) == 1
    assert "UserPromptSubmit" in violations[0]


def test_check_parity_segments_split_only_on_middle_dot_not_colon(tmp_path: Path) -> None:
    # "alpha" and "beta" each appear standalone in AGENTS.md, but "alpha: beta" as a
    # contiguous phrase does not — proves the per-segment text is never re-split (or
    # re-partitioned) on ":", only the outer remainder is ever split, and only on " · ".
    root = tmp_path
    _write(root, "AGENTS.md", "# Doc\n\nalpha appears standalone here.\n\nbeta appears standalone here too.\n")
    _write(root, ".claude/settings.json", _settings_ups("Label: alpha: beta"))
    violations = ccb.check_parity(root)
    assert len(violations) == 1
    assert "alpha: beta" in violations[0]


def test_check_parity_live_repository_user_prompt_submit_clean() -> None:
    # Pins the step-1 UserPromptSubmit capsule content against the live AGENTS.md.
    assert ccb.check_parity(_REPO_ROOT) == []


# --- conditional trigger -------------------------------------------------------


@pytest.mark.parametrize(
    "rel",
    [
        "AGENTS.md",
        "CLAUDE.md",
        ".claude/settings.json",
        "scripts/check_context_budget.py",
        ".agents/policy/alpha.md",
        ".agents/context/beta.md",
        "docs/misc/architecture-notes.md",
        "tests/smoke/CLAUDE.md",
        ".claude/rules/smoke.md",
    ],
)
def test_touches_context_surface_true(rel: str) -> None:
    assert ccb.touches_context_surface(["src/other.inc", rel])


def test_touches_context_surface_false_on_unrelated() -> None:
    assert not ccb.touches_context_surface(["src/usr/local/www/x.php", "docs/history/incidents.md"])


# --- CLI against scratch repos -------------------------------------------------


def _run_cli(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_TOOL), *args, "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_staged_skips_when_no_context_surface_staged(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    subprocess.run(
        ["git", "-C", root, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "base"],
        check=True,
    )
    _write(root, ".agents/policy/alpha.md", "# Alpha\n\n" + _HEADER + "x" * 20_000)
    _write(root, "src/thing.inc", "<?php\n")
    subprocess.run(["git", "-C", root, "add", "src/thing.inc"], check=True)
    proc = _run_cli(root, "--staged")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "skipped" in proc.stdout


def test_cli_staged_runs_and_fails_on_staged_over_budget_policy(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    subprocess.run(
        ["git", "-C", root, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "base"],
        check=True,
    )
    _write(root, ".agents/policy/alpha.md", "# Alpha\n\n" + _HEADER + "x" * 20_000)
    subprocess.run(["git", "-C", root, "add", "-A"], check=True)
    proc = _run_cli(root, "--staged")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert ".agents/policy/alpha.md" in proc.stdout and "> budget 12288" in proc.stdout


def test_cli_staged_checks_index_content_not_working_tree(tmp_path: Path) -> None:
    # Staged over-budget + worktree fixed back under budget: the commit would
    # still ship the violation, so --staged must fail (index is the snapshot).
    root = _scratch_repo(tmp_path)
    subprocess.run(
        ["git", "-C", root, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "base"],
        check=True,
    )
    _write(root, ".agents/policy/alpha.md", "# Alpha\n\n" + _HEADER + "x" * 20_000)
    subprocess.run(["git", "-C", root, "add", "-A"], check=True)
    _write(root, ".agents/policy/alpha.md", f"# Alpha\n\n{_HEADER}")
    proc = _run_cli(root, "--staged")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert ".agents/policy/alpha.md" in proc.stdout and "> budget 12288" in proc.stdout


def test_cli_staged_ignores_unstaged_working_tree_violation(tmp_path: Path) -> None:
    # Staged content clean + worktree bloated: the commit ships the clean index,
    # so --staged must pass instead of false-failing on the dirty worktree.
    root = _scratch_repo(tmp_path)
    subprocess.run(
        ["git", "-C", root, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "base"],
        check=True,
    )
    _write(root, ".agents/policy/alpha.md", f"# Alpha (tweaked)\n\n{_HEADER}")
    subprocess.run(["git", "-C", root, "add", "-A"], check=True)
    _write(root, ".agents/policy/alpha.md", "# Alpha\n\n" + _HEADER + "x" * 20_000)
    proc = _run_cli(root, "--staged")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_cli_diff_fires_on_over_budget_commit_vs_base(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    git = ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.com"]
    subprocess.run([*git, "commit", "-qm", "base"], check=True)
    _write(root, ".agents/policy/alpha.md", "# Alpha\n\n" + _HEADER + "x" * 20_000)
    subprocess.run(["git", "-C", root, "add", "-A"], check=True)
    subprocess.run([*git, "commit", "-qm", "bloat"], check=True)
    proc = _run_cli(root, "--diff", "HEAD~1")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert ".agents/policy/alpha.md" in proc.stdout and "> budget 12288" in proc.stdout


def test_cli_all_flags_non_ascii_named_policy_file(tmp_path: Path) -> None:
    # Under default core.quotePath, ls-files C-quotes non-ASCII names and the
    # quoted string would match no budget — the checker must still see the file.
    root = _scratch_repo(tmp_path)
    _write(root, ".agents/policy/pölicy.md", "# P\n\n" + _HEADER + "x" * 20_000)
    subprocess.run(["git", "-C", root, "add", "-A"], check=True)
    proc = _run_cli(root, "--all")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    # NFC/NFD filename normalization differs per OS — match the ASCII tail only.
    assert "licy.md" in proc.stdout and "> budget 12288" in proc.stdout


def test_cli_all_clean_scratch_repo_exits_zero(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    proc = _run_cli(root, "--all")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_cli_all_missing_git_exits_two(tmp_path: Path) -> None:
    proc = _run_cli(tmp_path / "not-a-repo", "--all")
    assert proc.returncode == 2


# --- CI wiring ------------------------------------------------------------------


def test_ci_workflow_paths_match_checker_triggers() -> None:
    # The gate rides its own path-filtered workflow (test.yml's global
    # `paths-ignore: '**/*.md'` would skip an md-only change — the exact class
    # this gate polices). Both trigger blocks must mirror the checker's surfaces.
    text = (_REPO_ROOT / ".github/workflows/context-budget.yml").read_text(encoding="utf-8")
    expected = (
        set(ccb._TRIGGER_FILES)
        | {f"{d}**" for d in ccb._TRIGGER_DIRS}
        # the basename trigger (nested dir stubs anywhere) as workflow globs:
        | {"**/AGENTS.md", "**/CLAUDE.md"}
    )
    # Compare each trigger block INDEPENDENTLY: the two hand-duplicated paths
    # lists drift exactly one-block-at-a-time, and a whole-file set comparison
    # cannot see an entry dropped from only one of them.
    assert "push:" in text, "md-only pushes straight to devel are the dominant re-accretion vector"
    push_block, _, tail = text.partition("pull_request:")
    pr_block = tail.partition("permissions:")[0]
    for name, block in (("push", push_block), ("pull_request", pr_block)):
        listed = re.findall(r"^\s+- '([^']+)'\s*$", block, re.MULTILINE)
        assert len(listed) == len(expected), f"{name} paths list has duplicates or gaps: {sorted(listed)}"
        assert set(listed) == expected, f"{name} paths {sorted(listed)} != checker triggers {sorted(expected)}"


# --- the live tree stays within its own budgets --------------------------------


def test_live_repository_tree_is_clean() -> None:
    tracked = _tracked(_REPO_ROOT)
    assert ccb.run_checks(_REPO_ROOT, tracked) == []
