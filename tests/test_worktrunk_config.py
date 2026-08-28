import tomllib
from pathlib import Path

import pytest

from tests._workflow_steps import extract_between

ROOT = Path(__file__).resolve().parents[1]
PROJECT_CONFIG = ROOT / ".config" / "wt.toml"
WORKTREE_DOCS = (
    ROOT / ".agents" / "policy" / "git.md",
    ROOT / ".agents" / "context" / "repository-intelligence.md",
)
LANDING_POLICY = ROOT / ".agents" / "policy" / "landing.md"
REQUIRED_HOOKS = {
    "pre-start": "sh scripts/agent/init-worktree-tools.sh .",
    "post-merge": "git worktree prune",
    "post-remove": "git worktree prune",
}


def test_tracked_worktrunk_project_config_defines_required_hooks() -> None:
    assert PROJECT_CONFIG.is_file(), "tracked project config .config/wt.toml is missing"
    config = tomllib.loads(PROJECT_CONFIG.read_text(encoding="utf-8"))

    missing = REQUIRED_HOOKS.keys() - config.keys()
    assert not missing, f"missing required Worktrunk hooks: {sorted(missing)}"
    assert {hook: config[hook] for hook in REQUIRED_HOOKS} == REQUIRED_HOOKS


def _assert_supported_creation_command(text: str, source: str) -> None:
    assert "wt start" not in text, f"{source} documents nonexistent `wt start`"
    assert "wt --yes switch --create" in text, f"{source} must document noninteractive `wt --yes switch --create`"


def test_worktrunk_docs_use_the_supported_creation_command() -> None:
    for path in WORKTREE_DOCS:
        _assert_supported_creation_command(path.read_text(encoding="utf-8"), str(path.relative_to(ROOT)))


def test_worktrunk_creation_guard_rejects_the_legacy_command() -> None:
    fixture = "Use wt start only after wt --yes switch --create was attempted."
    with pytest.raises(AssertionError, match="nonexistent"):
        _assert_supported_creation_command(fixture, "fixture")


def test_landing_fetches_before_json_cleanup_and_reports_branch_deletion() -> None:
    landing = LANDING_POLICY.read_text(encoding="utf-8")
    merge_section = extract_between(landing, "## Merge step", "## Post-merge")

    merged = merge_section.index("PR's state must read `MERGED`")
    fetch = merge_section.index("Run `git fetch origin` after that verification", merged)
    remove = merge_section.index("wt remove --foreground --format=json --yes <head>", fetch)
    outcome = merge_section.index("Inspect and report its JSON `branch_outcome`", remove)
    deleted = merge_section.index("requires `deleted`", outcome)
    retained = merge_section.index("For any other branch-deletion outcome, retain the local branch", deleted)
    safe = merge_section.index("Never force removal or branch deletion here", retained)

    assert merged < fetch < remove < outcome < deleted < retained < safe
