import tomllib
from pathlib import Path

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


def test_worktrunk_docs_use_the_supported_creation_command() -> None:
    for path in WORKTREE_DOCS:
        text = path.read_text(encoding="utf-8")
        assert "wt start" not in text, f"{path.relative_to(ROOT)} documents nonexistent `wt start`"
        assert "wt switch --create" in text, f"{path.relative_to(ROOT)} must document `wt switch --create`"


def test_landing_fetches_before_json_cleanup_and_reports_branch_deletion() -> None:
    landing = LANDING_POLICY.read_text(encoding="utf-8")

    merged = landing.index("PR's state must read `MERGED`")
    fetch = landing.index("git fetch origin", merged)
    remove = landing.index("wt remove --foreground --format=json --yes <head>", fetch)
    outcome = landing.index("`branch_outcome`", remove)
    deleted = landing.index("`deleted`", outcome)
    reported = landing.index("branch-deletion outcome", deleted)

    assert merged < fetch < remove < outcome < deleted < reported
