"""External plugin activation belongs to user configuration, not this repository."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACTIVE_SURFACES = (
    "AGENTS.md",
    "CLAUDE.md",
    "GROK.md",
    ".agents/context/codex-adapter.md",
    ".agents/policy/delegation.md",
    ".claude/settings.json",
    ".codex/hooks.json",
    ".github/copilot-instructions.md",
    "docs/misc/codex-migration.md",
)
PLUGIN_BRIDGE_SCRIPTS = {
    "caveman-rolling.sh",
    "caveman-stats-refresh.sh",
    "plugin-install-path.sh",
    "statusline-rolling.sh",
    "statusline.sh",
}


def test_repository_does_not_activate_external_plugins() -> None:
    claude = json.loads((ROOT / ".claude/settings.json").read_text(encoding="utf-8"))
    assert {"enabledPlugins", "extraKnownMarketplaces", "statusLine"}.isdisjoint(claude)
    assert "Stop" not in claude["hooks"]
    assert "SubagentStart" not in claude["hooks"]

    for relative in ACTIVE_SURFACES:
        body = (ROOT / relative).read_text(encoding="utf-8").lower()
        assert "ponytail" not in body, f"{relative} still activates Ponytail"
        assert "caveman" not in body, f"{relative} still activates Caveman"

    hooks = ROOT / ".claude/hooks"
    assert not ({path.name for path in hooks.iterdir()} & PLUGIN_BRIDGE_SCRIPTS)
