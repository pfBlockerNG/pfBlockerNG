"""External plugin activation belongs to user configuration, not this repository."""

import json
import re
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
ACTIVE_DIRECTORIES = (
    ".agents/context",
    ".agents/policy",
    ".claude/rules",
    ".codex/agents",
    ".github/agents",
    ".grok/rules",
)
PLUGIN_BRIDGE_SCRIPTS = {
    "caveman-rolling.sh",
    "caveman-stats-refresh.sh",
    "plugin-install-path.sh",
    "statusline-rolling.sh",
    "statusline.sh",
}
ACTIVATION_PATTERNS = (
    re.compile(r"\b(?:activate|enable|load(?:ing)?)\b[^\n]{0,120}\b(?:ponytail|caveman)\b", re.IGNORECASE),
    re.compile(r"\b(?:ponytail|caveman)\b[^\n]{0,120}\b(?:active|activation|enable|mode)\b", re.IGNORECASE),
)


def _active_instruction_files() -> set[Path]:
    paths = {ROOT / relative for relative in ACTIVE_SURFACES}
    for relative in ACTIVE_DIRECTORIES:
        paths.update(path for path in (ROOT / relative).rglob("*") if path.is_file())
    return paths


def test_repository_does_not_activate_external_plugins() -> None:
    claude = json.loads((ROOT / ".claude/settings.json").read_text(encoding="utf-8"))
    codex = json.loads((ROOT / ".codex/hooks.json").read_text(encoding="utf-8"))
    assert {"enabledPlugins", "extraKnownMarketplaces"}.isdisjoint(claude)

    hook_commands = json.dumps((claude.get("hooks"), codex.get("hooks"))).lower()
    for token in ("ponytail", "caveman", *PLUGIN_BRIDGE_SCRIPTS):
        assert token not in hook_commands, f"repository hook still activates {token}"

    for path in _active_instruction_files():
        body = path.read_text(encoding="utf-8")
        for pattern in ACTIVATION_PATTERNS:
            assert not pattern.search(body), f"{path.relative_to(ROOT)} still activates an external plugin"

    hooks = ROOT / ".claude/hooks"
    assert not ({path.name for path in hooks.iterdir()} & PLUGIN_BRIDGE_SCRIPTS)
