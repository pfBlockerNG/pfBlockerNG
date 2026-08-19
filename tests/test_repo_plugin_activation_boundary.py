"""External plugin activation belongs to user configuration, not this repository."""

import json
import re
from pathlib import Path

import pytest

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
    ".claude/hooks",
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


def _active_instruction_files(root: Path, surfaces: tuple[str, ...], directories: tuple[str, ...]) -> set[Path]:
    paths = {root / relative for relative in surfaces}
    for relative in directories:
        paths.update(path for path in (root / relative).rglob("*") if path.is_file())
    return paths


def _assert_no_external_plugin_activation(
    root: Path,
    surfaces: tuple[str, ...] = ACTIVE_SURFACES,
    directories: tuple[str, ...] = ACTIVE_DIRECTORIES,
) -> None:
    claude = json.loads((root / ".claude/settings.json").read_text(encoding="utf-8"))
    codex = json.loads((root / ".codex/hooks.json").read_text(encoding="utf-8"))
    assert {"enabledPlugins", "extraKnownMarketplaces"}.isdisjoint(claude)

    hook_commands = json.dumps((claude.get("hooks"), codex.get("hooks"))).lower()
    for token in ("ponytail", "caveman", *PLUGIN_BRIDGE_SCRIPTS):
        assert token not in hook_commands, f"repository hook still activates {token}"

    for path in _active_instruction_files(root, surfaces, directories):
        body = path.read_text(encoding="utf-8")
        for pattern in ACTIVATION_PATTERNS:
            assert not pattern.search(body), f"{path.relative_to(root)} still activates an external plugin"

    hooks = root / ".claude/hooks"
    assert not ({path.name for path in hooks.iterdir()} & PLUGIN_BRIDGE_SCRIPTS)


def test_repository_does_not_activate_external_plugins() -> None:
    _assert_no_external_plugin_activation(ROOT)


def test_boundary_rejects_prohibited_activation_fixture(tmp_path: Path) -> None:
    claude = tmp_path / ".claude"
    codex = tmp_path / ".codex"
    grok_rules = tmp_path / ".grok/rules"
    for directory in (claude / "hooks", codex, grok_rules):
        directory.mkdir(parents=True)
    (codex / "hooks.json").write_text('{"hooks":{}}', encoding="utf-8")
    (grok_rules / "harness.md").write_text("", encoding="utf-8")
    surfaces = (".claude/settings.json", ".codex/hooks.json")
    directories = (".claude/hooks", ".grok/rules")

    (claude / "settings.json").write_text(
        '{"hooks":{"SubagentStart":[{"hooks":[{"command":"activate Ponytail"}]}]}}', encoding="utf-8"
    )
    with pytest.raises(AssertionError, match="repository hook still activates ponytail"):
        _assert_no_external_plugin_activation(tmp_path, surfaces, directories)

    (claude / "settings.json").write_text('{"hooks":{}}', encoding="utf-8")
    (grok_rules / "harness.md").write_text("Activate Caveman at every session start.", encoding="utf-8")
    with pytest.raises(AssertionError, match="still activates an external plugin"):
        _assert_no_external_plugin_activation(tmp_path, surfaces, directories)
