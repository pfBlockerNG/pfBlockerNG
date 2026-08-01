"""Cross-agent mode, Token Savior, and skill-plugin wiring."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODES = ("PONYTAIL", "CAVEMAN", "TOKEN-SAVIOR")


def _commands(path: str, event: str) -> str:
    config = json.loads((ROOT / path).read_text(encoding="utf-8"))
    return "\n".join(
        hook["command"] for group in config["hooks"][event] for hook in group["hooks"] if "command" in hook
    )


def test_modes_and_token_savior_reach_every_agent_start() -> None:
    for path in (".claude/settings.json", ".codex/hooks.json"):
        for event in ("SessionStart", "SubagentStart"):
            commands = _commands(path, event)
            missing = [mode for mode in MODES if mode not in commands]
            assert not missing, f"{path} {event} missing {missing}"


def test_token_savior_hooks_preserve_upstream_opt_in_defaults() -> None:
    for path in (".claude/settings.json", ".codex/hooks.json"):
        config = json.loads((ROOT / path).read_text(encoding="utf-8"))
        commands = json.dumps(config.get("hooks", {}).get("PostToolUse", []))
        assert "tool_capture_hook" in commands, f"{path} lost Token Savior lifecycle wiring"

        serialized = json.dumps(config)
        for variable in ("TS_BASH_COMPACT", "TS_BASH_REWRITE", "TS_CAPTURE_DISABLED"):
            assert variable not in serialized, f"{path} overrides opt-in {variable}"


def test_mattpocock_skills_are_project_enabled_for_claude_and_listed_for_codex() -> None:
    claude = json.loads((ROOT / ".claude/settings.json").read_text(encoding="utf-8"))
    assert claude["enabledPlugins"]["mattpocock-skills@mattpocock"] is True
    assert claude["extraKnownMarketplaces"]["mattpocock"]["source"] == {
        "source": "directory",
        "path": "./plugins/mattpocock-skills",
    }

    codex = json.loads((ROOT / ".agents/plugins/marketplace.json").read_text(encoding="utf-8"))
    entries = {plugin["name"] for plugin in codex["plugins"]}
    assert {"mattpocock-skills", "ponytail"} <= entries
